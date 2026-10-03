import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from triage import allow_reply
from triage.commands import (
    Command,
    allow_entries_for,
    allow_problems,
    append_block,
    block_problems,
    entries_for,
    entry_block,
    insert_allow_block,
    parse,
)
from triage.discord import Discord, plain_embed
from triage.github_api import GitHub
from triage.issue_form import IssueRequest, from_issue
from triage.repo_ops import MergeConflict, RepoOps
from triage.state import TriageState, parse_state

CHANGE_ATTEMPTS = 4
TIMING_NOW = "A rebuild has started, so the change will be in the lists once that run finishes."
TIMING_WEEKLY = "It takes effect at the next weekly rebuild (Sundays 00:00 UTC)."


@dataclass
class Actor:
    login: str
    api_key: str | None = None


@dataclass
class Merged:
    pr: int
    pr_url: str
    entries: list[str]
    timing: str


def run(number: int, comment_id: int, repo_root: Path, discord: Discord | None) -> int:
    github = GitHub.from_env()
    ops = RepoOps(github)
    comment = github.comment(number, comment_id)
    if comment.get("author_association") != "OWNER":
        print("ignoring: command is not from the repository owner")
        return 0
    command = parse(comment.get("body") or "")
    if command is None:
        return 0
    if command.error:
        return refuse(ops, number, comment_id, command.error)
    issue = github.issue(number)
    actor = Actor((comment.get("user") or {}).get("login", ""), os.environ.get("MINIMAX_API_KEY"))
    try:
        return handle(github, ops, issue, command, comment_id, repo_root, discord, actor)
    except Exception as error:
        ops.comment(number, f"`/{command.action}` failed: {type(error).__name__}: {error}\n\nIf no merged PR is linked above, nothing was changed.")
        ops.react(comment_id, "confused")
        raise


def refuse(ops: RepoOps, number: int, comment_id: int, reason: str) -> int:
    ops.comment(number, reason)
    ops.react(comment_id, "confused")
    return 0


def handle(github: GitHub, ops: RepoOps, issue: dict, command: Command, comment_id: int, repo_root: Path, discord: Discord | None, actor: Actor | None = None) -> int:
    number = issue["number"]
    if command.action == "retriage":
        ops.dispatch("issue-triage.yml", {"issue": str(number)})
        ops.react(comment_id, "rocket")
        return 0
    if command.action == "decline":
        ops.add_labels(number, ["declined"])
        ops.comment(number, command.message or "Closing this without a change to the lists.")
        ops.close_issue(number, "not_planned")
        ops.react(comment_id, "rocket")
        return 0
    if issue.get("state") != "open":
        return refuse(ops, number, comment_id, "This issue is closed. Reopen it first if you want to change the lists from here.")
    state = parse_state((github.report(number) or {}).get("body"))
    request = from_issue(issue)
    domains = command.domains or [d for d in (request.domain or (state.domain if state else None),) if d]
    if not domains:
        return refuse(ops, number, comment_id, "There's no valid domain on this issue. Name one, e.g. `/block example.com`.")
    problems = block_problems(domains, repo_root) if command.action == "block" else allow_problems(domains, repo_root, command.scope)
    if problems:
        return refuse(ops, number, comment_id, "Nothing changed:\n" + "\n".join(f"- {p}" for p in problems))
    merged = change(ops, issue, command, domains, state, request.category, request.service)
    if command.action == "block":
        closing = f"Blocked in #{merged.pr} ({', '.join(f'`{entry}`' for entry in merged.entries)}). {merged.timing}"
        ops.comment(number, f"{command.message}\n\n{closing}" if command.message else closing)
    else:
        closing = allow_reply.closing_line(merged.pr, merged.entries, command.scope, merged.timing)
        post_allow_replies(ops, command, domains, state, request, merged, closing, actor or Actor(""))
    ops.close_issue(number, "completed")
    if discord:
        verb = "Blocked" if command.action == "block" else "Allowed"
        discord.send(f"{verb} {', '.join(domains)} from #{number}.", plain_embed(number, issue["title"], merged.pr_url, command.action, closing), ping=False)
    ops.react(comment_id, "rocket")
    return 0


def file_note(command: Command, domains: list[str], state: TriageState | None, number: int, pr: int | None) -> str:
    reported = bool(state and state.domain in domains)
    reason = command.message.split("\n\n")[0].strip() if command.message else ""
    if not reason:
        reason = state.site if reported and state.site else "found while triaging this issue"
    evidence = state.evidence if reported and state.evidence else ""
    source = f"(#{number}, PR #{pr})" if pr else f"(#{number})"
    parts = [f"{', '.join(domains)}: {reason}".rstrip(": "), evidence, source]
    return " ".join(part.rstrip(".") + "." if part != source else part for part in parts if part)


def post_allow_replies(ops: RepoOps, command: Command, domains: list[str], state: TriageState | None, request: IssueRequest, merged: Merged, closing: str, actor: Actor) -> None:
    ops.comment(request.number, allow_reply.mention(actor.login, closing))
    context = allow_reply.reply_context(domains, merged.entries, command.scope, merged.pr, merged.timing, request, state)
    ops.comment(request.number, allow_reply.reporter_comment(request.author, command.message, context, actor.api_key))


def change_once(ops: RepoOps, issue: dict, command: Command, domains: list[str], state: TriageState | None, category: str | None, service: str) -> Merged:
    number = issue["number"]
    block = command.action == "block"
    category = command.category or category or "malicious"
    path = f"custom/{category}.txt" if block else "whitelist.txt"
    entries = entries_for(domains, command.exact) if block else allow_entries_for(domains, command.scope)
    more = " and others" if len(domains) > 1 else ""
    title = f"feat(blocklist): add {domains[0]}{more} to {category} list" if block else f"fix(whitelist): add {domains[0]}{more} for {service.strip() or 'reported false positive'}"
    today = datetime.now(UTC).strftime("%d/%m/%Y")
    original, sha = ops.read_file(path, "main")

    def render(pr: int | None) -> str:
        text = entry_block(entries, file_note(command, domains, state, number, pr))
        return append_block(original, text) if block else insert_allow_block(original, text, today, f"Allowlisted {', '.join(domains)} (#{number})")

    branch = f"triage/issue-{number}-{command.action}-{int(time.time())}"
    ops.create_branch(branch, ops.main_sha())
    sha = ops.write_file(path, branch, render(None), sha, title)
    pr, pr_url = ops.open_pr(title, branch, pr_body(command, domains, entries, path, state, number))
    ops.write_file(path, branch, render(pr), sha, f"docs: reference PR #{pr}")
    try:
        ops.merge_pr(pr, title)
    except MergeConflict:
        ops.close_pr(pr)
        ops.delete_branch(branch)
        raise
    ops.delete_branch(branch)
    if command.now:
        ops.dispatch("update-blocklists.yml")
    return Merged(pr, pr_url, entries, TIMING_NOW if command.now else TIMING_WEEKLY)


def change(ops: RepoOps, issue: dict, command: Command, domains: list[str], state: TriageState | None, category: str | None, service: str) -> Merged:
    for attempt in range(CHANGE_ATTEMPTS):
        try:
            return change_once(ops, issue, command, domains, state, category, service)
        except MergeConflict:
            if attempt == CHANGE_ATTEMPTS - 1:
                raise
    raise AssertionError("unreachable")


def pr_body(command: Command, domains: list[str], entries: list[str], path: str, state: TriageState | None, number: int) -> str:
    lines = [f"Adds {', '.join(f'`{e}`' for e in entries)} to `{path}`, from the maintainer's `/{command.action}` command on #{number}."]
    if state and state.evidence and state.domain in domains:
        lines += ["", f"Evidence from the triage report: {state.evidence}"]
    if command.message:
        lines += ["", command.message]
    lines += ["", f"Closes #{number}"]
    return "\n".join(lines)
