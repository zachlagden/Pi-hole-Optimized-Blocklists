import json
import os
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from triage import allow_reply
from triage.commands import (
    Command,
    allow_entries_for,
    append_block,
    entries_for,
    entry_block,
    insert_allow_block,
    normalized_domains,
    parse,
    plan_domains,
)
from triage.discord import Discord, plain_embed
from triage.github_api import GitHub
from triage.issue_form import from_issue
from triage.publication import MAX_DOMAINS, PendingChange
from triage.repo_ops import MergeConflict, RepoOps
from triage.state import TriageState, parse_state

CHANGE_ATTEMPTS = 4
TIMING_NOW = "A rebuild was queued. Publication is pending verification of a successful build."
TIMING_WEEKLY = "Publication is pending the next successful weekly rebuild (Sundays 00:00 UTC)."


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
    domains: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    path: str = ""
    merge_sha: str = ""
    failures: list[str] = field(default_factory=list)


@dataclass
class CommandOutcome:
    status: str
    pr: int | None = None
    pr_url: str = ""
    skipped: list[str] = field(default_factory=list)
    failed_stages: list[str] = field(default_factory=list)
    merged: bool = False


class RefusedChange(Exception):
    pass


class SkippedChange(Exception):
    def __init__(self, skipped: list[str]) -> None:
        self.skipped = skipped


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
    issue = github.issue(number)
    actor = Actor((comment.get("user") or {}).get("login", ""), os.environ.get("MINIMAX_API_KEY"))
    try:
        outcome = refuse(ops, number, comment_id, command.error) if command.error else handle(github, ops, issue, command, comment_id, repo_root, discord, actor)
    except Exception as error:
        print(json.dumps({"status": "failed", "stage": "merge result not recorded", "error_type": type(error).__name__}))
        ops.comment(number, f"`/{command.action}` could not complete merge processing ({type(error).__name__}). The merge outcome was not confirmed; check related PRs before retrying.")
        ops.react(comment_id, "confused")
        return 1
    print(json.dumps(asdict(outcome), sort_keys=True))
    return 1 if outcome.failed_stages else 0


def refuse(ops: RepoOps, number: int, comment_id: int, reason: str) -> CommandOutcome:
    ops.comment(number, reason)
    ops.react(comment_id, "confused")
    return CommandOutcome("refused")


def handle(github: GitHub, ops: RepoOps, issue: dict, command: Command, comment_id: int, repo_root: Path, discord: Discord | None, actor: Actor | None = None) -> CommandOutcome:
    number = issue["number"]
    if command.action == "retriage":
        ops.dispatch("issue-triage.yml", {"issue": str(number)})
        ops.react(comment_id, "rocket")
        return CommandOutcome("queued")
    if command.action == "decline":
        ops.add_labels(number, ["declined"])
        ops.comment(number, command.message or "Closing this without a change to the lists.")
        ops.remove_label(number, "needs info")
        ops.close_issue(number, "not_planned")
        ops.react(comment_id, "rocket")
        return CommandOutcome("declined")
    if issue.get("state") != "open" and not command.domains:
        return refuse(ops, number, comment_id, "This issue is closed. Name explicit domains in `/block` or `/allow`, or reopen it before using an implicit domain.")
    state = parse_state((github.report(number) or {}).get("body"))
    request = from_issue(issue)
    domains = normalized_domains(command.domains or [d for d in (request.domain or (state.domain if state else None),) if d])
    if not domains:
        return refuse(ops, number, comment_id, "There's no valid domain on this issue. Name one, e.g. `/block example.com`.")
    if len(domains) > MAX_DOMAINS:
        return refuse(ops, number, comment_id, f"Use at most {MAX_DOMAINS} domains per command so publication can be tracked.")
    merged: Merged | None = None
    try:
        with ops.lock():
            merged = change(ops, issue, command, domains, state, request.category, request.service)
    except RefusedChange as error:
        return refuse(ops, number, comment_id, str(error))
    except SkippedChange as error:
        ops.comment(number, "No configuration change needed:\n" + "\n".join(f"- {skip}" for skip in error.skipped))
        ops.remove_label(number, "needs info")
        ops.react(comment_id, "rocket")
        return CommandOutcome("skipped", skipped=error.skipped)
    except Exception as error:
        if merged is None:
            raise
        merged.failures.append(f"lock release ({type(error).__name__})")
    assert merged is not None

    def stage(name: str, action: Callable[[], object]) -> bool:
        try:
            action()
            return True
        except Exception as error:
            merged.failures.append(f"{name} ({type(error).__name__})")
            return False

    pending = PendingChange(number, merged.pr, merged.pr_url, merged.merge_sha, command.action, merged.path, merged.domains, merged.entries, command.scope)
    timing = TIMING_WEEKLY
    closing = f"Configuration merged in [#{merged.pr}]({merged.pr_url}) ({', '.join(f'`{entry}`' for entry in merged.entries)}). {timing}"
    if command.action == "allow":
        closing = allow_reply.mention((actor or Actor("")).login, allow_reply.closing_line(merged.pr, merged.entries, command.scope, timing)) + f"\n\nMerged PR: {merged.pr_url}"
    elif command.message:
        closing = command.message + "\n\n" + closing
    if merged.skipped:
        closing += "\n\nSkipped:\n" + "\n".join(f"- {skip}" for skip in merged.skipped)
    tracked = stage("pending change comment", lambda: ops.comment(number, closing + "\n\n" + pending.marker()))
    if command.now:
        if stage("rebuild dispatch", lambda: ops.dispatch("update-blocklists.yml")):
            merged.timing = TIMING_NOW
            stage("rebuild queued comment", lambda: ops.comment(number, f"Merged PR: {merged.pr_url}. {TIMING_NOW}"))
        else:
            merged.timing = "Immediate rebuild was not queued. Publication remains pending a successful rebuild."
    if command.action == "allow":
        context = allow_reply.reply_context(merged.domains, merged.entries, command.scope, merged.pr, merged.timing, request, state)
        stage("reporter reply", lambda: ops.comment(number, allow_reply.reporter_comment(request.author, command.message, context, (actor or Actor("")).api_key)))
    stage("remove needs info", lambda: ops.remove_label(number, "needs info"))
    stage("issue closure", lambda: ops.close_issue(number, "completed"))
    if discord:
        stage("Discord notification", lambda: discord.send(f"Configuration merged from #{number}.", plain_embed(number, issue["title"], merged.pr_url, command.action, closing), ping=False))
    stage("success reaction", lambda: ops.react(comment_id, "rocket"))
    if merged.failures:
        failure_body = f"Configuration was merged in [#{merged.pr}]({merged.pr_url}); publication is still pending. Failed stages: {', '.join(merged.failures)}."
        if not tracked:
            failure_body += "\n\n" + pending.marker()
        stage("post-merge failure comment", lambda: ops.comment(number, failure_body))
    return CommandOutcome("pending_publication", merged.pr, merged.pr_url, merged.skipped, merged.failures, merged=True)


def file_note(command: Command, domains: list[str], state: TriageState | None, number: int, pr: int | None) -> str:
    reported = bool(state and state.domain in domains)
    reason = command.message.split("\n\n")[0].strip() if command.message else ""
    if not reason:
        reason = state.site if reported and state and state.site else "found while triaging this issue"
    evidence = state.evidence if reported and state and state.evidence else ""
    source = f"(#{number}, PR #{pr})" if pr else f"(#{number})"
    parts = [f"{', '.join(domains)}: {reason}".rstrip(": "), evidence, source]
    return " ".join(part.rstrip(".") + "." if part != source else part for part in parts if part)


def change_once(ops: RepoOps, issue: dict, command: Command, domains: list[str], state: TriageState | None, category: str | None, service: str) -> Merged:
    number = issue["number"]
    base_sha = ops.main_sha()
    files = ops.read_configuration(base_sha)
    plan = plan_domains(command, domains, files)
    if plan.problems:
        raise RefusedChange("Nothing changed:\n" + "\n".join(f"- {problem}" for problem in plan.problems))
    if not plan.domains:
        raise SkippedChange(plan.skipped)
    domains = plan.domains
    block = command.action == "block"
    category = command.category or category or "malicious"
    path = f"custom/{category}.txt" if block else "whitelist.txt"
    entries = entries_for(domains, command.exact) if block else allow_entries_for(domains, command.scope)
    more = " and others" if len(domains) > 1 else ""
    title = f"feat(blocklist): add {domains[0]}{more} to {category} list" if block else f"fix(whitelist): add {domains[0]}{more} for {service.strip() or 'reported false positive'}"
    today = datetime.now(UTC).strftime("%d/%m/%Y")
    original, sha = ops.read_file(path, base_sha)

    def render(pr: int | None) -> str:
        text = entry_block(entries, file_note(command, domains, state, number, pr))
        return append_block(original, text) if block else insert_allow_block(original, text, today, f"Allowlisted {', '.join(domains)} (#{number})")

    branch = f"triage/issue-{number}-{command.action}-{int(time.time())}"
    ops.create_branch(branch, base_sha)
    sha = ops.write_file(path, branch, render(None), sha, title)
    pr, pr_url = ops.open_pr(title, branch, pr_body(command, domains, entries, path, state, number))
    ops.write_file(path, branch, render(pr), sha, f"docs: reference PR #{pr}")
    try:
        merge_sha = ops.merge_pr(pr, title)
    except MergeConflict:
        ops.close_pr(pr)
        ops.delete_branch(branch)
        raise
    merged = Merged(pr, pr_url, entries, TIMING_WEEKLY, domains, plan.skipped, path, merge_sha)
    try:
        ops.delete_branch(branch)
    except Exception as error:
        merged.failures.append(f"branch cleanup ({type(error).__name__})")
    return merged


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
    lines += ["", f"Related issue: #{number}"]
    return "\n".join(lines)
