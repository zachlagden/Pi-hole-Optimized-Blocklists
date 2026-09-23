import argparse
import json
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

from triage import ai_review, live, render, reputation, screenshot, signals
from triage.coverage import build_coverage
from triage.discord import Discord, plain_embed, triage_embed
from triage.domains import registrable, self_and_parents, shared_platform
from triage.evidence import Evidence
from triage.github_api import GitHub
from triage.issue_form import IssueRequest, from_issue
from triage.labels import NEEDS_INFO, LabelPlan, merge, plan_impact, plan_needs_info, plan_type
from triage.policy import TYPOSQUAT_POOL
from triage.repo_state import custom_matches, whitelist_matches
from triage.sources import load_sources, scan_sources
from triage.typosquat import find_lookalikes

T = TypeVar("T")
CACHE_DIR = Path.home() / ".cache" / "issue-triage"


def attempt(evidence: Evidence, label: str, action: Callable[[], T], default: T) -> T:
    try:
        return action()
    except Exception as error:
        evidence.failures.append(f"{label}: {type(error).__name__}: {error}")
        print(f"::warning::{label} failed: {type(error).__name__}: {error}", file=sys.stderr)
        return default


def gather_repo_and_sources(evidence: Evidence, repo_root: Path) -> None:
    domain, apex = evidence.domain, evidence.apex
    evidence.custom = custom_matches(repo_root, domain)
    evidence.whitelist = whitelist_matches(repo_root, domain)
    targets = set(self_and_parents(domain)) | {apex}
    sources = load_sources(repo_root)
    evidence.sources = attempt(evidence, "source scan", lambda: scan_sources(sources, targets), [])
    evidence.coverage = build_coverage(domain, evidence.sources, evidence.custom, evidence.whitelist)
    if apex != domain:
        evidence.apex_coverage = build_coverage(
            apex, evidence.sources, custom_matches(repo_root, apex), whitelist_matches(repo_root, apex)
        )


def gather_reputation(evidence: Evidence, vt_key: str | None) -> None:
    names = [evidence.domain] + ([evidence.apex] if evidence.apex != evidence.domain else [])
    if vt_key:
        evidence.virustotal = [attempt(evidence, f"VirusTotal {name}", lambda n=name: reputation.virustotal(n, vt_key), None) for name in names]
        evidence.virustotal = [vt for vt in evidence.virustotal if vt is not None]
    evidence.registration = attempt(evidence, "RDAP", lambda: reputation.registration(evidence.apex), None)
    ranks = attempt(evidence, "Tranco", lambda: reputation.tranco_ranks(CACHE_DIR / "tranco"), {})
    evidence.tranco_rank = ranks.get(evidence.domain)
    evidence.apex_tranco_rank = ranks.get(evidence.apex)
    if evidence.request.kind == "block" and ranks:
        evidence.lookalikes = find_lookalikes(evidence.domain, ranks, TYPOSQUAT_POOL)


def gather_live(evidence: Evidence, take_screenshot: bool) -> None:
    evidence.addresses = live.resolve(evidence.domain)
    evidence.fetches = attempt(evidence, "live fetch", lambda: live.fetch_all(evidence.domain), [])
    evidence.cloaking = live.cloaking_summary(evidence.fetches)
    if take_screenshot and evidence.addresses:
        evidence.capture = attempt(evidence, "screenshot", lambda: screenshot.capture(evidence.domain), None)
        if evidence.capture and evidence.capture.error:
            evidence.failures.append(f"screenshot: {evidence.capture.error}")


def gather(request: IssueRequest, repo_root: Path, github: GitHub, options: argparse.Namespace) -> Evidence:
    domain = request.domain or ""
    evidence = Evidence(request=request, domain=domain, apex=registrable(domain), platform=shared_platform(domain))
    gather_repo_and_sources(evidence, repo_root)
    gather_reputation(evidence, os.environ.get("VIRUSTOTAL_API_KEY"))
    gather_live(evidence, not options.no_screenshot)
    evidence.reporter = attempt(evidence, "reporter lookup", lambda: github.reporter(request.author, domain), None)
    return evidence


def invalid_domain_comment(request: IssueRequest) -> str:
    raw = render.safe(request.raw_domain, 120) or "nothing"
    return (
        f"{render.MARKER}\nThe triage bot could not read a valid domain from this issue (it found: `{raw}`). "
        "Please edit the domain field so it holds a single domain such as `example.com`, without a path."
    )


def write_dry_run(options, number: int, comment: str | None, embed: dict, png: bytes | None, plan: LabelPlan) -> None:
    out = Path(options.out)
    out.mkdir(parents=True, exist_ok=True)
    if comment:
        (out / f"issue-{number}.md").write_text(comment)
    (out / f"issue-{number}-discord.json").write_text(json.dumps(embed, indent=2, default=str))
    (out / f"issue-{number}-labels.json").write_text(json.dumps({"add": sorted(plan.add), "remove": sorted(plan.remove), "notes": plan.notes}, indent=2))
    if png:
        (out / f"issue-{number}.png").write_bytes(png)
    print(f"Dry run written to {out}")


def deliver(github: GitHub, discord: Discord | None, options, number: int, comment: str | None, embed: dict, png: bytes | None, plan: LabelPlan) -> None:
    if options.dry_run:
        write_dry_run(options, number, comment, embed, png, plan)
        return
    if not plan.empty:
        github.edit_labels(number, plan.add, plan.remove)
    if comment:
        embed["url"] = github.upsert_report(number, comment)
    if plan.notes:
        embed.setdefault("fields", []).append({"name": "Labels set by the AI", "value": "\n".join(plan.notes)[:1000]})
    if discord:
        discord.send("New issue needs your review.", embed, png)


def classify_issue(issue: dict, api_key: str | None) -> tuple[ai_review.Classification | None, LabelPlan]:
    current = {label["name"] for label in issue.get("labels", [])}
    if not api_key:
        return None, LabelPlan()
    result = ai_review.classify(issue.get("title", ""), issue.get("body") or "", sorted(current), api_key)
    if result.error:
        print(f"::warning::classification failed: {result.error}", file=sys.stderr)
        return result, LabelPlan()
    return result, plan_type(current, result.type, result.type_reason)


def with_labels(issue: dict, plan: LabelPlan) -> dict:
    names = ({label["name"] for label in issue.get("labels", [])} - plan.remove) | plan.add
    return {**issue, "labels": [{"name": name} for name in sorted(names)]}


def run_issue(options: argparse.Namespace) -> int:
    github = GitHub.from_env()
    discord = make_discord(options)
    api_key = None if options.no_ai else os.environ.get("MINIMAX_API_KEY")
    issue = github.issue(options.number)
    classification, type_plan = classify_issue(issue, api_key)
    issue = with_labels(issue, type_plan)
    current = {label["name"] for label in issue["labels"]}
    request = from_issue(issue)
    today = datetime.now(UTC).date()
    if request.kind == "other":
        impact_plan = plan_impact(current, classification.impact, classification.impact_reason) if classification else LabelPlan()
        embed = plain_embed(request.number, request.title, issue["html_url"], "other", request.body[:1500])
        deliver(github, discord, options, request.number, None, embed, None, merge(type_plan, impact_plan))
        return 0
    if request.domain is None:
        embed = plain_embed(request.number, request.title, issue["html_url"], request.kind, "No valid domain in the issue. Asked the reporter to fix it.")
        impact_plan = plan_impact(current, classification.impact, classification.impact_reason) if classification else LabelPlan()
        plan = merge(type_plan, impact_plan, LabelPlan(add={NEEDS_INFO}, notes=["needs info: no valid domain in the issue"]))
        deliver(github, discord, options, request.number, invalid_domain_comment(request), embed, None, plan)
        return 0
    evidence = gather(request, Path(options.repo_root), github, options)
    found = signals.collect(evidence, today)
    bar = signals.evidence_bar(evidence) if request.kind == "block" else None
    review = ai_review.review(evidence, render.facts_text(evidence, found, bar), api_key) if api_key else None
    plan = merge(type_plan, review_label_plan(current, review, classification))
    comment = render.comment_markdown(evidence, found, bar, review, plan.notes)
    embed = triage_embed(evidence, review, issue["html_url"], today)
    deliver(github, discord, options, request.number, comment, embed, evidence.capture.png if evidence.capture else None, plan)
    return 0


def review_label_plan(current: set[str], review: ai_review.Review | None, classification: ai_review.Classification | None) -> LabelPlan:
    if review and not review.error and review.impact:
        return merge(plan_impact(current, review.impact, review.impact_reason), plan_needs_info(current, review.recommendation))
    if classification and classification.impact:
        return plan_impact(current, classification.impact, classification.impact_reason)
    return LabelPlan()


def run_reply(options: argparse.Namespace) -> int:
    discord = make_discord(options)
    if discord is None:
        return 0
    github = GitHub.from_env()
    issue = github.issue(options.number)
    comment = github.comment(options.number, options.comment_id)
    note = f"{comment['user']['login']} replied:\n\n{comment.get('body') or ''}"
    discord.send("New reply on an issue.", plain_embed(options.number, issue["title"], comment["html_url"], "other", note))
    return 0


def make_discord(options: argparse.Namespace) -> Discord | None:
    webhook = os.environ.get("DISCORD_TRIAGE_WEBHOOK")
    if options.no_discord or not webhook:
        return None
    return Discord(webhook, os.environ.get("DISCORD_PING_USER_ID", ""))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="triage")
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue")
    issue.add_argument("number", type=int)
    issue.add_argument("--repo-root", default=os.environ.get("REPO_ROOT", "../.."))
    issue.add_argument("--dry-run", action="store_true")
    issue.add_argument("--out", default="triage-output")
    issue.add_argument("--no-ai", action="store_true")
    issue.add_argument("--no-discord", action="store_true")
    issue.add_argument("--no-screenshot", action="store_true")
    reply = commands.add_parser("reply")
    reply.add_argument("number", type=int)
    reply.add_argument("comment_id", type=int)
    reply.add_argument("--no-discord", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    options = parse_args(argv)
    return run_issue(options) if options.command == "issue" else run_reply(options)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
