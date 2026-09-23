import argparse
import json
import os
from pathlib import Path

from triage import buildcheck, reputation, watch
from triage.discord import Discord, report_embed
from triage.github_api import GitHub
from triage.repo_ops import RepoOps

CACHE_DIR = Path.home() / ".cache" / "issue-triage"


def run_buildcheck(options: argparse.Namespace, discord: Discord | None) -> int:
    ranks = reputation.tranco_ranks(CACHE_DIR / "tranco")
    stats = Path(options.stats)
    report = buildcheck.check(Path(options.repo_root), Path(options.old), Path(options.new), Path(options.base), stats, ranks)
    text = buildcheck.summary(report)
    print(text)
    if not report.hold:
        stats.write_text(json.dumps(report.counts, indent=2) + "\n")
    write_outputs(report.hold, "", "list shrank" if report.hold else "")
    if discord:
        title = "Weekly build HELD" if report.hold else "Weekly build check"
        discord.send(title + ".", report_embed(title, text, run_url(), report.needs_attention), ping=report.needs_attention)
    return 0


def run_watch(options: argparse.Namespace, discord: Discord | None) -> int:
    root = Path(options.repo_root)
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    github = GitHub.from_env()
    if options.task == "held":
        finding, rose = watch.held(github, vt_key)
        for number in rose:
            RepoOps(github).dispatch("issue-triage.yml", {"issue": str(number)})
    elif options.task == "remediated":
        finding = watch.remediated(root, vt_key)
    else:
        finding = watch.scorecard(root)
    print(finding.text)
    if discord and (finding.urgent or options.task != "held"):
        title = {"held": "Held block requests", "remediated": "Review-if-remediated entries", "scorecard": "Feed false-positive scorecard"}[options.task]
        discord.send(title + ".", report_embed(title, finding.text, run_url(), finding.urgent), ping=finding.urgent)
    return 0


def run_url() -> str:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repository = os.environ.get("GITHUB_REPOSITORY", "zachlagden/Pi-hole-Optimized-Blocklists")
    run_id = os.environ.get("GITHUB_RUN_ID")
    return f"{server}/{repository}/actions/runs/{run_id}" if run_id else f"{server}/{repository}"


def write_outputs(run: bool, trigger: str, reason: str) -> None:
    target = os.environ.get("GITHUB_OUTPUT")
    if not target:
        return
    with open(target, "a") as handle:
        handle.write(f"run={'true' if run else 'false'}\n")
        handle.write(f"trigger={' '.join(trigger.split())}\n")
        handle.write(f"reason={' '.join(reason.split())}\n")
