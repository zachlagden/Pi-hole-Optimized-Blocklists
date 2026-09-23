import re
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from triage.commands import SECTION_RULE
from triage.domains import clean_domain
from triage.github_api import GitHub
from triage.issue_form import from_issue
from triage.listparse import extract_entry
from triage.policy import MIN_REPUTABLE_VT_HITS, RAISE_REPUTABLE_HITS, SCORECARD_ALERT
from triage.reputation import virustotal
from triage.sources import load_sources, scan_sources
from triage.state import parse_state

VT_PAUSE_SECONDS = 16
ISSUE_RE = re.compile(r"\(#(\d+)")


@dataclass
class Finding:
    text: str
    urgent: bool


def held(github: GitHub, vt_key: str) -> tuple[Finding, list[int]]:
    rose, lines = [], []
    for issue in github.open_issues("blocklist"):
        state = parse_state((github.report(issue["number"]) or {}).get("body"))
        domain = (state.domain if state else "") or from_issue(issue).domain
        if not domain:
            continue
        result = virustotal(domain, vt_key)
        hits = len(result.reputable_hits)
        before = state.vt_reputable if state else 0
        if hits >= MIN_REPUTABLE_VT_HITS and hits >= before + RAISE_REPUTABLE_HITS:
            rose.append(issue["number"])
            lines.append(f"- #{issue['number']} {domain}: reputable VirusTotal engines {before} → {hits} ({', '.join(result.reputable_hits)}). Re-triaging.")
        time.sleep(VT_PAUSE_SECONDS)
    if not lines:
        return Finding("No open block request has new reputable VirusTotal detections.", False), []
    return Finding("\n".join(["VirusTotal detections rose on open block requests:"] + lines), True), rose


def comment_blocks(text: str) -> list[tuple[list[str], list[str]]]:
    blocks, comments, entries = [], [], []
    for line in text.splitlines():
        if line.startswith("#"):
            if entries:
                blocks.append((comments, entries))
                comments, entries = [], []
            comments.append(line)
        elif entry := extract_entry(line, allow_wildcards=True):
            entries.append(entry.domain)
    if entries:
        blocks.append((comments, entries))
    return blocks


def remediation_candidates(repo_root: Path) -> list[str]:
    found: list[str] = []
    for path in sorted((repo_root / "custom").glob("*.txt")):
        for comments, entries in comment_blocks(path.read_text()):
            flagged = [line.lstrip("# ").strip() for line in comments if "remediat" in line.lower()]
            if not flagged:
                continue
            named = [domain for domain in entries if any(line.startswith(domain) for line in flagged)]
            found += named or entries
    return found


def remediated(repo_root: Path, vt_key: str) -> Finding:
    clean, flagged = [], []
    for domain in remediation_candidates(repo_root):
        result = virustotal(domain, vt_key)
        if result.found and result.malicious + result.suspicious == 0:
            clean.append(f"- {domain}: 0/{result.total} on VirusTotal (scanned {result.last_analysis})")
        else:
            flagged.append(f"{domain} ({result.malicious + result.suspicious} detections)")
        time.sleep(VT_PAUSE_SECONDS)
    lines = []
    if clean:
        lines += ["Blocked as compromised, now clean on VirusTotal. Check the live site before removing:"] + clean
    if flagged:
        lines.append("Still flagged: " + ", ".join(flagged))
    return Finding("\n".join(lines) or "No entries are marked 'review if remediated'.", bool(clean))


def reported_false_positives(repo_root: Path) -> dict[str, str]:
    lines = (repo_root / "whitelist.txt").read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "# REPORTED FALSE POSITIVES")
    end = next((i for i in range(start + 2, len(lines)) if SECTION_RULE.match(lines[i])), len(lines))
    found: dict[str, str] = {}
    report = ""
    for line in lines[start + 2 : end]:
        if not line.strip():
            report = ""
            continue
        if line.startswith("#"):
            report = (ISSUE_RE.findall(line) or [report])[-1]
            continue
        text = line.split("#", 1)[0].strip()
        if "*" not in text and not text.startswith("/") and (domain := clean_domain(text)):
            found[domain] = f"#{report}" if report else domain
    return found


def scorecard(repo_root: Path) -> Finding:
    reports = reported_false_positives(repo_root)
    per_source: dict[str, set[str]] = defaultdict(set)
    domains_by_source: dict[str, set[str]] = defaultdict(set)
    for result in scan_sources(load_sources(repo_root), set(reports)):
        for entry in result.entries:
            per_source[result.source.name].add(reports[entry.domain])
            domains_by_source[result.source.name].add(entry.domain)
    ranked = sorted(per_source.items(), key=lambda item: -len(item[1]))
    alerts = [name for name, hits in ranked if len(hits) >= SCORECARD_ALERT]
    total = len(set(reports.values()))
    lines = [f"Of {total} whitelisted false-positive reports, these feeds still list domains from some:"]
    lines += [
        f"- {name}: {len(hits)} report{'s' if len(hits) != 1 else ''} ({', '.join(sorted(domains_by_source[name])[:6])})"
        for name, hits in ranked
    ] or ["- none"]
    if alerts:
        lines.append(f"**{', '.join(alerts)} reached {SCORECARD_ALERT}+ separate false-positive reports. Consider reviewing or removing.**")
    return Finding("\n".join(lines), bool(alerts))
