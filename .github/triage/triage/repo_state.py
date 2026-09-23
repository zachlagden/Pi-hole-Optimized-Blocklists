import re
from dataclasses import dataclass
from pathlib import Path

from triage.domains import clean_domain
from triage.listparse import entry_blocks, extract_entry


@dataclass(frozen=True)
class RepoMatch:
    path: str
    line: int
    entry: str
    how: str


def custom_matches(repo_root: Path, domain: str) -> list[RepoMatch]:
    matches: list[RepoMatch] = []
    for path in sorted((repo_root / "custom").glob("*.txt")):
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            entry = extract_entry(line, allow_wildcards=True)
            if entry is None or not entry_blocks(entry, domain):
                continue
            how = "exact" if entry.domain == domain else f"parent {entry.domain} with subdomains"
            matches.append(RepoMatch(f"custom/{path.name}", number, line.strip(), how))
    return matches


def _pattern_for(line: str) -> re.Pattern[str] | None:
    try:
        if line.startswith("/") and line.endswith("/") and len(line) > 2:
            return re.compile(line[1:-1])
        if "*" in line:
            return re.compile("^" + line.replace(".", r"\.").replace("*", ".*") + "$")
    except re.error:
        return None
    return None


def _whitelist_hit(line: str, domain: str) -> str | None:
    pattern = _pattern_for(line)
    if pattern is not None:
        return "pattern" if pattern.search(domain) else None
    entry = clean_domain(line)
    if entry == domain:
        return "exact"
    if entry and domain.endswith("." + entry):
        return f"subdomain of {entry}"
    return None


def whitelist_matches(repo_root: Path, domain: str) -> list[RepoMatch]:
    matches: list[RepoMatch] = []
    text = (repo_root / "whitelist.txt").read_text()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if how := _whitelist_hit(line, domain):
            matches.append(RepoMatch("whitelist.txt", number, line, how))
    return matches
