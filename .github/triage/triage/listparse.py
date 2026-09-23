import re
from dataclasses import dataclass

from triage.domains import is_valid_domain

ADBLOCK_RE = re.compile(r"^\|\|(.+?)\^(?:\$.*)?$")
IP_DOMAIN_RE = re.compile(r"^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+(\S+)$")
COMMENT_RE = re.compile(r"[#!].*$")


@dataclass(frozen=True)
class Entry:
    domain: str
    subdomains: bool


def _make(domain: str, subdomains: bool) -> Entry | None:
    normalized = domain.lower().rstrip(".")
    if "*" in normalized or not is_valid_domain(normalized):
        return None
    return Entry(normalized, subdomains)


def extract_entry(line: str, allow_wildcards: bool) -> Entry | None:
    line = line.strip()
    if not line or line.startswith(("#", "!")):
        return None
    line = COMMENT_RE.sub("", line).strip()
    if not line:
        return None
    if match := IP_DOMAIN_RE.match(line):
        return _make(match.group(1), False)
    if match := ADBLOCK_RE.match(line):
        return _make(match.group(1), allow_wildcards)
    if line.startswith("*."):
        return _make(line[2:], allow_wildcards)
    if " " not in line and "/" not in line and "?" not in line:
        return _make(line, False)
    return None


def entry_blocks(entry: Entry, domain: str) -> bool:
    if entry.domain == domain:
        return True
    return entry.subdomains and domain.endswith("." + entry.domain)
