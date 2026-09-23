import re
from dataclasses import dataclass, field

from triage.domains import clean_domain

HEADING_RE = re.compile(r"^###\s+(.+?)\s*$", re.MULTILINE)
DOMAIN_TOKEN_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]+", re.IGNORECASE)
NO_RESPONSE = "_No response_"

CATEGORY_FILES = {
    "malicious": "malicious",
    "advertising": "advertising",
    "tracking": "tracking",
    "suspicious": "suspicious",
    "nsfw": "nsfw",
}


@dataclass
class IssueRequest:
    number: int
    kind: str
    title: str
    author: str
    body: str
    raw_domain: str
    domain: str | None
    category: str | None = None
    service: str = ""
    lists: list[str] = field(default_factory=list)
    evidence: str = ""
    details: str = ""
    thread: list = field(default_factory=list)


def parse_sections(body: str) -> dict[str, str]:
    matches = list(HEADING_RE.finditer(body or ""))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        value = body[match.end() : end].strip()
        sections[match.group(1).strip().lower()] = "" if value == NO_RESPONSE else value
    return sections


def issue_kind(labels: list[str]) -> str:
    if "blocklist" in labels:
        return "block"
    if "whitelist" in labels:
        return "allow"
    return "other"


def parse_category(value: str) -> str | None:
    lowered = value.lower()
    for key, name in CATEGORY_FILES.items():
        if lowered.startswith(key):
            return name
    return None


def first_domain_in(text: str) -> tuple[str, str | None]:
    for token in DOMAIN_TOKEN_RE.findall(text or ""):
        if cleaned := clean_domain(token):
            return token, cleaned
    return "", None


def from_issue(issue: dict) -> IssueRequest:
    labels = [label["name"] for label in issue.get("labels", [])]
    kind = issue_kind(labels)
    body = issue.get("body") or ""
    sections = parse_sections(body)
    raw = sections.get("domain") or sections.get("blocked domain") or ""
    domain = clean_domain(raw.splitlines()[0]) if raw.strip() else None
    if raw.strip() and domain is None:
        _, domain = first_domain_in(raw)
    if not raw.strip():
        raw, domain = first_domain_in(issue.get("title", ""))
    return IssueRequest(
        number=issue["number"],
        kind=kind,
        title=issue.get("title", ""),
        author=(issue.get("user") or {}).get("login", ""),
        body=body,
        raw_domain=raw.strip(),
        domain=domain,
        category=parse_category(sections.get("category", "")) if kind == "block" else None,
        service=sections.get("service/application affected", ""),
        lists=[line.strip() for line in sections.get("which blocklist are you using?", "").split(",") if line.strip()],
        evidence=sections.get("evidence / reason") or sections.get("evidence (optional)", ""),
        details=sections.get("what broke?") or sections.get("additional context", ""),
    )
