import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

from triage.domains import clean_domain, shared_platform
from triage.policy import SHARED_PATH_HOSTS
from triage.repo_state import custom_matches, whitelist_matches

ACTIONS = {"block", "allow", "decline", "retriage"}
CATEGORIES = {"malicious", "advertising", "tracking", "suspicious", "nsfw"}
HELP = (
    "Commands: `/block [category] [exact] [now] [domain ...]`, `/allow [now] [domain ...]`, "
    "`/decline <reason>`, `/retriage`. Text on the lines after the command is posted as the closing message."
)
SECTION_RULE = re.compile(r"^# =+\s*$")
WRAP = 100


@dataclass
class Command:
    action: str
    category: str | None = None
    exact: bool = False
    now: bool = False
    domains: list[str] = field(default_factory=list)
    message: str = ""
    error: str | None = None


def parse(body: str) -> Command | None:
    lines = (body or "").strip().splitlines()
    if not lines or not lines[0].strip().startswith("/"):
        return None
    words = lines[0].strip()[1:].split()
    action = words[0].lower() if words else ""
    rest = "\n".join(lines[1:]).strip()
    if action not in ACTIONS:
        return Command(action, error=f"Unknown command `/{action}`. {HELP}")
    if action == "decline":
        reason = " ".join(words[1:]).strip()
        return Command(action, message="\n\n".join(part for part in (reason, rest) if part))
    command = Command(action, message=rest)
    for token in words[1:]:
        lowered = token.lower()
        if action == "block" and lowered in CATEGORIES:
            command.category = lowered
        elif action == "block" and lowered == "exact":
            command.exact = True
        elif lowered == "now":
            command.now = True
        elif domain := clean_domain(token):
            command.domains.append(domain)
        else:
            command.error = f"I don't understand `{token}` in `/{action}`. {HELP}"
            return command
    return command


def block_problems(domains: list[str], repo_root: Path) -> list[str]:
    problems = []
    for domain in domains:
        if domain in SHARED_PATH_HOSTS:
            problems.append(f"`{domain}` serves many users by path ({SHARED_PATH_HOSTS[domain]}), so it can't be blocked")
        elif shared_platform(domain) == domain:
            problems.append(f"`{domain}` is a shared platform itself; block the tenant host instead")
        for match in custom_matches(repo_root, domain):
            problems.append(f"`{domain}` is already covered by `{match.entry}` in `{match.path}` line {match.line}")
        for match in whitelist_matches(repo_root, domain):
            problems.append(f"`{domain}` is whitelisted by `{match.entry}` (`whitelist.txt` line {match.line}); remove that first")
    return problems


def allow_problems(domains: list[str], repo_root: Path) -> list[str]:
    problems = []
    for domain in domains:
        for match in whitelist_matches(repo_root, domain):
            problems.append(f"`{domain}` is already allowed by `{match.entry}` (`whitelist.txt` line {match.line})")
    return problems


def comment_lines(text: str) -> list[str]:
    flat = " ".join(re.sub(r"[^\x20-\x7e -￿]", " ", text or "").split())
    return [f"# {line}" for line in textwrap.wrap(flat, WRAP - 2)] if flat else []


def entry_block(entries: list[str], note: str) -> str:
    return "\n".join(comment_lines(note) + entries) + "\n"


def append_block(existing: str, block: str) -> str:
    return existing.rstrip("\n") + "\n" + block


def insert_allow_block(existing: str, block: str, today: str, headline: str) -> str:
    lines = existing.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "# REPORTED FALSE POSITIVES")
    end = next((i for i in range(start + 2, len(lines)) if SECTION_RULE.match(lines[i])), len(lines))
    while end > start and not lines[end - 1].strip():
        end -= 1
    updated = lines[:end] + [""] + block.rstrip("\n").splitlines() + lines[end:]
    header = next((i for i, line in enumerate(updated) if line.startswith("# Last Updated:")), None)
    if header is not None:
        updated[header] = f"# Last Updated: {today} - {headline}"
    return "\n".join(updated) + "\n"


def entries_for(domains: list[str], exact: bool) -> list[str]:
    return [domain if exact else f"||{domain}^" for domain in domains]
