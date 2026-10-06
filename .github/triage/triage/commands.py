import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

from triage.domains import clean_domain, shared_platform
from triage.policy import SHARED_PATH_HOSTS
from triage.listparse import extract_entry
from triage.repo_state import custom_matches_text, whitelist_matches_text

ACTIONS = {"block", "allow", "decline", "retriage"}
CATEGORIES = {"malicious", "advertising", "tracking", "suspicious", "nsfw"}
HELP = (
    "Commands: `/block [category] [exact] [now] [domain ...]`, `/allow [exact | subdomains] [now] [domain ...]`, "
    "`/decline <reason>`, `/retriage`. `/allow` covers the domain and all its subdomains, `exact` only that host, "
    "`subdomains` only its subdomains. Text on the lines after the command is posted as the closing message."
)
SECTION_RULE = re.compile(r"^# =+\s*$")
WRAP = 100


@dataclass
class Command:
    action: str
    category: str | None = None
    exact: bool = False
    subdomains: bool = False
    now: bool = False
    domains: list[str] = field(default_factory=list)
    message: str = ""
    error: str | None = None

    @property
    def scope(self) -> str:
        return "exact" if self.exact else "subdomains" if self.subdomains else "domain"


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
        elif lowered == "exact":
            command.exact = True
        elif action == "allow" and lowered == "subdomains":
            command.subdomains = True
        elif lowered == "now":
            command.now = True
        elif domain := clean_domain(token):
            if domain not in command.domains:
                command.domains.append(domain)
        else:
            command.error = f"I don't understand `{token}` in `/{action}`. {HELP}"
            return command
    if command.exact and command.subdomains:
        command.error = f"Use either `exact` or `subdomains` with `/allow`, not both. {HELP}"
    return command


@dataclass
class DomainPlan:
    domains: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def normalized_domains(domains: list[str]) -> list[str]:
    return list(dict.fromkeys(domain for raw in domains if (domain := clean_domain(raw))))


def allow_covers(text: str, domain: str, scope: str) -> bool:
    lines = [raw.split("#", 1)[0].strip() for raw in text.splitlines()]
    if scope == "exact":
        return bool(whitelist_matches_text(text, domain))
    for line in lines:
        base = clean_domain(line)
        if not base or line.startswith("/"):
            continue
        if line.startswith("*."):
            if scope == "subdomains" and domain == base or domain.endswith("." + base):
                return True
        elif "*" not in line and (domain == base or domain.endswith("." + base)):
            return True
    return False


def block_covers(files: dict[str, str], domain: str, exact: bool) -> bool:
    for match in custom_matches_text(files, domain):
        entry = extract_entry(match.entry, allow_wildcards=True)
        if entry and (exact or entry.subdomains):
            return True
    return False


def whitelist_conflicts(text: str, domain: str, exact: bool) -> bool:
    if whitelist_matches_text(text, domain):
        return True
    if exact:
        return False
    if whitelist_matches_text(text, "x." + domain):
        return True
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("/^") and line.endswith("$/"):
            line = line[2:-2].replace(r"\.", ".")
        base = clean_domain(line)
        if base and base.endswith("." + domain):
            return True
    return False


def plan_domains(command: Command, domains: list[str], files: dict[str, str]) -> DomainPlan:
    plan = DomainPlan()
    whitelist = files["whitelist.txt"]
    normalized = normalized_domains(domains)
    for domain in normalized:
        if domain in SHARED_PATH_HOSTS:
            plan.problems.append(f"`{domain}` serves many users by path; target a dedicated host instead")
        elif shared_platform(domain) == domain:
            plan.problems.append(f"`{domain}` is a shared platform itself; target the tenant host instead")
        if command.action == "block" and whitelist_conflicts(whitelist, domain, command.exact):
            plan.problems.append(f"`{domain}` conflicts with `whitelist.txt`; remove that allowance first")
        covered = block_covers(files, domain, command.exact) if command.action == "block" else allow_covers(whitelist, domain, command.scope)
        broader_input = any(
            domain.endswith("." + parent) for parent in normalized
            if parent != domain and (command.action == "block" and not command.exact or command.action == "allow" and command.scope != "exact")
        )
        if covered or broader_input:
            reason = "already covered in the requested scope" if covered else "covered by another domain in this batch"
            plan.skipped.append(f"`{domain}`: {reason}")
        else:
            plan.domains.append(domain)
    return plan


def local_configuration(repo_root: Path) -> dict[str, str]:
    return {"whitelist.txt": (repo_root / "whitelist.txt").read_text()} | {
        f"custom/{path.name}": path.read_text() for path in (repo_root / "custom").glob("*.txt")
    }


def block_problems(domains: list[str], repo_root: Path) -> list[str]:
    plan = plan_domains(Command("block"), domains, local_configuration(repo_root))
    return plan.problems + plan.skipped


def allow_problems(domains: list[str], repo_root: Path, scope: str = "domain") -> list[str]:
    plan = plan_domains(Command("allow", exact=scope == "exact", subdomains=scope == "subdomains"), domains, local_configuration(repo_root))
    return plan.problems + plan.skipped


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


def allow_entry(domain: str, scope: str) -> str:
    if scope == "exact":
        return "/^" + domain.replace(".", r"\.") + "$/"
    if scope == "subdomains":
        return f"*.{domain}"
    return domain


def allow_entries_for(domains: list[str], scope: str) -> list[str]:
    return [allow_entry(domain, scope) for domain in domains]
