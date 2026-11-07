import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import httpx

from triage.domains import hosted_platform, is_valid_domain, shared_platform
from triage.listparse import extract_entry
from triage.policy import PLATFORM_ALLOW_EXCEPTIONS
from triage.sources import USER_AGENT

CATEGORIES = {"advertising", "tracking", "malicious", "suspicious", "nsfw", "comprehensive"}
CUSTOM_CATEGORIES = CATEGORIES - {"comprehensive"}
SOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9_+-]+$")
RUST_UNSUPPORTED_RE = re.compile(r"\(\?<?[=!]|\\[1-9]")


@dataclass(frozen=True)
class Problem:
    path: str
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.message}"


def _lines(text: str) -> list[tuple[int, str]]:
    return [(number, line.strip()) for number, line in enumerate(text.splitlines(), start=1)]


def lint_sources(text: str, path: str = "blocklists.conf") -> list[Problem]:
    problems: list[Problem] = []
    names: dict[str, int] = {}
    urls: dict[str, int] = {}
    for number, line in _lines(text):
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) not in (3, 4):
            problems.append(Problem(path, number, "expected url|name|category or url|name|category|abp"))
            continue
        url, name, category = parts[:3]
        if not url.startswith("https://"):
            problems.append(Problem(path, number, f"source URL must use https: {url}"))
        if not SOURCE_NAME_RE.match(name):
            problems.append(Problem(path, number, f"name may use only letters, digits, _, + and -: {name}"))
        if category not in CATEGORIES:
            problems.append(Problem(path, number, f"unknown category {category!r}, expected one of {', '.join(sorted(CATEGORIES))}"))
        if len(parts) == 4 and parts[3] != "abp":
            problems.append(Problem(path, number, f"unknown flag {parts[3]!r}, the only flag is abp"))
        if name in names:
            problems.append(Problem(path, number, f"name {name} is already used on line {names[name]}"))
        if url in urls:
            problems.append(Problem(path, number, f"URL is already listed on line {urls[url]}"))
        names.setdefault(name, number)
        urls.setdefault(url, number)
    return problems


def lint_custom(text: str, path: str) -> list[Problem]:
    problems: list[Problem] = []
    if Path(path).stem not in CUSTOM_CATEGORIES:
        problems.append(Problem(path, 1, f"custom lists must be named after a category: {', '.join(sorted(CUSTOM_CATEGORIES))}"))
    seen: dict[tuple[str, bool], int] = {}
    for number, line in _lines(text):
        if not line or line.startswith("#"):
            continue
        entry = extract_entry(line, allow_wildcards=True)
        if entry is None:
            problems.append(Problem(path, number, f"not a domain, ||domain^ or *.domain entry: {line}"))
            continue
        key = (entry.domain, entry.subdomains)
        if key in seen:
            problems.append(Problem(path, number, f"duplicate of line {seen[key]}: {line}"))
        seen.setdefault(key, number)
        if shared_platform(entry.domain) == entry.domain:
            problems.append(Problem(path, number, f"{entry.domain} is a hosting platform; block the customer host instead"))
        elif entry.subdomains and (platform := hosted_platform(entry.domain)):
            problems.append(Problem(path, number, f"||{entry.domain}^ would block every customer site on {platform}"))
    return problems


def _whitelist_problem(line: str) -> str | None:
    if line.startswith("/") and line.endswith("/") and len(line) > 2:
        pattern = line[1:-1]
        if RUST_UNSUPPORTED_RE.search(pattern):
            return f"the optimizer's regex engine has no lookaround or backreferences: {line}"
        try:
            re.compile(pattern)
        except re.error as error:
            return f"invalid regex ({error}): {line}"
        return None
    if "*" in line:
        platform = hosted_platform(line[2:]) if line.startswith("*.") else None
        if platform and line[2:] not in PLATFORM_ALLOW_EXCEPTIONS:
            return f"{line} allows every customer site on {platform}; allow the specific host instead"
        return None
    domain = line.lower().rstrip(".")
    if not is_valid_domain(domain):
        return f"not a valid domain, *wildcard or /regex/: {line}"
    platform = hosted_platform(domain)
    if platform and domain not in PLATFORM_ALLOW_EXCEPTIONS:
        exact = "/^" + re.escape(domain) + "$/"
        return f"{domain} also allows every customer site on {platform}; use {exact} for the platform itself"
    return None


def lint_whitelist(text: str, path: str = "whitelist.txt") -> list[Problem]:
    problems: list[Problem] = []
    seen: dict[str, int] = {}
    for number, raw in _lines(text):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line in seen:
            problems.append(Problem(path, number, f"duplicate of line {seen[line]}: {line}"))
        seen.setdefault(line, number)
        if message := _whitelist_problem(line):
            problems.append(Problem(path, number, message))
    return problems


def lint_text(path: str, text: str) -> list[Problem]:
    if path == "blocklists.conf":
        return lint_sources(text, path)
    if path == "whitelist.txt":
        return lint_whitelist(text, path)
    if path.startswith("custom/") and path.endswith(".txt"):
        return lint_custom(text, path)
    return []


def lint_repo(repo_root: Path) -> list[Problem]:
    paths = ["blocklists.conf", "whitelist.txt"] + [f"custom/{p.name}" for p in sorted((repo_root / "custom").glob("*.txt"))]
    return [problem for path in paths for problem in lint_text(path, (repo_root / path).read_text())]


def new_problems(path: str, before: str, after: str) -> list[Problem]:
    existing = Counter(problem.message for problem in lint_text(path, before))
    added: list[Problem] = []
    for problem in lint_text(path, after):
        if existing[problem.message]:
            existing[problem.message] -= 1
        else:
            added.append(problem)
    return added


def _source_lines(text: str) -> set[str]:
    return {line for _, line in _lines(text) if line and not line.startswith("#")}


def added_sources(repo_root: Path, base_ref: str) -> list[tuple[str, str]]:
    shown = subprocess.run(
        ["git", "show", f"{base_ref}:blocklists.conf"], cwd=repo_root, capture_output=True, text=True, check=True
    )
    current = _source_lines((repo_root / "blocklists.conf").read_text())
    added = current - _source_lines(shown.stdout)
    sources = []
    for line in sorted(added):
        parts = [part.strip() for part in line.split("|")]
        if len(parts) >= 3:
            sources.append((parts[0], parts[1]))
    return sources


def check_source(client: httpx.Client, url: str) -> str | None:
    try:
        with client.stream("GET", url) as response:
            if response.status_code != 200:
                return f"HTTP {response.status_code}"
            for line in response.iter_lines():
                if extract_entry(line, allow_wildcards=True):
                    return None
    except httpx.HTTPError as error:
        return f"{type(error).__name__}: {error}"
    return "downloaded, but no domain entries were found"


def check_added_sources(repo_root: Path, base_ref: str) -> list[Problem]:
    problems: list[Problem] = []
    text = (repo_root / "blocklists.conf").read_text()
    line_of = {line: number for number, line in _lines(text)}
    headers = {"User-Agent": USER_AGENT}
    with httpx.Client(follow_redirects=True, timeout=httpx.Timeout(60, connect=20), headers=headers) as client:
        for url, name in added_sources(repo_root, base_ref):
            if error := check_source(client, url):
                number = next((n for line, n in line_of.items() if line.startswith(url)), 1)
                problems.append(Problem("blocklists.conf", number, f"new source {name} failed: {error}"))
    return problems
