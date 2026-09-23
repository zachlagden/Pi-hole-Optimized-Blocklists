from dataclasses import dataclass

from triage.repo_state import RepoMatch
from triage.sources import SourceResult

CATEGORY_LISTS = ["advertising", "tracking", "malicious", "suspicious", "comprehensive", "nsfw"]


@dataclass
class Coverage:
    domain: str
    by_list: dict[str, list[str]]
    whitelisted: bool

    @property
    def blocked_in(self) -> list[str]:
        if self.whitelisted:
            return []
        return [name for name, sources in self.by_list.items() if sources]


def output_lists_for(category: str) -> list[str]:
    if category == "nsfw":
        return ["nsfw.txt", "nsfw_abp.txt"]
    return [f"{category}.txt", "all_domains.txt"]


def build_coverage(
    domain: str,
    results: list[SourceResult],
    custom: list[RepoMatch],
    whitelist: list[RepoMatch],
) -> Coverage:
    by_list: dict[str, list[str]] = {}
    for category in CATEGORY_LISTS:
        for name in output_lists_for(category):
            by_list.setdefault(name, [])
    for result in results:
        if result.blocks(domain):
            for name in output_lists_for(result.source.category):
                by_list[name].append(result.source.name)
    for match in custom:
        category = match.path.removeprefix("custom/").removesuffix(".txt")
        for name in output_lists_for(category):
            by_list.setdefault(name, []).append(f"custom_{category}")
    return Coverage(domain, by_list, whitelisted=bool(whitelist))
