import asyncio
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from triage.listparse import Entry, entry_blocks, extract_entry

REPO_SOURCE_PREFIX = "https://raw.githubusercontent.com/zachlagden/Pi-hole-Optimized-Blocklists/"
USER_AGENT = "Pi-hole-Optimized-Blocklists issue triage (+https://github.com/zachlagden/Pi-hole-Optimized-Blocklists)"


@dataclass(frozen=True)
class Source:
    url: str
    name: str
    category: str
    abp: bool

    @property
    def is_repo_custom(self) -> bool:
        return self.url.startswith(REPO_SOURCE_PREFIX)


@dataclass
class SourceResult:
    source: Source
    entries: list[Entry] = field(default_factory=list)
    error: str | None = None

    def blocks(self, domain: str) -> bool:
        return any(entry_blocks(entry, domain) for entry in self.entries)


def load_sources(repo_root: Path) -> list[Source]:
    sources: list[Source] = []
    for line in (repo_root / "blocklists.conf").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        abp = len(parts) > 3 and parts[3].strip() == "abp"
        sources.append(Source(parts[0].strip(), parts[1].strip(), parts[2].strip(), abp))
    return sources


async def _scan(client: httpx.AsyncClient, source: Source, targets: set[str]) -> SourceResult:
    result = SourceResult(source)
    try:
        async with client.stream("GET", source.url) as response:
            if response.status_code != 200:
                result.error = f"HTTP {response.status_code}"
                return result
            async for line in response.aiter_lines():
                entry = extract_entry(line, allow_wildcards=source.abp)
                if entry is not None and entry.domain in targets:
                    result.entries.append(entry)
    except httpx.HTTPError as error:
        result.error = f"{type(error).__name__}: {error}"
    return result


async def _scan_all(sources: list[Source], targets: set[str]) -> list[SourceResult]:
    limits = httpx.Limits(max_connections=8)
    timeout = httpx.Timeout(120, connect=20)
    headers = {"User-Agent": USER_AGENT}
    async with httpx.AsyncClient(follow_redirects=True, limits=limits, timeout=timeout, headers=headers) as client:
        return await asyncio.gather(*(_scan(client, source, targets) for source in sources))


def scan_sources(sources: list[Source], targets: set[str]) -> list[SourceResult]:
    upstream = [source for source in sources if not source.is_repo_custom]
    return asyncio.run(_scan_all(upstream, targets))
