from dataclasses import dataclass, field

from triage.coverage import Coverage
from triage.github_api import Reporter
from triage.issue_form import IssueRequest
from triage.live import Fetch
from triage.repo_state import RepoMatch
from triage.reputation import Registration, VirusTotal
from triage.screenshot import Capture
from triage.sources import SourceResult
from triage.typosquat import Lookalike


@dataclass
class Evidence:
    request: IssueRequest
    domain: str
    apex: str
    platform: str | None = None
    custom: list[RepoMatch] = field(default_factory=list)
    whitelist: list[RepoMatch] = field(default_factory=list)
    sources: list[SourceResult] = field(default_factory=list)
    coverage: Coverage | None = None
    apex_coverage: Coverage | None = None
    virustotal: list[VirusTotal] = field(default_factory=list)
    registration: Registration | None = None
    tranco_rank: int | None = None
    apex_tranco_rank: int | None = None
    addresses: list[str] = field(default_factory=list)
    fetches: list[Fetch] = field(default_factory=list)
    cloaking: str | None = None
    capture: Capture | None = None
    lookalikes: list[Lookalike] = field(default_factory=list)
    reporter: Reporter | None = None
    failures: list[str] = field(default_factory=list)

    @property
    def listing_sources(self) -> list[SourceResult]:
        return [result for result in self.sources if result.entries]

    @property
    def blocking_sources(self) -> list[str]:
        return [result.source.name for result in self.sources if result.blocks(self.domain)]

    @property
    def failed_sources(self) -> list[SourceResult]:
        return [result for result in self.sources if result.error]
