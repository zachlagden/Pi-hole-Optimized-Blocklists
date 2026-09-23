import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from triage.listparse import extract_entry
from triage.policy import FEED_DROP_RATIO, HOLD_SHRINK_RATIO, NEW_FP_RANK
from triage.sources import load_sources

TOTAL_RE = re.compile(r"^# Total domains: (\d+)", re.MULTILINE)
CHECKED_LISTS = ["all_domains.txt", "nsfw.txt"]


@dataclass
class FeedProblem:
    name: str
    problem: str


@dataclass
class NewBlock:
    domain: str
    rank: int
    lists: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    verdict: str = ""
    reason: str = ""

    @property
    def cleared(self) -> bool:
        return self.verdict == "likely_correct"


@dataclass
class BuildReport:
    old_total: int
    new_total: int
    feed_problems: list[FeedProblem]
    new_blocks: list[NewBlock]
    counts: dict[str, int]
    review_note: str = ""

    @property
    def shrink(self) -> float:
        return 1 - self.new_total / self.old_total if self.old_total else 0.0

    @property
    def big_shrink(self) -> bool:
        return self.shrink > HOLD_SHRINK_RATIO

    @property
    def hold(self) -> bool:
        return self.big_shrink and bool(self.feed_problems)

    @property
    def single_source(self) -> list[NewBlock]:
        return [block for block in self.new_blocks if len(block.sources) <= 1]

    @property
    def needs_attention(self) -> bool:
        return self.big_shrink or bool(self.feed_problems) or any(not block.cleared for block in self.single_source)


def list_total(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open() as handle:
        match = TOTAL_RE.search(handle.read(4096))
    return int(match.group(1)) if match else 0


def count_entries(path: Path) -> int:
    with path.open(errors="replace") as handle:
        return sum(1 for line in handle if extract_entry(line, allow_wildcards=True))


def feed_counts(repo_root: Path, base_dir: Path) -> dict[str, int | None]:
    counts: dict[str, int | None] = {}
    for source in load_sources(repo_root):
        if source.is_repo_custom:
            continue
        path = base_dir / source.category / f"{source.name}.txt"
        counts[source.name] = count_entries(path) if path.exists() else None
    return counts


def feed_problems(counts: dict[str, int | None], previous: dict[str, int]) -> list[FeedProblem]:
    problems = []
    for name, count in counts.items():
        before = previous.get(name)
        if count is None:
            problems.append(FeedProblem(name, "download failed, so it was left out of this build"))
        elif count == 0:
            problems.append(FeedProblem(name, "downloaded but empty"))
        elif before and count < before * FEED_DROP_RATIO:
            problems.append(FeedProblem(name, f"shrank from {before:,} to {count:,} entries"))
    return problems


def domains_in(path: Path, candidates: set[str]) -> set[str]:
    found = set()
    if not path.exists():
        return found
    with path.open(errors="replace") as handle:
        for line in handle:
            parts = line.split()
            if not parts or parts[-1].strip("|^").lower() not in candidates:
                continue
            entry = extract_entry(line, allow_wildcards=True)
            if entry and entry.domain in candidates:
                found.add(entry.domain)
    return found


def popular_candidates(ranks: dict[str, int]) -> dict[str, int]:
    popular = {domain: rank for domain, rank in ranks.items() if rank <= NEW_FP_RANK}
    return popular | {f"www.{domain}": rank for domain, rank in popular.items()}


def new_popular_blocks(old_dir: Path, new_dir: Path, base_dir: Path, ranks: dict[str, int]) -> list[NewBlock]:
    popular = popular_candidates(ranks)
    candidates = set(popular)
    found: dict[str, NewBlock] = {}
    for name in CHECKED_LISTS:
        added = domains_in(new_dir / name, candidates) - domains_in(old_dir / name, candidates)
        for domain in added:
            found.setdefault(domain, NewBlock(domain, popular[domain])).lists.append(name)
    for path in sorted(base_dir.glob("*/*.txt")):
        for domain in domains_in(path, set(found)):
            found[domain].sources.append(path.stem)
    return sorted(found.values(), key=lambda block: block.rank)


def load_previous(stats_path: Path) -> dict[str, int]:
    return json.loads(stats_path.read_text()) if stats_path.exists() else {}


def next_stats(counts: dict[str, int | None], previous: dict[str, int]) -> dict[str, int]:
    return {name: count if count else previous.get(name, 0) for name, count in sorted(counts.items())}


def check(repo_root: Path, old_dir: Path, new_dir: Path, base_dir: Path, stats_path: Path, ranks: dict[str, int]) -> BuildReport:
    previous = load_previous(stats_path)
    counts = feed_counts(repo_root, base_dir)
    old_total = list_total(old_dir / "all_domains.txt")
    return BuildReport(
        old_total=old_total,
        new_total=list_total(new_dir / "all_domains.txt"),
        feed_problems=feed_problems(counts, previous),
        new_blocks=new_popular_blocks(old_dir, new_dir, base_dir, ranks) if old_total else [],
        counts=next_stats(counts, previous),
    )


def summary(report: BuildReport) -> str:
    lines = [f"all_domains: {report.old_total:,} → {report.new_total:,} ({-report.shrink:+.1%})."]
    if report.hold:
        lines.append(f"**Held:** the list shrank by more than {HOLD_SHRINK_RATIO:.0%} while feeds were failing, so this week's lists were NOT committed. Users keep last week's.")
    elif report.big_shrink:
        lines.append(f"The list shrank by more than {HOLD_SHRINK_RATIO:.0%} but every feed downloaded, so it looks like upstream pruning. Committed as normal.")
    if report.feed_problems:
        lines.append("**Feed problems:**")
        lines += [f"- {problem.name}: {problem.problem}" for problem in report.feed_problems]
    single = report.single_source
    groups = [
        ("likely_fp", "**Likely false positives, please check:**"),
        ("unclear", "**Unclear, worth a look:**"),
        ("", "**Not reviewed:**"),
        ("likely_correct", "Reviewed, likely correct:"),
    ]
    if single:
        lines.append(f"Newly blocked popular sites from a single feed (Tranco top {NEW_FP_RANK:,}):")
    for verdict, heading in groups:
        members = [block for block in single if block.verdict == verdict]
        if not members:
            continue
        lines.append(heading)
        for block in members[:25]:
            reason = f": {block.reason}" if block.reason else ""
            lines.append(f"- {block.domain} (#{block.rank:,}) in {', '.join(block.lists)}, from {', '.join(block.sources) or 'unknown feed'}{reason}")
    if report.review_note:
        lines.append(report.review_note)
    corroborated = [block for block in report.new_blocks if len(block.sources) > 1]
    if corroborated:
        names = ", ".join(block.domain for block in corroborated[:8])
        lines.append(f"Also newly blocked by several feeds (likely correct): {names}" + (" and more" if len(corroborated) > 8 else ""))
    if not report.needs_attention:
        lines.append("No feed problems, and nothing that looks like a new false positive.")
    return "\n".join(lines)
