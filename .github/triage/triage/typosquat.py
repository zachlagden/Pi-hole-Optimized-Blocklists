from dataclasses import dataclass

from triage.domains import registrable, registrable_label

MIN_BRAND_LENGTH = 5


@dataclass(frozen=True)
class Lookalike:
    brand: str
    rank: int
    reason: str


def edit_distance(left: str, right: str) -> int:
    previous = list(range(len(right) + 1))
    before_previous: list[int] = []
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            best = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and left_char == right[j - 2] and left[i - 2] == right_char:
                best = min(best, before_previous[j - 2] + 1)
            current.append(best)
        before_previous, previous = previous, current
    return previous[-1]


def _reason(label: str, brand_label: str) -> str | None:
    if len(brand_label) < MIN_BRAND_LENGTH or label == brand_label:
        return None
    limit = 1 if len(brand_label) < 10 else 2
    if abs(len(label) - len(brand_label)) <= limit and edit_distance(label, brand_label) <= limit:
        return "one or two characters away"
    tokens = label.replace("_", "-").split("-")
    if brand_label in tokens and len(tokens) > 1:
        return "brand name plus extra words"
    return None


def find_lookalikes(domain: str, ranks: dict[str, int], pool: int, limit: int = 5) -> list[Lookalike]:
    own = registrable(domain)
    own_rank = ranks.get(own)
    if own_rank is not None and own_rank <= pool:
        return []
    label = registrable_label(domain)
    found: list[Lookalike] = []
    for brand, rank in ranks.items():
        if rank > pool or brand == own:
            continue
        if reason := _reason(label, brand.split(".")[0]):
            found.append(Lookalike(brand, rank, reason))
    return sorted(found, key=lambda item: item.rank)[:limit]
