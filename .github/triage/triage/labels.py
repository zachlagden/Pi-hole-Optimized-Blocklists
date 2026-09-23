from dataclasses import dataclass, field

TYPE_LABELS = {"blocklist", "whitelist", "bug", "enhancement"}
IMPACT_LABELS = {"high": "impact: high", "medium": "impact: medium", "low": "impact: low"}
NEEDS_INFO = "needs info"
KIND_BY_LABEL = {"blocklist": "block", "whitelist": "allow"}

IMPACT_RUBRIC = """\
Impact says how much the outcome matters to users of the lists.
For a false-positive (whitelist) report:
  high: a popular site or service (roughly Tranco top 100k), a bank, government, CDN or other
        infrastructure, or anything whose block breaks things for many users.
  medium: an established business, organisation or service with a real user base.
  low: a small shop, personal site, niche hobby site or anything few users will ever visit.
For a block request:
  high: active phishing or malware impersonating a major brand, or a widely seen ad or tracking host.
  medium: a scam or malicious site with solid evidence but narrow reach.
  low: weak evidence, tiny reach, or a minor nuisance.
For a bug: high if the lists or the build are broken for everyone, medium if some users are
affected, low if cosmetic. For a feature request: usually low unless many users would benefit.
"""


@dataclass
class LabelPlan:
    add: set[str] = field(default_factory=set)
    remove: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.add and not self.remove


def plan_type(current: set[str], suggested: str | None, reason: str) -> LabelPlan:
    plan = LabelPlan()
    if suggested not in TYPE_LABELS or suggested in current:
        return plan
    wrong = current & TYPE_LABELS
    plan.add.add(suggested)
    plan.remove |= wrong
    was = ", ".join(sorted(wrong)) or "no type label"
    plan.notes.append(f"type changed from {was} to {suggested}: {reason}")
    return plan


def plan_impact(current: set[str], impact: str | None, reason: str) -> LabelPlan:
    plan = LabelPlan()
    label = IMPACT_LABELS.get(impact or "")
    if label is None or label in current:
        return plan
    plan.add.add(label)
    plan.remove |= current & set(IMPACT_LABELS.values())
    plan.notes.append(f"{label}: {reason}")
    return plan


def plan_needs_info(current: set[str], recommendation: str) -> LabelPlan:
    plan = LabelPlan()
    if recommendation == "needs_info" and NEEDS_INFO not in current:
        plan.add.add(NEEDS_INFO)
        plan.notes.append("needs info: the AI review found the evidence too thin to decide")
    return plan


def merge(*plans: LabelPlan) -> LabelPlan:
    merged = LabelPlan()
    for plan in plans:
        merged.add |= plan.add
        merged.remove |= plan.remove
        merged.notes += plan.notes
    merged.remove -= merged.add
    return merged
