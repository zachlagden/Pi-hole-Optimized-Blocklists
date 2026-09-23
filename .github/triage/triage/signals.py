from dataclasses import dataclass
from datetime import date

from triage.evidence import Evidence
from triage.policy import (
    FP_PRONE_SOURCES,
    MIN_REPUTABLE_VT_HITS,
    POPULAR_RANK,
    THREAT_INTEL_SOURCES,
    YOUNG_DOMAIN_DAYS,
)

TOWARD_BLOCK = "toward block"
TOWARD_ALLOW = "toward allow"
NOTE = "note"


@dataclass(frozen=True)
class Signal:
    lean: str
    text: str


def _created(evidence: Evidence) -> date | None:
    if evidence.registration and evidence.registration.created:
        return evidence.registration.created
    return next((vt.created for vt in evidence.virustotal if vt.created), None)


def _age_signals(evidence: Evidence, today: date) -> list[Signal]:
    if evidence.platform:
        return []
    created = _created(evidence)
    if created is None:
        return []
    days = (today - created).days
    if days < YOUNG_DOMAIN_DAYS:
        return [Signal(TOWARD_BLOCK, f"{evidence.apex} was registered {days} days ago ({created})")]
    if days > 3 * 365:
        return [Signal(TOWARD_ALLOW, f"{evidence.apex} has been registered since {created}")]
    return []


def _virustotal_signals(evidence: Evidence) -> list[Signal]:
    signals = []
    for vt in evidence.virustotal:
        if not vt.found:
            continue
        reputable = vt.reputable_hits
        if len(reputable) >= MIN_REPUTABLE_VT_HITS:
            names = ", ".join(reputable)
            signals.append(Signal(TOWARD_BLOCK, f"VirusTotal: {len(reputable)} reputable engines flag {vt.domain} ({names})"))
        elif vt.malicious + vt.suspicious == 0:
            signals.append(Signal(TOWARD_ALLOW, f"VirusTotal: no engine flags {vt.domain}"))
        elif not reputable:
            signals.append(Signal(NOTE, f"VirusTotal: only minor engines flag {vt.domain}, which is not enough by itself"))
    return signals


def _source_signals(evidence: Evidence) -> list[Signal]:
    blocking = evidence.blocking_sources
    signals = []
    intel = [name for name in blocking if name in THREAT_INTEL_SOURCES]
    if intel:
        signals.append(Signal(TOWARD_BLOCK, "Listed by threat-intel sources: " + ", ".join(intel)))
    if len(blocking) == 1 and blocking[0] in FP_PRONE_SOURCES:
        signals.append(Signal(TOWARD_ALLOW, f"Only one source blocks it, {blocking[0]}: {FP_PRONE_SOURCES[blocking[0]]}"))
    elif len(blocking) == 1:
        signals.append(Signal(NOTE, f"Only one source blocks it: {blocking[0]}"))
    elif len(blocking) >= 3:
        signals.append(Signal(TOWARD_BLOCK, f"{len(blocking)} independent sources block it"))
    return signals


def _popularity_signals(evidence: Evidence) -> list[Signal]:
    rank = evidence.tranco_rank or evidence.apex_tranco_rank
    if rank and rank <= POPULAR_RANK:
        return [Signal(TOWARD_ALLOW, f"Tranco rank {rank:,} (top {POPULAR_RANK:,} sites)")]
    return []


def _site_signals(evidence: Evidence) -> list[Signal]:
    signals = []
    if evidence.cloaking:
        signals.append(Signal(TOWARD_BLOCK, f"Possible cloaking: {evidence.cloaking}"))
    for lookalike in evidence.lookalikes:
        signals.append(Signal(TOWARD_BLOCK, f"Looks like {lookalike.brand} (Tranco #{lookalike.rank:,}): {lookalike.reason}"))
    if evidence.fetches and all(fetch.status is None for fetch in evidence.fetches):
        signals.append(Signal(NOTE, "The site did not load for any visitor type"))
    return signals


def _platform_signals(evidence: Evidence) -> list[Signal]:
    if not evidence.platform:
        return []
    return [Signal(NOTE, f"{evidence.apex} is a site on the shared platform {evidence.platform}. Any entry must target {evidence.apex} or a host under it, never {evidence.platform} itself")]


def collect(evidence: Evidence, today: date) -> list[Signal]:
    others = (
        _platform_signals(evidence)
        + _source_signals(evidence)
        + _virustotal_signals(evidence)
        + _popularity_signals(evidence)
        + _site_signals(evidence)
    )
    age = _age_signals(evidence, today)
    if any(signal.lean == TOWARD_BLOCK for signal in others):
        age = [signal for signal in age if signal.lean != TOWARD_ALLOW]
    return others + age


def evidence_bar(evidence: Evidence) -> tuple[bool, str]:
    reasons = []
    for vt in evidence.virustotal:
        if len(vt.reputable_hits) >= MIN_REPUTABLE_VT_HITS:
            reasons.append(f"{len(vt.reputable_hits)} reputable VirusTotal engines flag {vt.domain}")
    intel = [name for name in evidence.blocking_sources if name in THREAT_INTEL_SOURCES]
    if intel:
        reasons.append("listed by " + ", ".join(intel))
    if reasons:
        return True, "; ".join(reasons)
    return False, "no reputable multi-engine detection and no threat-intel listing; needs evidence such as a captured phishing page"
