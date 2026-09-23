import re

from triage.ai_review import Review
from triage.evidence import Evidence
from triage.github_api import MARKER
from triage.signals import NOTE, TOWARD_ALLOW, TOWARD_BLOCK, Signal
from triage.signals import provider_flags as _provider_flags

LEAN_LABEL = {TOWARD_BLOCK: "Points to block", TOWARD_ALLOW: "Points to allow", NOTE: "Note"}
UNSAFE_MD_RE = re.compile(r"[<>`|\[\]]")


def safe(text: str, limit: int = 160) -> str:
    return UNSAFE_MD_RE.sub("", text or "").strip()[:limit]


def repo_lines(evidence: Evidence) -> list[str]:
    lines = []
    for match in evidence.custom:
        lines.append(f"Already in `{match.path}` line {match.line}: `{match.entry}` ({match.how})")
    for match in evidence.whitelist:
        lines.append(f"Already allowed by `whitelist.txt` line {match.line}: `{match.entry}` ({match.how})")
    return lines or ["Not in `custom/*.txt` or `whitelist.txt`"]


def coverage_lines(evidence: Evidence) -> list[str]:
    lines = []
    for coverage in (evidence.coverage, evidence.apex_coverage):
        if coverage is None:
            continue
        lists = ", ".join(f"`{name}`" for name in coverage.blocked_in) or "none"
        suffix = " (whitelisted, so removed at build)" if coverage.whitelisted and any(coverage.by_list.values()) else ""
        lines.append(f"`{coverage.domain}` would be in: {lists}{suffix}")
    return lines


def source_rows(evidence: Evidence) -> list[str]:
    rows = []
    for result in evidence.listing_sources:
        for entry in result.entries:
            form = f"`||{entry.domain}^` (with subdomains)" if entry.subdomains else f"`{entry.domain}`"
            effect = "blocks it" if result.blocks(evidence.domain) else "blocks that host only"
            rows.append(f"| {result.source.name} | {result.source.category} | {form} | {effect} |")
    return rows


def virustotal_lines(evidence: Evidence) -> list[str]:
    lines = []
    for vt in evidence.virustotal:
        if vt.error:
            lines.append(f"VirusTotal `{vt.domain}`: lookup failed ({safe(vt.error)})")
        elif not vt.found:
            lines.append(f"VirusTotal `{vt.domain}`: no record")
        else:
            flagged = ", ".join(f"{name} ({safe(result or category, 40)})" for name, category, result in vt.engines) or "none"
            lines.append(
                f"[VirusTotal `{vt.domain}`]({vt.link}): {vt.malicious} malicious, {vt.suspicious} suspicious of {vt.total}, "
                f"last scanned {vt.last_analysis or 'unknown'}. Flagged by: {flagged}"
            )
    return lines


def registration_lines(evidence: Evidence) -> list[str]:
    reg = evidence.registration
    vt_created = next((vt.created for vt in evidence.virustotal if vt.created), None)
    vt_registrar = next((vt.registrar for vt in evidence.virustotal if vt.registrar), "")
    created = (reg.created if reg else None) or vt_created
    registrar = (reg.registrar if reg else "") or vt_registrar
    if evidence.platform:
        lines = [f"`{evidence.apex}` is a subdomain on `{evidence.platform}`, so registration data describes the platform, not this site"]
    else:
        lines = [f"`{evidence.apex}` registered {created or 'unknown'}, registrar {safe(registrar) or 'unknown'}"]
    if reg and reg.nameservers:
        lines.append("Nameservers: " + ", ".join(f"`{ns}`" for ns in reg.nameservers))
    rank = evidence.tranco_rank or evidence.apex_tranco_rank
    lines.append(f"Tranco rank: {rank:,}" if rank else "Tranco rank: not in the top 1M")
    return lines


def live_lines(evidence: Evidence) -> list[str]:
    lines = ["Resolves to: " + (", ".join(f"`{ip}`" for ip in evidence.addresses) or "nothing (no DNS answer)")]
    for fetch in evidence.fetches:
        if fetch.status is None:
            lines.append(f"{fetch.profile}: failed ({safe(fetch.error or 'unknown')})")
            continue
        hops = " → ".join(f"`{safe(url, 120)}`" for url in fetch.chain)
        lines.append(f"{fetch.profile}: HTTP {fetch.status}, title \"{safe(fetch.title, 100)}\", {fetch.size:,} bytes, via {hops}")
    if evidence.fetches:
        lines.append(f"Cloaking check: {evidence.cloaking or 'all visitor types got the same site'}")
    for fetch in evidence.quoted_fetches:
        start = safe(fetch.start or (fetch.chain[0] if fetch.chain else ""), 160)
        if fetch.status is None:
            lines.append(f"Reported URL `{start}`: failed ({safe(fetch.error or 'unknown')})")
            continue
        hops = " → ".join(f"`{safe(url, 120)}`" for url in fetch.chain[1:]) or "no redirect"
        lines.append(f"Reported URL `{start}`: HTTP {fetch.status}, title \"{safe(fetch.title, 100)}\", {fetch.size:,} bytes, then {hops}")
        if fetch.script_redirects:
            targets = ", ".join(f"`{safe(url, 120)}`" for url in fetch.script_redirects)
            lines.append(f"Its script sends the browser on to {targets}")
    return lines


def facts_text(evidence: Evidence, signals: list[Signal], bar: tuple[bool, str] | None) -> str:
    sections = [
        ("Repository", repo_lines(evidence) + coverage_lines(evidence)),
        ("Upstream sources that list it or a parent", [row.strip("| ").replace(" | ", ", ") for row in source_rows(evidence)] or ["none"]),
        ("Reputation", virustotal_lines(evidence) + registration_lines(evidence)),
        ("Live site", live_lines(evidence)),
        ("Signals", [f"{LEAN_LABEL[s.lean]}: {s.text}" for s in signals] or ["none"]),
    ]
    if bar is not None:
        sections.append(("Block evidence bar", [("met: " if bar[0] else "not met: ") + bar[1]]))
    return "\n".join(f"{title}:\n" + "\n".join(f"- {line}" for line in lines) for title, lines in sections)


def _review_block(review: Review | None) -> list[str]:
    if review is None:
        return []
    heading = ["### AI view (MiniMax M3, advisory only)", ""]
    if review.error:
        return heading + [f"The AI review failed: {safe(review.error, 200)}", ""]
    lines = heading + [
        f"**Suggests:** {review.recommendation.replace('_', ' ')} ({review.confidence} confidence)",
        "",
        f"**Impact:** {review.impact or 'unclear'}. {review.impact_reason}",
        "",
        f"**What the site is:** {review.site}",
        "",
    ]
    lines += [f"- {reason}" for reason in review.reasons]
    if review.suggested_entry:
        lines += ["", f"**Suggested entry:** `{review.suggested_entry.replace('`', '')}`"]
    if review.questions:
        lines += ["", "**Questions for the reporter:**"] + [f"- {q}" for q in review.questions]
    return lines + [""]


def _section(title: str, lines: list[str]) -> list[str]:
    return [f"### {title}", ""] + [f"- {line}" for line in lines] + [""]


def label_lines(notes: list[str]) -> list[str]:
    if not notes:
        return []
    return _section("Labels set by the AI", [safe(note, 300) for note in notes])


def comment_markdown(
    evidence: Evidence,
    signals: list[Signal],
    bar: tuple[bool, str] | None,
    review: Review | None,
    label_notes: list[str],
    history: list[str] | None = None,
    state_marker: str = "",
) -> str:
    request = evidence.request
    action = f"block as {request.category or 'malicious'}" if request.kind == "block" else "allow (false positive)"
    rows = source_rows(evidence)
    lines = [
        MARKER,
        f"## Triage report: `{evidence.domain}`",
        "",
        f"Request: **{action}**. This report collects evidence for the maintainer. It does not change any list.",
        "",
    ]
    if history and len(history) > 1:
        lines += _section("Triage history", [safe(entry, 300) for entry in history])
    lines += label_lines(label_notes)
    lines += _section("Signals", [f"{LEAN_LABEL[s.lean]}: {s.text}" for s in signals] or ["No strong signals either way"])
    if bar is not None:
        lines += [f"**Block evidence bar:** {'met' if bar[0] else 'not met'}. {bar[1]}", ""]
    lines += _review_block(review)
    lines += _section("This repository", repo_lines(evidence) + coverage_lines(evidence))
    lines += ["### Upstream sources", ""]
    if rows:
        lines += ["| Source | Category | Entry | Effect on this domain |", "|---|---|---|---|"] + rows + [""]
    else:
        lines += [f"None of the {len(evidence.sources)} upstream sources list it or a parent domain.", ""]
    if evidence.failed_sources:
        failed = ", ".join(f"{r.source.name} ({safe(r.error or '', 40)})" for r in evidence.failed_sources)
        lines += [f"Could not check: {failed}", ""]
    lines += _section("Reputation", virustotal_lines(evidence) + registration_lines(evidence))
    lines += _section("Live site", live_lines(evidence))
    if evidence.failures:
        lines += _section("Checks that failed", [safe(f, 200) for f in evidence.failures])
    lines += ["<sub>Generated by the issue-triage workflow. Upstream results reflect today's feeds, not last Sunday's build. "
              "It runs again when the issue is edited or someone adds useful information.</sub>"]
    if state_marker:
        lines.append(state_marker)
    return "\n".join(lines)


def evidence_note(evidence: Evidence) -> str:
    parts = []
    for vt in evidence.virustotal:
        if vt.found and vt.malicious + vt.suspicious:
            names = ", ".join(vt.reputable_hits[:4])
            parts.append(f"VT {vt.malicious + vt.suspicious}/{vt.total} for {vt.domain}" + (f" incl. {names}" if names else ""))
    created = evidence.registration.created if evidence.registration else None
    if created and not evidence.platform:
        parts.append(f"registered {created}")
    parts += [flag for flag in _provider_flags(evidence)]
    return "; ".join(parts)


def first_sentence(text: str, limit: int = 180) -> str:
    sentence = (text or "").replace("&lt;", "<").replace("&gt;", ">").split(". ")[0].strip().rstrip(".")
    return sentence[:limit]
