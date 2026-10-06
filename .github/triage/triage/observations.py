from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Literal

from triage.evidence import Evidence
from triage.issue_form import NO_RESPONSE, parse_sections
from triage.live import URL_RE
from triage.policy import MIN_REPUTABLE_VT_HITS, SHARED_PATH_HOSTS, THREAT_INTEL_SOURCES
from triage.publication_safety import public_text, safe_data
from triage.signals import provider_flags

ObservationKind = Literal["bot_measurement", "reporter_claim", "website_text", "fetched_corroboration"]


@dataclass(frozen=True)
class Observation:
    id: str
    kind: ObservationKind
    source: str
    fact: str
    supports: tuple[str, ...] = ()
    image: bool = False

    def public_fact(self) -> str:
        return f"[{self.id}; {self.kind}; {public_text(self.source, 160)}] {public_text(self.fact)}"


def probe_name(profile: str) -> str:
    if profile == "google referral":
        return "HTTP probe with Google Referer (not a crawler)"
    return f"{profile} HTTP probe"


def collect(
    evidence: Evidence, today: date | None = None, image_ids: set[str] | None = None
) -> list[Observation]:
    today = today or datetime.now(UTC).date()
    image_ids = image_ids or set()
    observations: list[Observation] = []

    def add(
        identifier: str, kind: ObservationKind, source: str, fact: str,
        supports: tuple[str, ...] = (), image: bool = False,
    ) -> None:
        observations.append(Observation(identifier, kind, source, fact, supports, image))

    add("target.host", "bot_measurement", "validated review target", evidence.domain)
    if evidence.domain in SHARED_PATH_HOSTS or evidence.domain == evidence.platform:
        add("scope.restriction", "bot_measurement", "project shared-host policy",
            f"{evidence.domain} serves unrelated users; a domain-wide block is prohibited.", ("decline",))
    for index, match in enumerate(evidence.custom):
        add(f"repo.block.{index}", "bot_measurement", match.path,
            f"Already blocked by {match.entry} at line {match.line} ({match.how}).",
            ("decline",) if evidence.request.kind == "block" else ())
    for index, match in enumerate(evidence.whitelist):
        add(f"repo.allow.{index}", "bot_measurement", "whitelist.txt",
            f"Already allowed by {match.entry} at line {match.line} ({match.how}).",
            ("allow", "decline") if evidence.request.kind == "allow" else ())
    for index, result in enumerate(evidence.sources):
        if result.error:
            add(f"feed.{index}", "bot_measurement", result.source.name, f"Feed check failed: {result.error}.")
        elif result.blocks(evidence.domain):
            support = ("block",) if result.source.name in THREAT_INTEL_SOURCES else ()
            add(f"feed.{index}", "bot_measurement", result.source.name,
                f"{result.source.name} lists an entry blocking {evidence.domain}.", support)
    for index, vt in enumerate(evidence.virustotal):
        if vt.error or not vt.found:
            fact = f"VirusTotal lookup for {vt.domain}: {vt.error or 'no record'}."
        else:
            names = ", ".join(vt.reputable_hits) or "none"
            fact = (f"VirusTotal {vt.domain}: {vt.malicious} malicious, {vt.suspicious} suspicious "
                    f"of {vt.total}; recorded scan date {vt.last_analysis or 'unknown'}; reputable hits: {names}.")
        support = ("block",) if not vt.error and vt.found and len(vt.reputable_hits) >= MIN_REPUTABLE_VT_HITS else ()
        add(f"vt.{index}", "bot_measurement", "VirusTotal recorded scan", fact, support)
    rdap_created = evidence.registration.created if evidence.registration else None
    created = rdap_created or next((vt.created for vt in evidence.virustotal if vt.created), None)
    if created and not evidence.platform:
        days = (today - created).days
        fact = f"{evidence.apex} registered {created}; age {days} days as of {today}." if days >= 0 else (
            f"Registration date {created} is later than observation date {today}; age is unavailable."
        )
        source = "RDAP registration record" if rdap_created else "VirusTotal registration record"
        add("registration.age", "bot_measurement", source, fact)
    elif evidence.platform:
        add("registration.platform", "bot_measurement", "domain classification",
            f"Registration data describes shared platform {evidence.platform}, not this site's age.")
    rank = evidence.tranco_rank or evidence.apex_tranco_rank
    add("rank", "bot_measurement", "Tranco", f"Recorded rank: {rank:,}." if rank else "Not in the top 1M.")
    add("dns", "bot_measurement", "DNS lookup", "Resolved addresses: " + (", ".join(evidence.addresses) or "no answer") + ".")
    for index, fetch in enumerate(evidence.fetches + evidence.quoted_fetches):
        source = f"{probe_name(fetch.profile)}: {fetch.start or fetch.final_url}"
        fact = f"HTTP {fetch.status}; final URL {fetch.final_url or 'unknown'}." if fetch.status is not None else (
            f"Probe failed: {fetch.error or 'unknown error'}; browser availability is not established."
        )
        add(f"probe.{index}", "bot_measurement", source, fact)
        if fetch.title or fetch.excerpt:
            add(f"probe.text.{index}", "website_text", source,
                f"Page supplied title {fetch.title!r}; excerpt {fetch.excerpt!r}.")
    for index, flag in enumerate(provider_flags(evidence)):
        add(f"provider.{index}", "bot_measurement", "HTTP page title matched provider warning", flag, ("block",))
    capture = evidence.capture
    if capture:
        outcome = getattr(capture, "outcome", "") or ("failed" if capture.error else "captured")
        status = getattr(capture, "status", None)
        add("browser", "bot_measurement", "browser capture",
            f"Browser outcome: {outcome}; HTTP status {status if status is not None else 'unrecorded'}; "
            f"final URL {capture.final_url or 'unknown'}; error {capture.error or 'none'}.")
        if "browser.image" in image_ids:
            add("browser.image", "fetched_corroboration", f"browser screenshot at {capture.final_url}",
                "A bounded browser screenshot was supplied to the review model; its interpretation is advisory.", image=True)
        if capture.text:
            add("browser.text", "website_text", f"browser page at {capture.final_url}", f"Page supplied text: {capture.text}")
    request = evidence.request
    form = parse_sections(request.body)
    if not form:
        form = {"title": request.title, "evidence": request.evidence, "details": request.details, "service": request.service}
    for index, (name, value) in enumerate(form.items()):
        if value.strip() and value.strip() != NO_RESPONSE:
            add(f"report.form.{index}", "reporter_claim", f"issue form field: {name}", f"Reporter supplied: {value}")
    for index, comment in enumerate(request.thread):
        if comment.body.strip():
            add(f"report.comment.{index}", "reporter_claim", f"issue comment by {comment.author} ({comment.role})",
                f"Comment supplied: {comment.body}")
    inspected: set[str] = {fetch.start for fetch in evidence.fetches + evidence.quoted_fetches if fetch.status is not None}
    for index, material in enumerate(getattr(evidence, "materials", ())):
        url = str(getattr(material, "url", ""))
        status = str(getattr(material, "status", "unrecorded"))
        outcome = str(getattr(material, "outcome", "unknown"))
        note = str(getattr(material, "note", "Source claims remain unverified."))
        error = str(getattr(material, "error", "") or "")
        source = str(getattr(material, "source", "submitted material"))
        text = str(getattr(material, "text", "") or "")
        image_id = f"material.image.{index}"
        image = image_id in image_ids
        if image or text:
            inspected.add(url)
        add(f"material.{index}", "bot_measurement", source,
            f"Submitted {getattr(material, 'kind', 'link')} {url}: outcome {outcome}; status {status}; "
            f"{'content supplied to model' if image or text else 'uninspected content'}. {note} "
            f"Collection limitation: {error or 'none'}.")
        if text:
            add(f"material.text.{index}", "fetched_corroboration", f"{source}: {url}", f"Fetched source supplied: {text}")
        if image:
            add(image_id, "fetched_corroboration", f"{source}: {url}",
                "A bounded submitted image was supplied to the review model; its interpretation is advisory.", image=True)
    raw_text = "\n".join([request.body, request.evidence, request.details] + [c.body for c in request.thread])
    urls = list(dict.fromkeys(url.rstrip(".,;:!?") for url in URL_RE.findall(raw_text)))
    for index, url in enumerate(urls):
        if url not in inspected:
            add(f"link.{index}", "reporter_claim", "issue link or attachment", f"Uninspected link/attachment: {url}")
    return observations


def model_text(observations: list[Observation]) -> str:
    return safe_data([
        {"id": observation.id, "kind": observation.kind, "source": observation.source[:300],
         "fact": observation.fact[:6000], "image": observation.image}
        for observation in observations[:150]
    ])
