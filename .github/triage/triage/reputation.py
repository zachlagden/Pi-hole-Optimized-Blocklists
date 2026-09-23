import csv
import io
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

import httpx

from triage.policy import REPUTABLE_VT_ENGINES

VT_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
RDAP_URL = "https://rdap.org/domain/{domain}"
TRANCO_LATEST = "https://tranco-list.eu/api/lists/date/latest"


@dataclass
class VirusTotal:
    domain: str
    found: bool
    malicious: int = 0
    suspicious: int = 0
    total: int = 0
    engines: list[tuple[str, str, str]] = field(default_factory=list)
    last_analysis: date | None = None
    created: date | None = None
    registrar: str = ""
    categories: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def link(self) -> str:
        return f"https://www.virustotal.com/gui/domain/{self.domain}"

    @property
    def reputable_hits(self) -> list[str]:
        return [name for name, _, _ in self.engines if name in REPUTABLE_VT_ENGINES]


@dataclass
class Registration:
    domain: str
    created: date | None = None
    registrar: str = ""
    nameservers: list[str] = field(default_factory=list)
    error: str | None = None


def _to_date(timestamp: int | None) -> date | None:
    return datetime.fromtimestamp(timestamp, UTC).date() if timestamp else None


def virustotal(domain: str, api_key: str) -> VirusTotal:
    try:
        response = httpx.get(VT_URL.format(domain=domain), headers={"x-apikey": api_key}, timeout=30)
    except httpx.HTTPError as error:
        return VirusTotal(domain, found=False, error=str(error))
    if response.status_code == 404:
        return VirusTotal(domain, found=False)
    if response.status_code != 200:
        return VirusTotal(domain, found=False, error=f"HTTP {response.status_code}")
    attributes = response.json()["data"]["attributes"]
    stats = attributes.get("last_analysis_stats", {})
    engines = [
        (name, verdict.get("category", ""), verdict.get("result", ""))
        for name, verdict in attributes.get("last_analysis_results", {}).items()
        if verdict.get("category") in {"malicious", "suspicious"}
    ]
    return VirusTotal(
        domain=domain,
        found=True,
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        total=sum(stats.values()),
        engines=sorted(engines),
        last_analysis=_to_date(attributes.get("last_analysis_date")),
        created=_to_date(attributes.get("creation_date")),
        registrar=attributes.get("registrar", ""),
        categories=sorted(set(attributes.get("categories", {}).values())),
    )


def _registrar_name(entities: list[dict]) -> str:
    for entity in entities:
        if "registrar" not in entity.get("roles", []):
            continue
        for item in entity.get("vcardArray", [None, []])[1]:
            if item[0] == "fn":
                return str(item[3])
    return ""


def registration(domain: str) -> Registration:
    try:
        response = httpx.get(RDAP_URL.format(domain=domain), follow_redirects=True, timeout=30)
    except httpx.HTTPError as error:
        return Registration(domain, error=str(error))
    if response.status_code != 200:
        return Registration(domain, error=f"RDAP HTTP {response.status_code}")
    data = response.json()
    created = next(
        (event["eventDate"][:10] for event in data.get("events", []) if event.get("eventAction") == "registration"),
        None,
    )
    return Registration(
        domain=domain,
        created=date.fromisoformat(created) if created else None,
        registrar=_registrar_name(data.get("entities", [])),
        nameservers=sorted(ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])),
    )


def tranco_ranks(cache_dir: Path) -> dict[str, int]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    latest = httpx.get(TRANCO_LATEST, timeout=30).json()
    cached = cache_dir / f"tranco-{latest['list_id']}.csv"
    if not cached.exists():
        response = httpx.get(latest["download"], follow_redirects=True, timeout=120)
        response.raise_for_status()
        content = response.content
        if content[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                content = archive.read(archive.namelist()[0])
        cached.write_bytes(content)
    reader = csv.reader(io.StringIO(cached.read_text()))
    return {row[1]: int(row[0]) for row in reader if len(row) == 2}
