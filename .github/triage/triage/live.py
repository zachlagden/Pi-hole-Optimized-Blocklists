import hashlib
import html
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

PROFILES = {
    "desktop": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
    },
    "mobile": {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1",
    },
    "google referral": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
        "Referer": "https://www.google.com/",
    },
}
MAX_REDIRECTS = 8
MAX_BODY = 2_000_000
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class Fetch:
    profile: str
    chain: list[str] = field(default_factory=list)
    status: int | None = None
    title: str = ""
    size: int = 0
    digest: str = ""
    error: str | None = None

    @property
    def final_url(self) -> str:
        return self.chain[-1] if self.chain else ""


def resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def is_public_host(host: str) -> bool:
    addresses = resolve(host)
    return bool(addresses) and all(ipaddress.ip_address(address).is_global for address in addresses)


def _title(body: bytes) -> str:
    match = TITLE_RE.search(body[:200_000].decode("utf-8", errors="replace"))
    return " ".join(html.unescape(match.group(1)).split())[:200] if match else ""


def fetch(domain: str, profile: str) -> Fetch:
    result = Fetch(profile)
    url = f"https://{domain}/"
    with httpx.Client(headers=PROFILES[profile], timeout=20, follow_redirects=False, verify=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            host = urlsplit(url).hostname or ""
            if not is_public_host(host):
                result.error = f"stopped at {host}: does not resolve to a public address"
                return result
            result.chain.append(url)
            try:
                response = client.get(url)
            except httpx.HTTPError as error:
                if len(result.chain) == 1 and url.startswith("https://"):
                    url = f"http://{domain}/"
                    result.chain.clear()
                    continue
                result.error = f"{type(error).__name__}"
                return result
            if response.is_redirect and "location" in response.headers:
                url = urljoin(url, response.headers["location"])
                continue
            body = response.content[:MAX_BODY]
            result.status = response.status_code
            result.title = _title(body)
            result.size = len(body)
            result.digest = hashlib.sha256(body).hexdigest()[:12]
            return result
    result.error = "too many redirects"
    return result


def fetch_all(domain: str) -> list[Fetch]:
    return [fetch(domain, profile) for profile in PROFILES]


def cloaking_summary(fetches: list[Fetch]) -> str | None:
    usable = [item for item in fetches if item.status is not None]
    if len(usable) < 2:
        return None
    hosts = {urlsplit(item.final_url).hostname for item in usable}
    titles = {item.title for item in usable}
    if len(hosts) > 1:
        return "different visitors are sent to different final hosts: " + ", ".join(sorted(h or "" for h in hosts))
    if len(titles) > 1:
        return "different visitors get pages with different titles"
    sizes = [item.size for item in usable]
    if max(sizes) > 0 and (max(sizes) - min(sizes)) / max(sizes) > 0.5:
        return "page size differs by more than half between visitor types"
    return None
