import hashlib
import html
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

DESKTOP_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
MOBILE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1"
BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
}
PROFILES = {
    "desktop": {**BROWSER_HEADERS, "User-Agent": DESKTOP_UA},
    "mobile": {**BROWSER_HEADERS, "User-Agent": MOBILE_UA},
    "google referral": {**BROWSER_HEADERS, "User-Agent": DESKTOP_UA, "Referer": "https://www.google.com/"},
    "email link": {**BROWSER_HEADERS, "User-Agent": DESKTOP_UA, "Referer": "https://t.co/"},
}
MAX_REDIRECTS = 8
MAX_BODY = 2_000_000
URL_RE = re.compile(r"(?:blob:)?https?://[^\s<>()\[\]\"'`]+", re.IGNORECASE)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class Fetch:
    profile: str
    start: str = ""
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


def quoted_urls(text: str, domain: str, limit: int = 3) -> list[str]:
    found: list[str] = []
    for match in URL_RE.findall(text or ""):
        url = match.removeprefix("blob:").rstrip(".,;:!?'\")>")
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if host != domain and not host.endswith("." + domain):
            continue
        if parts.path in {"", "/"} and not parts.query:
            continue
        if url not in found:
            found.append(url)
    return found[:limit]


def fetch(domain: str, profile: str) -> Fetch:
    return fetch_url(f"https://{domain}/", profile, fallback_http=True)


def fetch_url(start: str, profile: str, fallback_http: bool = False) -> Fetch:
    result = Fetch(profile, start)
    url = start
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
                if fallback_http and len(result.chain) == 1 and url.startswith("https://"):
                    url = "http://" + url.removeprefix("https://")
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
