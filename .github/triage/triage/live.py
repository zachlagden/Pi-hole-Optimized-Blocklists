import hashlib
import html
import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from triage.decoding import decode_page

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
URL_RE = re.compile(r"(?<![\w:])(?:blob:)?https?://[^\s<>()\[\]\"'`*]+", re.IGNORECASE)
CHALLENGE_RE = re.compile(r"just a moment|checking (?:your )?browser|verify (?:that )?you are human|captcha|access denied|suspected phishing|attention required|enable javascript and cookies", re.IGNORECASE)
LITERAL_REDIRECT_RE = re.compile(r"""location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*["'](https?://[^"']+)["']""")
VARIABLE_REDIRECT_RE = re.compile(r"""location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*([A-Za-z_$][\w$]*)""")
ASSIGNMENT_RE = r"""(?:var|let|const)\s+{name}\s*=\s*["'](https?://[^"']+)["']"""
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
    script_redirects: list[str] = field(default_factory=list)
    excerpt: str = ""
    error: str | None = None
    outcome: str = "unknown"

    @property
    def final_url(self) -> str:
        return self.chain[-1] if self.chain else ""


def resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({str(info[4][0]) for info in infos})


def is_public_host(host: str) -> bool:
    addresses = resolve(host)
    return bool(addresses) and all(ipaddress.ip_address(address).is_global for address in addresses)


def _text(page: str | bytes) -> str:
    return page if isinstance(page, str) else decode_page(page)


def _title(page: str | bytes) -> str:
    match = TITLE_RE.search(_text(page)[:200_000])
    return " ".join(html.unescape(match.group(1)).split())[:200] if match else ""


def extracted_urls(text: str, limit: int = 30) -> list[str]:
    found: list[str] = []
    for match in URL_RE.findall((text or "")[:50_000]):
        if match.lower().startswith("blob:"):
            continue
        url = html.unescape(match).rstrip(".,;:!?'\")>")
        try:
            urlsplit(url).port
        except ValueError:
            continue
        if url not in found:
            found.append(url)
        if len(found) >= limit:
            break
    return found


def quoted_urls(text: str, domain: str, limit: int = 3) -> list[str]:
    found: list[str] = []
    for url in extracted_urls(text):
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if host != domain and not host.endswith("." + domain):
            continue
        if parts.path in {"", "/"} and not parts.query:
            continue
        if url not in found:
            found.append(url)
    return found[:limit]


def visible_text(page: str | bytes, limit: int = 1500) -> str:
    text = _text(page)[:400_000]
    text = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", text)
    text = html.unescape(re.sub(r"(?s)<[^>]+>", " ", text))
    return " ".join(text.split())[:limit]


def script_redirects(page: str | bytes) -> list[str]:
    text = _text(page)[:500_000]
    found = LITERAL_REDIRECT_RE.findall(text)
    for name in VARIABLE_REDIRECT_RE.findall(text):
        found += re.findall(ASSIGNMENT_RE.format(name=re.escape(name)), text)
    unique: list[str] = []
    for url in found:
        if url not in unique:
            unique.append(url)
    return unique[:5]


def fetch(domain: str, profile: str) -> Fetch:
    return fetch_url(f"https://{domain}/", profile, fallback_http=True)


@dataclass
class RequestBudget:
    remaining: int = 12
    deadline: float = field(default_factory=lambda: time.monotonic() + 60)


@dataclass
class BoundedResponse:
    chain: list[str] = field(default_factory=list)
    status: int | None = None
    headers: httpx.Headers = field(default_factory=httpx.Headers)
    body: bytes = b""
    error: str | None = None

    @property
    def text(self) -> str:
        return decode_page(self.body, httpx.Response(200, headers=self.headers).charset_encoding)


def safe_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        return (
            parts.scheme in {"http", "https"}
            and bool(parts.hostname)
            and parts.username is None
            and parts.password is None
            and parts.port in {None, 80, 443}
            and not any(ord(char) < 32 or char == "\\" for char in url)
            and is_public_host(parts.hostname or "")
        )
    except (ValueError, OSError):
        return False


def bounded_get(client: httpx.Client, start: str, max_body: int = MAX_BODY, max_redirects: int = MAX_REDIRECTS, budget: RequestBudget | None = None) -> BoundedResponse:
    budget = budget if budget is not None else RequestBudget()
    result = BoundedResponse()
    url = start
    for _ in range(max_redirects + 1):
        if budget.remaining <= 0 or time.monotonic() >= budget.deadline:
            result.error = "request budget exhausted"
            return result
        if not safe_url(url):
            result.error = "unsafe or non-public destination"
            return result
        if time.monotonic() >= budget.deadline:
            result.error = "request budget exhausted"
            return result
        budget.remaining -= 1
        result.chain.append(url)
        try:
            with client.stream("GET", url, headers={"Accept-Encoding": "identity"}, timeout=min(10, max(0.1, budget.deadline - time.monotonic()))) as response:
                result.status = response.status_code
                result.headers = response.headers
                if response.is_redirect and "location" in response.headers:
                    url = urljoin(url, response.headers["location"])
                    continue
                if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
                    result.error = "encoded response not accepted within byte budget"
                    return result
                length = response.headers.get("content-length", "")
                if length.isdigit() and int(length) > max_body:
                    result.error = "response exceeds byte limit"
                    return result
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes(chunk_size=16_384):
                    size += len(chunk)
                    if size > max_body or time.monotonic() >= budget.deadline:
                        result.error = "response exceeds byte or time limit"
                        return result
                    chunks.append(chunk)
                result.body = b"".join(chunks)
                return result
        except (httpx.HTTPError, ValueError) as error:
            result.error = type(error).__name__
            return result
    result.error = "too many redirects"
    return result


def content_outcome(status: int | None, text: str, error: str | None = None) -> str:
    if CHALLENGE_RE.search(text[:6000]):
        return "challenge"
    if error:
        return "failed"
    if status is None or status >= 400 or status < 200:
        return "http_error" if status is not None else "failed"
    if status >= 300 or len(text.strip()) < 40:
        return "insufficient"
    return "rendered"


def fetch_url(start: str, profile: str, fallback_http: bool = False) -> Fetch:
    result = Fetch(profile, start)
    budget = RequestBudget()
    with httpx.Client(headers=PROFILES[profile], timeout=10, follow_redirects=False, verify=False, trust_env=False) as client:
        response = bounded_get(client, start, budget=budget)
        if fallback_http and response.error in {"ConnectError", "ConnectTimeout"} and len(response.chain) == 1 and start.startswith("https://"):
            response = bounded_get(client, "http://" + start.removeprefix("https://"), budget=budget)
    result.chain = response.chain
    result.status = response.status
    result.error = response.error
    body = response.body
    text = response.text
    result.title = _title(text)
    result.size = len(body)
    result.digest = hashlib.sha256(body).hexdigest()[:12] if body else ""
    result.script_redirects = script_redirects(text)
    result.excerpt = visible_text(text)
    result.outcome = content_outcome(result.status, result.title + " " + result.excerpt, result.error)
    return result


def fetch_all(domain: str) -> list[Fetch]:
    return [fetch(domain, profile) for profile in PROFILES]


def usable_fetches(fetches: list[Fetch]) -> list[Fetch]:
    return [item for item in fetches if content_outcome(item.status, item.title + " " + item.excerpt, item.error) == "rendered"]


def cloaking_outcome(fetches: list[Fetch]) -> str:
    if len(usable_fetches(fetches)) < 2:
        return "insufficient"
    return "different" if cloaking_summary(fetches) else "matching"


def cloaking_summary(fetches: list[Fetch]) -> str | None:
    usable = usable_fetches(fetches)
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
