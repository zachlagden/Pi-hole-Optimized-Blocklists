import re
from functools import lru_cache
from pathlib import Path

import tldextract

MAX_DOMAIN_LENGTH = 253
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$"
)
SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def is_valid_domain(domain: str) -> bool:
    if not domain or domain == "localhost" or domain.endswith(".local"):
        return False
    if len(domain) > MAX_DOMAIN_LENGTH:
        return False
    return bool(DOMAIN_RE.match(domain))


def clean_domain(raw: str) -> str | None:
    text = raw.strip().strip("`'\"<>").strip()
    if not text:
        return None
    text = SCHEME_RE.sub("", text)
    text = re.split(r"[/?#\s]", text, maxsplit=1)[0]
    text = text.rsplit("@", 1)[-1]
    text = re.sub(r":\d+$", "", text)
    text = text.removeprefix("||").removesuffix("^").removeprefix("*.")
    text = text.strip(".").lower()
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return text if is_valid_domain(text) else None


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    cache_dir = Path.home() / ".cache" / "issue-triage" / "tldextract"
    return tldextract.TLDExtract(cache_dir=str(cache_dir), include_psl_private_domains=True)


def registrable(domain: str) -> str:
    parts = _extractor()(domain)
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}"
    return domain


def registrable_label(domain: str) -> str:
    return _extractor()(domain).domain or domain.split(".")[0]


def self_and_parents(domain: str) -> list[str]:
    base = registrable(domain)
    labels = domain.split(".")
    chain = [".".join(labels[i:]) for i in range(len(labels))]
    if base in chain:
        return chain[: chain.index(base) + 1]
    return chain[:-1] or [domain]


def shared_platform(domain: str) -> str | None:
    parts = _extractor()(domain)
    return parts.suffix if parts.is_private else None
