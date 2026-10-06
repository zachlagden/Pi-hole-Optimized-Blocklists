import re
from typing import Any

from triage.domains import is_valid_domain

SENTENCE_END_RE = re.compile(r"[.!?](?=\s|$)")
SAFE_QUESTION = (
    "Please share only minimal, redacted evidence from what you have already observed, "
    "such as a cropped screenshot or a short description of what broke. "
    "Remove all personal and confidential information; do not make a purchase or enter "
    "sensitive information to gather evidence."
)


def trim_sentences(text: str, limit: int) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    ends = [match.end() for match in SENTENCE_END_RE.finditer(text[:limit])]
    if ends:
        return text[:ends[-1]]
    prefix = text[:max(0, limit - 1)]
    boundary = prefix.rfind(" ")
    return prefix[:boundary].rstrip() + "…" if boundary > 0 else "…"


def safe_questions(questions: list[str], needs_info: bool = False) -> list[str]:
    return [SAFE_QUESTION] if questions or needs_info else []


SCOPE_KEYS = {
    "domain": "domain", "the domain and all its subdomains": "domain", "each domain and all its subdomains": "domain",
    "exact": "exact", "this exact host only": "exact", "these exact hosts only": "exact",
    "subdomains": "subdomains", "its subdomains only": "subdomains", "their subdomains only": "subdomains",
}
SCOPE_TEXT = {
    "domain": "the specified domains and all their subdomains",
    "exact": "the specified exact hosts only",
    "subdomains": "subdomains of the specified domains only, not the bare domains",
}


def deterministic_reporter_reply(context: dict[str, Any], audience: str = "unknown", limit: int = 1200) -> str:
    domains = context.get("domains")
    entries = context.get("entries_written")
    scope = SCOPE_KEYS.get(str(context.get("scope", "")))
    pr = context.get("pull_request")
    timing = context.get("timing_sentence")
    if (not isinstance(domains, list) or not domains or scope is None
            or not all(isinstance(domain, str) and is_valid_domain(domain) for domain in domains)
            or not isinstance(entries, list) or len(entries) != len(domains)
            or not isinstance(pr, str) or not re.fullmatch(r"#[1-9][0-9]*", pr)
            or not isinstance(timing, str) or not timing.endswith(".") or len(timing) > 300
            or re.search(r"[<>`\[\]@\r\n]", timing)):
        return ""
    expected = [
        "/^" + domain.replace(".", r"\.") + "$/" if scope == "exact" else
        f"*.{domain}" if scope == "subdomains" else domain
        for domain in domains
    ]
    if entries != expected:
        return ""
    listed = ", ".join(f"`{domain}`" for domain in domains)
    verb = "was" if len(domains) == 1 else "were"
    change = f"{listed} {verb} added to this project's allowlist in {pr}, covering {SCOPE_TEXT[scope]}."
    feeds = context.get("upstream_feeds_that_blocked_it", [])
    feed_sentence = ""
    if isinstance(feeds, list) and feeds and all(
        isinstance(feed, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,79}", feed) for feed in feeds
    ):
        feed_sentence = "Recorded upstream feeds listing the reported domain: " + ", ".join(feeds) + ". "
    audience_sentence = {
        "owner": "The allowlist change applies to people accessing the covered hosts through these lists after the rebuild.",
        "visitor": "If you run a Pi-hole yourself, you can apply the same scoped allowlist entry there in the meantime.",
    }.get(audience, "The change applies only to the scope stated above.")
    message = f"Thanks for the report. {change} {feed_sentence}{timing} {audience_sentence}"
    if len(message) > limit:
        change = f"The requested entries were added to this project's allowlist in {pr}, covering {SCOPE_TEXT[scope]}."
        message = f"Thanks for the report. {change} {timing} {audience_sentence}"
    return message if len(message) <= limit else ""


def safe_data(data: object) -> str:
    import json

    return json.dumps(data, ensure_ascii=False, default=str).replace("<", "\\u003c").replace(">", "\\u003e")


def public_text(text: str, limit: int = 600) -> str:
    text = " ".join(re.sub(r"[<>`|\[\]]", "", text).replace("@", "@​").split())
    return trim_sentences(text, limit)
