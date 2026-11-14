import re
from urllib.parse import parse_qs, urlsplit

ATTRIBUTION_RE = re.compile(r"^On\b[^\n]{0,300}(?:\n[^\n>]{0,300})?\bwrote:[ \t]*$", re.MULTILINE)
QUOTED_LINE_RE = re.compile(r"^[ \t]*>")
FOOTER_RE = re.compile(r"^[ \t]*Reply to this email directly\b", re.MULTILINE)
NOTIFICATION_HINT_RE = re.compile(r"github\.com/notifications/|[?&]email_(?:token|source)=", re.IGNORECASE)
EMAIL_QUERY_KEYS = {"email_token", "email_source"}


def looks_like_email_reply(body: str) -> bool:
    text = body or ""
    attribution = ATTRIBUTION_RE.search(text)
    quoted_after = bool(attribution and any(QUOTED_LINE_RE.match(line) for line in text[attribution.end():].splitlines()))
    return quoted_after or bool(FOOTER_RE.search(text)) or bool(NOTIFICATION_HINT_RE.search(text))


def strip_email_reply(body: str) -> str:
    text = body or ""
    if not looks_like_email_reply(text):
        return text
    text = ATTRIBUTION_RE.sub("", text)
    if footer := FOOTER_RE.search(text):
        text = text[:footer.start()]
    kept = [line for line in text.splitlines() if not QUOTED_LINE_RE.match(line)]
    return "\n".join(kept).strip()


def is_notification_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        query = parse_qs(parts.query, keep_blank_values=True)
    except ValueError:
        return True
    host = (parts.hostname or "").lower()
    if host in {"github.com", "www.github.com"} and parts.path.lower().startswith("/notifications/"):
        return True
    return any(key.lower() in EMAIL_QUERY_KEYS for key in query)
