from triage import ai_review
from triage.issue_form import IssueRequest
from triage.publication_safety import deterministic_reporter_reply
from triage.state import TriageState

WHAT_CHANGED = (
    "The domain was added to this project's allowlist (whitelist.txt). The allowlist overrides any "
    "upstream feed that lists the domain when a successful rebuild consumes the merged configuration. "
    "The configuration is merged, but publication is still pending verification; do not say the "
    "published lists have already changed."
)
SCOPE_WORDS = {
    "domain": ("the domain and all its subdomains", "each domain and all its subdomains"),
    "exact": ("this exact host only", "these exact hosts only"),
    "subdomains": ("its subdomains only", "their subdomains only"),
}


def scope_words(scope: str, count: int) -> str:
    single, plural = SCOPE_WORDS[scope]
    return plural if count > 1 else single


def mention(login: str, text: str) -> str:
    return f"@{login} {text}" if login else text


def closing_line(pr: int, entries: list[str], scope: str, timing: str) -> str:
    listed = ", ".join(f"`{entry}`" for entry in entries)
    return f"Allowed in #{pr} ({listed}, {scope_words(scope, len(entries))}). {timing}"


def reply_context(domains: list[str], entries: list[str], scope: str, pr: int, timing: str, request: IssueRequest, state: TriageState | None) -> dict:
    reported = bool(state and state.domain in domains)
    context: dict = {
        "domains": domains,
        "entries_written": entries,
        "scope": scope_words(scope, len(domains)),
        "pull_request": f"#{pr}",
        "timing_sentence": timing,
        "what_changed": WHAT_CHANGED,
    }
    if reported and state:
        context |= {
            "upstream_feeds_that_blocked_it": state.listed_by,
        }
    context["reporter"] = {
        "title": request.title,
        "service_affected": request.service,
        "what_broke": request.details,
        "evidence": request.evidence,
    }
    return context


def fallback_reply(context: dict) -> str:
    return deterministic_reporter_reply(context)


def reporter_comment(login: str, owner_text: str, context: dict, api_key: str | None) -> str:
    text = owner_text.strip() or ai_review.reporter_reply(context, api_key or "")
    if not text:
        raise ValueError("invalid verified reporter-reply context")
    return mention(login, text)
