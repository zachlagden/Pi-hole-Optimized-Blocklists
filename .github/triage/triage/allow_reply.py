from triage import ai_review
from triage.issue_form import IssueRequest
from triage.state import TriageState

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
    }
    if reported and state:
        context |= {
            "site_description": state.site,
            "evidence_summary": state.evidence,
            "last_ai_suggestion": state.recommendation,
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
    listed = ", ".join(f"`{domain}`" for domain in context["domains"])
    verb = "are" if len(context["domains"]) > 1 else "is"
    return (
        f"Thanks for the report. {listed} {verb} now allowed in {context['pull_request']}. "
        f"{context['timing_sentence']} Until then, you can allow it on your own Pi-hole."
    )


def reporter_comment(login: str, owner_text: str, context: dict, api_key: str | None) -> str:
    text = owner_text.strip()
    if not text and api_key:
        text = ai_review.reporter_reply(context, api_key)
    if not text:
        text = fallback_reply(context)
    return mention(login, text)
