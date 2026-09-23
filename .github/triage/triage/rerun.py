from dataclasses import dataclass
from datetime import UTC, datetime

from triage import ai_review, live, render
from triage.evidence import Evidence
from triage.github_api import ThreadComment
from triage.issue_form import IssueRequest
from triage.domains import clean_domain
from triage.state import MAX_STORED_BODY, TriageState, added_words, body_diff, body_sha

COSMETIC_WORD_LIMIT = 3


@dataclass
class Check:
    run: bool
    trigger: str
    reason: str


def unseen_comments(thread: list[ThreadComment], state: TriageState) -> list[ThreadComment]:
    seen = set(state.seen_comments)
    return [comment for comment in thread if comment.id not in seen and comment.role != "maintainer"]


def describe_trigger(body_changed: bool, comments: list[ThreadComment]) -> str:
    parts = []
    if body_changed:
        parts.append("an edit to the issue")
    authors = sorted({comment.author for comment in comments})
    if authors:
        parts.append("new comments from " + ", ".join(authors))
    return " and ".join(parts)


def new_urls(request: IssueRequest, comments: list[ThreadComment], state: TriageState) -> list[str]:
    domain = request.domain or state.domain
    text = "\n".join([request.body] + [comment.body for comment in comments])
    return [url for url in live.quoted_urls(text, domain, limit=10) if url not in state.seen_urls]


def is_cosmetic_edit(state: TriageState, new_body: str) -> bool:
    if not state.body:
        return False
    words = added_words(state.body, new_body)
    if any("://" in word or clean_domain(word) for word in words if "." in word):
        return False
    return len(words) <= COSMETIC_WORD_LIMIT


def _ai_verdict(request: IssueRequest, state: TriageState, body_changed: bool, comments: list[ThreadComment], api_key: str) -> tuple[bool, str]:
    context = {
        "domain": state.domain,
        "request": request.kind,
        "last_suggestion": state.recommendation,
        "open_questions": state.questions,
        "history": state.history[-3:],
    }
    material = [{"from": c.author, "role": c.role, "text": c.body[:3000]} for c in comments]
    if body_changed:
        change = body_diff(state.body, request.body) if state.body else "Edited issue body (no earlier copy to compare):\n" + request.body[:6000]
        material.insert(0, {"from": request.author, "role": "reporter", "text": "Edit to the issue body, as a diff (- removed, + added):\n" + change})
    try:
        return ai_review.is_useful(context, material, api_key)
    except Exception as error:
        return True, f"usefulness check failed ({type(error).__name__}), re-running to be safe"


def check(issue: dict, request: IssueRequest, thread: list[ThreadComment], state: TriageState | None, api_key: str | None) -> Check:
    if issue.get("state") != "open":
        return Check(False, "", "the issue is closed")
    if state is None:
        return Check(True, "new activity on an issue with no triage state yet", "no previous triage to compare against")
    body_changed = body_sha(request.body) != state.body_sha
    comments = unseen_comments(thread, state)
    if body_changed and not comments and is_cosmetic_edit(state, request.body):
        return Check(False, "", "the edit only changed a few words, with no new URL or domain")
    if not body_changed and not comments:
        return Check(False, "", "nothing new since the last triage")
    trigger = describe_trigger(body_changed, comments)
    if request.domain and state.domain and request.domain != state.domain:
        return Check(True, trigger, f"the reported domain changed from {state.domain} to {request.domain}")
    if urls := new_urls(request, comments, state):
        return Check(True, trigger, "new URL on the reported domain: " + urls[0])
    if not api_key:
        return Check(True, trigger, "no AI key to judge usefulness")
    useful, reason = _ai_verdict(request, state, body_changed, comments, api_key)
    return Check(useful, trigger, reason)


def next_state(request: IssueRequest, previous: TriageState | None, review: ai_review.Review | None, trigger: str, fetched: list[str], evidence: Evidence | None = None) -> TriageState:
    today = datetime.now(UTC).date().isoformat()
    recommendation = review.recommendation if review and not review.error else "no AI view"
    confidence = review.confidence if review and not review.error else ""
    verdict = f"{recommendation.replace('_', ' ')} ({confidence})" if confidence else recommendation.replace("_", " ")
    history = list(previous.history) if previous else []
    if previous is None:
        history.append(f"{today}: first triage, suggested {verdict}")
    else:
        was = previous.recommendation.replace("_", " ") or "nothing"
        change = f"still {verdict}" if previous.recommendation == recommendation else f"{was} to {verdict}"
        history.append(f"{today}: re-run after {trigger or 'a manual request'}, {change}")
    return TriageState(
        domain=request.domain or "",
        body_sha=body_sha(request.body),
        body=request.body[:MAX_STORED_BODY],
        recommendation=recommendation if review and not review.error else (previous.recommendation if previous else ""),
        confidence=confidence,
        questions=review.questions if review and not review.error else [],
        site=render.first_sentence(review.site) if review and not review.error else "",
        evidence=render.evidence_note(evidence) if evidence else "",
        vt_reputable=max((len(vt.reputable_hits) for vt in evidence.virustotal), default=0) if evidence else (previous.vt_reputable if previous else 0),
        seen_comments=[c.id for c in request.thread],
        seen_urls=sorted(set(fetched) | set(previous.seen_urls if previous else [])),
        history=history[-10:],
    )


def rerun_text(previous: TriageState, state: TriageState, trigger: str) -> str:
    was = previous.recommendation.replace("_", " ") or "nothing"
    now = state.recommendation.replace("_", " ")
    change = f"still {now}" if was == now else f"{was} to {now}"
    return f"Re-triaged after {trigger or 'a manual request'}: {change}."
