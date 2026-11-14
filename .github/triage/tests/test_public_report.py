from datetime import date
from typing import cast

import httpx
import pytest

from triage import ai_review, live, materials, render
from triage.email_reply import is_notification_url, strip_email_reply
from triage.evidence import Evidence
from triage.github_api import GitHub, ThreadComment
from triage.issue_form import IssueRequest
from triage.live import Fetch
from triage.observations import collect
from triage.reputation import Registration, VirusTotal
from triage.rerun import next_state

HTTPX_CLIENT = httpx.Client
FAKE_TOKEN = "FAKETOKEN0000EXAMPLE1111"
REPORTER_TEXT = "I blocked the entire site and its regex and it worked for me.\n\nThanks for responding."
MAINTAINER_TEXT = (
    "Thanks for the report. example.com itself is Acme's company website, so blocking it wouldn't stop the ads "
    "in apps unless they're actually loaded from that domain. Could you post the hostnames it looks up?"
)
EMAIL_REPLY = f"""{REPORTER_TEXT}

On Sun, Nov 8, 2026 at 4:02 AM Sam Example ***@***.***> wrote:

> *sam-example* left a comment (Acme/example#7)
> <https://github.com/Acme/example/issues/7#issuecomment-1001>
>
> {MAINTAINER_TEXT}
>
> —
> Reply to this email directly, view it on GitHub
> <https://github.com/Acme/example/issues/9?email_source=notifications&email_token={FAKE_TOKEN}#issuecomment-1001>,
> or unsubscribe
> <https://github.com/notifications/unsubscribe-auth/{FAKE_TOKEN}>
> .
> Triage notifications on the go with GitHub Mobile for iOS
> <https://github.com/notifications/mobile/ios/{FAKE_TOKEN}>
> and Android
> <https://github.com/notifications/mobile/android/{FAKE_TOKEN}>.
> Download it today!
> You are receiving this because you authored the thread.Message ID:
> <Acme/example/issues/7/1001
> ***@***.***>
>
"""


def thread() -> list[ThreadComment]:
    return [ThreadComment(1001, "sam-example", "maintainer", MAINTAINER_TEXT),
            ThreadComment(1002, "alex-example", "reporter", EMAIL_REPLY)]


def report_evidence(comments: list[ThreadComment]) -> Evidence:
    request = IssueRequest(7, "block", "Acme ads", "alex-example", "", "example.com", "example.com", thread=comments)
    item = Evidence(request, "example.com", "example.com")
    item.virustotal = [VirusTotal("example.com", True, total=92, last_analysis=date(2031, 4, 10))]
    item.registration = Registration("example.com", date(2000, 5, 29))
    item.tranco_rank = 4197
    item.fetches = [Fetch("desktop", "https://example.com/", ["https://example.com/", "https://www.example.com/"], 200, "Acme")]
    return item


def review_for(item: Evidence) -> ai_review.Review:
    observations = collect(item, date(2031, 4, 11))
    comment_ids = [observation.id for observation in observations if observation.id.startswith("report.comment.")]
    return ai_review._parse({
        "recommendation": "needs_info", "confidence": "low", "impact": "low",
        "site_observation_ids": ["target.host", "vt.0"],
        "reason_observation_ids": ["target.host", "vt.0", "registration.age", "rank", "probe.0", *comment_ids],
    }, observations)


def test_email_reply_keeps_only_the_reporters_new_text() -> None:
    assert strip_email_reply(EMAIL_REPLY) == REPORTER_TEXT


def test_footer_without_attribution_is_still_removed() -> None:
    body = f"Here is the scan.\n\n—\nReply to this email directly, view it on GitHub\nhttps://github.com/notifications/unsubscribe-auth/{FAKE_TOKEN}"
    assert strip_email_reply(body) == "Here is the scan.\n\n—"


def test_ordinary_markdown_quotes_are_kept() -> None:
    body = "> The site asked for my card number\n\nOn the checkout page it wrote: pay now."
    assert strip_email_reply(body) == body


@pytest.mark.parametrize("url,blocked", [
    (f"https://github.com/notifications/unsubscribe-auth/{FAKE_TOKEN}", True),
    (f"https://github.com/notifications/mobile/ios/{FAKE_TOKEN}", True),
    (f"https://github.com/notifications/mobile/android/{FAKE_TOKEN}", True),
    (f"https://github.com/Acme/example/issues/9?email_source=notifications&email_token={FAKE_TOKEN}", True),
    (f"https://evidence.example/report?EMAIL_TOKEN={FAKE_TOKEN}", True),
    ("https://github.com/Acme/example/issues/9", False),
    ("https://evidence.example/report?id=4", False),
])
def test_notification_urls_are_recognised(url: str, blocked: bool) -> None:
    assert is_notification_url(url) is blocked


def test_github_thread_strips_quoted_email_content() -> None:
    raw = {"id": 1002, "user": {"login": "alex-example", "type": "User"}, "author_association": "NONE", "body": EMAIL_REPLY}

    def transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[raw])

    github = GitHub("fictional-token", "Acme/example")
    github.client = httpx.Client(base_url="https://example.com", transport=httpx.MockTransport(transport))
    [comment] = github.thread({"number": 7, "user": {"login": "alex-example"}})
    assert comment.body == REPORTER_TEXT


class FakeGitHub:
    repository = "Acme/example"

    def __init__(self) -> None:
        self.calls: list[int] = []

    def issue(self, number: int) -> dict[str, object]:
        self.calls.append(number)
        return {"title": "Acme related issue", "body": "Unverified related text.", "state": "open"}


def test_email_footer_links_are_never_collected_or_fetched(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def client(**kwargs: object) -> httpx.Client:
        def dispatch(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(200, headers={"content-type": "text/html"}, text="<p>Sign in to GitHub</p>")
        return HTTPX_CLIENT(transport=httpx.MockTransport(dispatch))

    monkeypatch.setattr(materials.httpx, "Client", client)
    monkeypatch.setattr(live, "is_public_host", lambda host: True)
    unquoted = (f"Footer pasted by hand: https://github.com/notifications/unsubscribe-auth/{FAKE_TOKEN} and "
                f"https://github.com/Acme/example/issues/9?email_source=notifications&email_token={FAKE_TOKEN}")
    comments = thread() + [ThreadComment(1003, "alex-example", "reporter", unquoted)]
    github = FakeGitHub()
    request = IssueRequest(7, "block", "Acme ads", "alex-example", "", "example.com", "example.com", thread=comments)
    collected = materials.collect_materials(request, cast(GitHub, github))
    assert calls == [] and github.calls == []
    assert not any("notifications" in material.url or "email_token" in material.url for material in collected)


def test_ai_input_and_observations_omit_quoted_email_and_footer_links() -> None:
    stripped = [ThreadComment(c.id, c.author, c.role, strip_email_reply(c.body)) for c in thread()]
    item = report_evidence(stripped)
    content = ai_review._user_content(item, "", observations=collect(item, date(2031, 4, 11)), images={})
    text = " ".join(part["text"] for part in content if part["type"] == "text")
    assert "worked for me" in text
    assert FAKE_TOKEN not in text and "Reply to this email directly" not in text and "wrote:" not in text
    unquoted = ThreadComment(1003, "alex-example", "reporter", f"https://github.com/notifications/unsubscribe-auth/{FAKE_TOKEN}")
    observations = collect(report_evidence([unquoted]), date(2031, 4, 11))
    assert not any(FAKE_TOKEN in observation.fact for observation in observations if observation.id.startswith("link."))


def test_public_ai_view_is_plain_prose_without_observation_tags_or_comment_echoes() -> None:
    item = report_evidence(thread())
    review = review_for(item)
    block = "\n".join(render._review_block(review))
    assert "[" not in block and "]" not in block
    for tag in ("bot_measurement", "reporter_claim", "target.host", "vt.0", "report.comment", "Comment supplied"):
        assert tag not in block
    assert MAINTAINER_TEXT[:40] not in block and "worked for me" not in block
    assert "**What the site is:** VirusTotal example.com: 0 malicious, 0 suspicious of 92" in block
    assert "- Reviewed host: example.com." in block
    assert "- Tranco rank: 4,197." in block
    assert "- Desktop HTTP probe of https://example.com/: HTTP 200; final URL https://www.example.com/." in block
    assert "- example.com registered 2000-05-29; age" in block
    report = render.comment_markdown(item, [], None, review, [])
    assert "bot_measurement" not in report and "report.comment" not in report


def test_comment_only_site_selection_does_not_become_a_bound_site_note() -> None:
    item = report_evidence(thread())
    observations = collect(item, date(2031, 4, 11))
    review = ai_review._parse({"recommendation": "needs_info", "site_observation_ids": ["report.comment.1"]}, observations)
    assert "No referenced site observations" in review.site
    state = next_state(item.request, None, review, "", [], item)
    assert not state.site and not state.site_observation_bound
