from triage import rerun
from triage.github_api import ThreadComment
from triage.issue_form import from_issue
from triage.labels import plan_needs_info
from triage.state import TriageState, body_sha, parse_state

BODY = "### Domain\n\npub-abc.r2.dev\n\n### Category\n\nMalicious (fake shops, scams, phishing)\n\n### Evidence / Reason\n\nphishing"


def issue(body: str = BODY, state: str = "open") -> dict:
    return {"number": 7, "title": "Block", "body": body, "state": state, "labels": [{"name": "blocklist"}], "user": {"login": "rep"}}


def saved_state(**overrides) -> TriageState:
    base = TriageState(domain="pub-abc.r2.dev", body_sha=body_sha(BODY), recommendation="needs_info", seen_comments=[1])
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def test_state_round_trips_through_the_report_marker():
    state = saved_state(questions=["Which path?"], history=["first"])
    assert parse_state(f"report text\n{state.to_marker()}") == state
    assert parse_state("no marker here") is None


def test_closed_issue_never_reruns():
    result = rerun.check(issue(state="closed"), from_issue(issue()), [], saved_state(), None)
    assert not result.run


def test_nothing_new_does_nothing():
    old = [ThreadComment(1, "rep", "reporter", "old")]
    result = rerun.check(issue(), from_issue(issue()), old, saved_state(), None)
    assert not result.run and result.reason == "nothing new since the last triage"


def test_maintainer_comments_do_not_trigger():
    thread = [ThreadComment(2, "zach", "maintainer", "https://pub-abc.r2.dev/new.html")]
    assert not rerun.check(issue(), from_issue(issue()), thread, saved_state(), None).run


def test_new_url_on_the_domain_reruns_without_asking_the_ai():
    thread = [ThreadComment(2, "rep", "reporter", "the kit is at https://pub-abc.r2.dev/new.html")]
    result = rerun.check(issue(), from_issue(issue()), thread, saved_state(), "unused-key")
    assert result.run and "new URL" in result.reason and "rep" in result.trigger


def test_already_seen_url_is_not_new():
    thread = [ThreadComment(2, "rep", "reporter", "again https://pub-abc.r2.dev/new.html")]
    state = saved_state(seen_urls=["https://pub-abc.r2.dev/new.html"])
    assert rerun.new_urls(from_issue(issue()), thread, state) == []


def test_domain_change_reruns():
    edited = BODY.replace("pub-abc.r2.dev", "pub-xyz.r2.dev")
    result = rerun.check(issue(edited), from_issue(issue(edited)), [], saved_state(), None)
    assert result.run and "domain changed" in result.reason


def test_useless_comment_is_ignored_when_the_ai_says_so(monkeypatch):
    monkeypatch.setattr(rerun.ai_review, "is_useful", lambda context, material, key: (False, "just a thank-you"))
    thread = [ThreadComment(2, "rep", "reporter", "thanks!")]
    result = rerun.check(issue(), from_issue(issue()), thread, saved_state(), "key")
    assert not result.run and result.reason == "just a thank-you"


def test_ai_failure_reruns_to_be_safe(monkeypatch):
    def boom(context, material, key):
        raise ValueError("bad json")
    monkeypatch.setattr(rerun.ai_review, "is_useful", boom)
    thread = [ThreadComment(2, "rep", "reporter", "here is more context about the page")]
    assert rerun.check(issue(), from_issue(issue()), thread, saved_state(), "key").run


def test_needs_info_is_removed_once_the_review_can_decide():
    assert plan_needs_info({"needs info"}, "block").remove == {"needs info"}
    assert plan_needs_info({"needs info"}, "needs_info").empty
