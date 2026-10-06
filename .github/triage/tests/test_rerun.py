from typing import Any

import pytest
from pytest import MonkeyPatch

from triage import rerun
from triage.github_api import ThreadComment
from triage.issue_form import from_issue
from triage.labels import plan_needs_info
from triage.state import TriageState, body_sha, parse_state

BODY = "### Domain\n\nreports.example\n\n### Category\n\nMalicious (fake shops, scams, phishing)\n\n### Evidence / Reason\n\nphishing"


def issue(body: str = BODY, state: str = "open") -> dict:
    return {"number": 7, "title": "Block", "body": body, "state": state, "labels": [{"name": "blocklist"}], "user": {"login": "rep"}}


def saved_state(**overrides: Any) -> TriageState:
    base = TriageState(domain="reports.example", body_sha=body_sha(BODY), recommendation="needs_info", seen_comments=[1])
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


def test_maintainer_comments_do_not_trigger() -> None:
    thread = [ThreadComment(2, "Sam", "maintainer", "https://reports.example/new.html")]
    assert not rerun.check(issue(), from_issue(issue()), thread, saved_state(), None).run


def test_new_url_on_the_domain_reruns_without_asking_the_ai() -> None:
    thread = [ThreadComment(2, "rep", "reporter", "the kit is at https://reports.example/new.html")]
    result = rerun.check(issue(), from_issue(issue()), thread, saved_state(), "unused-key")
    assert result.run and "new URL" in result.reason and "rep" in result.trigger


def test_already_seen_url_is_not_new() -> None:
    thread = [ThreadComment(2, "rep", "reporter", "again https://reports.example/new.html")]
    state = saved_state(seen_urls=["https://reports.example/new.html"])
    assert rerun.new_urls(from_issue(issue()), thread, state) == []


def test_domain_change_reruns() -> None:
    edited = BODY.replace("reports.example", "other.example")
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


def test_typo_edit_is_cosmetic_and_skips_the_ai(monkeypatch):
    def fail(*args):
        raise AssertionError("AI should not be asked about a typo edit")
    monkeypatch.setattr(rerun.ai_review, "is_useful", fail)
    edited = BODY.replace("phishing", "phishing, sadly")
    result = rerun.check(issue(edited), from_issue(issue(edited)), [], saved_state(body=BODY), "key")
    assert not result.run and "few words" in result.reason


def test_edit_adding_a_redirect_host_is_not_cosmetic() -> None:
    state = saved_state(body=BODY)
    edited = BODY + "\nIt redirects to redirect.example"
    assert not rerun.is_cosmetic_edit(state, edited)


def test_edit_diff_is_what_the_ai_sees(monkeypatch):
    seen = {}
    def capture(context, material, key):
        seen["text"] = material[0]["text"]
        return True, "new detail"
    monkeypatch.setattr(rerun.ai_review, "is_useful", capture)
    edited = BODY + "\nIt asked for my card number, expiry date, CVV and billing postcode on the second page."
    rerun.check(issue(edited), from_issue(issue(edited)), [], saved_state(body=BODY), "key")
    assert "+It asked for my card number" in seen["text"] and "### Category" not in seen["text"]


def test_report_is_reposted_only_when_someone_else_commented_after_it() -> None:
    from triage.github_api import is_buried
    def c(login: str, association: str = "NONE", kind: str = "User") -> dict[str, Any]:
        return {"user": {"login": login, "type": kind}, "author_association": association}
    report = {**c("github-actions[bot]", kind="Bot"), "body": "report"}
    assert not is_buried([c("rep"), report], report)
    assert not is_buried([c("rep"), report, c("Sam", "OWNER")], report)
    assert is_buried([c("rep"), report, c("Sam", "OWNER"), c("rep")], report)
    assert is_buried([report, c("Alex")], report)


@pytest.mark.parametrize("before,after", [("It is phishing", "It is not phishing"), ("It is not phishing", "It is phishing"), ("It requested payment", "It no longer requested payment"), ("It requested payment", "It requested credentials"), ("It requested payment", "")])
def test_short_substantive_edits_and_deletions_are_not_cosmetic(before: str, after: str) -> None:
    assert not rerun.is_cosmetic_edit(saved_state(body=before), after)


@pytest.mark.parametrize("before,after", [("Acme evidence", "**Acme evidence**"), ("Acme evidence", "Acme   evidence\n"), ("### Evidence\n\n_No response_", "### Evidence\n\n"), ("### Evidence\n\nN/A", "### Evidence\n\n_No response_")])
def test_formatting_and_placeholders_do_not_rerun(before: str, after: str) -> None:
    assert rerun.is_cosmetic_edit(saved_state(body=before), after)


def test_short_changed_evidence_is_offered_to_advisory_usefulness_check(monkeypatch: MonkeyPatch) -> None:
    observed: list[str] = []

    def useful(context: dict[str, Any], material: list[dict[str, str]], key: str) -> tuple[bool, str]:
        observed.append(material[0]["text"])
        return True, "changed evidence"

    monkeypatch.setattr(rerun.ai_review, "is_useful", useful)
    edited = BODY.replace("\n\nphishing", "\n\nnot phishing")
    result = rerun.check(issue(edited), from_issue(issue(edited)), [], saved_state(body=BODY), "fictional-unused-key")
    assert result.run and result.reason == "changed evidence" and "+not phishing" in observed[0]


def test_attachment_url_edit_is_not_cosmetic() -> None:
    before = "![evidence](https://github.com/user-attachments/assets/old-example)"
    after = "![evidence](https://github.com/user-attachments/assets/new-example)"
    assert not rerun.is_cosmetic_edit(saved_state(body=before), after)


def test_markdown_url_does_not_rerun_as_a_different_path() -> None:
    edited = BODY + "\n**https://reports.example/path**"
    state = saved_state(seen_urls=["https://reports.example/path"])
    assert rerun.new_urls(from_issue(issue(edited)), [], state) == []
