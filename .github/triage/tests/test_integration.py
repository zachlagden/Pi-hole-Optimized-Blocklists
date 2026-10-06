import argparse
import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from triage import __main__ as cli
from triage import ai_review, allow_reply, buildcheck, command_runner, render, rerun, scheduled
from triage.commands import Command
from triage.evidence import Evidence
from triage.github_api import GitHub, ThreadComment
from triage.issue_form import IssueRequest
from triage.materials import Material
from triage.observations import Observation
from triage.screenshot import Capture
from triage.state import TriageState


def request() -> IssueRequest:
    return IssueRequest(7, "block", "Acme report", "Alex", "https://report.example/page", "example.com", "example.com")


def test_gather_collects_materials_from_loaded_thread_and_isolates_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    item = request()
    item.thread = [ThreadComment(10, "Sam", "reporter", "https://report.example/page")]
    monkeypatch.setattr(cli, "gather_repo_and_sources", lambda *args: None)
    monkeypatch.setattr(cli, "gather_reputation", lambda *args: None)
    monkeypatch.setattr(cli, "gather_live", lambda *args: None)
    material = Material("corroboration", "https://report.example/page", "comment #10", 200,
                        text="Acme source statement", inspected=True, outcome="inspected")
    github: Any = type("FakeGitHub", (), {"reporter": lambda *args: None})()

    def collect(actual: IssueRequest, actual_github: Any) -> list[Material]:
        assert actual is item and actual.thread[0].id == 10 and actual_github is github
        return [material]

    monkeypatch.setattr(cli, "collect_materials", collect)
    found = cli.gather(item, tmp_path, github, argparse.Namespace(no_screenshot=True))
    assert found.materials == [material]

    def fail(*args: Any) -> list[Material]:
        raise ValueError("fictional collection failure")

    monkeypatch.setattr(cli, "collect_materials", fail)
    failed = cli.gather(item, tmp_path, github, argparse.Namespace(no_screenshot=True))
    assert failed.materials == [] and "referenced materials" in failed.failures[0]


def test_run_issue_passes_observation_date_and_materials_before_ai(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    raw = {"number": 7, "title": "Acme block report", "body": "### Domain\n\nexample.com",
           "labels": [{"name": "blocklist"}], "user": {"login": "Alex"}, "html_url": "https://example.com/issues/7"}
    item = Evidence(request(), "example.com", "example.com", materials=[Material("link", "https://report.example", "issue body")])

    class FakeGitHub:
        def issue(self, number: int) -> dict:
            return raw

        def report(self, number: int) -> None:
            return None

        def thread(self, issue: dict) -> list[ThreadComment]:
            return [ThreadComment(10, "Sam", "reporter", "Acme evidence")]

    class Clock:
        @classmethod
        def now(cls, timezone: Any) -> datetime:
            assert timezone == UTC
            return datetime(2031, 4, 11, tzinfo=UTC)

    monkeypatch.setattr(cli.GitHub, "from_env", lambda: FakeGitHub())
    monkeypatch.setattr(cli, "datetime", Clock)
    monkeypatch.setattr(cli, "make_discord", lambda options: None)
    monkeypatch.setattr(cli, "classify_issue", lambda *args: (None, cli.LabelPlan()))
    monkeypatch.setattr(cli, "gather", lambda *args: item)
    monkeypatch.setenv("MINIMAX_API_KEY", "fictional-test-key")
    seen: list[str] = []

    def review(evidence: Evidence, facts: str, api_key: str, previous: TriageState | None, today: date | None = None) -> ai_review.Review:
        assert today == date(2031, 4, 11) and evidence.materials
        assert "Referenced materials" in facts
        seen.append("review")
        return ai_review.Review(recommendation="needs_info", confidence="low")

    monkeypatch.setattr(ai_review, "review", review)
    monkeypatch.setattr(cli, "deliver", lambda *args: seen.append("deliver"))
    options = argparse.Namespace(number=7, no_ai=False, repo_root=str(tmp_path), trigger="", no_discord=True)
    assert cli.run_issue(options) == 0 and seen == ["review", "deliver"]


def test_material_rendering_preserves_unverified_and_unavailable_boundaries() -> None:
    item = Evidence(request(), "example.com", "example.com")
    item.materials = [
        Material("related_issue", "https://example.com/issues/8", "issue body", 200,
                 text="Sam alleges Acme fraud", inspected=True, outcome="inspected",
                 note="Relatedness alone is not evidence for blocking; claims are unverified."),
        Material("attachment", "https://image.example/capture", "comment #10", 403,
                 error="HTTP 403, unavailable", outcome="unavailable"),
    ]
    item.capture = Capture(None, "Acme text", "https://example.com", "worker blocked", 200, "partial")
    rendered = render.comment_markdown(item, [], None, None, [])
    assert "source claims remain unverified" in rendered
    assert "Relatedness alone is not evidence for blocking" in rendered
    assert "unavailable (content not inspected, HTTP 403)" in rendered
    assert "Browser capture: partial, HTTP 200" in rendered
    assert "site is offline" not in rendered


@pytest.mark.parametrize("scope,entries", [("exact", ["/^example\\.com$/"]), ("subdomains", ["*.example.com"]), ("domain", ["example.com"])])
def test_no_key_reply_is_scope_correct_and_ignores_legacy_descriptions(scope: str, entries: list[str]) -> None:
    state = TriageState(domain="example.com", site="Invented Acme claim", evidence="old model summary")
    context = allow_reply.reply_context(["example.com"], entries, scope, 133, command_runner.TIMING_WEEKLY, request(), state)
    text = allow_reply.reporter_comment("Alex", "", context, None)
    assert command_runner.TIMING_WEEKLY in text and "Invented" not in text and "old model" not in text
    assert "site_description" not in context and "evidence_summary" not in context
    if scope == "subdomains":
        assert "not the bare domains" in text
    elif scope == "exact":
        assert "exact hosts only" in text
    assert "allow it there" not in text


def test_legacy_state_site_is_not_reused_as_a_verified_file_note() -> None:
    state = TriageState(domain="example.com", site="Unbound old model claim", evidence="Recorded VT evidence")
    note = command_runner.file_note(Command("block"), ["example.com"], state, 7, 133)
    assert "Unbound old model" not in note and "found while triaging" in note
    review = ai_review.Review(site="Invented description", recommendation="needs_info")
    next_state = rerun.next_state(request(), state, review, "new evidence", [])
    assert not next_state.site and not next_state.site_observation_bound
    review.observations = [Observation("browser.text", "website_text", "browser", "Page supplied Acme text")]
    review.site_observation_ids = ["browser.text"]
    next_state = rerun.next_state(request(), state, review, "new evidence", [])
    assert next_state.site_observation_bound and "website_text" in next_state.site and "Invented" not in next_state.site
    assert TriageState(site="legacy").site_observation_bound is False


@pytest.mark.parametrize("problems,old,new,held", [([], 100, 100, False), ([buildcheck.FeedProblem("Acme", "missing")], 100, 100, False), ([buildcheck.FeedProblem("Acme", "missing")], 100, 50, True)])
def test_buildcheck_serializes_actual_deterministic_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                          problems: list[buildcheck.FeedProblem], old: int, new: int, held: bool) -> None:
    report = buildcheck.BuildReport(old, new, problems, [], {"Acme": 20})
    target = tmp_path / "feed-check.json"
    outputs = tmp_path / "outputs"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    monkeypatch.setattr(scheduled.reputation, "tranco_ranks", lambda *args: {})
    monkeypatch.setattr(scheduled.buildcheck, "check", lambda *args: report)
    monkeypatch.setattr(scheduled, "apply_review", lambda *args: None)
    options = argparse.Namespace(feed_check=target, repo_root=tmp_path, old=tmp_path, new=tmp_path, base=tmp_path, stats=tmp_path / "stats.json")
    assert scheduled.run_buildcheck(options, None) == 0
    actual = json.loads(target.read_text())
    assert actual == {"successful": True, "held": held, "feed_problems": [{"name": p.name, "problem": p.problem} for p in problems]}
    assert f"run={'true' if held else 'false'}" in outputs.read_text()


def test_failed_deterministic_check_cannot_leave_stale_healthy_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "feed-check.json"
    target.write_text('{"successful": true, "held": false, "feed_problems": []}')

    def fail(*args: Any) -> dict:
        raise ValueError("fictional deterministic check failure")

    monkeypatch.setattr(scheduled.reputation, "tranco_ranks", fail)
    with pytest.raises(ValueError):
        scheduled.run_buildcheck(argparse.Namespace(feed_check=target), None)
    assert not target.exists()


def test_publication_main_provenance_uses_authenticated_read_api() -> None:
    github = GitHub("fictional-test-key", "Acme/blocklists")
    github.client.close()

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET" and request.url.path == "/repos/Acme/blocklists/git/ref/heads/main"
        assert request.headers["Authorization"] == "Bearer fictional-test-key"
        return httpx.Response(200, json={"object": {"sha": "a" * 40}})

    with httpx.Client(base_url="https://api.example", headers={"Authorization": "Bearer fictional-test-key"},
                      transport=httpx.MockTransport(handle)) as client:
        github.client = client
        assert github.main_sha() == "a" * 40
