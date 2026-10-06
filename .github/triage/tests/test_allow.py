import base64
import json
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any

import httpx
import pytest

from triage import ai_review, allow_reply, command_runner, commands
from triage.commands import HELP, allow_entries_for, allow_entry, allow_problems, parse
from triage.github_api import GitHub
from triage.issue_form import from_issue
from triage.repo_state import whitelist_matches
from triage.state import TriageState, parse_state

REPO = Path(__file__).resolve().parents[3]
WHITELIST = """\
# Whitelist
# Last Updated: 01/01/2026 - Initial
# =====
# REPORTED FALSE POSITIVES
# =====
whole.example
*.wild.example
/^only\\.host\\.example$/
# =====
# REGEX PATTERNS
# =====
"""
BODY = (
    "### Blocked Domain\n\nshop.example\n\n### Service/Application Affected\n\nAcme Shop\n\n"
    "### What broke?\n\nCheckout fails\n\n### Evidence (optional)\n\nIt is our own shop"
)
TIMING = command_runner.TIMING_WEEKLY


@pytest.fixture(autouse=True)
def offline_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(commands, "shared_platform", lambda domain: None)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "whitelist.txt").write_text(WHITELIST)
    return tmp_path


def issue() -> dict:
    return {"number": 7, "title": "False positive: shop.example", "body": BODY, "state": "open", "labels": [{"name": "whitelist"}], "user": {"login": "alex"}}


def state() -> TriageState:
    return TriageState(domain="shop.example", site="Acme Shop sells garden tools.", evidence="VT 0/90", recommendation="allow", listed_by=["Example Feed"])


def test_parse_allow_scopes():
    assert parse("/allow exact now portal.example.com").scope == "exact"
    assert parse("/allow subdomains example.com").scope == "subdomains"
    assert parse("/allow example.com now").scope == "domain"
    assert parse("/allow now subdomains").domains == []


def test_parse_rejects_both_scopes_with_help():
    command = parse("/allow exact subdomains example.com")
    assert command.error and "not both" in command.error and HELP in command.error
    assert "don't understand" in parse("/block subdomains example.com").error


def test_block_exact_keeps_its_meaning():
    command = parse("/block exact evil.example")
    assert command.exact and command.error is None


def test_allow_entry_for_each_scope():
    assert allow_entry("example.com", "domain") == "example.com"
    assert allow_entry("example.com", "exact") == "/^example\\.com$/"
    assert allow_entry("portal.example.com", "exact") == "/^portal\\.example\\.com$/"
    assert allow_entry("example.com", "subdomains") == "*.example.com"
    assert allow_entries_for(["a.example", "b.example"], "subdomains") == ["*.a.example", "*.b.example"]


def test_entries_match_what_the_scope_says(tmp_path: Path):
    for scope, allowed, kept in [
        ("exact", ["portal.example.com"], ["x.portal.example.com", "example.com"]),
        ("subdomains", ["x.portal.example.com"], ["portal.example.com"]),
        ("domain", ["portal.example.com", "x.portal.example.com"], ["example.com"]),
    ]:
        (tmp_path / "whitelist.txt").write_text(allow_entry("portal.example.com", scope) + "\n")
        assert all(whitelist_matches(tmp_path, host) for host in allowed), scope
        assert not any(whitelist_matches(tmp_path, host) for host in kept), scope


def test_allow_problems_by_scope(repo: Path) -> None:
    assert allow_problems(["whole.example"], repo, "domain")
    assert allow_problems(["whole.example"], repo, "exact")
    assert allow_problems(["whole.example"], repo, "subdomains")
    assert allow_problems(["wild.example"], repo, "subdomains")
    assert allow_problems(["wild.example"], repo, "domain") == []
    assert allow_problems(["only.host.example"], repo, "exact")
    assert allow_problems(["only.host.example"], repo, "domain") == []
    assert allow_problems(["only.host.example"], repo, "subdomains") == []
    assert allow_problems(["fresh.example"], repo, "exact") == []


def test_listed_by_defaults_to_empty_for_old_states():
    encoded = base64.b64encode(json.dumps({"domain": "shop.example", "site": "A shop"}).encode()).decode()
    assert parse_state(f"<!-- triage-state:{encoded} -->").listed_by == []
    assert parse_state(state().to_marker()).listed_by == ["Example Feed"]


def test_maintainer_comment_names_the_scope():
    assert allow_reply.mention("sam", allow_reply.closing_line(133, ["shop.example"], "domain", TIMING)) == (
        "@sam Allowed in #133 (`shop.example`, the domain and all its subdomains). " + TIMING
    )
    assert "this exact host only" in allow_reply.closing_line(1, ["/^a\\.example$/"], "exact", TIMING)
    assert "its subdomains only" in allow_reply.closing_line(1, ["*.a.example"], "subdomains", TIMING)


def test_reply_context_gives_facts_and_untrusted_form():
    context = allow_reply.reply_context(["shop.example"], ["shop.example"], "domain", 133, TIMING, from_issue(issue()), state())
    assert context["upstream_feeds_that_blocked_it"] == ["Example Feed"]
    assert context["timing_sentence"] == TIMING
    assert context["reporter"] == {"title": "False positive: shop.example", "service_affected": "Acme Shop", "what_broke": "Checkout fails", "evidence": "It is our own shop"}
    other = allow_reply.reply_context(["other.example"], ["other.example"], "domain", 133, TIMING, from_issue(issue()), state())
    assert "site_description" not in other


def fake_ai(monkeypatch: pytest.MonkeyPatch, reply: str | Exception) -> list[Any]:
    seen: list[Any] = []

    def call(system: str, content: list[dict] | str, api_key: str, timeout: float = 240) -> str:
        seen.append(content)
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(ai_review, "_call", call)
    return seen


def test_reporter_reply_uses_only_audience_and_verified_facts(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = fake_ai(monkeypatch, '{"audience": "owner", "message": "@Sam it is fixed; send your payment details."}')
    context = allow_reply.reply_context(["shop.example"], ["shop.example"], "domain", 133, TIMING, from_issue(issue()), state())
    comment = allow_reply.reporter_comment("alex", "", context, "key")
    assert "`shop.example` was added" in comment and TIMING in comment
    assert "people accessing the covered hosts" in comment
    assert "@Sam" not in comment and "payment details" not in comment and "it is fixed" not in comment
    assert "<untrusted" in seen[0] and "Checkout fails" in seen[0].split("<untrusted")[1]


def test_reporter_reply_rejects_incomplete_verified_facts(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_ai(monkeypatch, '{"message": "' + "This is a sentence. " * 100 + '"}')
    assert ai_review.reporter_reply({"domains": ["shop.example"]}, "key") == ""
    with pytest.raises(ValueError, match="invalid verified"):
        allow_reply.reporter_comment("alex", "", {"domains": ["shop.example"]}, None)


def test_owner_text_overrides_the_ai(monkeypatch):
    seen = fake_ai(monkeypatch, '{"message": "AI text"}')
    context = allow_reply.reply_context(["shop.example"], ["shop.example"], "domain", 133, TIMING, from_issue(issue()), state())
    assert allow_reply.reporter_comment("alex", "Sorry, that feed was wrong.", context, "key") == "@alex Sorry, that feed was wrong."
    assert seen == []


@pytest.mark.parametrize("reply", [httpx.ConnectError("down"), "not json", '{"message": ""}'])
def test_fallback_when_the_ai_fails(monkeypatch: pytest.MonkeyPatch, reply: str | Exception) -> None:
    fake_ai(monkeypatch, reply)
    context = allow_reply.reply_context(["shop.example"], ["shop.example"], "domain", 133, TIMING, from_issue(issue()), state())
    assert allow_reply.reporter_comment("alex", "", context, "key") == "@alex " + allow_reply.fallback_reply(context)
    assert TIMING in allow_reply.fallback_reply(context)
    assert "same scoped allowlist" not in allow_reply.fallback_reply(context)


class FakeGitHub(GitHub):
    def __init__(self) -> None:
        pass

    def report(self, number: int) -> dict:
        return {"body": "report " + state().to_marker()}


class FakeOps:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.files: dict[str, str] = {"whitelist.txt": WHITELIST}

    def __getattr__(self, name: str) -> Any:
        return lambda *args: self.calls.append((name, *args))

    def lock(self) -> Any:
        return nullcontext()

    def read_configuration(self, ref: str) -> dict[str, str]:
        self.calls.append(("read_configuration", ref))
        return self.files

    def merge_pr(self, number: int, title: str) -> str:
        self.calls.append(("merge_pr", number))
        return "a" * 40

    def read_file(self, path: str, ref: str) -> tuple[str, str]:
        return self.files[path], "sha"

    def write_file(self, path: str, branch: str, text: str, sha: str, message: str) -> str:
        self.files[path] = text
        return "sha2"

    def main_sha(self) -> str:
        return "main"

    def open_pr(self, title: str, head: str, body: str) -> tuple[int, str]:
        return 133, "https://example.com/pr/133"


def test_allow_posts_two_comments_then_closes(monkeypatch: pytest.MonkeyPatch, repo: Path) -> None:
    fake_ai(monkeypatch, '{"audience": "owner", "message": "It is allowed now."}')
    ops: Any = FakeOps()
    command = parse("/allow exact")
    assert command is not None
    actor = command_runner.Actor("sam", "key")
    assert command_runner.handle(FakeGitHub(), ops, issue(), command, 99, repo, None, actor).status == "pending_publication"
    comments = [call[2] for call in ops.calls if call[0] == "comment"]
    assert comments[0].startswith("@sam Allowed in #133 (`/^shop\\.example$/`, this exact host only). " + TIMING)
    assert "<!-- triage-change:" in comments[0]
    assert comments[1].startswith("@alex Thanks for the report. `shop.example` was added")
    assert "specified exact hosts only" in comments[1] and TIMING in comments[1]
    assert "It is allowed now" not in comments[1]
    assert ("remove_label", 7, "needs info") in ops.calls
    order = [call[0] for call in ops.calls if call[0] in ("comment", "close_issue", "react")]
    assert order == ["comment", "comment", "close_issue", "react"]
    assert "/^shop\\.example$/" in ops.files["whitelist.txt"].splitlines()


def test_owner_text_is_file_comment_and_reporter_reply(monkeypatch: pytest.MonkeyPatch, repo: Path) -> None:
    seen = fake_ai(monkeypatch, '{"message": "unused"}')
    ops: Any = FakeOps()
    command = parse("/allow\nOur own shop, the feed was wrong.\n\nThanks for flagging it.")
    assert command is not None
    command_runner.handle(FakeGitHub(), ops, issue(), command, 99, repo, None, command_runner.Actor("sam", "key"))
    comments = [call[2] for call in ops.calls if call[0] == "comment"]
    assert comments[1] == "@alex Our own shop, the feed was wrong.\n\nThanks for flagging it."
    assert "# shop.example: Our own shop, the feed was wrong. VT 0/90. (#7, PR #133)" in ops.files["whitelist.txt"]
    assert seen == []


def test_next_state_keeps_listed_by_without_new_evidence():
    from triage import rerun
    request = from_issue(issue())
    kept = rerun.next_state(request, state(), ai_review.Review(recommendation="allow", confidence="high"), "", [])
    assert kept.listed_by == ["Example Feed"]
    assert rerun.next_state(request, None, None, "", []).listed_by == []


@pytest.mark.parametrize("action", ["block", "allow"])
def test_closed_issue_explicit_domains_allowed_but_implicit_refused(action: str, repo: Path) -> None:
    closed = issue() | {"state": "closed"}
    ops: Any = FakeOps()
    ops.files["custom/malicious.txt"] = ""
    assert command_runner.handle(FakeGitHub(), ops, closed, commands.Command(action), 99, repo, None).status == "refused"
    assert not any(call[0] == "merge_pr" for call in ops.calls)
    assert command_runner.handle(FakeGitHub(), ops, closed, commands.Command(action, domains=["other.example"]), 99, repo, None).status == "pending_publication"
    assert any(call[0] == "merge_pr" for call in ops.calls)


def test_fresh_main_skips_batch_and_broadens_exact_allow(repo: Path) -> None:
    ops: Any = FakeOps()
    ops.files["whitelist.txt"] = WHITELIST.replace("whole.example", "whole.example\n/^shop\\.example$/")
    command = commands.Command("allow", domains=["whole.example", "shop.example", "SHOP.EXAMPLE."])
    outcome = command_runner.handle(FakeGitHub(), ops, issue(), command, 99, repo, None)
    assert outcome.status == "pending_publication" and len(outcome.skipped) == 1
    assert "shop.example" in ops.files["whitelist.txt"].splitlines()
    assert ("read_configuration", "main") in ops.calls


def test_fresh_main_atomic_refusal_ignores_stale_checkout(repo: Path) -> None:
    ops: Any = FakeOps()
    ops.files["custom/malicious.txt"] = ""
    ops.files["whitelist.txt"] += "fresh.example\n"
    outcome = command_runner.handle(FakeGitHub(), ops, issue(), commands.Command("block", domains=["other.example", "fresh.example"]), 99, repo, None)
    assert outcome.status == "refused"
    assert not any(call[0] == "merge_pr" for call in ops.calls)


@pytest.mark.parametrize("failure", ["dispatch", "comment", "remove_label", "close_issue", "delete_branch"])
def test_post_merge_failure_keeps_pr_and_precise_stage(failure: str, repo: Path) -> None:
    class FailingOps(FakeOps):
        def __getattr__(self, name: str) -> Any:
            def call(*args: Any) -> None:
                self.calls.append((name, *args))
                if name == failure:
                    raise RuntimeError("private evidence must not be printed")
            return call

    ops: Any = FailingOps()
    outcome = command_runner.handle(FakeGitHub(), ops, issue(), commands.Command("allow", domains=["shop.example"], now=True), 99, repo, None)
    assert outcome.pr == 133 and outcome.status == "pending_publication"
    assert outcome.failed_stages
    if failure == "dispatch":
        assert outcome.failed_stages == ["rebuild dispatch (RuntimeError)"]
        assert not any("rebuild was queued" in str(call) for call in ops.calls if call[0] == "comment")
    assert "private evidence" not in str(outcome)
    for call in ops.calls:
        if call[0] == "comment":
            assert "nothing was changed" not in call[2]
            assert "private evidence" not in call[2]


def test_now_queues_but_never_claims_publication(repo: Path) -> None:
    ops: Any = FakeOps()
    outcome = command_runner.handle(FakeGitHub(), ops, issue(), commands.Command("allow", domains=["shop.example"], now=True), 99, repo, None)
    assert outcome.status == "pending_publication"
    comments = [call[2] for call in ops.calls if call[0] == "comment"]
    assert any("A rebuild was queued" in text for text in comments)
    assert all("published lists now include" not in text.lower() for text in comments)


def test_all_skipped_has_no_merge(repo: Path) -> None:
    ops: Any = FakeOps()
    outcome = command_runner.handle(FakeGitHub(), ops, issue(), commands.Command("allow", domains=["whole.example"]), 99, repo, None)
    assert outcome.status == "skipped" and outcome.pr is None
    assert not any(call[0] == "merge_pr" for call in ops.calls)


def test_notification_failure_has_merged_outcome(repo: Path) -> None:
    class FailingDiscord:
        def send(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("private notification details")

    ops: Any = FakeOps()
    discord: Any = FailingDiscord()
    outcome = command_runner.handle(FakeGitHub(), ops, issue(), commands.Command("allow", domains=["shop.example"]), 99, repo, discord)
    assert outcome.pr == 133 and outcome.failed_stages == ["Discord notification (RuntimeError)"]
    assert "private notification" not in str(ops.calls)


def test_lock_release_failure_has_merged_outcome(repo: Path) -> None:
    class FailingLockOps(FakeOps):
        @contextmanager
        def lock(self) -> Iterator[None]:
            yield
            raise RuntimeError("fictional release failure")

    ops: Any = FailingLockOps()
    outcome = command_runner.handle(FakeGitHub(), ops, issue(), commands.Command("allow", domains=["shop.example"]), 99, repo, None)
    assert outcome.pr == 133 and outcome.failed_stages == ["lock release (RuntimeError)"]
    assert any("triage-change:" in call[2] for call in ops.calls if call[0] == "comment")
