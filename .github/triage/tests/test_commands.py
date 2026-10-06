from pathlib import Path

import pytest

from triage.command_runner import file_note
from triage.commands import (
    Command,
    allow_problems,
    append_block,
    block_problems,
    entries_for,
    entry_block,
    insert_allow_block,
    parse,
)
from triage.state import TriageState

REPO = Path(__file__).resolve().parents[3]


def test_parse_block_with_options_and_message():
    command = parse("/block tracking exact now evil.example.com\nConfirmed tracker.\n\nMore detail.")
    assert (command.action, command.category, command.exact, command.now) == ("block", "tracking", True, True)
    assert command.domains == ["evil.example.com"]
    assert command.message == "Confirmed tracker.\n\nMore detail."
    assert command.error is None


def test_parse_ignores_normal_comments_and_rejects_unknown():
    assert parse("thanks, looking into it") is None
    assert parse("/frobnicate").error.startswith("Unknown command")
    assert "don't understand" in parse("/block not_a_domain!").error


def test_parse_decline_takes_the_rest_as_reason() -> None:
    command = parse("/decline Shared platform, report the bucket to Acme instead.\nThanks for the report.")
    assert command is not None
    assert command.action == "decline"
    assert command.message == "Shared platform, report the bucket to Acme instead.\n\nThanks for the report."


def test_block_problems_catch_shared_hosts_duplicates_and_whitelisted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from triage import commands
    (tmp_path / "custom").mkdir()
    (tmp_path / "custom/malicious.txt").write_text("||blocked.example^\n")
    (tmp_path / "whitelist.txt").write_text("allowed.example\n")
    monkeypatch.setattr(commands, "SHARED_PATH_HOSTS", {"shared.example": "Acme hosting"})
    monkeypatch.setattr(commands, "shared_platform", lambda domain: domain if domain == "platform.example" else None)
    problems = " ".join(block_problems(["shared.example", "platform.example", "blocked.example", "allowed.example"], tmp_path))
    assert "serves many users by path" in problems
    assert "shared platform itself" in problems
    assert "already covered" in problems
    assert "conflicts with `whitelist.txt`" in problems
    assert block_problems(["fresh.example"], tmp_path) == []


def test_allow_problems_catch_existing_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from triage import commands
    monkeypatch.setattr(commands, "shared_platform", lambda domain: None)
    (tmp_path / "whitelist.txt").write_text("allowed.example\n")
    assert allow_problems(["allowed.example"], tmp_path)
    assert allow_problems(["fresh.example"], tmp_path) == []


def test_append_block_formats_entries():
    block = entry_block(entries_for(["a.example"], exact=False), "a.example: fake shop. (#9, PR #10)")
    assert append_block("# header\n||old.example^\n\n", block) == "# header\n||old.example^\n# a.example: fake shop. (#9, PR #10)\n||a.example^\n"
    assert entries_for(["a.example"], exact=True) == ["a.example"]


def test_insert_allow_block_goes_at_the_end_of_the_reported_section_and_bumps_the_header():
    original = (REPO / "whitelist.txt").read_text()
    before = original.splitlines()
    regex_at = before.index("# REGEX PATTERNS")
    last_entry = next(line for line in reversed(before[: regex_at - 1]) if line.strip() and not line.startswith("#"))
    block = entry_block(["legit.example"], "legit.example: shop. (#9, PR #10)")
    updated = insert_allow_block(original, block, "23/09/2026", "Allowlisted legit.example (#9)")
    lines = updated.splitlines()
    assert lines[1] == "# Last Updated: 23/09/2026 - Allowlisted legit.example (#9)"
    at = lines.index("legit.example")
    assert lines[at - 1] == "# legit.example: shop. (#9, PR #10)"
    assert lines[at + 1] == "" and lines[at + 2].startswith("# ====") and lines[at + 3] == "# REGEX PATTERNS"
    assert lines[at - 3] == last_entry and lines[at - 2] == ""
    assert len(lines) == len(original.splitlines()) + 3


def test_file_note_uses_message_then_site_and_evidence() -> None:
    state = TriageState(domain="bad.example", site="Fake Acme login page", evidence="Fictional evidence for bad.example")
    note = file_note(Command("block"), ["bad.example"], state, 9, 10)
    assert note == "bad.example: Fake Acme login page. Fictional evidence for bad.example. (#9, PR #10)"
    note = file_note(Command("block", message="Confirmed kit host."), ["bad.example"], state, 9, None)
    assert note == "bad.example: Confirmed kit host. Fictional evidence for bad.example. (#9)"
    assert file_note(Command("block"), ["other.example"], state, 9, 10) == "other.example: found while triaging this issue. (#9, PR #10)"


def test_owner_commands_are_not_thread_context():
    from triage.github_api import is_command
    assert is_command({"author_association": "OWNER", "body": "/block now"})
    assert not is_command({"author_association": "OWNER", "body": "Looks like a kit host to me"})
    assert not is_command({"author_association": "NONE", "body": "/block everything"})


def test_parse_normalizes_and_deduplicates() -> None:
    command = parse("/block HTTPS://EXAMPLE.COM/ example.com. ||example.com^")
    assert command is not None and command.domains == ["example.com"]


def test_batch_scope_and_atomic_conflicts(monkeypatch: pytest.MonkeyPatch) -> None:
    from triage import commands
    monkeypatch.setattr(commands, "shared_platform", lambda domain: None)
    monkeypatch.setattr(commands, "SHARED_PATH_HOSTS", {"shared.example": "Acme hosting"})
    files = {"whitelist.txt": "allowed.example\n/^child\\.conflict\\.example$/\n", "custom/malicious.txt": "existing.example\n||broad.example^\n"}
    plan = commands.plan_domains(Command("block"), ["existing.example", "child.broad.example", "fresh.example"], files)
    assert plan.domains == ["existing.example", "fresh.example"]
    assert len(plan.skipped) == 1
    plan = commands.plan_domains(Command("block", exact=True), ["existing.example", "fresh.example"], files)
    assert plan.domains == ["fresh.example"] and len(plan.skipped) == 1
    plan = commands.plan_domains(Command("block"), ["fresh.example", "shared.example", "allowed.example", "conflict.example"], files)
    assert len(plan.problems) == 3
    plan = commands.plan_domains(Command("allow"), ["fresh.example", "shared.example"], files)
    assert len(plan.problems) == 1


def test_reports_require_actual_actions_bot_and_keep_human_markers() -> None:
    import httpx
    from triage.github_api import GitHub, MARKER
    from triage.state import TriageState
    forged = {"id": 1, "user": {"login": "Alex", "type": "User"}, "body": MARKER + TriageState(domain="forged.example").to_marker()}
    impostor = {"id": 2, "user": {"login": "Sam", "type": "Bot"}, "body": MARKER}
    old = {"id": 3, "user": {"login": "github-actions[bot]", "type": "Bot"}, "body": MARKER + TriageState(domain="example.com").to_marker()}
    calls: list[tuple[str, str]] = []

    def transport(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        return httpx.Response(200, json=[forged, impostor, old] if request.method == "GET" else {"html_url": "https://example.com/comment"})

    github = GitHub("fictional-token", "Acme/example")
    github.client = httpx.Client(base_url="https://example.com", transport=httpx.MockTransport(transport))
    assert github.report(7) == old
    assert [comment.id for comment in github.thread({"number": 7, "user": {"login": "Alex"}})] == [1]
    github.upsert_report(7, MARKER + "updated")
    assert ("PATCH", "/repos/Acme/example/issues/comments/3") in calls
    assert not any(method == "DELETE" for method, _ in calls)
