from pathlib import Path

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


def test_parse_decline_takes_the_rest_as_reason():
    command = parse("/decline Shared platform, report the bucket to Google instead.\nThanks for the report.")
    assert command.action == "decline"
    assert command.message == "Shared platform, report the bucket to Google instead.\n\nThanks for the report."


def test_block_problems_catch_shared_hosts_duplicates_and_whitelisted():
    problems = " ".join(block_problems(["storage.googleapis.com", "r2.dev", "amexp.com", "commbank.com.au"], REPO))
    assert "serves many users by path" in problems
    assert "shared platform itself" in problems
    assert "already covered by `||amexp.com^`" in problems
    assert "whitelisted" in problems
    assert block_problems(["fresh-new-scam-domain-example.com"], REPO) == []


def test_allow_problems_catch_existing_entries():
    assert allow_problems(["commbank.com.au"], REPO)
    assert allow_problems(["fresh-new-legit-example.com"], REPO) == []


def test_append_block_formats_entries():
    block = entry_block(entries_for(["a.example"], exact=False), "a.example: fake shop. (#9, PR #10)")
    assert append_block("# header\n||old.example^\n\n", block) == "# header\n||old.example^\n# a.example: fake shop. (#9, PR #10)\n||a.example^\n"
    assert entries_for(["a.example"], exact=True) == ["a.example"]


def test_insert_allow_block_goes_at_the_end_of_the_reported_section_and_bumps_the_header():
    original = (REPO / "whitelist.txt").read_text()
    block = entry_block(["legit.example"], "legit.example: shop. (#9, PR #10)")
    updated = insert_allow_block(original, block, "23/09/2026", "Allowlisted legit.example (#9)")
    lines = updated.splitlines()
    assert lines[1] == "# Last Updated: 23/09/2026 - Allowlisted legit.example (#9)"
    at = lines.index("legit.example")
    assert lines[at - 1] == "# legit.example: shop. (#9, PR #10)"
    assert lines[at + 1] == "" and lines[at + 2].startswith("# ====") and lines[at + 3] == "# REGEX PATTERNS"
    assert lines[at - 3] == "archidekt-cloudflare.com" and lines[at - 2] == ""
    assert len(lines) == len(original.splitlines()) + 3


def test_file_note_uses_message_then_site_and_evidence():
    state = TriageState(domain="bad.example", site="Fake Amex login page", evidence="VT 8/89 for bad.example incl. ESET")
    note = file_note(Command("block"), ["bad.example"], state, 9, 10)
    assert note == "bad.example: Fake Amex login page. VT 8/89 for bad.example incl. ESET. (#9, PR #10)"
    note = file_note(Command("block", message="Confirmed kit host."), ["bad.example"], state, 9, None)
    assert note == "bad.example: Confirmed kit host. VT 8/89 for bad.example incl. ESET. (#9)"
    assert file_note(Command("block"), ["other.example"], state, 9, 10) == "other.example: found while triaging this issue. (#9, PR #10)"


def test_owner_commands_are_not_thread_context():
    from triage.github_api import is_command
    assert is_command({"author_association": "OWNER", "body": "/block now"})
    assert not is_command({"author_association": "OWNER", "body": "Looks like a kit host to me"})
    assert not is_command({"author_association": "NONE", "body": "/block everything"})
