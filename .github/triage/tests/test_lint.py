import pytest

from tests.test_change_conflicts import FakeOps
from triage.command_runner import LintRefusal, change
from triage.commands import Command
from triage.lint import lint_custom, lint_sources, lint_whitelist, new_problems


def messages(problems) -> str:
    return " | ".join(problem.message for problem in problems)


def test_sources_accept_the_documented_format():
    text = "# comment\nhttps://example.com/a.txt|list_a|advertising\nhttps://example.com/b.txt|list_b|nsfw|abp\n"
    assert lint_sources(text) == []


def test_sources_reject_bad_fields_categories_flags_and_duplicates():
    text = "\n".join(
        [
            "https://example.com/a.txt|list_a|advertising",
            "http://example.com/b.txt|list_b|advertising",
            "https://example.com/c.txt|list a|adverts",
            "https://example.com/d.txt|list_d|tracking|wild",
            "https://example.com/a.txt|list_a|tracking",
            "https://example.com/e.txt|only_two",
        ]
    )
    found = messages(lint_sources(text))
    for expected in ["must use https", "may use only", "unknown category", "unknown flag", "name list_a is already used", "URL is already listed", "expected url|name|category"]:
        assert expected in found


def test_custom_lists_reject_junk_duplicates_and_platforms():
    text = "\n".join(["# header", "shop.example", "||shop.example^", "shop.example", "not a domain", "github.io", "||amazonaws.com^", "fake.github.io"])
    found = messages(lint_custom(text, "custom/malicious.txt"))
    assert "duplicate of line 2" in found
    assert "not a domain" in found
    assert "github.io is a hosting platform" in found
    assert "||amazonaws.com^ would block every customer site" in found
    assert "fake.github.io" not in found


def test_custom_lists_must_be_named_after_a_category():
    assert "named after a category" in messages(lint_custom("shop.example\n", "custom/misc.txt"))


def test_whitelist_rejects_platform_apexes_but_accepts_exact_patterns_and_exceptions():
    text = "\n".join(["github.io", "*.github.io", "/^github\\.io$/", "myaddr.io", "*.githubusercontent.com", "cloudsync-prod.s3.amazonaws.com"])
    problems = lint_whitelist(text)
    assert [problem.line for problem in problems] == [1, 2]
    assert "use /^github\\.io$/" in problems[0].message


def test_whitelist_rejects_regexes_the_optimizer_cannot_compile_and_invalid_domains():
    text = "\n".join(["/^(?!ads).*\\.example\\.com$/", "/(a)\\1/", "/[unclosed/", "bad domain!", "fine.example.com # note", "fine.example.com"])
    found = messages(lint_whitelist(text))
    assert found.count("no lookaround or backreferences") == 2
    assert "invalid regex" in found
    assert "not a valid domain" in found
    assert "duplicate of line 5" in found


def test_new_problems_ignore_problems_that_were_already_there():
    before = "dup.example\ndup.example\n"
    assert new_problems("custom/malicious.txt", before, before + "fresh.example\n") == []
    added = new_problems("custom/malicious.txt", before, before + "github.io\n")
    assert [problem.line for problem in added] == [3]


def test_bot_change_is_refused_before_any_branch_when_it_adds_a_problem():
    ops = FakeOps(conflicts=0)
    with pytest.raises(LintRefusal):
        change(ops, {"number": 7, "title": "Block"}, Command(action="block"), ["github.io"], None, "malicious", "")
    assert ops.opened == []
