from triage.domains import clean_domain, self_and_parents
from triage.issue_form import from_issue
from triage.listparse import Entry, entry_blocks, extract_entry
from triage.typosquat import edit_distance, find_lookalikes


def test_clean_domain_strips_url_parts():
    assert clean_domain("https://pttv.click-tt.de/path?x=1") == "pttv.click-tt.de"
    assert clean_domain("||uacred.com^") == "uacred.com"
    assert clean_domain("*.Example.COM.") == "example.com"
    assert clean_domain("user@host.example.org:8080") == "host.example.org"
    assert clean_domain("not a domain") is None
    assert clean_domain("localhost") is None


def test_self_and_parents_stops_at_registrable():
    assert self_and_parents("a.b.example.co.uk") == ["a.b.example.co.uk", "b.example.co.uk", "example.co.uk"]
    assert self_and_parents("example.com") == ["example.com"]


def test_extract_entry_matches_optimizer_rules():
    assert extract_entry("0.0.0.0 ads.example.com", True) == Entry("ads.example.com", False)
    assert extract_entry("||foo.com^", False) == Entry("foo.com", False)
    assert extract_entry("||foo.com^$third-party", True) == Entry("foo.com", True)
    assert extract_entry("*.bar.com", True) == Entry("bar.com", True)
    assert extract_entry("@@||foo.com^", True) is None
    assert extract_entry("ads.example.com # note", True) == Entry("ads.example.com", False)
    assert extract_entry("# comment", True) is None


def test_entry_blocks_respects_subdomain_flag():
    assert entry_blocks(Entry("foo.com", True), "a.foo.com")
    assert not entry_blocks(Entry("foo.com", False), "a.foo.com")
    assert not entry_blocks(Entry("foo.com", True), "barfoo.com")


def test_issue_form_parses_false_positive_with_url():
    body = "### Blocked Domain\nhttps://pttv.click-tt.de\n\n### Service/Application Affected\n\nTable tennis\n\n### Which blocklist are you using?\n\ncomprehensive.txt, nsfw.txt\n\n### Evidence (optional)\n\n_No response_"
    request = from_issue({"number": 83, "title": "[False Positive] ", "body": body, "labels": [{"name": "whitelist"}], "user": {"login": "someone"}})
    assert request.kind == "allow"
    assert request.domain == "pttv.click-tt.de"
    assert request.lists == ["comprehensive.txt", "nsfw.txt"]
    assert request.evidence == ""


def test_issue_form_parses_block_category():
    body = "### Domain\n\ninfozaem.com\n\n### Category\n\nSuspicious (cryptojacking, etc.)\n\n### Evidence / Reason\n\nreason"
    request = from_issue({"number": 75, "title": "Block", "body": body, "labels": [{"name": "blocklist"}], "user": {"login": "x"}})
    assert (request.kind, request.domain, request.category) == ("block", "infozaem.com", "suspicious")


def test_typosquat_detection():
    assert edit_distance("netflxi", "netflix") == 1
    ranks = {"netflix.com": 30, "github.com": 20, "example.com": 5}
    assert [item.brand for item in find_lookalikes("netflxi.com", ranks, 10_000)] == ["netflix.com"]
    assert find_lookalikes("netflix.com", ranks, 10_000) == []
    assert [item.brand for item in find_lookalikes("secure-github.help", ranks, 10_000)] == ["github.com"]


def test_popular_domain_is_never_its_own_lookalike():
    ranks = {"google.com": 1, "googll.store": 1657}
    assert find_lookalikes("google.com", ranks, 10_000) == []
    assert [item.brand for item in find_lookalikes("gooogle.com", ranks, 10_000)] == ["google.com"]
