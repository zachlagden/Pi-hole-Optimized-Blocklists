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


def test_shared_platform_hosts_are_their_own_site():
    from triage.domains import registrable, shared_platform
    assert registrable("pub-abc.r2.dev") == "pub-abc.r2.dev"
    assert shared_platform("pub-abc.r2.dev") == "r2.dev"
    assert shared_platform("a.b.example.co.uk") is None
    assert self_and_parents("x.fatlantmxppress.us.cc") == ["x.fatlantmxppress.us.cc", "fatlantmxppress.us.cc"]


def test_quoted_urls_keep_paths_on_the_reported_host():
    from triage.live import quoted_urls
    text = (
        "lands on https://fatlantmxppress.us.cc/2b6848c72a3e, then "
        "blob:https://pub-abc.r2.dev/daaab2f0 and https://t.co/nlVIYkWx9I plus https://fatlantmxppress.us.cc/"
    )
    assert quoted_urls(text, "fatlantmxppress.us.cc") == ["https://fatlantmxppress.us.cc/2b6848c72a3e"]
    assert quoted_urls(text, "pub-abc.r2.dev") == ["https://pub-abc.r2.dev/daaab2f0"]
    assert quoted_urls(text, "example.com") == []


def test_old_age_gives_no_allow_credit_when_block_signals_exist():
    from datetime import date
    from triage.evidence import Evidence
    from triage.issue_form import IssueRequest
    from triage.reputation import Registration, VirusTotal
    from triage.signals import TOWARD_ALLOW, collect
    request = IssueRequest(1, "block", "t", "a", "", "amexp.com", "amexp.com")
    flagged = VirusTotal("amexp.com", True, engines=[("Fortinet", "malicious", "phishing"), ("Webroot", "malicious", "x")])
    evidence = Evidence(request, "amexp.com", "amexp.com", virustotal=[flagged], registration=Registration("amexp.com", date(2002, 5, 24)))
    assert not [s for s in collect(evidence, date(2026, 9, 23)) if s.lean == TOWARD_ALLOW]
    evidence.virustotal = [VirusTotal("amexp.com", True)]
    assert any("registered since" in s.text for s in collect(evidence, date(2026, 9, 23)))


def test_provider_phishing_page_meets_the_bar():
    from triage.evidence import Evidence
    from triage.issue_form import IssueRequest
    from triage.live import Fetch
    from triage.signals import evidence_bar
    request = IssueRequest(1, "block", "t", "a", "", "pub-x.r2.dev", "pub-x.r2.dev")
    evidence = Evidence(request, "pub-x.r2.dev", "pub-x.r2.dev")
    assert evidence_bar(evidence)[0] is False
    evidence.quoted_fetches = [Fetch("desktop", chain=["https://pub-x.r2.dev/new.html"], status=403, title="Suspected Phishing  Cloudflare")]
    met, reason = evidence_bar(evidence)
    assert met and "Cloudflare" in reason
