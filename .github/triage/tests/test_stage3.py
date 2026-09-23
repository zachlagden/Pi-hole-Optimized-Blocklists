from pathlib import Path

from triage import buildcheck, watch

REPO = Path(__file__).resolve().parents[3]


def test_remediation_candidates_match_the_marked_entries_only():
    found = watch.remediation_candidates(REPO)
    assert {"halaalstyle.com", "kfhomeloans.com", "ozkocinsaat.com.tr"} <= set(found)
    assert "ringgo-portal.ink" not in found and "my-ringgo.com" not in found


def test_reported_false_positives_reads_only_that_section():
    reports = watch.reported_false_positives(REPO)
    assert reports["click-tt.de"] == "#83"
    assert reports["chat.z.ai"] == "#54" and reports["genspark.ai"] == "#52"
    assert reports["myaddr.io"] == reports["myaddr.tools"] == reports["myaddr.dev"] == "#84"
    assert "rei.com" in reports and "clients.google.com" not in reports


def test_feed_problems_flag_failed_empty_and_shrunk_feeds():
    counts = {"ok": 1000, "gone": None, "empty": 0, "shrunk": 400, "new": 50}
    previous = {"ok": 1100, "shrunk": 1000}
    problems = {p.name: p.problem for p in buildcheck.feed_problems(counts, previous)}
    assert set(problems) == {"gone", "empty", "shrunk"}
    assert "1,000 to 400" in problems["shrunk"]
    assert buildcheck.next_stats(counts, previous)["gone"] == 0 and buildcheck.next_stats(counts, previous)["shrunk"] == 400


def write(path: Path, total: int, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# Pi-hole Master Blocklist\n# Last updated: x\n# Total domains: {total}\n\n" + "\n".join(lines) + "\n")


def test_new_popular_blocks_and_hold(tmp_path):
    old, new, base = tmp_path / "old", tmp_path / "new", tmp_path / "base"
    write(old / "all_domains.txt", 1000, ["0.0.0.0 ads.example", "0.0.0.0 bank.example"])
    write(new / "all_domains.txt", 850, ["0.0.0.0 ads.example", "0.0.0.0 bank.example", "0.0.0.0 shop.example", "0.0.0.0 www.news.example", "0.0.0.0 cdn.shop.example"])
    write(base / "malicious" / "noisy_feed.txt", 3, ["0.0.0.0 shop.example"])
    ranks = {"bank.example": 10, "shop.example": 20, "news.example": 30, "rare.example": 500_000}
    blocks = buildcheck.new_popular_blocks(old, new, base, ranks)
    assert [(b.domain, b.sources) for b in blocks] == [("shop.example", ["noisy_feed"]), ("www.news.example", [])]
    churn = buildcheck.BuildReport(1000, 850, [], blocks, {})
    assert not churn.hold and churn.big_shrink and churn.needs_attention
    assert "upstream pruning" in buildcheck.summary(churn) and "shop.example (#20)" in buildcheck.summary(churn)
    broken = buildcheck.BuildReport(1000, 850, [buildcheck.FeedProblem("hagezi_pro", "download failed")], [], {})
    assert broken.hold and "Held" in buildcheck.summary(broken)
    assert not buildcheck.BuildReport(1000, 950, [], [], {}).needs_attention
    corroborated = buildcheck.NewBlock("ads.example", 5, ["all_domains.txt"], ["a", "b"])
    quiet = buildcheck.BuildReport(1000, 990, [], [corroborated], {})
    assert not quiet.needs_attention and "likely correct" in buildcheck.summary(quiet)


def test_reviewed_hits_are_grouped_and_only_doubtful_ones_ping():
    fp = buildcheck.NewBlock("uni.example", 50, ["all_domains.txt"], ["hagezi_pro"], "likely_fp", "University homepage")
    fine = buildcheck.NewBlock("ads.example", 60, ["all_domains.txt"], ["hagezi_pro"], "likely_correct", "Ad redirect domain")
    quiet = buildcheck.BuildReport(1000, 995, [], [fine], {})
    assert not quiet.needs_attention
    loud = buildcheck.BuildReport(1000, 995, [], [fine, fp], {})
    text = buildcheck.summary(loud)
    assert loud.needs_attention
    assert text.index("Likely false positives") < text.index("uni.example") < text.index("likely correct") < text.index("ads.example")
    unreviewed = buildcheck.BuildReport(1000, 995, [], [buildcheck.NewBlock("x.example", 70, ["nsfw.txt"], ["oisd_nsfw"])], {})
    assert unreviewed.needs_attention and "Not reviewed" in buildcheck.summary(unreviewed)


def test_visible_text_drops_scripts_and_tags():
    from triage.live import visible_text
    page = b"<html><script>var x=1</script><style>p{}</style><h1>Univ &amp; Co</h1><p>Welcome</p></html>"
    assert visible_text(page) == "Univ & Co Welcome"
