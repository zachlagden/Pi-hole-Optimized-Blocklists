import json
from pathlib import Path
from typing import Any

import pytest

from triage import publication
from triage.publication import PendingChange, parse_change

SHA = "a" * 40
BOT = {"login": "github-actions[bot]", "type": "Bot"}


@pytest.fixture
def build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    root = tmp_path / "checkout"
    lists = tmp_path / "generated"
    lists.mkdir()
    (root / "lists").mkdir(parents=True)
    for name in publication.CONFIG:
        path = root / name
        path.parent.mkdir(exist_ok=True)
        path.write_text("# fictional configuration\n")
    (root / "custom/malicious.txt").write_text("||example.com^\n")
    (root / "blocklists.conf").write_text("".join(
        f"{publication.REPO_SOURCE_PREFIX}main/custom/{category}.txt|custom_{category}|{category}|abp\n"
        for category in sorted(publication.CATEGORIES)
    ))
    (root / "committed-lfs").mkdir()
    for name in publication.OUTPUTS:
        (lists / name).write_text("unrelated.example\n")
        (root / "lists" / name).write_text("unrelated.example\n")
    monkeypatch.setattr(publication, "is_ancestor", lambda *args: True)
    def fake_git(root: Path, *args: str) -> str:
        if args[0] == "rev-parse":
            return SHA
        path = args[1].split(":", 1)[1]
        if path.startswith("lists/"):
            return (root / "committed-lfs" / Path(path).name).read_text().strip()
        return (root / path).read_text().strip()

    monkeypatch.setattr(publication, "git", fake_git)
    monkeypatch.setattr(publication.subprocess, "check_output", lambda args, **kwargs: (root / args[-1].split(":", 1)[1]).read_bytes())
    return root, lists


def record(root: Path, lists: Path, feed_check: dict | None = None) -> dict:
    for name in publication.OUTPUTS:
        (root / "lists" / name).write_bytes((lists / name).read_bytes())
        (root / "committed-lfs" / name).write_text(
            f"version https://git-lfs.github.com/spec/v1\noid sha256:{publication.digest(lists / name)}\nsize {(lists / name).stat().st_size}\n"
        )
    effective = root / "effective.conf"
    effective.write_text(publication.pinned_config((root / "blocklists.conf").read_text(), SHA)[0])
    base = root / "parsed"
    for category in sorted(publication.CATEGORIES):
        (base / category).mkdir(parents=True, exist_ok=True)
        (base / category / f"custom_{category}.txt.raw").write_bytes((root / f"custom/{category}.txt").read_bytes())
    check = feed_check or {"successful": True, "held": False, "feed_problems": []}
    manifest = publication.record_manifest(lists, root, SHA, check, effective, base)
    if check == {"successful": True, "held": False, "feed_problems": []}:
        publication.record_publication(lists, root, SHA)
        manifest = json.loads((lists / publication.MANIFEST).read_text())
    return manifest


def pending(action: str = "block", scope: str = "domain", category: str = "malicious") -> PendingChange:
    entries = publication.entries_for(["example.com"], scope == "exact") if action == "block" else publication.allow_entries_for(["example.com"], scope)
    return PendingChange(7, 133, "https://example.com/pr/133", SHA, action, f"custom/{category}.txt" if action == "block" else "whitelist.txt", ["example.com"], entries, scope)


class FakeGitHub:
    def __init__(self, change: PendingChange) -> None:
        self.data = [{"id": 10, "user": BOT, "body": "Configuration merged. Publication pending.\n" + change.marker()}]
        self.edits: list[int] = []
        self.pr: dict = {"merged": True, "merge_commit_sha": SHA, "base": {"ref": "main"}}

    def main_sha(self) -> str:
        return SHA

    def pending_issues(self) -> list[dict]:
        return [{"number": 7}]

    def comments(self, number: int) -> list[dict]:
        return self.data

    def pull_request(self, number: int) -> dict:
        return self.pr

    def edit_comment(self, comment_id: int, body: str) -> None:
        self.edits.append(comment_id)
        self.data[0]["body"] = body


def change_status(comment: dict) -> str:
    change = parse_change(comment)
    assert change is not None
    return change.status


def test_markers_authenticated_and_schema_checked() -> None:
    change = pending()
    assert parse_change({"user": BOT, "body": change.marker()}) == change
    for user in [{"login": "Alex", "type": "User"}, {"login": "github-actions[bot]", "type": "User"}, {"login": "Sam", "type": "Bot"}]:
        assert parse_change({"user": user, "body": change.marker()}) is None
    change.entries = ["forged.example"]
    assert parse_change({"user": BOT, "body": change.marker()}) is None
    assert parse_change({"user": BOT, "body": "<!-- triage-change:bad== -->"}) is None


def test_pending_vs_published_and_rerun_idempotency(build: tuple[Path, Path]) -> None:
    root, lists = build
    for name in ("malicious.txt", "all_domains.txt"):
        (lists / name).write_text("||example.com^\n")
    record(root, lists)
    github: Any = FakeGitHub(pending())
    assert change_status(github.data[0]) == "pending"
    assert publication.publish(github, lists, root).published == [133]
    assert "Published lists now include" in github.data[0]["body"]
    assert change_status(github.data[0]) == "published"
    assert publication.publish(github, lists, root).published == []
    assert github.edits == [10]


def test_flattened_broad_block_is_not_confirmed(build: tuple[Path, Path]) -> None:
    root, lists = build
    for name in ("malicious.txt", "all_domains.txt"):
        (lists / name).write_text("example.com\n")
    record(root, lists)
    github: Any = FakeGitHub(pending())
    result = publication.publish(github, lists, root)
    assert result.published == [] and "requested block scope" in result.pending[0]["reason"]
    assert github.edits == []


def test_exact_block_accepts_host_or_ancestor_wildcard(build: tuple[Path, Path]) -> None:
    root, lists = build
    (root / "custom/malicious.txt").write_text("example.com\n")
    (lists / "malicious.txt").write_text("example.com\n")
    (lists / "all_domains.txt").write_text("||example.com^\n")
    record(root, lists)
    github: Any = FakeGitHub(pending(scope="exact"))
    assert publication.publish(github, lists, root).published == [133]


def test_nsfw_host_and_abp_formats(build: tuple[Path, Path]) -> None:
    root, lists = build
    (root / "custom/nsfw.txt").write_text("||example.com^\n")
    (lists / "nsfw.txt").write_text("example.com\n")
    (lists / "nsfw_abp.txt").write_text("||example.com^\n")
    record(root, lists)
    github: Any = FakeGitHub(pending(category="nsfw"))
    assert publication.publish(github, lists, root).published == [133]
    assert "NSFW descendants are covered by nsfw_abp.txt" in github.data[0]["body"]


@pytest.mark.parametrize("output,scope,blocking", [
    ("tracking.txt", "domain", "child.example.com"),
    ("nsfw_abp.txt", "domain", "||example.com^"),
    ("all_domains.txt", "exact", "||example.com^"),
    ("comprehensive.txt", "subdomains", "child.example.com"),
])
def test_allow_requires_entire_scope_absent_from_every_output(build: tuple[Path, Path], output: str, scope: str, blocking: str) -> None:
    root, lists = build
    change = pending(action="allow", scope=scope)
    (root / "whitelist.txt").write_text("\n".join(change.entries) + "\n")
    (lists / output).write_text(blocking + "\n")
    record(root, lists)
    github: Any = FakeGitHub(change)
    result = publication.publish(github, lists, root)
    assert not result.published and output in result.pending[0]["reason"]


def test_subdomains_allow_can_leave_bare_host_blocked(build: tuple[Path, Path]) -> None:
    root, lists = build
    (root / "whitelist.txt").write_text("*.example.com\n")
    (lists / "all_domains.txt").write_text("example.com\n")
    record(root, lists)
    github: Any = FakeGitHub(pending(action="allow", scope="subdomains"))
    assert publication.publish(github, lists, root).published == [133]


@pytest.mark.parametrize("check", [
    {"successful": False, "held": False, "feed_problems": []},
    {"successful": True, "held": True, "feed_problems": []},
    {"successful": True, "held": False, "feed_problems": ["Acme Feed missing"]},
])
def test_failed_or_missing_feeds_never_confirm(build: tuple[Path, Path], check: dict) -> None:
    root, lists = build
    record(root, lists, check)
    github: Any = FakeGitHub(pending())
    with pytest.raises(ValueError):
        publication.publish(github, lists, root)
    assert github.edits == []


def test_manifest_and_published_checkout_hashes_required(build: tuple[Path, Path]) -> None:
    root, lists = build
    github: Any = FakeGitHub(pending())
    with pytest.raises(FileNotFoundError):
        publication.publish(github, lists, root)
    record(root, lists)
    (root / "lists/tracking.txt").write_text("changed.example\n")
    with pytest.raises(ValueError, match="not present in published"):
        publication.publish(github, lists, root)
    assert github.edits == []


def test_config_change_after_build_is_not_confirmation(build: tuple[Path, Path]) -> None:
    root, lists = build
    record(root, lists)
    (root / "whitelist.txt").write_text("example.com\n")
    github: Any = FakeGitHub(pending())
    with pytest.raises(ValueError, match="hash mismatch"):
        publication.publish(github, lists, root)


def test_merge_must_be_in_build_checkout(build: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    root, lists = build
    record(root, lists)
    github: Any = FakeGitHub(pending())
    monkeypatch.setattr(publication, "is_ancestor", lambda root, ancestor, descendant: ancestor != SHA or descendant != SHA)
    with pytest.raises(ValueError):
        publication.publish(github, lists, root)
    manifest = json.loads((lists / publication.MANIFEST).read_text())
    assert publication.verify_change(pending(), root, manifest, publication.output_entries(lists), github.pr) == "change was not in the optimizer checkout"


def test_dry_run_leaves_marker_pending(build: tuple[Path, Path]) -> None:
    root, lists = build
    for name in ("malicious.txt", "all_domains.txt"):
        (lists / name).write_text("||example.com^\n")
    record(root, lists)
    github: Any = FakeGitHub(pending())
    result = publication.publish(github, lists, root, dry_run=True)
    assert result.published == [] and result.would_publish == [133]
    assert github.edits == [] and change_status(github.data[0]) == "pending"


def test_edit_failure_can_retry_without_duplicate_notification(build: tuple[Path, Path]) -> None:
    root, lists = build
    for name in ("malicious.txt", "all_domains.txt"):
        (lists / name).write_text("||example.com^\n")
    record(root, lists)

    class FailingGitHub(FakeGitHub):
        def edit_comment(self, comment_id: int, body: str) -> None:
            raise RuntimeError("fictional transport failure")

    github: Any = FailingGitHub(pending())
    with pytest.raises(RuntimeError):
        publication.publish(github, lists, root)
    assert change_status(github.data[0]) == "pending"
    healthy: Any = FakeGitHub(pending())
    healthy.data = github.data
    assert publication.publish(healthy, lists, root).published == [133]
    assert publication.publish(healthy, lists, root).published == []


def test_candidate_retention_bounds_large_outputs(build: tuple[Path, Path]) -> None:
    root, lists = build
    (lists / "all_domains.txt").write_text("||example.com^\nexample.com\n" + "".join(f"child{index}.example.com\n" for index in range(1000)))
    outputs = publication.output_entries(lists, {"example.com"})
    assert len(outputs["all_domains.txt"]) == 3


def test_dry_run_cli_uses_read_only_fake_api(build: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    root, lists = build
    for name in ("malicious.txt", "all_domains.txt"):
        (lists / name).write_text("||example.com^\n")
    record(root, lists)
    github = FakeGitHub(pending())
    monkeypatch.setattr(publication.GitHub, "from_env", lambda: github)
    assert publication.main(["--lists", str(lists), "--repo-root", str(root), "--dry-run"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["would_publish"] == [133] and output["published"] == [] and github.edits == []


def test_manifest_provenance_and_unmerged_pr_refuse(build: tuple[Path, Path]) -> None:
    root, lists = build
    manifest = record(root, lists)
    outputs = publication.output_entries(lists)
    assert publication.verify_change(pending(), root, manifest, outputs, {"merged": False}) == "PR merge provenance does not match"
    (root / "custom/malicious.txt").write_text("different.example\n")
    assert publication.verify_change(pending(), root, manifest, outputs, {"merged": True, "merge_commit_sha": SHA, "base": {"ref": "main"}}) == "merged configuration is no longer present"


def test_effective_config_pins_only_the_five_repository_inputs(build: tuple[Path, Path]) -> None:
    root, _ = build
    original = (root / "blocklists.conf").read_text() + "https://feed.example/list|Acme|malicious\n"
    (root / "blocklists.conf").write_text(original)
    target = root / "optimizer.conf"
    publication.prepare_config(root, SHA, target)
    effective = target.read_text()
    assert (root / "blocklists.conf").read_text() == original
    assert "https://feed.example/list|Acme|malicious" in effective
    assert f"{publication.REPO_SOURCE_PREFIX}main/custom/" not in effective
    assert effective.count(f"{publication.REPO_SOURCE_PREFIX}{SHA}/custom/") == 5
    with pytest.raises(ValueError, match="overwrite"):
        publication.prepare_config(root, SHA, root / "blocklists.conf")


@pytest.mark.parametrize("fault", ["effective", "raw", "missing_raw"])
def test_recording_requires_exact_effective_and_downloaded_custom_inputs(build: tuple[Path, Path], fault: str) -> None:
    root, lists = build
    record(root, lists)
    effective = root / "effective.conf"
    raw = root / "parsed/malicious/custom_malicious.txt.raw"
    if fault == "effective":
        effective.write_text((root / "blocklists.conf").read_text())
    elif fault == "raw":
        raw.write_text("||new.example^\n")
    else:
        raw.unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        publication.record_manifest(lists, root, SHA, {"successful": True, "held": False, "feed_problems": []}, effective, root / "parsed")
    assert not (lists / publication.MANIFEST).exists()


@pytest.mark.parametrize("field", ["effective_config_sha256", "custom_source_urls", "downloaded_custom_sha256", "published_sha", "published_ref"])
def test_missing_provenance_never_confirms(build: tuple[Path, Path], field: str) -> None:
    root, lists = build
    manifest = record(root, lists)
    del manifest[field]
    (lists / publication.MANIFEST).write_text(json.dumps(manifest))
    github: Any = FakeGitHub(pending())
    with pytest.raises(ValueError):
        publication.publish(github, lists, root)
    assert not github.edits


@pytest.mark.parametrize("fault", ["oid", "size", "uncommitted", "sha"])
def test_successful_push_path_requires_committed_lfs_output(build: tuple[Path, Path], fault: str) -> None:
    root, lists = build
    record(root, lists)
    pointer = root / "committed-lfs/tracking.txt"
    if fault == "oid":
        pointer.write_text(pointer.read_text().replace(publication.digest(lists / "tracking.txt"), "b" * 64))
    elif fault == "size":
        pointer.write_text(pointer.read_text().replace(f"size {(lists / 'tracking.txt').stat().st_size}", "size 1"))
    elif fault == "uncommitted":
        (lists / "tracking.txt").write_text("changed.example\n")
        (root / "lists/tracking.txt").write_bytes((lists / "tracking.txt").read_bytes())
        manifest = json.loads((lists / publication.MANIFEST).read_text())
        manifest["output_sha256"]["tracking.txt"] = publication.digest(lists / "tracking.txt")
        (lists / publication.MANIFEST).write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        publication.record_publication(lists, root, "b" * 40 if fault == "sha" else SHA)


def test_main_moving_after_checkout_does_not_confirm_later_change(build: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    root, lists = build
    for name in ("malicious.txt", "all_domains.txt"):
        (lists / name).write_text("||example.com^\n")
    manifest = record(root, lists)
    later_sha = "b" * 40
    change = pending()
    change.merge_sha = later_sha
    github: Any = FakeGitHub(change)
    github.pr["merge_commit_sha"] = later_sha
    monkeypatch.setattr(publication, "is_ancestor", lambda root, ancestor, descendant: ancestor != later_sha)
    result = publication.publish(github, lists, root)
    assert not result.published and not github.edits
    assert result.pending[0]["reason"] == "change was not in the optimizer checkout"
    assert all(SHA in url and later_sha not in url for url in manifest["custom_source_urls"].values())


def test_manifest_publication_is_local_only_and_requires_distinct_modes(build: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    root, lists = build
    record(root, lists)

    def no_api() -> None:
        pytest.fail("local manifest modes must not use the GitHub API")

    monkeypatch.setattr(publication.GitHub, "from_env", no_api)
    assert publication.main(["--lists", str(lists), "--repo-root", str(root), "--record-publication", "--published-sha", SHA]) == 0
    assert publication.main(["--lists", str(lists), "--repo-root", str(root), "--prepare-config", "--config-sha", SHA, "--effective-config", str(root / "new.conf")]) == 0


def test_non_main_or_moved_main_publication_never_confirms(build: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    root, lists = build
    for name in ("malicious.txt", "all_domains.txt"):
        (lists / name).write_text("||example.com^\n")
    manifest = record(root, lists)
    github: Any = FakeGitHub(pending())
    monkeypatch.setattr(github, "main_sha", lambda: "b" * 40)
    with pytest.raises(ValueError, match="main moved"):
        publication.publish(github, lists, root)
    assert not github.edits
    manifest["published_ref"] = "refs/heads/feature"
    (lists / publication.MANIFEST).write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="production-main"):
        publication.validate_manifest(lists, root)
    tracked_git = publication.git

    def wrong_main(root: Path, *args: str) -> str:
        return "b" * 40 if args == ("rev-parse", "refs/remotes/origin/main") else tracked_git(root, *args)

    monkeypatch.setattr(publication, "git", wrong_main)
    with pytest.raises(ValueError, match="production main ref"):
        publication.record_publication(lists, root, SHA)


def test_missing_feed_check_cli_removes_stale_manifest(build: tuple[Path, Path]) -> None:
    root, lists = build
    record(root, lists)
    assert publication.main(["--lists", str(lists), "--repo-root", str(root), "--record-manifest", "--config-sha", SHA,
                             "--base", str(root / "parsed"), "--effective-config", str(root / "effective.conf"),
                             "--feed-check", str(root / "missing.json")]) == 1
    assert not (lists / publication.MANIFEST).exists()
