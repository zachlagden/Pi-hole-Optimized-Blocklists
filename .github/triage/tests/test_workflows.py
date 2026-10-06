import asyncio
import socket
from pathlib import Path
from typing import Any, cast

import httpx
import playwright.sync_api
import pytest
import requests
import yaml

from triage import cache_warm, domains

REPO = Path(__file__).resolve().parents[3]
CACHE_PREFIX = "triage-v2-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('.github/triage/uv.lock') }}-"
PUBLICATION_GATE = (
    "steps.buildcheck.outcome == 'success' "
    "&& steps.buildcheck.outputs.run == 'false' "
    "&& steps.manifest.outcome == 'success' "
    "&& (steps.publish.outcome == 'success' || steps.no_changes.outcome == 'success')"
)


def workflow(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], yaml.load((REPO / ".github" / "workflows" / name).read_text(), Loader=yaml.BaseLoader))


def named_step(job: dict[str, Any], name: str) -> dict[str, Any]:
    return next(step for step in job["steps"] if step.get("name") == name)


def action_steps(job: dict[str, Any], action: str) -> list[dict[str, Any]]:
    return [step for step in job["steps"] if step.get("uses", "").split("@")[0] == action]


def test_workflows_parse_actions_triggers_and_step_structure() -> None:
    for path in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        content = workflow(path.name)
        assert "on" in content and isinstance(content["on"], dict)
        assert content["jobs"]
        for job in content["jobs"].values():
            assert job["runs-on"] == "ubuntu-latest"
            for step in job["steps"]:
                assert ("uses" in step) != ("run" in step)
                if "uses" in step:
                    assert "@" in step["uses"]


def test_normal_issue_jobs_are_read_only_and_never_save_caches() -> None:
    content = workflow("issue-triage.yml")
    assert set(content["on"]) == {"issues", "issue_comment", "workflow_dispatch"}
    assert content["permissions"] == {"contents": "read", "issues": "write"}
    for name in ("triage", "update"):
        job = content["jobs"][name]
        assert job.get("permissions", content["permissions"])["contents"] == "read"
        restores = action_steps(job, "actions/cache/restore")
        assert len(restores) == 1
        assert restores[0]["with"]["key"] == CACHE_PREFIX + "current"
        assert restores[0]["with"]["restore-keys"] == CACHE_PREFIX
        assert restores[0]["with"]["path"].splitlines() == ["~/.cache/issue-triage", "~/.cache/ms-playwright"]
        assert not action_steps(job, "actions/cache")
        assert not action_steps(job, "actions/cache/save")
    assert content["jobs"]["command"]["permissions"]["contents"] == "write"
    assert "author_association == 'OWNER'" in content["jobs"]["command"]["if"]


def test_only_trusted_cache_warming_saves_data_and_uv_caches() -> None:
    for path in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        content = workflow(path.name)
        for job in content["jobs"].values():
            setups = action_steps(job, "astral-sh/setup-uv")
            assert len(setups) == 1
            assert setups[0]["with"]["cache-dependency-glob"] == ".github/triage/uv.lock"
            trusted = path.name == "triage-cache.yml"
            assert setups[0]["with"]["save-cache"] == ("true" if trusted else "false")
            assert not action_steps(job, "actions/cache")
            assert bool(action_steps(job, "actions/cache/save")) == trusted


def test_cache_warmer_is_main_only_daily_and_credential_free() -> None:
    content = workflow("triage-cache.yml")
    assert set(content["on"]) == {"push", "schedule", "workflow_dispatch"}
    assert content["on"]["push"]["branches"] == ["main"]
    assert content["on"]["schedule"] == [{"cron": "15 3 * * *"}]
    assert content["permissions"] == {"contents": "read"}
    assert content["concurrency"]["cancel-in-progress"] == "false"
    job = content["jobs"]["warm"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert not job.get("env") and not job.get("permissions")
    assert action_steps(job, "actions/checkout")[0]["with"]["persist-credentials"] == "false"
    assert "date -u +%F" in named_step(job, "Choose daily cache key")["run"]
    restore = action_steps(job, "actions/cache/restore")[0]
    save = action_steps(job, "actions/cache/save")[0]
    assert restore["with"]["key"] == CACHE_PREFIX + "${{ steps.cache-date.outputs.day }}"
    assert restore["with"]["restore-keys"] == CACHE_PREFIX
    assert "run_id" not in restore["with"]["key"]
    assert save["with"]["key"] == "${{ steps.cache.outputs.cache-primary-key }}"
    assert save["with"]["path"] == restore["with"]["path"]
    warm = named_step(job, "Warm browser, Tranco and suffix list")
    assert save["if"] == warm["if"] == "steps.cache.outputs.cache-hit != 'true'"
    assert "uv sync --frozen --no-dev" in warm["run"]
    assert "playwright install --with-deps chromium" in warm["run"]
    assert "python -m triage.cache_warm" in warm["run"]
    for step in job["steps"]:
        assert not step.get("env")
        assert "secrets." not in str(step)
        assert "python -m triage issue" not in step.get("run", "")
    assert job["steps"].index(warm) < job["steps"].index(save)


def test_offline_ci_runs_frozen_tests_for_prs_and_main_pushes() -> None:
    content = workflow("triage-tests.yml")
    assert set(content["on"]) == {"pull_request", "push"}
    assert content["on"]["push"]["branches"] == ["main"]
    assert content["permissions"] == {"contents": "read"}
    job = content["jobs"]["pytest"]
    assert job["defaults"]["run"]["working-directory"] == ".github/triage"
    assert named_step(job, "Install frozen dependencies")["run"] == "uv sync --frozen"
    assert named_step(job, "Run offline tests")["run"] == "uv run --frozen pytest -q"
    assert action_steps(job, "astral-sh/setup-uv")[0]["with"]["python-version"] == "3.12"
    assert not action_steps(job, "actions/cache/restore")
    assert "secrets." not in str(job)
    assert "playwright install" not in str(job)


def test_held_build_never_mutates_or_publishes_lists() -> None:
    content = workflow("update-blocklists.yml")
    assert content["permissions"] == {"contents": "read", "issues": "write", "pull-requests": "read"}
    job = content["jobs"]["update-blocklists"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert named_step(job, "Check feeds and new blocks")["continue-on-error"] == "true"
    for name in ("Extract statistics", "Update README", "Check for changes", "Configure Git"):
        assert named_step(job, name)["if"] == "steps.buildcheck.outputs.run != 'true'"
    publish = named_step(job, "Commit and push")
    assert publish["id"] == "publish"
    assert publish["if"] == "steps.check_changes.outputs.changes_detected == 'true' && steps.buildcheck.outputs.run != 'true'"
    unchanged = named_step(job, "No changes")
    assert unchanged["id"] == "no_changes"
    assert unchanged["if"] == "steps.check_changes.outputs.changes_detected == 'false' && steps.buildcheck.outputs.run != 'true'"
    assert named_step(job, "Held build")["if"] == "steps.buildcheck.outputs.run == 'true'"
    checkout = action_steps(job, "actions/checkout")[0]
    assert checkout["with"]["token"] == "${{ secrets.GH_PAT }}"
    assert checkout["with"]["lfs"] == "true"
    assert "git push" in publish["run"]
    assert "fetch-depth" in checkout["with"] and checkout["with"]["fetch-depth"] == "0"
    assert "cmp" in unchanged["run"] and "nsfw_abp" in unchanged["run"]


def test_publication_requires_successful_unheld_check_and_publish_path() -> None:
    job = workflow("update-blocklists.yml")["jobs"]["update-blocklists"]
    publication = named_step(job, "Verify publication")
    assert publication["if"] == PUBLICATION_GATE
    assert publication["continue-on-error"] == "true"
    assert publication["env"] == {"REPO_ROOT": "${{ github.workspace }}", "GITHUB_TOKEN": "${{ secrets.GITHUB_TOKEN }}"}
    assert "python -m triage.publication" in publication["run"]
    assert '--lists "$REPO_ROOT/pihole_blocklists_prod" --repo-root "$REPO_ROOT"' in publication["run"]
    assert job["steps"].index(named_step(job, "Commit and push")) < job["steps"].index(publication)
    assert job["steps"].index(named_step(job, "No changes")) < job["steps"].index(publication)
    assert "--record-publication" in publication["run"] and "--published-sha" in publication["run"]
    assert publication["run"].index("--record-publication") < publication["run"].rindex("python -m triage.publication")
    failure = named_step(job, "Report publication verification failure")
    assert failure["if"] == "steps.publication.outcome == 'failure' || steps.manifest.outcome == 'failure'"
    assert failure["continue-on-error"] == "true"
    assert "$GITHUB_STEP_SUMMARY" in failure["run"]
    assert "::warning::" in failure["run"] and "did not fail" in failure["run"]
    assert "curl -fsS" in failure["run"]


def test_manifest_uses_actual_checks_and_pinned_pre_optimizer_inputs() -> None:
    job = workflow("update-blocklists.yml")["jobs"]["update-blocklists"]
    optimizer = named_step(job, "Run optimizer")
    check = named_step(job, "Check feeds and new blocks")
    manifest = named_step(job, "Record optimizer publication manifest")
    assert optimizer["run"].index("git rev-parse HEAD") < optimizer["run"].index("--prepare-config")
    assert optimizer["run"].index("--prepare-config") < optimizer["run"].index("./pihole-optimizer")
    assert '--config "$RUNNER_TEMP/triage-optimizer.conf"' in optimizer["run"]
    assert '--feed-check "$RUNNER_TEMP/triage-feed-check.json"' in check["run"]
    assert manifest["env"]["OPTIMIZER_CONFIG_SHA"] == "${{ steps.optimizer.outputs.config_sha }}"
    assert "--record-manifest" in manifest["run"] and "--effective-config" in manifest["run"] and "--base" in manifest["run"]
    assert manifest["if"] == "steps.buildcheck.outcome == 'success' && steps.buildcheck.outputs.run == 'false'"
    assert job["steps"].index(check) < job["steps"].index(manifest) < job["steps"].index(named_step(job, "Commit and push"))
    assert "triage-publication.json" not in named_step(job, "Commit and push")["run"]


def test_retired_source_is_not_replaced() -> None:
    assert "nextdns_cname" not in (REPO / "blocklists.conf").read_text()


def test_suffix_extractor_uses_the_bundled_snapshot() -> None:
    assert domains._extractor().suffix_list_urls == ()
    assert domains.registrable("sam.example.com") == "example.com"


def test_unexpected_external_calls_fail_instead_of_becoming_empty_evidence() -> None:
    calls = [
        lambda: httpx.get("https://example.com"),
        lambda: requests.get("https://example.com"),
        lambda: socket.getaddrinfo("example.com", 443),
        playwright.sync_api.sync_playwright,
    ]
    for call in calls:
        with pytest.raises(pytest.fail.Exception, match="Unexpected external call"):
            call()


def test_httpx_mock_transport_remains_available() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"site": "Acme"})

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        assert client.get("https://example.com").json() == {"site": "Acme"}


def test_async_external_calls_fail_but_mock_transports_work() -> None:
    async def check() -> None:
        async with httpx.AsyncClient() as client:
            with pytest.raises(pytest.fail.Exception, match="Unexpected external call"):
                await client.get("https://example.com")
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
            assert (await client.get("https://example.com")).status_code == 200

    asyncio.run(check())


def test_cache_warming_prunes_old_tranco_snapshots_and_refreshes_suffixes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tranco = tmp_path / "tranco"
    tranco.mkdir()
    (tranco / "tranco-old.csv").write_text("1,old.example\n")
    (tranco / "other.txt").write_text("keep")
    monkeypatch.setattr(cache_warm, "CACHE_DIR", tmp_path)
    calls: list[str] = []

    def ranks(cache_dir: Path) -> dict[str, int]:
        assert cache_dir == tranco
        assert not list(cache_dir.glob("tranco-*.csv"))
        (cache_dir / "tranco-new.csv").write_text("1,example.com\n")
        calls.append("tranco")
        return {"example.com": 1}

    def refresh(fetch_now: bool = False) -> None:
        assert fetch_now
        calls.append("suffix")

    monkeypatch.setattr(cache_warm.reputation, "tranco_ranks", ranks)
    monkeypatch.setattr(domains._extractor(), "update", refresh)
    cache_warm.warm()
    assert calls == ["tranco", "suffix"]
    assert [path.name for path in tranco.glob("*.csv")] == ["tranco-new.csv"]
    assert (tranco / "other.txt").read_text() == "keep"


def test_cache_warming_refuses_empty_tranco_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cache_warm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(cache_warm.reputation, "tranco_ranks", lambda cache_dir: {})
    with pytest.raises(ValueError, match="no ranks"):
        cache_warm.warm()
