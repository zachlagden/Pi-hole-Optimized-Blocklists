from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest

from triage import repo_ops
from triage.repo_ops import LockTimeout, RepoOps


class FakeGitHub:
    def __init__(self, lock_commit_age: float | None = None) -> None:
        self.lock_sha: str | None = None
        self.lock_created: datetime | None = None
        if lock_commit_age is not None:
            self.lock_sha = "held"
            self.lock_created = datetime.now(UTC) - timedelta(seconds=lock_commit_age)
        self.created = 0
        self.deleted = 0
        self.created_on_retry = False

    def handle(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path.endswith("/git/ref/heads/main"):
            return httpx.Response(200, json={"object": {"sha": "mainsha"}})
        if path.endswith("/git/commits/mainsha"):
            return httpx.Response(200, json={"sha": "mainsha", "tree": {"sha": "tree"}})
        if method == "POST" and path.endswith("/git/commits"):
            return httpx.Response(201, json={"sha": "stamp"})
        if path.endswith("/git/ref/heads/triage-lock"):
            if self.lock_sha is None:
                return httpx.Response(404)
            return httpx.Response(200, json={"object": {"sha": self.lock_sha}})
        if path.endswith(f"/git/commits/{self.lock_sha}") and self.lock_sha:
            return httpx.Response(200, json={"committer": {"date": self.lock_created.isoformat()}})
        if method == "POST" and path.endswith("/git/refs"):
            if self.lock_sha is not None:
                return httpx.Response(422)
            self.lock_sha, self.lock_created = "stamp", datetime.now(UTC)
            self.created += 1
            return httpx.Response(201, json={})
        if method == "DELETE" and path.endswith("/git/refs/heads/triage-lock"):
            self.lock_sha = None
            self.deleted += 1
            return httpx.Response(204)
        raise AssertionError(f"unexpected {method} {path}")


def make_ops(fake: FakeGitHub) -> RepoOps:
    client = httpx.Client(transport=httpx.MockTransport(fake.handle), base_url="https://api.github.com")
    return RepoOps(SimpleNamespace(client=client, repository="owner/repo"))


def test_lock_is_taken_and_released():
    fake = FakeGitHub()
    with make_ops(fake).lock():
        assert fake.lock_sha is not None
    assert fake.lock_sha is None
    assert (fake.created, fake.deleted) == (1, 1)


def test_lock_is_released_when_the_change_fails():
    fake = FakeGitHub()
    with pytest.raises(RuntimeError):
        with make_ops(fake).lock():
            raise RuntimeError("boom")
    assert fake.lock_sha is None


def test_lock_waits_for_a_fresh_lock_then_times_out(monkeypatch):
    monkeypatch.setattr(repo_ops.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(repo_ops, "LOCK_WAIT_SECONDS", -1)
    fake = FakeGitHub(lock_commit_age=5)
    with pytest.raises(LockTimeout):
        with make_ops(fake).lock():
            pass
    assert fake.lock_sha == "held"


def test_lock_waits_until_the_holder_releases(monkeypatch):
    fake = FakeGitHub(lock_commit_age=5)

    def release(seconds):
        fake.lock_sha = None

    monkeypatch.setattr(repo_ops.time, "sleep", release)
    with make_ops(fake).lock():
        assert fake.lock_sha == "stamp"


def test_lock_takes_over_a_stale_lock():
    fake = FakeGitHub(lock_commit_age=repo_ops.LOCK_STALE_SECONDS + 60)
    with make_ops(fake).lock():
        assert fake.lock_sha == "stamp"
    assert fake.created == 1
