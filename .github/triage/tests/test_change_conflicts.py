from contextlib import nullcontext
from typing import Any

import pytest

from triage import command_runner
from triage.command_runner import change
from triage.commands import Command
from triage.repo_ops import MergeConflict


class FakeOps:
    def __init__(self, conflicts: int) -> None:
        self.conflicts = conflicts
        self.merges = 0
        self.opened: list[int] = []
        self.closed: list[int] = []
        self.deleted: list[str] = []
        self.file = "||existing.example^\n"

    def read_configuration(self, ref: str) -> dict[str, str]:
        return {"custom/malicious.txt": self.file, "whitelist.txt": ""}

    def read_file(self, path: str, ref: str) -> tuple[str, str]:
        return self.file, "sha"

    def main_sha(self) -> str:
        return "main"

    def create_branch(self, name: str, sha: str) -> None:
        pass

    def write_file(self, path: str, branch: str, text: str, sha: str, message: str) -> str:
        return "sha"

    def open_pr(self, title: str, head: str, body: str) -> tuple[int, str]:
        number = 100 + len(self.opened)
        self.opened.append(number)
        return number, f"https://example.com/pull/{number}"

    def merge_pr(self, number: int, title: str) -> str:
        self.merges += 1
        if self.merges <= self.conflicts:
            raise MergeConflict(f"PR #{number} could not be merged: 405")
        return "a" * 40

    def close_pr(self, number: int) -> None:
        self.closed.append(number)

    def delete_branch(self, name: str) -> None:
        self.deleted.append(name)

    def lock(self) -> Any:
        return nullcontext()

    def dispatch(self, workflow: str, inputs: dict | None = None) -> None:
        pass


def run_change(ops: Any) -> command_runner.Merged:
    issue = {"number": 7, "title": "Block"}
    return change(ops, issue, Command(action="block"), ["shop.example"], None, "malicious", "")


@pytest.fixture(autouse=True)
def offline_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("triage.commands.shared_platform", lambda domain: None)


def test_change_retries_from_fresh_main_after_a_merge_conflict() -> None:
    ops = FakeOps(conflicts=2)
    merged = run_change(ops)
    assert merged.pr == 102
    assert ops.closed == [100, 101]
    assert len(ops.deleted) == 3


def test_change_gives_up_after_the_last_attempt_and_closes_every_pr() -> None:
    ops = FakeOps(conflicts=command_runner.CHANGE_ATTEMPTS)
    with pytest.raises(MergeConflict):
        run_change(ops)
    assert len(ops.closed) == command_runner.CHANGE_ATTEMPTS


def test_retry_revalidates_new_main_before_creating_another_pr() -> None:
    class UpdatedOps(FakeOps):
        def read_configuration(self, ref: str) -> dict[str, str]:
            return {"custom/malicious.txt": "||shop.example^\n" if self.merges else self.file, "whitelist.txt": ""}

    ops = UpdatedOps(conflicts=1)
    with pytest.raises(command_runner.SkippedChange):
        run_change(ops)
    assert ops.opened == [100] and ops.closed == [100]
