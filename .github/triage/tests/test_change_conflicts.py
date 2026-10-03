from contextlib import nullcontext

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

    def read_file(self, path, ref):
        return self.file, "sha"

    def main_sha(self):
        return "main"

    def create_branch(self, name, sha):
        pass

    def write_file(self, path, branch, text, sha, message):
        return "sha"

    def open_pr(self, title, head, body):
        number = 100 + len(self.opened)
        self.opened.append(number)
        return number, f"https://example.com/pull/{number}"

    def merge_pr(self, number, title):
        self.merges += 1
        if self.merges <= self.conflicts:
            raise MergeConflict(f"PR #{number} could not be merged: 405")

    def close_pr(self, number):
        self.closed.append(number)

    def delete_branch(self, name):
        self.deleted.append(name)

    def lock(self):
        return nullcontext()

    def dispatch(self, workflow, inputs=None):
        pass


def run_change(ops: FakeOps):
    issue = {"number": 7, "title": "Block"}
    return change(ops, issue, Command(action="block"), ["shop.example"], None, "malicious", "")


def test_change_retries_from_fresh_main_after_a_merge_conflict():
    ops = FakeOps(conflicts=2)
    merged = run_change(ops)
    assert merged.pr == 102
    assert ops.closed == [100, 101]
    assert len(ops.deleted) == 3


def test_change_gives_up_after_the_last_attempt_and_closes_every_pr():
    ops = FakeOps(conflicts=command_runner.CHANGE_ATTEMPTS)
    with pytest.raises(MergeConflict):
        run_change(ops)
    assert len(ops.closed) == command_runner.CHANGE_ATTEMPTS
