import base64
import time

import httpx

from triage.github_api import GitHub

MERGE_ATTEMPTS = 5
MERGE_RETRY_SECONDS = 4


class RepoOps:
    def __init__(self, github: GitHub) -> None:
        self.client = github.client
        self.base = f"/repos/{github.repository}"

    def _send(self, method: str, path: str, **kwargs) -> httpx.Response:
        response = self.client.request(method, self.base + path, **kwargs)
        response.raise_for_status()
        return response

    def main_sha(self) -> str:
        return self._send("GET", "/git/ref/heads/main").json()["object"]["sha"]

    def create_branch(self, name: str, sha: str) -> None:
        self._send("POST", "/git/refs", json={"ref": f"refs/heads/{name}", "sha": sha})

    def delete_branch(self, name: str) -> None:
        response = self.client.delete(f"{self.base}/git/refs/heads/{name}")
        if response.status_code not in (204, 404, 422):
            response.raise_for_status()

    def read_file(self, path: str, ref: str) -> tuple[str, str]:
        data = self._send("GET", f"/contents/{path}", params={"ref": ref}).json()
        return base64.b64decode(data["content"]).decode(), data["sha"]

    def write_file(self, path: str, branch: str, text: str, sha: str, message: str) -> str:
        payload = {"message": message, "content": base64.b64encode(text.encode()).decode(), "sha": sha, "branch": branch}
        return self._send("PUT", f"/contents/{path}", json=payload).json()["content"]["sha"]

    def open_pr(self, title: str, head: str, body: str) -> tuple[int, str]:
        data = self._send("POST", "/pulls", json={"title": title, "head": head, "base": "main", "body": body}).json()
        return data["number"], data["html_url"]

    def merge_pr(self, number: int, title: str) -> None:
        for attempt in range(MERGE_ATTEMPTS):
            response = self.client.put(f"{self.base}/pulls/{number}/merge", json={"merge_method": "squash", "commit_title": f"{title} (#{number})"})
            if response.status_code == 200:
                return
            if attempt == MERGE_ATTEMPTS - 1 or response.status_code not in (405, 409):
                response.raise_for_status()
            time.sleep(MERGE_RETRY_SECONDS)

    def comment(self, number: int, body: str) -> None:
        self._send("POST", f"/issues/{number}/comments", json={"body": body})

    def close_issue(self, number: int, reason: str) -> None:
        self._send("PATCH", f"/issues/{number}", json={"state": "closed", "state_reason": reason})

    def add_labels(self, number: int, labels: list[str]) -> None:
        self._send("POST", f"/issues/{number}/labels", json={"labels": labels})

    def react(self, comment_id: int, content: str) -> None:
        self.client.post(f"{self.base}/issues/comments/{comment_id}/reactions", json={"content": content})

    def dispatch(self, workflow: str, inputs: dict | None = None) -> None:
        self._send("POST", f"/actions/workflows/{workflow}/dispatches", json={"ref": "main", "inputs": inputs or {}})
