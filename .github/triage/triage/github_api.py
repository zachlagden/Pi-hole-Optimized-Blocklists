import os
from dataclasses import dataclass, field
from datetime import date, datetime
from urllib.parse import quote

import httpx

API = "https://api.github.com"
MARKER = "<!-- issue-triage-report -->"


@dataclass
class Reporter:
    login: str
    created: date | None = None
    public_repos: int = 0
    followers: int = 0
    other_filings: list[str] = field(default_factory=list)
    error: str | None = None


class GitHub:
    def __init__(self, token: str, repository: str) -> None:
        self.repository = repository
        self.client = httpx.Client(
            base_url=API,
            timeout=30,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

    @classmethod
    def from_env(cls) -> "GitHub":
        return cls(os.environ["GITHUB_TOKEN"], os.environ.get("GITHUB_REPOSITORY", "zachlagden/Pi-hole-Optimized-Blocklists"))

    def _get(self, path: str, **params) -> dict | list:
        response = self.client.get(path, params=params or None)
        response.raise_for_status()
        return response.json()

    def issue(self, number: int) -> dict:
        return self._get(f"/repos/{self.repository}/issues/{number}")

    def comment(self, number: int, comment_id: int) -> dict:
        return self._get(f"/repos/{self.repository}/issues/comments/{comment_id}")

    def upsert_report(self, number: int, body: str) -> str:
        comments = self._get(f"/repos/{self.repository}/issues/{number}/comments", per_page=100)
        existing = next((c for c in comments if MARKER in (c.get("body") or "")), None)
        if existing:
            response = self.client.patch(f"/repos/{self.repository}/issues/comments/{existing['id']}", json={"body": body})
        else:
            response = self.client.post(f"/repos/{self.repository}/issues/{number}/comments", json={"body": body})
        response.raise_for_status()
        return response.json()["html_url"]

    def edit_labels(self, number: int, add: set[str], remove: set[str]) -> None:
        for name in sorted(remove):
            response = self.client.delete(f"/repos/{self.repository}/issues/{number}/labels/{quote(name, safe='')}")
            if response.status_code != 404:
                response.raise_for_status()
        if add:
            response = self.client.post(f"/repos/{self.repository}/issues/{number}/labels", json={"labels": sorted(add)})
            response.raise_for_status()

    def reporter(self, login: str, domain: str | None) -> Reporter:
        try:
            user = self._get(f"/users/{login}")
        except httpx.HTTPError as error:
            return Reporter(login, error=str(error))
        reporter = Reporter(
            login=login,
            created=datetime.fromisoformat(user["created_at"].replace("Z", "+00:00")).date(),
            public_repos=user.get("public_repos", 0),
            followers=user.get("followers", 0),
        )
        if domain:
            reporter.other_filings = self._other_filings(domain)
        return reporter

    def _other_filings(self, domain: str) -> list[str]:
        query = f'"{domain}" is:issue -repo:{self.repository}'
        try:
            found = self._get("/search/issues", q=query, per_page=20)
        except httpx.HTTPError:
            return []
        filings = []
        for item in found.get("items", []):
            repo = item["repository_url"].removeprefix(f"{API}/repos/")
            filings.append(f"{repo}#{item['number']} by {item['user']['login']} on {item['created_at'][:10]}")
        return filings
