import json
from datetime import date

import httpx

from triage.ai_review import Review
from triage.evidence import Evidence
from triage.github_api import Reporter

COLOURS = {"block": 0xD9534F, "allow": 0x5CB85C, "other": 0x5BC0DE}


class Discord:
    def __init__(self, webhook: str, ping_user_id: str) -> None:
        self.webhook = webhook
        self.ping_user_id = ping_user_id

    def _content(self, text: str, ping: bool) -> str:
        return f"<@{self.ping_user_id}> {text}" if self.ping_user_id and ping else text

    def send(self, text: str, embed: dict, png: bytes | None = None, ping: bool = True) -> None:
        payload = {
            "content": self._content(text, ping),
            "embeds": [embed],
            "allowed_mentions": {"users": [self.ping_user_id] if self.ping_user_id and ping else []},
        }
        if png:
            embed["image"] = {"url": "attachment://site.png"}
            files = {"files[0]": ("site.png", png, "image/png")}
            response = httpx.post(self.webhook, data={"payload_json": json.dumps(payload)}, files=files, timeout=30)
        else:
            response = httpx.post(self.webhook, json=payload, timeout=30)
        response.raise_for_status()


def _trim(text: str, limit: int = 1000) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def reporter_lines(reporter: Reporter | None, today: date) -> str:
    if reporter is None:
        return "not checked"
    if reporter.error:
        return f"lookup failed: {reporter.error}"
    age = (today - reporter.created).days if reporter.created else None
    lines = [f"{reporter.login}: account {age} days old, {reporter.public_repos} public repos, {reporter.followers} followers"]
    if reporter.other_filings:
        lines.append("Same domain filed elsewhere:")
        lines += [f"• {filing}" for filing in reporter.other_filings[:8]]
    else:
        lines.append("No issues about this domain in other repos")
    return "\n".join(lines)


def triage_embed(evidence: Evidence, review: Review | None, report_url: str, today: date) -> dict:
    request = evidence.request
    vt = ", ".join(f"{v.domain} {v.malicious + v.suspicious}/{v.total}" for v in evidence.virustotal if v.found) or "no record"
    fields = [
        {"name": "Blocking sources", "value": _trim(", ".join(evidence.blocking_sources) or "none"), "inline": True},
        {"name": "VirusTotal", "value": _trim(vt), "inline": True},
        {"name": "Reporter (private)", "value": _trim(reporter_lines(evidence.reporter, today)), "inline": False},
    ]
    if review and not review.error:
        summary = f"**{review.recommendation.replace('_', ' ')}** ({review.confidence})\n{review.site}"
        fields.insert(0, {"name": "AI view", "value": _trim(summary), "inline": False})
    kind = {"block": "Block request", "allow": "False positive"}.get(request.kind, "Issue")
    return {
        "title": _trim(f"#{request.number} {kind}: {evidence.domain}", 250),
        "url": report_url,
        "color": COLOURS.get(request.kind, COLOURS["other"]),
        "fields": fields,
    }


def plain_embed(number: int, title: str, url: str, kind: str, note: str) -> dict:
    return {
        "title": _trim(f"#{number} {title}", 250),
        "url": url,
        "color": COLOURS.get(kind, COLOURS["other"]),
        "description": _trim(note, 2000),
    }


def report_embed(title: str, description: str, url: str, urgent: bool) -> dict:
    return {"title": _trim(title, 250), "url": url, "color": 0xD9534F if urgent else 0x5CB85C, "description": _trim(description, 4000)}
