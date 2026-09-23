import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field

STATE_RE = re.compile(r"<!-- triage-state:([A-Za-z0-9+/=]+) -->")


@dataclass
class TriageState:
    domain: str = ""
    body_sha: str = ""
    recommendation: str = ""
    confidence: str = ""
    questions: list[str] = field(default_factory=list)
    seen_comments: list[int] = field(default_factory=list)
    seen_urls: list[str] = field(default_factory=list)
    history: list[str] = field(default_factory=list)

    def to_marker(self) -> str:
        encoded = base64.b64encode(json.dumps(asdict(self)).encode()).decode()
        return f"<!-- triage-state:{encoded} -->"


def body_sha(body: str) -> str:
    normalized = "\n".join(line.rstrip() for line in (body or "").strip().splitlines())
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def parse_state(comment_body: str | None) -> TriageState | None:
    match = STATE_RE.search(comment_body or "")
    if not match:
        return None
    try:
        data = json.loads(base64.b64decode(match.group(1)))
    except (ValueError, json.JSONDecodeError):
        return None
    known = {key: data[key] for key in TriageState.__dataclass_fields__ if key in data}
    return TriageState(**known)
