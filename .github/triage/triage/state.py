import base64
import difflib
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field

STATE_RE = re.compile(r"<!-- triage-state:([A-Za-z0-9+/=]+) -->")


@dataclass
class TriageState:
    domain: str = ""
    body_sha: str = ""
    body: str = ""
    recommendation: str = ""
    confidence: str = ""
    questions: list[str] = field(default_factory=list)
    site: str = ""
    evidence: str = ""
    vt_reputable: int = 0
    seen_comments: list[int] = field(default_factory=list)
    seen_urls: list[str] = field(default_factory=list)
    history: list[str] = field(default_factory=list)

    def to_marker(self) -> str:
        encoded = base64.b64encode(json.dumps(asdict(self)).encode()).decode()
        return f"<!-- triage-state:{encoded} -->"


MAX_STORED_BODY = 8000
WORD_RE = re.compile(r"[\w.:/?=&%-]+")


def normalize_body(body: str) -> str:
    return "\n".join(line.rstrip() for line in (body or "").strip().splitlines())


def body_sha(body: str) -> str:
    return hashlib.sha256(normalize_body(body).encode()).hexdigest()[:16]


def added_words(old: str, new: str) -> list[str]:
    old_words = {word.lower().strip(".,:;") for word in WORD_RE.findall(old)}
    return [word for word in WORD_RE.findall(new) if word.lower().strip(".,:;") not in old_words]


def body_diff(old: str, new: str) -> str:
    lines = difflib.unified_diff(normalize_body(old).splitlines(), normalize_body(new).splitlines(), lineterm="", n=1)
    return "\n".join(list(lines)[2:])[:6000]


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
