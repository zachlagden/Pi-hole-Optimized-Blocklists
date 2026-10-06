import io
import re
import time
import warnings
from dataclasses import dataclass
from urllib.parse import urldefrag, urlsplit

import httpx

from triage.github_api import GitHub
from triage.issue_form import IssueRequest
from triage.live import RequestBudget, bounded_get, content_outcome, extracted_urls, visible_text

MAX_MATERIALS = 12
MAX_FETCHES = 6
MAX_ISSUES = 3
MAX_IMAGE_BYTES = 4_000_000
MAX_PAGE_BYTES = 256_000
MAX_PIXELS = 12_000_000
MAX_IMAGE_EDGE = 1024
MAX_TEXT = 4000
MAX_INPUT = 100_000


@dataclass
class Material:
    kind: str
    url: str
    source: str
    status: int | None = None
    content_type: str = ""
    text: str = ""
    image: bytes | None = None
    error: str | None = None
    inspected: bool = False
    outcome: str = "mentioned"
    final_url: str = ""
    note: str = "Mentioned in the issue or thread; not independently verified."


def _attachment(url: str) -> bool:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    return (
        host == "user-images.githubusercontent.com"
        or host == "github.com" and parts.path.startswith("/user-attachments/assets/")
        or host == "github.com" and bool(re.fullmatch(r"/[^/]+/[^/]+/assets/[^/]+/.+", parts.path))
    )


def _issue_number(url: str, repository: str) -> int | None:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != "github.com" or parts.username is not None or parts.port is not None:
        return None
    match = re.fullmatch(r"/" + re.escape(repository) + r"/issues/([1-9]\d{0,8})/?", parts.path, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _validated_image(body: bytes) -> bytes:
    from PIL import Image

    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(io.BytesIO(body)) as image:
            if image.width * image.height > MAX_PIXELS or image.width <= 0 or image.height <= 0:
                raise ValueError("image exceeds pixel limit")
            if image.format not in {"PNG", "JPEG", "GIF", "WEBP"}:
                raise ValueError("unsupported image format")
            image.verify()
        with Image.open(io.BytesIO(body)) as image:
            image.seek(0)
            image.thumbnail((MAX_IMAGE_EDGE, MAX_IMAGE_EDGE))
            output = io.BytesIO()
            image.convert("RGB").save(output, format="PNG")
            resized = output.getvalue()
            if len(resized) > MAX_IMAGE_BYTES:
                raise ValueError("resized image exceeds byte limit")
            return resized


def _inspect_link(material: Material, client: httpx.Client, budget: RequestBudget) -> None:
    response = bounded_get(
        client, material.url,
        max_body=MAX_IMAGE_BYTES if material.kind == "attachment" else MAX_PAGE_BYTES,
        max_redirects=3, budget=budget,
    )
    material.status = response.status
    material.final_url = response.chain[-1] if response.chain else ""
    material.content_type = response.headers.get("content-type", "").split(";", 1)[0].lower().strip()
    material.error = response.error
    material.outcome = "unavailable"
    if response.error:
        return
    if response.status is None or not 200 <= response.status < 300:
        material.error = f"HTTP {response.status}; source unavailable to this collector, not evidence that the reported site is offline"
        return
    if material.kind == "attachment":
        if not material.content_type.startswith("image/"):
            material.error = "attachment response is not an image"
            return
        try:
            material.image = _validated_image(response.body)
        except Exception as error:
            material.error = f"image validation failed ({type(error).__name__})"
            return
    else:
        if material.content_type not in {"text/html", "application/xhtml+xml", "text/plain"}:
            material.error = "unsupported corroborating content type"
            return
        material.text = visible_text(response.text, MAX_TEXT)
        if content_outcome(response.status, material.text) != "rendered":
            material.error = "challenge or insufficient usable source content"
            return
    material.inspected = True
    material.outcome = "inspected"
    material.note = "Source content inspected; source claims and reporter descriptions remain unverified."


def _inspect_issue(material: Material, number: int, github: GitHub) -> None:
    material.outcome = "unavailable"
    try:
        issue = github.issue(number)
        if "pull_request" in issue:
            material.error = "reference is a pull request, not an issue"
            return
        material.status = 200
        material.text = (
            f"Referenced issue #{number} ({issue.get('state', 'unknown')}): {str(issue.get('title') or '')[:300]}\n"
            + str(issue.get("body") or "")[:MAX_TEXT - 400]
        )
        material.inspected = True
        material.outcome = "inspected"
        material.note = "Referenced issue content inspected; its claims are unverified and relatedness alone is not evidence for blocking."
    except (httpx.HTTPError, ValueError, KeyError) as error:
        material.status = error.response.status_code if isinstance(error, httpx.HTTPStatusError) else None
        material.error = f"referenced issue unavailable ({type(error).__name__})"


def collect_materials(request: IssueRequest, github: GitHub) -> list[Material]:
    sources = [("issue body", request.body)] + [(f"comment #{comment.id}", comment.body) for comment in request.thread[:20]]
    materials: list[Material] = []
    seen: set[str] = set()
    remaining_input = MAX_INPUT
    for source, raw in sources:
        text = raw[:min(50_000, remaining_input)]
        remaining_input -= len(text)
        urls = extracted_urls(text, MAX_MATERIALS)
        urls += [f"https://github.com/{github.repository}/issues/{number}" for number in re.findall(r"(?<![\w/])#([1-9]\d{0,8})\b", text)[:MAX_ISSUES]]
        for original in urls:
            url = urldefrag(original)[0]
            if url in seen or len(materials) >= MAX_MATERIALS:
                continue
            seen.add(url)
            number = _issue_number(url, github.repository)
            if number == request.number:
                continue
            host = (urlsplit(url).hostname or "").lower()
            same_domain = bool(request.domain and (host == request.domain or host.endswith("." + request.domain)))
            other_issue = host == "github.com" and bool(re.search(r"/issues/\d+", urlsplit(url).path))
            kind = "related_issue" if number else "attachment" if _attachment(url) else "link" if same_domain or other_issue else "corroboration"
            materials.append(Material(kind, url, source))
        if remaining_input <= 0 or len(materials) >= MAX_MATERIALS:
            break
    budget = RequestBudget(remaining=12, deadline=time.monotonic() + 60)
    fetches = issues = 0
    with httpx.Client(timeout=10, follow_redirects=False, trust_env=False, headers={"User-Agent": "issue-triage evidence collector", "Accept": "text/html,text/plain,image/*"}) as client:
        for material in materials:
            if material.kind == "link":
                material.note = "URL mentioned only; reported-domain inspection belongs to separate live probes and other-repository issues are outside this collector."
                continue
            if time.monotonic() >= budget.deadline or budget.remaining <= 0:
                material.error = "collection budget exhausted; not inspected"
                continue
            if material.kind == "related_issue":
                if issues >= MAX_ISSUES:
                    material.error = "issue inspection limit reached"
                    continue
                issues += 1
                budget.remaining -= 1
                _inspect_issue(material, _issue_number(material.url, github.repository) or 0, github)
            elif fetches < MAX_FETCHES:
                fetches += 1
                _inspect_link(material, client, budget)
            else:
                material.error = "link inspection limit reached"
    return materials
