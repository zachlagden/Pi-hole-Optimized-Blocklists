import io
from collections.abc import Callable
from typing import cast

import httpx
import pytest
from PIL import Image
from pytest import MonkeyPatch

from triage import live, materials
from triage.evidence import Evidence
from triage.github_api import GitHub, ThreadComment
from triage.issue_form import IssueRequest

HTTPX_CLIENT = httpx.Client


class FakeGitHub:
    repository = "Acme/example"

    def __init__(self) -> None:
        self.calls: list[int] = []

    def issue(self, number: int) -> dict[str, object]:
        self.calls.append(number)
        return {"title": "Alex reported a related concern", "body": "Sam mentions example.com and #99; claims remain unverified.", "state": "closed"}


def request(body: str, thread: list[ThreadComment] | None = None) -> IssueRequest:
    return IssueRequest(1, "block", "Example", "Alex", body, "example.com", "example.com", thread=thread or [])


def fake_network(monkeypatch: MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> list[str]:
    calls: list[str] = []
    def dispatch(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        response = handler(req)
        if response.is_stream_consumed:
            return httpx.Response(response.status_code, headers=response.headers,
                                  stream=httpx.ByteStream(response.content))
        return response

    def client(**kwargs: object) -> httpx.Client:
        return HTTPX_CLIENT(transport=httpx.MockTransport(dispatch))

    monkeypatch.setattr(materials.httpx, "Client", client)
    monkeypatch.setattr(live, "is_public_host", lambda host: host in {"github.com", "user-images.githubusercontent.com", "evidence.example", "cdn.example", "example.com"})
    return calls


def png(width: int = 1800, height: int = 900) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (width, height), "white").save(output, "PNG")
    return output.getvalue()


def test_attachment_is_validated_resized_and_deduplicated(monkeypatch: MonkeyPatch) -> None:
    calls = fake_network(monkeypatch, lambda req: httpx.Response(200, headers={"content-type": "image/png"}, content=png()))
    url = "https://github.com/user-attachments/assets/example-image"
    req = request(f"![Reporter describes a scam]({url})", [ThreadComment(2, "Sam", "someone else", url + "#duplicate")])
    result = materials.collect_materials(req, cast(GitHub, FakeGitHub()))
    assert len(calls) == len(result) == 1
    image = result[0]
    assert image.kind == "attachment" and image.inspected and image.outcome == "inspected"
    assert image.source == "issue body" and "unverified" in image.note
    assert image.image is not None
    with Image.open(io.BytesIO(image.image)) as decoded:
        assert decoded.size == (1024, 512)
    assert Evidence(req, "example.com", "example.com").materials == []


@pytest.mark.parametrize("body,content_type", [(b"not an image", "image/png"), (b"<svg>example</svg>", "image/svg+xml"), (b"a page instead", "text/html")])
def test_invalid_images_fail_safely(monkeypatch: MonkeyPatch, body: bytes, content_type: str) -> None:
    fake_network(monkeypatch, lambda req: httpx.Response(200, headers={"content-type": content_type}, content=body))
    result = materials.collect_materials(request("https://user-images.githubusercontent.com/example.png"), cast(GitHub, FakeGitHub()))[0]
    assert not result.inspected and result.image is None and result.error and result.outcome == "unavailable"


def test_pixel_limit_fails_safely(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(materials, "MAX_PIXELS", 100)
    fake_network(monkeypatch, lambda req: httpx.Response(200, headers={"content-type": "image/png"}, content=png(11, 10)))
    result = materials.collect_materials(request("https://user-images.githubusercontent.com/example.png"), cast(GitHub, FakeGitHub()))[0]
    assert not result.inspected and result.error and result.image is None


def test_pillow_decompression_failure_is_unavailable(monkeypatch: MonkeyPatch) -> None:
    def bomb(body: bytes) -> bytes:
        raise Image.DecompressionBombError("fictional oversized image")

    monkeypatch.setattr(materials, "_validated_image", bomb)
    fake_network(monkeypatch, lambda req: httpx.Response(200, headers={"content-type": "image/png"}, content=b"example"))
    result = materials.collect_materials(request("https://user-images.githubusercontent.com/example.png"), cast(GitHub, FakeGitHub()))[0]
    assert result.error and "DecompressionBombError" in result.error and not result.inspected


@pytest.mark.parametrize("destination", ["http://127.0.0.1/private", "http://[::1]/private", "https://Alex:Sam@evidence.example/private", "file:///etc/example", "ftp://evidence.example/file", "https://evidence.example:8443/private"])
def test_unsafe_redirect_is_never_requested(monkeypatch: MonkeyPatch, destination: str) -> None:
    calls = fake_network(monkeypatch, lambda req: httpx.Response(302, headers={"location": destination}))
    result = materials.collect_materials(request("https://evidence.example/report"), cast(GitHub, FakeGitHub()))[0]
    assert calls == ["https://evidence.example/report"]
    assert not result.inspected and result.error == "unsafe or non-public destination"


def test_initial_credentials_and_private_hosts_are_rejected(monkeypatch: MonkeyPatch) -> None:
    calls = fake_network(monkeypatch, lambda req: httpx.Response(200, text="should never be requested"))
    results = materials.collect_materials(request("https://Alex:Sam@evidence.example/report https://127.0.0.1/private"), cast(GitHub, FakeGitHub()))
    assert calls == [] and len(results) == 2
    assert all(item.error == "unsafe or non-public destination" for item in results)


def test_public_redirect_and_text_limit(monkeypatch: MonkeyPatch) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "evidence.example":
            return httpx.Response(302, headers={"location": "https://cdn.example/report"})
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<title>Acme public evidence</title><p>" + "Source claim, not verified. " * 500 + "</p>")

    calls = fake_network(monkeypatch, handler)
    result = materials.collect_materials(request("https://evidence.example/report"), cast(GitHub, FakeGitHub()))[0]
    assert len(calls) == 2 and result.inspected and len(result.text) == materials.MAX_TEXT
    assert result.final_url == "https://cdn.example/report" and "unverified" in result.note


@pytest.mark.parametrize("declared", [True, False])
def test_oversized_download_is_not_inspected(monkeypatch: MonkeyPatch, declared: bool) -> None:
    monkeypatch.setattr(materials, "MAX_PAGE_BYTES", 32)
    fake_network(monkeypatch, lambda req: httpx.Response(200, headers={"content-type": "text/plain", **({"content-length": "1000"} if declared else {"content-length": "invalid"})}, content=b"x" * 1000))
    result = materials.collect_materials(request("https://evidence.example/report"), cast(GitHub, FakeGitHub()))[0]
    assert not result.inspected and result.error and "limit" in result.error and not result.text


def test_403_and_challenges_do_not_verify_claims_or_imply_site_offline(monkeypatch: MonkeyPatch) -> None:
    fake_network(monkeypatch, lambda req: httpx.Response(403, headers={"content-type": "text/html"}, text="Access denied"))
    result = materials.collect_materials(request("https://evidence.example/report"), cast(GitHub, FakeGitHub()))[0]
    assert result.status == 403 and not result.inspected and result.error
    assert "not evidence that the reported site is offline" in result.error
    fake_network(monkeypatch, lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text="Verify you are human. " * 5))
    result = materials.collect_materials(request("https://evidence.example/report"), cast(GitHub, FakeGitHub()))[0]
    assert not result.inspected and "challenge" in (result.error or "")


def test_direct_issue_references_only_and_no_duplicate_live_probe(monkeypatch: MonkeyPatch) -> None:
    calls = fake_network(monkeypatch, lambda req: httpx.Response(200))
    github = FakeGitHub()
    results = materials.collect_materials(request("See #2 and https://github.com/Acme/example/issues/2#note and https://github.com/Acme/other/issues/3. https://example.com/path"), cast(GitHub, github))
    assert github.calls == [2] and calls == []
    assert results[0].kind == "related_issue" and results[0].inspected
    assert "relatedness alone is not evidence for blocking" in results[0].note
    assert all(item.outcome == "mentioned" for item in results[1:])
    assert not any(item.url.endswith("/99") for item in results)


def test_request_and_input_budgets_are_bounded(monkeypatch: MonkeyPatch) -> None:
    calls = fake_network(monkeypatch, lambda req: httpx.Response(302, headers={"location": str(req.url) + "/again"}))
    body = " ".join(f"https://evidence.example/{i}" for i in range(30)) + "x" * materials.MAX_INPUT
    results = materials.collect_materials(request(body), cast(GitHub, FakeGitHub()))
    assert len(results) == materials.MAX_MATERIALS and len(calls) == 12
    assert all(not item.inspected for item in results)


def test_unsupported_download_and_timeouts_are_unavailable(monkeypatch: MonkeyPatch) -> None:
    def timeout(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("fictional timeout")

    fake_network(monkeypatch, timeout)
    result = materials.collect_materials(request("https://evidence.example/report"), cast(GitHub, FakeGitHub()))[0]
    assert result.error == "ReadTimeout" and not result.inspected
    fake_network(monkeypatch, lambda req: httpx.Response(200, headers={"content-type": "application/octet-stream"}, content=b"example"))
    result = materials.collect_materials(request("https://evidence.example/report"), cast(GitHub, FakeGitHub()))[0]
    assert result.error == "unsupported corroborating content type"
