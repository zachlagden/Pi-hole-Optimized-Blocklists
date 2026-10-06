import time
from collections.abc import Iterator
from datetime import date
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from playwright.sync_api import Error, Page, Request
from pytest import MonkeyPatch

from triage import live, reputation, screenshot


@pytest.mark.parametrize("text", ["**https://example.com/evidence**", "[evidence](https://example.com/evidence)", "<https://example.com/evidence>"])
def test_markdown_url_delimiters_are_not_path_suffixes(text: str) -> None:
    assert live.quoted_urls(text, "example.com") == ["https://example.com/evidence"]


def test_blob_urls_are_not_network_urls() -> None:
    assert live.quoted_urls("blob:https://example.com/image https://example.com/evidence", "example.com") == ["https://example.com/evidence"]
    assert live.extracted_urls("blob:https://example.com/image") == []
    assert live.extracted_urls("javascript:https://example.com/image") == []


def probe(status: int, title: str, host: str = "example.com", size: int = 100) -> live.Fetch:
    return live.Fetch("desktop", chain=[f"https://{host}/"], status=status, title=title, size=size, excerpt="Acme offers a fictional useful page with ordinary source content.")


@pytest.mark.parametrize("status,title", [(403, "Forbidden"), (403, "Access denied"), (403, "Suspected Phishing"), (200, "Just a moment"), (503, "Temporary error")])
def test_challenges_and_errors_are_not_cloaking(status: int, title: str) -> None:
    fetches = [probe(200, "Acme site"), probe(status, title, "other.example", 1000)]
    assert live.cloaking_summary(fetches) is None and live.cloaking_outcome(fetches) == "insufficient"


def test_matching_different_and_insufficient_are_distinct() -> None:
    matching = [probe(200, "Acme site"), probe(200, "Acme site")]
    assert live.cloaking_outcome(matching) == "matching" and live.cloaking_summary(matching) is None
    assert live.cloaking_outcome([live.Fetch("desktop", status=200), live.Fetch("mobile", status=200)]) == "insufficient"
    different = matching + [probe(200, "Other page", "other.example")]
    assert live.cloaking_outcome(different) == "different" and "different final hosts" in (live.cloaking_summary(different) or "")


def test_live_fetch_streams_bounded_input_and_rejects_redirects(monkeypatch: MonkeyPatch) -> None:
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        return httpx.Response(302, headers={"location": "http://127.0.0.1/private"})

    monkeypatch.setattr(live, "is_public_host", lambda host: host == "example.com")
    original = httpx.Client
    monkeypatch.setattr(live.httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handler)))
    result = live.fetch_url("https://example.com/path", "desktop")
    assert calls == ["https://example.com/path"] and result.outcome == "failed"
    assert result.error == "unsafe or non-public destination"


def test_time_budget_makes_no_request(monkeypatch: MonkeyPatch) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError("exhausted collection must not request")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = live.bounded_get(client, "https://example.com", budget=live.RequestBudget(deadline=time.monotonic() - 1))
    assert result.error == "request budget exhausted"


class SmallChunkStream(httpx.SyncByteStream):
    def __init__(self, clock: list[float], advance: float) -> None:
        self.clock = clock
        self.advance = advance
        self.received = 0
        self.exhausted = False
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        for _ in range(100):
            self.clock[0] += self.advance
            self.received += 1
            yield b"x"
        self.exhausted = True

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize("advance,max_body", [(1.0, 1000), (0.0, 2)])
def test_small_transport_chunks_enforce_deadline_and_body_budget_before_exhaustion(
    monkeypatch: MonkeyPatch, advance: float, max_body: int,
) -> None:
    clock = [0.0]
    stream = SmallChunkStream(clock, advance)
    monkeypatch.setattr(live.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(live, "safe_url", lambda url: True)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Accept-Encoding"] == "identity"
        assert request.extensions["timeout"]["read"] == 3.0
        return httpx.Response(200, headers={"content-encoding": "identity"}, stream=stream)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = live.bounded_get(client, "https://example.com/drip", max_body=max_body,
                                  budget=live.RequestBudget(deadline=3.0))
    assert result.error == "response exceeds byte or time limit" and not result.body
    assert stream.received == 3 and not stream.exhausted and stream.closed
    if advance:
        assert clock[0] == 3.0


class FakePage:
    url = "https://example.com/path"
    main_frame = "main"

    def __init__(self, text: str, screenshot_error: bool = False) -> None:
        self.text = text
        self.screenshot_error = screenshot_error

    def inner_text(self, selector: str, timeout: int) -> str:
        return self.text

    def screenshot(self, full_page: bool, timeout: int) -> bytes:
        if self.screenshot_error:
            raise RuntimeError("fictional safe timeout")
        return b"fictional screenshot"


@pytest.mark.parametrize("status,text,error,outcome", [(200, "Acme page with useful rendered content for this fictional example.", None, "rendered"), (200, "Acme page with useful rendered content for this fictional example.", "TimeoutError", "partial"), (403, "Forbidden", None, "http_error"), (403, "Verify you are human. Please solve the CAPTCHA.", None, "challenge"), (200, "", "TimeoutError", "failed")])
def test_browser_http_status_and_outcome(monkeypatch: MonkeyPatch, status: int, text: str, error: str | None, outcome: str) -> None:
    monkeypatch.setattr(screenshot, "safe_url", lambda url: True)
    result = screenshot._capture_page(cast(Page, FakePage(text)), status, error)
    assert result.status == status and result.outcome == outcome and result.final_url == "https://example.com/path"
    assert result.text == text


def test_browser_preserves_text_if_screenshot_fails(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(screenshot, "safe_url", lambda url: True)
    result = screenshot._capture_page(cast(Page, FakePage("Acme page with useful partial content for this fictional example.", True)), 200, None)
    assert result.png is None and result.text and result.outcome == "partial" and result.error
    assert screenshot.Capture(None, "", "", "old positional error").status is None


def test_browser_does_not_expose_private_final_content(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(screenshot, "safe_url", lambda url: False)
    result = screenshot._capture_page(cast(Page, FakePage("private content")), 200, None)
    assert not result.text and result.png is None and result.outcome == "failed"


def test_registration_date_is_not_analysis_date(monkeypatch: MonkeyPatch) -> None:
    response = httpx.Response(200, json={"data": {"attributes": {"creation_date": 1735689600, "last_analysis_date": 1748736000, "last_analysis_stats": {"harmless": 3}}}})
    monkeypatch.setattr(reputation, "_virustotal_get", lambda domain, key: response)
    result = reputation.virustotal("example.com", "fictional-unused-key")
    assert result.created == date(2025, 1, 1) and result.last_analysis == date(2025, 6, 1)
    assert reputation._to_date(10 ** 100) is None
    assert reputation._to_date(0) == date(1970, 1, 1)


def test_rdap_dates_remain_explicit_and_malformed_data_is_unknown(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(reputation, "bounded_get", lambda *args, **kwargs: live.BoundedResponse(status=200, body=b'{"events":[{"eventAction":"registration","eventDate":"2025-02-03T00:00:00Z"}]}'))
    result = reputation.registration("example.com")
    assert result.created == date(2025, 2, 3) and not result.error
    monkeypatch.setattr(reputation, "bounded_get", lambda *args, **kwargs: live.BoundedResponse(status=200, body=b'{"events":[{"eventAction":"registration","eventDate":"invalid"}]}'))
    result = reputation.registration("example.com")
    assert result.created is None and result.error and "unknown" in result.error


def test_rdap_403_does_not_infer_offline(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(reputation, "bounded_get", lambda *args, **kwargs: live.BoundedResponse(status=403))
    result = reputation.registration("example.com")
    assert result.created is None and result.error == "RDAP HTTP 403"


@pytest.mark.parametrize("url,method", [("http://127.0.0.1/private", "GET"), ("https://Alex:Sam@example.com/path", "GET"), ("blob:https://example.com/image", "GET"), ("https://example.com/payment", "POST")])
def test_browser_redirect_and_method_guards(monkeypatch: MonkeyPatch, url: str, method: str) -> None:
    monkeypatch.setattr(screenshot, "safe_url", lambda candidate: candidate.startswith("https://example.com/"))
    budget = screenshot._BrowserBudget()
    assert budget.allow("https://example.com/path", "GET", True) is None
    assert budget.allow(url, method, True) == "unsafe browser request aborted"


def test_browser_request_navigation_transfer_and_elapsed_budgets(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(screenshot, "safe_url", lambda url: True)
    budget = screenshot._BrowserBudget(requests=screenshot.MAX_REQUESTS)
    assert budget.allow("https://example.com/path", "GET", False)
    budget = screenshot._BrowserBudget(navigations=screenshot.MAX_NAVIGATIONS)
    assert budget.allow("https://example.com/path", "GET", True)
    budget = screenshot._BrowserBudget(deadline=time.monotonic() - 1)
    assert budget.allow("https://example.com/path", "GET", False)
    budget = screenshot._BrowserBudget()
    assert budget.receive("example-resource", screenshot.MAX_RESOURCE + 1)
    assert budget.allow("https://example.com/path", "GET", False)
    budget = screenshot._BrowserBudget(transferred=screenshot.MAX_TRANSFER)
    assert budget.receive("example-resource", 1)


def test_child_frame_popup_and_worker_requests_are_denied(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(screenshot, "safe_url", lambda url: True)
    page = cast(Page, FakePage("example"))
    request = SimpleNamespace(url="https://example.com/resource", method="GET", frame="main")
    budget = screenshot._BrowserBudget()
    assert screenshot._context_request_reason(cast(Request, request), page, budget) is None
    request.frame = "child-or-popup"
    assert "single-page" in (screenshot._context_request_reason(cast(Request, request), page, budget) or "")

    class WorkerRequest:
        @property
        def frame(self) -> str:
            raise Error("worker has no frame")

    assert "worker" in (screenshot._context_request_reason(cast(Request, WorkerRequest()), page, budget) or "")


class FakeBrowserPage(FakePage):
    def __init__(self) -> None:
        super().__init__("Acme page with usable rendered content for a fictional partial capture.")
        self.handlers: dict[str, Any] = {}

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


class FakeSession:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler

    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append((method, params))
        return {"frameTree": {"frame": {"id": "main"}}}


class FakeContext:
    def __init__(self) -> None:
        self.page = FakeBrowserPage()
        self.session = FakeSession()
        self.worker_script = ""

    def new_page(self) -> FakeBrowserPage:
        return self.page

    def new_cdp_session(self, page: Page) -> FakeSession:
        return self.session

    def add_init_script(self, script: str) -> None:
        self.worker_script = script

    def route(self, pattern: str, handler: Any) -> None:
        self.route_handler = handler

    def route_web_socket(self, pattern: str, handler: Any) -> None:
        self.websocket_handler = handler

    def on(self, event: str, handler: Any) -> None:
        self.extra_page_handler = handler


class FakeBrowser:
    def __init__(self) -> None:
        self.context = FakeContext()
        self.closed = False

    def new_context(self, **kwargs: Any) -> FakeContext:
        assert kwargs["service_workers"] == "block" and not kwargs["accept_downloads"]
        return self.context

    def close(self) -> None:
        self.closed = True


class FakePlaywright:
    def __init__(self, browser: FakeBrowser) -> None:
        self.chromium = SimpleNamespace(launch=lambda: browser)

    def __enter__(self) -> "FakePlaywright":
        return self

    def __exit__(self, *args: Any) -> None:
        pass


def test_native_browser_capture_preserves_safe_timeout_and_checks_redirects(monkeypatch: MonkeyPatch) -> None:
    import playwright.sync_api

    browser = FakeBrowser()
    monkeypatch.setattr(playwright.sync_api, "sync_playwright", lambda: FakePlaywright(browser))
    monkeypatch.setattr(screenshot, "safe_url", lambda url: url.startswith("https://example.com/"))

    def open_page(page: Page, domain: str, url: str | None, error_type: type[Exception]) -> None:
        session = browser.context.session
        for request_id, destination in [("first", "https://example.com/path"), ("redirect", "http://127.0.0.1/private")]:
            session.handlers["Fetch.requestPaused"]({"requestId": request_id, "frameId": "main", "resourceType": "Document", "request": {"url": destination, "method": "GET"}})
        browser.context.page.handlers["response"](SimpleNamespace(request=SimpleNamespace(is_navigation_request=lambda: True), frame="main", status=200, headers={}))
        raise Error("fictional safe navigation timeout")

    monkeypatch.setattr(screenshot, "_open", open_page)
    result = screenshot.capture("example.com", "https://example.com/path")
    assert result.status == 200 and result.outcome == "partial" and result.text and result.png
    assert browser.closed and "SharedWorker" in browser.context.worker_script
    assert ("Fetch.continueRequest", {"requestId": "first"}) in browser.context.session.calls
    assert ("Fetch.failRequest", {"requestId": "redirect", "errorReason": "BlockedByClient"}) in browser.context.session.calls


def test_compressed_response_is_rejected_before_decoding(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(live, "is_public_host", lambda host: True)
    with httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=httpx.ByteStream(b"not a compressed stream")))) as client:
        result = live.bounded_get(client, "https://example.com/path")
    assert result.error == "encoded response not accepted within byte budget" and not result.body


def test_private_resolution_and_mixed_addresses_are_rejected(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(live, "resolve", lambda host: ["127.0.0.1", "::1"])
    assert not live.is_public_host("example.com")
    monkeypatch.setattr(live, "resolve", lambda host: ["10.0.0.1"])
    assert not live.is_public_host("example.com")
