import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from triage.live import DESKTOP_UA, content_outcome, safe_url

if TYPE_CHECKING:
    from playwright.sync_api import ConsoleMessage, Page, Request, Response, Route, WebSocketRoute

MAX_TEXT = 6000
MAX_REQUESTS = 60
MAX_NAVIGATIONS = 8
MAX_TRANSFER = 8_000_000
MAX_RESOURCE = 2_000_000


@dataclass
class Capture:
    png: bytes | None
    text: str
    final_url: str
    error: str | None = None
    status: int | None = None
    outcome: str = "unknown"


@dataclass
class _BrowserBudget:
    deadline: float = field(default_factory=lambda: time.monotonic() + 35)
    requests: int = 0
    navigations: int = 0
    transferred: int = 0
    resources: dict[str, int] = field(default_factory=dict)
    exhausted: str | None = None

    def allow(self, url: str, method: str, navigation: bool) -> str | None:
        self.requests += 1
        self.navigations += int(navigation)
        if self.requests > MAX_REQUESTS or self.navigations > MAX_NAVIGATIONS or time.monotonic() >= self.deadline:
            self.exhausted = self.exhausted or "browser request, navigation or time budget exhausted"
        if self.exhausted:
            return self.exhausted
        if method != "GET" or not safe_url(url):
            return "unsafe browser request aborted"
        if time.monotonic() >= self.deadline:
            self.exhausted = "browser time budget exhausted"
        return self.exhausted

    def receive(self, request_id: str, amount: int) -> str | None:
        self.transferred += max(0, amount)
        self.resources[request_id] = self.resources.get(request_id, 0) + max(0, amount)
        if self.transferred > MAX_TRANSFER or self.resources[request_id] > MAX_RESOURCE or time.monotonic() >= self.deadline:
            self.exhausted = "browser transfer or time budget exhausted"
        return self.exhausted


def _context_request_reason(request: "Request", page: "Page", budget: _BrowserBudget) -> str | None:
    try:
        if request.frame != page.main_frame:
            return "child-frame or worker request blocked by single-page capture boundary"
    except Exception:
        return "unattributed or worker request blocked by single-page capture boundary"
    return budget.allow(request.url, request.method, False)


def _open(page: "Page", domain: str, url: str | None, error_type: type[Exception]) -> "Response | None":
    try:
        return page.goto(url or f"https://{domain}/", wait_until="domcontentloaded", timeout=25_000)
    except error_type as error:
        if not url and page.url == "about:blank" and "net::ERR_" in str(error):
            return page.goto(f"http://{domain}/", wait_until="domcontentloaded", timeout=25_000)
        raise


def _capture_page(page: "Page", status: int | None, error: str | None) -> Capture:
    final_url = page.url
    if not safe_url(final_url):
        return Capture(None, "", "", error or "unsafe final browser URL", status, "failed")
    text = ""
    png = None
    try:
        text = page.inner_text("body", timeout=3000)[:MAX_TEXT]
        png = page.screenshot(full_page=False, timeout=3000)
    except Exception as capture_error:
        error = error or f"partial capture ({type(capture_error).__name__})"
    outcome = content_outcome(status, text)
    if error and outcome == "rendered":
        outcome = "partial"
    elif error and outcome != "challenge" and not text:
        outcome = "failed"
    return Capture(png, text, final_url, error, status, outcome)


def capture(domain: str, url: str | None = None) -> Capture:
    try:
        from playwright.sync_api import Error, sync_playwright
    except ImportError:
        return Capture(None, "", "", "playwright is not installed", outcome="failed")
    if not safe_url(url or f"https://{domain}/"):
        return Capture(None, "", "", "unsafe or non-public browser destination", outcome="failed")
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = browser.new_context(
                viewport={"width": 1280, "height": 900},
                locale="en-GB",
                user_agent=DESKTOP_UA,
                ignore_https_errors=True,
                accept_downloads=False,
                service_workers="block",
            )
            page = context.new_page()
            budget = _BrowserBudget()
            status: int | None = None
            failure: str | None = None

            def stop(reason: str) -> None:
                nonlocal failure
                failure = failure or reason
                budget.exhausted = reason
                try:
                    page.evaluate("window.stop()")
                except Error:
                    pass

            context.add_init_script("""
                for (const name of ['Worker', 'SharedWorker']) {
                    Object.defineProperty(globalThis, name, {
                        value: function() {
                            console.warn('issue-triage: worker blocked');
                            throw new Error('Workers disabled for bounded evidence collection');
                        }, writable: false, configurable: false
                    });
                }
            """)
            session = context.new_cdp_session(page)
            main_frame_id = session.send("Page.getFrameTree")["frameTree"]["frame"]["id"]

            def context_guard(route: "Route") -> None:
                nonlocal failure
                reason = _context_request_reason(route.request, page, budget)
                if reason:
                    failure = failure or reason
                    route.abort()
                else:
                    route.continue_()

            def close_extra_page(extra: "Page") -> None:
                nonlocal failure
                if extra != page:
                    failure = failure or "unexpected page blocked by single-page capture boundary"
                    extra.close()

            def console_seen(message: "ConsoleMessage") -> None:
                nonlocal failure
                if message.text == "issue-triage: worker blocked":
                    failure = failure or "worker creation blocked by single-page capture boundary"

            def guard(event: dict[str, Any]) -> None:
                nonlocal failure
                request = event.get("request", {})
                reason = (
                    "child target blocked by single-page capture boundary"
                    if event.get("frameId") != main_frame_id
                    else budget.allow(str(request.get("url", "")), str(request.get("method", "")), event.get("resourceType") == "Document")
                )
                if reason:
                    failure = failure or reason
                    session.send("Fetch.failRequest", {"requestId": event["requestId"], "errorReason": "BlockedByClient"})
                else:
                    session.send("Fetch.continueRequest", {"requestId": event["requestId"]})

            def reject_websocket(route: "WebSocketRoute") -> None:
                route.close()

            def response_seen(response: "Response") -> None:
                nonlocal status
                if response.request.is_navigation_request() and response.frame == page.main_frame:
                    status = response.status
                length = response.headers.get("content-length", "")
                if length.isdigit() and int(length) > MAX_RESOURCE:
                    stop("browser resource exceeds byte budget")

            def data_received(event: dict[str, Any]) -> None:
                amount = event.get("dataLength", 0)
                reason = budget.receive(str(event.get("requestId", "")), int(amount) if isinstance(amount, (int, float)) else 0)
                if reason:
                    stop(reason)

            context.route("**/*", context_guard)
            context.on("page", close_extra_page)
            context.route_web_socket("**/*", reject_websocket)
            page.on("console", console_seen)
            page.on("response", response_seen)
            session.send("Network.enable")
            session.on("Network.dataReceived", data_received)
            session.on("Fetch.requestPaused", guard)
            session.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]})
            try:
                _open(page, domain, url, Error)
                page.wait_for_timeout(1500)
            except Error as error:
                failure = failure or str(error).splitlines()[0][:200]
            result = _capture_page(page, status, failure)
            browser.close()
            return result
    except Error as error:
        return Capture(None, "", "", str(error).splitlines()[0][:200], outcome="failed")
