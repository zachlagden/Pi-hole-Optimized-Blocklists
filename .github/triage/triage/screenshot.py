from dataclasses import dataclass
from urllib.parse import urlsplit

from triage.live import is_public_host

MAX_TEXT = 6000


@dataclass
class Capture:
    png: bytes | None
    text: str
    final_url: str
    error: str | None = None


def _open(page, domain: str, error_type: type[Exception]) -> None:
    try:
        page.goto(f"https://{domain}/", wait_until="load", timeout=30_000)
    except error_type:
        page.goto(f"http://{domain}/", wait_until="load", timeout=30_000)


def capture(domain: str) -> Capture:
    try:
        from playwright.sync_api import Error, sync_playwright
    except ImportError:
        return Capture(None, "", "", "playwright is not installed")
    checked: dict[str, bool] = {}

    def guard(route):
        host = urlsplit(route.request.url).hostname or ""
        if host not in checked:
            checked[host] = is_public_host(host)
        return route.continue_() if checked[host] else route.abort()

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = browser.new_context(
                viewport={"width": 1280, "height": 900},
                ignore_https_errors=True,
                accept_downloads=False,
                service_workers="block",
            )
            context.route("**/*", guard)
            page = context.new_page()
            _open(page, domain, Error)
            page.wait_for_timeout(2500)
            png = page.screenshot(full_page=False)
            text = page.inner_text("body")[:MAX_TEXT]
            final_url = page.url
            browser.close()
            return Capture(png, text, final_url)
    except Error as error:
        return Capture(None, "", "", str(error).splitlines()[0][:200])
