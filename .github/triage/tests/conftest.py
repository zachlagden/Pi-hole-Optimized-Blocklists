import socket
from typing import NoReturn

import httpx
import playwright.async_api
import playwright.sync_api
import pytest
import requests
import tldextract

from triage import domains


def deny_external_call(*args: object, **kwargs: object) -> NoReturn:
    pytest.fail("Unexpected external call; replace it with an explicit offline fake")


@pytest.fixture(autouse=True)
def offline_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    extractor = tldextract.TLDExtract(
        cache_dir=None,
        suffix_list_urls=(),
        include_psl_private_domains=True,
    )

    def bundled_extractor() -> tldextract.TLDExtract:
        return extractor

    monkeypatch.setattr(domains, "_extractor", bundled_extractor)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", deny_external_call)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", deny_external_call)
    monkeypatch.setattr(requests.Session, "request", deny_external_call)
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "create_connection"):
        monkeypatch.setattr(socket, name, deny_external_call)
    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(socket.socket, name, deny_external_call)
    monkeypatch.setattr(playwright.sync_api, "sync_playwright", deny_external_call)
    monkeypatch.setattr(playwright.async_api, "async_playwright", deny_external_call)
