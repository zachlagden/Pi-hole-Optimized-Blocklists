import httpx
from pytest import MonkeyPatch

from triage import live
from triage.decoding import decode_page, page_charset

RUSSIAN_TITLE = "Новости футбола России"
RUSSIAN_TEXT = (
    "Последние новости российского футбола, результаты матчей, таблицы чемпионата и трансферы. "
    "Сборная России провела тренировку перед матчем, а клубы готовятся к следующему туру."
)
CHINESE_TITLE = "浙江日康婴童用品有限公司"
CHINESE_TEXT = "日康奶瓶、奶嘴、水杯、餐具和洗护用品。公司专注于婴童用品的研发、生产和销售，产品通过多项安全认证。"


def russian_page(head: str = "") -> bytes:
    return f"<html><head>{head}<title>{RUSSIAN_TITLE}</title></head><body><p>{RUSSIAN_TEXT}</p></body></html>".encode("cp1251")


def chinese_page(head: str = "") -> bytes:
    return f"<html><head>{head}<title>{CHINESE_TITLE}</title></head><body><p>{CHINESE_TEXT}</p></body></html>".encode("gbk")


def test_header_charset_decodes_cp1251():
    page = russian_page()
    assert page_charset(page, "windows-1251") == "cp1251"
    assert live._title(decode_page(page, "windows-1251")) == RUSSIAN_TITLE


def test_meta_charset_decodes_gbk():
    page = chinese_page('<meta charset="gb2312">')
    assert page_charset(page) == "gb18030"
    assert live._title(page) == CHINESE_TITLE


def test_meta_http_equiv_decodes_cp1251():
    page = russian_page('<meta http-equiv="Content-Type" content="text/html; charset=windows-1251">')
    assert live.visible_text(page).startswith(RUSSIAN_TITLE)


def test_header_wins_over_meta():
    page = russian_page('<meta charset="utf-8">')
    assert live._title(decode_page(page, "windows-1251")) == RUSSIAN_TITLE


def test_undeclared_pages_are_detected():
    assert RUSSIAN_TEXT in live.visible_text(russian_page())
    assert CHINESE_TEXT in live.visible_text(chinese_page())


def test_utf8_stays_utf8_and_bad_bytes_are_replaced():
    assert decode_page("Café 日本".encode()) == "Café 日本"
    assert decode_page(b"\xef\xbb\xbfplain") == "plain"
    assert decode_page(b"abc\xff", "utf-8") == "abc�"


def test_unknown_declared_charset_falls_through():
    assert live._title(decode_page(chinese_page(), "not-a-charset")) == CHINESE_TITLE


def test_fetch_url_uses_the_response_charset(monkeypatch: MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(russian_page()), headers={"Content-Type": "text/html; charset=windows-1251"})

    real_client = httpx.Client
    monkeypatch.setattr(live, "is_public_host", lambda host: True)
    monkeypatch.setattr(live.httpx, "Client", lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))
    fetch = live.fetch_url("https://news.example/", "desktop")
    assert fetch.title == RUSSIAN_TITLE
    assert RUSSIAN_TEXT in fetch.excerpt
