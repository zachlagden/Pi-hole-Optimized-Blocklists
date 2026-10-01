import codecs
import re

import charset_normalizer

META_SCAN_BYTES = 4096
DETECT_BYTES = 200_000
META_CHARSET_RE = re.compile(rb"""<meta[^>]*?charset\s*=\s*["']?\s*([A-Za-z0-9_.:-]+)""", re.IGNORECASE)
BOMS = [(codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16")]
ALIASES = {
    "gb2312": "gb18030",
    "gbk": "gb18030",
    "x-gbk": "gb18030",
    "iso-8859-1": "cp1252",
    "latin1": "cp1252",
    "latin-1": "cp1252",
    "us-ascii": "cp1252",
    "ascii": "cp1252",
}


def codec_name(label: str | None) -> str | None:
    if not label:
        return None
    name = label.strip().strip("\"'").lower()
    try:
        return codecs.lookup(ALIASES.get(name, name)).name
    except LookupError:
        return None


def _from_bom(body: bytes) -> str | None:
    return next((name for bom, name in BOMS if body.startswith(bom)), None)


def _from_meta(body: bytes) -> str | None:
    match = META_CHARSET_RE.search(body[:META_SCAN_BYTES])
    if not match:
        return None
    name = codec_name(match.group(1).decode("ascii", errors="replace"))
    return "utf-8" if name and name.startswith("utf-16") else name


def _is_utf8(sample: bytes) -> bool:
    try:
        codecs.getincrementaldecoder("utf-8")().decode(sample, final=False)
    except UnicodeDecodeError:
        return False
    return True


def _detected(body: bytes) -> str | None:
    sample = body[:DETECT_BYTES]
    if _is_utf8(sample):
        return "utf-8"
    best = charset_normalizer.from_bytes(sample).best()
    return codec_name(best.encoding) if best else None


def page_charset(body: bytes, declared: str | None = None) -> str:
    return _from_bom(body) or codec_name(declared) or _from_meta(body) or _detected(body) or "utf-8"


def decode_page(body: bytes, declared: str | None = None) -> str:
    return body.decode(page_charset(body, declared), errors="replace")
