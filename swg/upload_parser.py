"""Pull uploaded files and pasted text out of an HTTP request body.

No mitmproxy import here, so it can be unit-tested on its own.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from urllib.parse import unquote, unquote_plus, urlparse


@dataclass
class Item:
    kind: str        # "file" or "text"
    name: str        # file name, or a label such as "(json body)"
    data: bytes


def _json_strings(value, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _json_strings(v, out)
    elif isinstance(value, list):
        for v in value:
            _json_strings(v, out)


def _multipart(content_type: str, body: bytes) -> list[Item]:
    head = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode()
    msg = BytesParser(policy=policy.default).parsebytes(head + body)
    items: list[Item] = []
    if not msg.is_multipart():
        return items
    for part in msg.iter_parts():
        payload = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename:
            items.append(Item("file", filename.replace("\\", "/").split("/")[-1], payload))
        elif payload.strip():
            field = part.get_param("name", header="content-disposition") or "field"
            items.append(Item("text", f"(form field {field})", payload))
    return items


def extract_items(content_type: str, body: bytes, url: str = "") -> list[Item]:
    """Return the files and text found in a request body."""
    if not body:
        return []
    ct = (content_type or "").lower()

    if ct.startswith("multipart/form-data"):
        return _multipart(content_type, body)

    if "json" in ct:
        try:
            strings: list[str] = []
            _json_strings(json.loads(body.decode("utf-8", errors="replace")), strings)
            text = "\n".join(strings)
        except ValueError:
            text = body.decode("utf-8", errors="replace")
        return [Item("text", "(json body)", text.encode("utf-8"))] if text.strip() else []

    if ct.startswith("application/x-www-form-urlencoded"):
        # Decode the whole body rather than parse pairs: tools such as
        # curl --data-binary send raw files with this content type.
        text = unquote_plus(body.decode("utf-8", errors="replace")).replace("&", "\n")
        return [Item("text", "(form body)", text.encode("utf-8"))] if text.strip() else []

    if ct.startswith("text/"):
        return [Item("text", "(text body)", body)]

    # Raw upload (PUT or POST of the file bytes, e.g. application/octet-stream).
    name = unquote(urlparse(url).path.rstrip("/").split("/")[-1]) or "upload.bin"
    if not re.search(r"\.[A-Za-z0-9]{1,5}$", name):
        name += ".bin"
    return [Item("file", name, body)]
