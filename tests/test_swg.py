import json

from swg.registry import UNCATEGORIZED, Registry
from swg.upload_parser import extract_items

# Generated with the checksum formula; not a real person's number.
VALID = "1101700230708"


def test_registry_matches_exact_and_subdomains():
    reg = Registry.load()
    assert reg.lookup("claude.ai").category == "genai"
    assert reg.lookup("www.claude.ai").name == "Claude"
    assert reg.lookup("notclaude.ai") is UNCATEGORIZED
    assert reg.lookup("CHAT.SHADOW-AI.TEST.").sanctioned is False
    assert reg.lookup("copilot.corp.test").sanctioned is True


def test_specific_entry_beats_parent():
    reg = Registry({"services": [
        {"name": "Google", "domains": ["google.com"], "category": "search", "risk": "low", "score": 1, "sanctioned": True},
        {"name": "Gemini", "domains": ["gemini.google.com"], "category": "genai", "risk": "high", "score": 7, "sanctioned": False},
    ]})
    assert reg.lookup("gemini.google.com").name == "Gemini"
    assert reg.lookup("mail.google.com").name == "Google"


def test_no_decrypt_list():
    reg = Registry.load()
    assert reg.no_decrypt("www.scb.co.th")
    assert not reg.no_decrypt("chat.shadow-ai.test")


def test_multipart_keeps_filename_and_bytes():
    boundary = "XyZ"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"C:\\\\x\\\\ลูกค้า.csv\"\r\n"
        f"Content-Type: text/csv\r\n\r\nid\r\n{VALID}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    items = extract_items(f"multipart/form-data; boundary={boundary}", body)
    files = [i for i in items if i.kind == "file"]
    assert files[0].name == "ลูกค้า.csv"
    assert VALID.encode() in files[0].data
    assert any(i.kind == "text" and i.data == b"hello" for i in items)


def test_json_prompt_is_unescaped():
    body = json.dumps({"messages": [{"content": f"ลูกค้า {VALID}"}]}).encode()  # \u-escaped Thai
    [item] = extract_items("application/json", body)
    assert "ลูกค้า" in item.data.decode("utf-8")
    assert VALID in item.data.decode("utf-8")


def test_raw_and_form_bodies():
    [raw] = extract_items("application/octet-stream", b"abc", "https://x.test/u/report.docx?t=1")
    assert raw.kind == "file" and raw.name == "report.docx"
    [form] = extract_items("application/x-www-form-urlencoded", f"id%0A{VALID}".encode())
    assert VALID in form.data.decode()
