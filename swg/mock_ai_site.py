"""Fake "AI chat / file share" site for the lab. Runs on the Ubuntu VM only.

It accepts uploads and prompts and throws them away (nothing is stored), so the
mini SWG has a realistic target without any data leaving the lab. The same
server answers for every *.test name; the page shows which one you reached.

    python3 swg/mock_ai_site.py --bind 127.0.0.1 --port 8000
"""
from __future__ import annotations

import argparse
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{host} (lab mock)</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#222}}
 .banner{{background:#fff3cd;border:1px solid #e0c36a;padding:8px 12px;border-radius:6px;font-size:14px}}
 textarea{{width:100%;height:90px}} section{{margin:24px 0}} #out{{white-space:pre-wrap;background:#f4f4f4;padding:8px}}
</style></head><body>
<h1>{host}</h1>
<p class="banner">PDPA lab mock site. Runs inside the lab, stores nothing. Use synthetic data only.</p>
<section><h2>Ask the AI</h2>
<textarea id="prompt" placeholder="paste text here"></textarea><br>
<button onclick="send()">Send prompt</button></section>
<section><h2>Upload a file</h2>
<form action="/api/upload" method="post" enctype="multipart/form-data">
<input type="file" name="file" required> <button>Upload</button></form></section>
<div id="out"></div>
<script>
async function send(){{
  const r = await fetch('/api/chat',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{model:'lab-mock-1',messages:[{{role:'user',content:document.getElementById('prompt').value}}]}})}});
  document.getElementById('out').textContent = await r.text();
}}
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "LabMock/1.0"

    def _host(self) -> str:
        return html.escape((self.headers.get("Host") or "lab").split(":")[0])

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, PAGE.format(host=self._host()).encode(), "text/html; charset=utf-8")

    def do_POST(self):
        size = int(self.headers.get("Content-Length") or 0)
        remaining = size
        while remaining > 0:                     # read and discard
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)
        if self.path.startswith("/api/upload"):
            body = (f"<p>Received {size} bytes on {self._host()} (discarded).</p>"
                    f"<p><a href='/'>back</a></p>").encode()
            self._send(200, body, "text/html; charset=utf-8")
        else:
            reply = {"model": "lab-mock-1", "received_bytes": size,
                     "reply": "This is a lab mock. Your text was discarded."}
            self._send(200, json.dumps(reply).encode(), "application/json")

    do_PUT = do_POST


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    print(f"lab mock site on http://{args.bind}:{args.port}")
    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
