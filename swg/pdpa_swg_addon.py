"""mitmproxy addon: a mini Secure Web Gateway for the PDPA lab.

For every request with a body it:
  1. looks the destination up in the mini Cloud Registry (category, risk, sanctioned),
  2. pulls out uploaded files and pasted text (multipart, JSON, form, raw body),
  3. scans each one with the same scanner the endpoint uses (Thai ID + checksum),
  4. appends a JSON line that the Wazuh manager reads (rules 100122-100141).

Monitor mode: uploads to the lab sites (*.test) go through to the mock site.
Lab safety guard (pdpa_sinkhole, on by default): a request carrying a file to
a real registry service, or carrying Thai IDs to any real site, is answered by
the proxy itself and never leaves the lab.

Run (from the repo root):
    mitmdump -s swg/pdpa_swg_addon.py --listen-host 192.168.56.102 -p 8080 \
        --set connection_strategy=lazy --set pdpa_log=/var/log/pdpa-swg/swg.json
"""
from __future__ import annotations

import json
import socket
import sys
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mitmproxy import ctx, http, tls  # noqa: E402

from scanner.scan import scan_file  # noqa: E402
from swg.registry import DEFAULT_PATH, Registry  # noqa: E402
from swg.upload_parser import extract_items  # noqa: E402

LAB_SUFFIX = ".test"


def _is_lab(host: str) -> bool:
    return host.lower().rstrip(".").endswith(LAB_SUFFIX)


def _strip_query(url: str) -> str:
    # Query strings often carry session tokens: keep them out of the SIEM.
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


class PdpaSwg:
    def __init__(self):
        self.registry: Registry | None = None
        self.clients: dict[str, str] = {}
        self._lock = threading.Lock()
        self.gateway = socket.gethostname()

    # ---- options -------------------------------------------------------
    def load(self, loader):
        loader.add_option("pdpa_log", str, "/var/log/pdpa-swg/swg.json", "JSON-lines log read by Wazuh")
        loader.add_option("pdpa_registry", str, str(DEFAULT_PATH), "cloud registry JSON")
        loader.add_option("pdpa_clients", str, "", "map client IP to user: '192.168.56.101=tt,10.0.0.5=bob'")
        loader.add_option("pdpa_lab_upstream", str, "127.0.0.1:8000", "where *.test sites are served")
        loader.add_option("pdpa_sinkhole", bool, True, "answer real-site uploads locally (lab safety guard)")
        loader.add_option("pdpa_max_bytes", int, 25 * 1024 * 1024, "skip bodies larger than this")

    def configure(self, updated):
        if "pdpa_registry" in updated:
            self.registry = Registry.load(ctx.options.pdpa_registry)
            ctx.log.info(f"pdpa-swg: registry loaded from {ctx.options.pdpa_registry}")
        if "pdpa_clients" in updated:
            self.clients = {}
            for pair in filter(None, (p.strip() for p in ctx.options.pdpa_clients.split(","))):
                ip, _, user = pair.partition("=")
                self.clients[ip.strip()] = user.strip()
        if "pdpa_log" in updated:
            Path(ctx.options.pdpa_log).parent.mkdir(parents=True, exist_ok=True)

    # ---- TLS inspection exemptions (bypass list on the proxy side) -------
    def tls_clienthello(self, data: tls.ClientHelloData):
        sni = data.client_hello.sni or ""
        if self.registry and self.registry.no_decrypt(sni):
            data.ignore_connection = True

    # ---- request inspection -------------------------------------------
    def request(self, flow: http.HTTPFlow):
        req = flow.request
        host = req.pretty_host
        body = req.raw_content or b""
        if req.method in ("POST", "PUT", "PATCH") and body and self.registry:
            if len(body) <= ctx.options.pdpa_max_bytes:
                self._inspect(flow, host, body)
        if flow.response is None and _is_lab(host):
            self._route_to_lab(flow, host)

    def _inspect(self, flow: http.HTTPFlow, host: str, body: bytes):
        req = flow.request
        svc = self.registry.lookup(host)
        known = self.registry.is_known(host)
        items = extract_items(req.headers.get("content-type", ""), body, req.pretty_url)
        if not items:
            return

        srcip = flow.client_conn.peername[0].removeprefix("::ffff:")
        events = [self._scan_item(item) for item in items]
        has_pii = any(e["event"] == "pii_detected" for e in events)
        has_file = any(i.kind == "file" for i in items)

        sinkhole = ctx.options.pdpa_sinkhole and not _is_lab(host) and ((known and has_file) or has_pii)
        action = "sinkholed" if sinkhole else ("lab_mock" if _is_lab(host) else "allowed")

        for item, ev in zip(items, events):
            # Log every hit; log clean/skipped files only for registry services
            # (shadow IT discovery). Clean pasted text is not logged: too noisy.
            if ev["event"] != "pii_detected" and not (known and item.kind == "file"):
                continue
            ev.update({
                "sensor": "mini-swg",
                "gateway": self.gateway,
                "host": self.gateway,
                "user": self.clients.get(srcip, f"ip:{srcip}"),
                "srcip": srcip,
                "file": item.name,
                "content_kind": item.kind,
                "location_type": "web_upload",
                "http_method": req.method,
                "url": _strip_query(req.pretty_url),
                "dest_host": host,
                "dest_name": svc.name,
                "dest_category": svc.category,
                "dest_risk": svc.risk,
                "dest_score": svc.score,
                "dest_sanctioned": "yes" if svc.sanctioned else "no",
                "action": action,
            })
            self._write(ev)
            ctx.log.info(f"pdpa-swg: {ev['event']} {ev.get('match_count', '-')} {item.name} -> {host} [{action}]")

        if sinkhole:
            flow.response = http.Response.make(
                403,
                b"PDPA lab safety guard: upload to a real site was stopped at the proxy. "
                b"Use the lab sites (*.test).\n",
                {"Content-Type": "text/plain; charset=utf-8"},
            )

    def _scan_item(self, item) -> dict:
        suffix = Path(item.name).suffix.lower() if item.kind == "file" else ".txt"
        tmp = tempfile.NamedTemporaryFile(prefix="pdpa-swg-", suffix=suffix or ".bin", delete=False)
        try:
            tmp.write(item.data)
            tmp.close()
            return scan_file(tmp.name, location_type="web_upload")
        finally:
            Path(tmp.name).unlink(missing_ok=True)

    def _route_to_lab(self, flow: http.HTTPFlow, host: str):
        up_host, _, up_port = ctx.options.pdpa_lab_upstream.rpartition(":")
        flow.request.scheme = "http"
        flow.request.host = up_host
        flow.request.port = int(up_port)
        flow.request.headers["Host"] = host

    def _write(self, event: dict):
        line = json.dumps(event, ensure_ascii=False)
        with self._lock, open(ctx.options.pdpa_log, "a", encoding="utf-8") as f:
            f.write(line + "\n")


addons = [PdpaSwg()]
