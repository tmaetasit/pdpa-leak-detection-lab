"""Scan one file or a folder and report Thai national IDs found.

Usage:
    python -m scanner.scan path/to/file_or_folder [--no-checksum] [--json]

Only masked IDs ever leave this module. Full numbers are never logged.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from .extract import SUPPORTED, UnsupportedFile, extract_text
from .thai_id import find_thai_ids

DEFAULT_THRESHOLDS = {"high": 10, "critical": 50}
MAX_SAMPLES = 3


def severity_for(count: int, thresholds: dict | None = None) -> str:
    t = thresholds or DEFAULT_THRESHOLDS
    if count >= t["critical"]:
        return "critical"
    if count >= t["high"]:
        return "high"
    if count > 0:
        return "low"
    return "none"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_file(
    path: str | Path,
    use_checksum: bool = True,
    thresholds: dict | None = None,
    location_type: str = "manual",
) -> dict:
    """Return one event dict describing the scan. Shape matches the Wazuh rules."""
    path = Path(path)
    event = {
        "tool": "pdpa-scanner",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "user": _current_user(),
        "file": str(path),
        "file_ext": path.suffix.lower(),
        "location_type": location_type,
    }
    try:
        text = extract_text(path)
    except UnsupportedFile:
        return {**event, "event": "skipped", "reason": "unsupported_type"}
    except Exception as exc:  # corrupt or locked file: report, never crash the watcher
        return {**event, "event": "error", "reason": type(exc).__name__}

    finding = find_thai_ids(text, use_checksum=use_checksum)
    count = len(finding.valid)
    return {
        **event,
        "event": "pii_detected" if count else "clean",
        "data_type": "thai_national_id",
        "match_count": count,
        "rejected_by_checksum": finding.invalid_count if use_checksum else 0,
        "severity": severity_for(count, thresholds),
        "samples": finding.valid[:MAX_SAMPLES],
        "file_size": path.stat().st_size,
        "sha256": sha256_of(path),
    }


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def iter_files(target: Path):
    if target.is_file():
        yield target
        return
    for p in sorted(target.rglob("*")):
        if p.is_file() and p.suffix.lower() in SUPPORTED:
            yield p


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan files for Thai national IDs")
    ap.add_argument("target", type=Path)
    ap.add_argument("--no-checksum", action="store_true", help="regex only (baseline)")
    ap.add_argument("--json", action="store_true", help="print one JSON event per line")
    args = ap.parse_args(argv)

    if not args.target.exists():
        print(f"not found: {args.target}", file=sys.stderr)
        return 2

    for path in iter_files(args.target):
        ev = scan_file(path, use_checksum=not args.no_checksum)
        if args.json:
            print(json.dumps(ev, ensure_ascii=False))
        elif ev["event"] == "pii_detected":
            print(f"[{ev['severity'].upper():8}] {ev['match_count']:4} IDs  {path}  e.g. {ev['samples'][0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
