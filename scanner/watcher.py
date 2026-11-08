"""Watch folders (and USB drives as they are plugged in) and scan new files.

Each scan with a hit is appended to a JSON-lines log that the Wazuh agent
reads (log_format json). Runs in monitor mode only: it never blocks or moves
files.

Usage (on the Windows VM):
    python -m scanner.watcher --config config.json
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .extract import SUPPORTED
from .scan import scan_file

log = logging.getLogger("pdpa-watcher")

IGNORE_PREFIXES = ("~$", ".~")       # Office lock files
IGNORE_SUFFIXES = (".tmp", ".crdownload", ".part")


class JsonLineLog:
    """Append-only JSON-lines writer, safe to call from several threads."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def wait_until_stable(path: Path, checks: int = 3, interval: float = 0.5, timeout: float = 30) -> bool:
    """A copy to USB fires 'created' before the bytes finish landing. Wait for the size to settle."""
    deadline = time.time() + timeout
    last, same = -1, 0
    while time.time() < deadline:
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            return False
        same = same + 1 if size == last else 0
        if same >= checks:
            return True
        last = size
        time.sleep(interval)
    return path.exists()


class ScanHandler(FileSystemEventHandler):
    def __init__(self, label: str, sink: JsonLineLog, thresholds: dict, log_clean: bool):
        self.label = label
        self.sink = sink
        self.thresholds = thresholds
        self.log_clean = log_clean
        self._recent: dict[str, float] = {}   # debounce: path -> last scan time

    def on_created(self, event):
        if not event.is_directory:
            self._handle(Path(event.src_path))

    def on_moved(self, event):
        if not event.is_directory:
            self._handle(Path(event.dest_path))

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(Path(event.src_path))

    def _handle(self, path: Path) -> None:
        name = path.name
        if path.suffix.lower() not in SUPPORTED:
            return
        if name.startswith(IGNORE_PREFIXES) or name.endswith(IGNORE_SUFFIXES):
            return
        now = time.time()
        if now - self._recent.get(str(path), 0) < 5:
            return
        self._recent[str(path)] = now
        threading.Thread(target=self._scan, args=(path,), daemon=True).start()

    def _scan(self, path: Path) -> None:
        if not wait_until_stable(path):
            return
        ev = scan_file(path, thresholds=self.thresholds, location_type=self.label)
        if ev["event"] == "pii_detected" or (self.log_clean and ev["event"] == "clean"):
            self.sink.write(ev)
        log.info("%s %s %s", ev["event"], ev.get("match_count", "-"), path)


def removable_drives() -> set[str]:
    """Mount points of removable drives (USB sticks). Windows reports 'removable' in opts."""
    import psutil

    drives = set()
    for part in psutil.disk_partitions(all=False):
        if "removable" in part.opts or part.mountpoint.startswith(("/media/", "/run/media/")):
            drives.add(part.mountpoint)
    return drives


def run(config: dict) -> None:
    sink = JsonLineLog(Path(config["log_path"]))
    thresholds = config.get("thresholds", {"high": 10, "critical": 50})
    log_clean = config.get("log_clean", False)
    observer = Observer()

    for item in config.get("watch", []):
        p = Path(item["path"]).expanduser()
        if not p.exists():
            log.warning("skip missing folder %s", p)
            continue
        observer.schedule(ScanHandler(item.get("label", "folder"), sink, thresholds, log_clean), str(p), recursive=True)
        log.info("watching %s as %s", p, item.get("label"))

    observer.start()
    watched_usb: dict[str, object] = {}
    try:
        while True:
            if config.get("auto_usb", True):
                current = removable_drives()
                for mount in current - watched_usb.keys():
                    handler = ScanHandler("usb", sink, thresholds, log_clean)
                    watched_usb[mount] = observer.schedule(handler, mount, recursive=True)
                    log.info("USB plugged in: watching %s", mount)
                for mount in watched_usb.keys() - current:
                    observer.unschedule(watched_usb.pop(mount))
                    log.info("USB removed: %s", mount)
            time.sleep(config.get("usb_poll_seconds", 3))
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Watch folders and USB drives for Thai PII")
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if not args.config.exists():
        print(f"config not found: {args.config} (copy config.example.json)", file=sys.stderr)
        return 2
    run(json.loads(args.config.read_text(encoding="utf-8")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
