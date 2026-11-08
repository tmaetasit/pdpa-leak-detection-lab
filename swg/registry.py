"""Mini Cloud Registry: look up a destination host's category and risk."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PATH = Path(__file__).with_name("cloud_registry.json")


@dataclass(frozen=True)
class Service:
    name: str
    category: str
    risk: str          # low / medium / high
    score: int         # 1-10
    sanctioned: bool


UNCATEGORIZED = Service("uncategorized", "uncategorized", "unknown", 0, False)


def _matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


class Registry:
    def __init__(self, data: dict):
        self._services: list[tuple[str, Service]] = []
        for s in data.get("services", []):
            svc = Service(s["name"], s["category"], s["risk"], int(s["score"]), bool(s["sanctioned"]))
            for d in s["domains"]:
                self._services.append((d.lower().strip("."), svc))
        # Longest domain first, so a specific entry beats its parent.
        self._services.sort(key=lambda t: len(t[0]), reverse=True)
        self._no_decrypt = [d.lower().strip(".") for d in data.get("no_decrypt", [])]

    @classmethod
    def load(cls, path: str | Path = DEFAULT_PATH) -> "Registry":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def lookup(self, host: str) -> Service:
        host = (host or "").lower().rstrip(".")
        for domain, svc in self._services:
            if _matches(host, domain):
                return svc
        return UNCATEGORIZED

    def is_known(self, host: str) -> bool:
        return self.lookup(host) is not UNCATEGORIZED

    def no_decrypt(self, host: str) -> bool:
        host = (host or "").lower().rstrip(".")
        return any(_matches(host, d) for d in self._no_decrypt)
