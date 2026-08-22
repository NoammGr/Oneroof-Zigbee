"""Append-only, tamper-evident audit log.

Each line is JSON with a `prev` field = SHA-256 of the previous line, so a
deleted or edited entry breaks the chain and `verify()` reports where.
Security events are also fanned out to subscribers (the gateway publishes
them on `<base>/bridge/event` so Home Assistant can raise a notification).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

log = logging.getLogger("oneroof_zigbee.audit")

Subscriber = Callable[[dict[str, Any]], None]


class Audit:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._subs: list[Subscriber] = []
        self._prev = self._tail_hash() if path else "0" * 64

    def subscribe(self, cb: Subscriber) -> None:
        self._subs.append(cb)

    def event(self, type_: str, **fields: Any) -> dict[str, Any]:
        return self._write("event", type_, fields)

    def security(self, type_: str, **fields: Any) -> dict[str, Any]:
        return self._write("security", type_, fields)

    def _write(self, level: str, type_: str, fields: dict[str, Any]) -> dict[str, Any]:
        rec = {"ts": time.time(), "level": level, "type": type_, **fields, "prev": self._prev}
        line = json.dumps(rec, separators=(",", ":"), sort_keys=True)
        self._prev = hashlib.sha256(line.encode()).hexdigest()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(line + "\n")
        (log.warning if level == "security" else log.info)("%s %s", type_, {k: v for k, v in fields.items()})
        for cb in self._subs:
            try:
                cb(rec)
            except Exception:
                log.exception("audit subscriber failed")
        return rec

    def _tail_hash(self) -> str:
        assert self.path is not None
        if not self.path.exists():
            return "0" * 64
        last = ""
        with self.path.open() as f:
            for line in f:
                if line.strip():
                    last = line.rstrip("\n")
        return hashlib.sha256(last.encode()).hexdigest() if last else "0" * 64

    @staticmethod
    def verify(path: Path) -> tuple[bool, int]:
        """Return (ok, first_bad_line_number)."""
        prev = "0" * 64
        with path.open() as f:
            for n, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return False, n
                if rec.get("prev") != prev:
                    return False, n
                prev = hashlib.sha256(line.encode()).hexdigest()
        return True, 0
