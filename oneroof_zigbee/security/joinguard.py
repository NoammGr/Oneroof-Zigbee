"""Join policy enforcement.

Rules (not configurable downward — only tighter):
* Permit-join is never "forever".  Hard maximum window, default 120 s.
* Every open/close is recorded in the audit log with who asked and why.
* Optional allow-list: when `require_install_code` is set, a join window
  may only be opened together with an install code for a specific IEEE, so
  unknown devices can never slip in while the window is open.
* Cooldown between windows, to make brute-force "keep it open" scripts noisy.
* Unexpected joins (device joined while our window is closed, or a device not
  on the allow-list) raise a SECURITY alert — the firmware should make that
  impossible, so if it happens something is very wrong.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from .audit import Audit

log = logging.getLogger("oneroof_zigbee.security.joinguard")


class JoinPolicyError(PermissionError):
    pass


@dataclass
class JoinPolicy:
    max_seconds: int = 120
    cooldown_seconds: int = 5
    require_install_code: bool = False


@dataclass
class JoinWindow:
    opened_at: float
    seconds: int
    requested_by: str
    allowed_ieee: int | None = None  # None → any device (only when install codes not required)
    closed: bool = False

    @property
    def expires_at(self) -> float:
        return self.opened_at + self.seconds

    def is_open(self, now: float | None = None) -> bool:
        return not self.closed and (now or time.monotonic()) < self.expires_at


@dataclass
class JoinGuard:
    policy: JoinPolicy
    audit: Audit
    _window: JoinWindow | None = None
    _last_close: float = field(default=0.0)
    _close_task: asyncio.Task[None] | None = None

    @property
    def window(self) -> JoinWindow | None:
        w = self._window
        return w if (w and w.is_open()) else None

    def request_open(self, seconds: int, requested_by: str, allowed_ieee: int | None = None) -> JoinWindow:
        now = time.monotonic()
        if seconds <= 0:
            raise JoinPolicyError("seconds must be > 0")
        if seconds > self.policy.max_seconds:
            self.audit.security("permit_join_clamped", requested=seconds, max=self.policy.max_seconds, by=requested_by)
            seconds = self.policy.max_seconds
        if self.policy.require_install_code and allowed_ieee is None:
            self.audit.security("permit_join_denied", reason="install code required", by=requested_by)
            raise JoinPolicyError("policy requires an install code for every join")
        if now - self._last_close < self.policy.cooldown_seconds and not self.window:
            self.audit.security("permit_join_denied", reason="cooldown", by=requested_by)
            raise JoinPolicyError(f"cooldown: wait {self.policy.cooldown_seconds}s between join windows")
        self._window = JoinWindow(now, seconds, requested_by, allowed_ieee)
        self.audit.event("permit_join_opened", seconds=seconds, by=requested_by,
                         ieee=(f"0x{allowed_ieee:016x}" if allowed_ieee is not None else "any"))
        return self._window

    def mark_closed(self, reason: str = "expired") -> None:
        if self._window and not self._window.closed:
            self._window.closed = True
            self._last_close = time.monotonic()
            self.audit.event("permit_join_closed", reason=reason)

    def on_device_joined(self, ieee: int, nwk: int) -> bool:
        """Return True if the join was expected; log a security alert otherwise."""
        w = self.window
        if w is None:
            self.audit.security("unexpected_join", ieee=f"0x{ieee:016x}", nwk=f"{nwk:#06x}",
                                reason="join window closed")
            return False
        if w.allowed_ieee is not None and w.allowed_ieee != ieee:
            self.audit.security("unexpected_join", ieee=f"0x{ieee:016x}", nwk=f"{nwk:#06x}",
                                reason="not the device the window was opened for")
            return False
        self.audit.event("device_joined", ieee=f"0x{ieee:016x}", nwk=f"{nwk:#06x}", by=w.requested_by)
        return True
