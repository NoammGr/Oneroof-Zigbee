"""Telegram notifications for security and network events.

The notifier subscribes to the audit stream, turns records into short plain-text
sentences (device names, not addresses, unless `include_addresses` is on) and
sends them through the egress client to the Telegram Bot API `sendMessage`.

* categories with their own on/off switch (see CATEGORIES);
* routine events are collected for `digest_seconds` and sent as one message;
  security events and anomalies go out immediately;
* hard limit of 20 messages per minute — what does not fit is summarised as
  "… and N more";
* optional quiet hours: routine messages wait until the quiet period ends,
  security and anomalies are still delivered;
* up to 3 attempts with backoff per message; failures are audited as
  `notify_failed` (an event, not a security record) and counted.

Nothing about the bot token is ever logged, audited or returned.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from .egress import EgressClient, EgressRefused

log = logging.getLogger("oneroof_zigbee.notify.telegram")

TELEGRAM_HOST = "api.telegram.org"
MAX_MESSAGE = 4096
RATE_LIMIT = 20            # messages per minute, hard
RATE_WINDOW_S = 60.0
RETRIES = 3
BACKOFF_S = (1.0, 3.0, 9.0)
PENDING_CAP = 200          # queued lines; beyond that lines are counted, not kept

CATEGORIES: dict[str, str] = {
    "join_window": "Join window opened or closed",
    "devices": "Devices joining, leaving, removed, interviewed",
    "security": "Security alerts: unexpected joins, unknown devices, denied requests, key and network integrity",
    "anomalies": "Behaviour anomalies on known devices (sequence jumps, bursts, unexpected commands)",
    "health": "Coordinator start, restarts, neighbour checks, gateway start/stop",
    "liveness": "A mains-powered device went silent",
}
IMMEDIATE = {"security", "anomalies"}

DEFAULT_SETTINGS: dict[str, Any] = {
    "enabled": False,
    "categories": {"join_window": True, "devices": True, "security": True, "anomalies": True, "health": False, "liveness": True},
    "digest_seconds": 30,
    "include_addresses": False,
    "quiet_start": None,   # "22:30"
    "quiet_end": None,     # "07:00"
}

Resolver = Callable[[str], "str | None"]


# ----------------------------------------------------------------- settings --

class NotifySettings:
    """Non-secret settings in <data_dir>/notify.yaml (0600), editable live."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.data: dict[str, Any] = _deep_copy(DEFAULT_SETTINGS)
        self.load()

    def load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            raw = yaml.safe_load(self.path.read_text()) or {}
        except (OSError, yaml.YAMLError):
            log.exception("notify.yaml unreadable; using defaults")
            return
        if isinstance(raw, dict):
            self.data = self.validate(raw, base=_deep_copy(DEFAULT_SETTINGS))

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(self.data, f, sort_keys=True)
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    @staticmethod
    def validate(patch: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
        """Merge `patch` over `base` after validating every value; raises ValueError."""
        out = _deep_copy(base)
        for k, v in patch.items():
            if k == "enabled" or k == "include_addresses":
                out[k] = bool(v)
            elif k == "categories":
                if not isinstance(v, dict):
                    raise ValueError("categories must be an object")
                for c, on in v.items():
                    if c not in CATEGORIES:
                        raise ValueError(f"unknown category {c!r}")
                    out["categories"][c] = bool(on)
            elif k == "digest_seconds":
                try:
                    n = int(v)
                except (TypeError, ValueError) as e:
                    raise ValueError("digest_seconds must be an integer") from e
                if not 0 <= n <= 3600:
                    raise ValueError("digest_seconds must be 0–3600")
                out[k] = n
            elif k in ("quiet_start", "quiet_end"):
                out[k] = _hhmm(v)
            else:
                raise ValueError(f"{k} is not a notification setting")
        if bool(out["quiet_start"]) != bool(out["quiet_end"]):
            raise ValueError("quiet hours need both a start and an end")
        return out

    def apply(self, patch: dict[str, Any]) -> list[str]:
        new = self.validate(patch, base=self.data)
        changed = [k for k in new if new[k] != self.data.get(k)]
        self.data = new
        if changed:
            self.save()
        return changed

    def __getitem__(self, k: str) -> Any:
        return self.data[k]


def _deep_copy(d: dict[str, Any]) -> dict[str, Any]:
    return {k: (dict(v) if isinstance(v, dict) else v) for k, v in d.items()}


def _hhmm(v: Any) -> str | None:
    if v in (None, ""):
        return None
    s = str(v).strip()
    try:
        h, m = s.split(":")
        if not (0 <= int(h) <= 23 and 0 <= int(m) <= 59):
            raise ValueError
    except ValueError as e:
        raise ValueError(f"{s!r} is not a time (HH:MM)") from e
    return f"{int(h):02d}:{int(m):02d}"


def in_quiet_hours(start: str | None, end: str | None, local: time.struct_time) -> bool:
    if not start or not end:
        return False
    now = local.tm_hour * 60 + local.tm_min
    s = int(start[:2]) * 60 + int(start[3:])
    e = int(end[:2]) * 60 + int(end[3:])
    if s == e:
        return False
    return s <= now < e if s < e else (now >= s or now < e)


# --------------------------------------------------------- event → message --

def _name(rec: dict[str, Any], resolve: Resolver | None, include_addresses: bool, key: str = "ieee",
          unknown: str = "an unregistered device") -> str:
    ieee = rec.get(key)
    if not ieee:
        return unknown
    name = None
    if resolve is not None:
        try:
            name = resolve(str(ieee))
        except Exception:
            name = None
    if name and include_addresses:
        return f"{name} ({ieee})"
    if name:
        return name
    return f"{unknown} ({ieee})" if include_addresses else unknown


def _model(rec: dict[str, Any]) -> str:
    m = " ".join(str(rec[k]) for k in ("manufacturer", "model") if rec.get(k))
    return f" ({m})" if m else ""


def describe(rec: dict[str, Any], resolve: Resolver | None = None, include_addresses: bool = False) -> tuple[str, str] | None:
    """Map an audit record to (category, sentence); None when the record is not worth a notification."""
    t = str(rec.get("type", ""))
    lvl = rec.get("level")
    nm = lambda key="ieee", unknown="an unregistered device": _name(rec, resolve, include_addresses, key, unknown)  # noqa: E731
    by = f" by {rec['by']}" if rec.get("by") else ""

    # join window
    if t == "permit_join_opened":
        target = f" for {nm()}" if rec.get("ieee") else ""
        code = " with install code" if rec.get("install_code") else ""
        return "join_window", f"Join window opened for {rec.get('seconds', '?')} s{target}{code}{by}."
    if t == "permit_join_closed":
        return "join_window", f"Join window closed ({rec.get('reason', 'closed')})."
    if t == "permit_join_closed_after_join":
        return "join_window", f"Join window closed after {nm(unknown='a new device')} joined."

    # devices
    if t == "device_joined":
        return "devices", f"New device joined: {nm(unknown='a new device')}{by}."
    if t == "device_rejoined":
        return "devices", f"{nm(unknown='A device')} rejoined the network."
    if t == "device_left":
        return "devices", f"{nm(unknown='A device')} left the network{' (rejoining)' if rec.get('rejoin') else ''}."
    if t in ("device_removed", "device_removed_by_request"):
        return "devices", f"{nm(unknown='A device')} was removed{by}."
    if t == "interview_done":
        return "devices", f"Interview finished: {nm(unknown='new device')}{_model(rec)}."

    # anomalies / liveness
    if t == "device_anomaly":
        kind = str(rec.get("kind", "unknown"))
        ev = ", ".join(f"{k} {rec[k]}" for k in sorted(rec) if k not in ("ts", "level", "type", "prev", "ieee", "kind"))
        evidence = f" — {ev}" if ev else ""
        if kind == "went_silent":
            return "liveness", f"{nm(unknown='A device')} went silent{evidence}."
        return "anomalies", f"Anomaly on {nm(unknown='a device')}: {kind.replace('_', ' ')}{evidence}."

    # security
    if t == "unexpected_join":
        return "security", f"UNEXPECTED JOIN: {nm(unknown='an unregistered device')} joined while no window was open ({rec.get('reason', 'no reason given')})."
    if t == "traffic_from_unknown_device":
        return "security", f"Traffic from {nm()} that is not in the device list (cluster {rec.get('cluster', '?')})."
    if t == "unknown_device_adopted":
        return "security", f"Unknown device adopted{by}: {nm()}."
    if t == "unknown_device_evicted":
        return "security", f"Unknown device evicted{by}: {nm()}."
    if t == "request_denied":
        return "security", f"Request denied: {rec.get('action', '?')}{by} ({rec.get('reason', '')})."
    if t == "permit_join_denied":
        return "security", f"Join window refused{by}: {rec.get('reason', '')}."
    if t == "permit_join_clamped":
        return "security", f"Join window request of {rec.get('requested', '?')} s{by} clamped to {rec.get('max', '?')} s."
    if t == "permit_join_unexpected_open":
        return "security", f"The radio reported an open join window that the gateway did not request ({rec.get('duration', '?')} s); it was closed."
    if t == "key_rotation_after_plain_join":
        return "security", f"Network key rotation started after {nm(unknown='a device')} was paired without an install code."
    if t == "network_key_rotation_scheduled":
        return "security", f"Network key and seed replacement scheduled{by}: every device must be paired again after the restart."
    if t == "network_key_rotation_started":
        return "security", f"Network key rotation started{by} (switch in {rec.get('window_s', '?')} s)."
    if t == "network_key_rotated":
        return "security", f"Network key rotated{by}: {rec.get('delivered', '?')} devices received the new key, {rec.get('failed', 0)} will pick it up when they rejoin."
    if t == "network_key_rotation_failed":
        return "security", f"Network key rotation FAILED: {rec.get('error', '')}"
    if t == "network_key_mismatch":
        return "security", "The coordinator's network key does not match the saved one; repair attempted."
    if t == "network_key_repaired":
        return "security", f"Network key repaired ({rec.get('method', '?')})."
    if t == "network_key_unrepaired":
        return "security", "Network key mismatch could NOT be repaired; devices may be unreachable."
    if t == "network_parameters_mismatch":
        return "security", (f"Network parameters on the radio differ from the saved ones (radio channel {rec.get('radio_channel', '?')}, "
                            f"PAN {rec.get('radio_pan_id', '?')}).")
    if t == "network_formed":
        return "security", f"A NEW network was formed (channel {rec.get('channel', '?')}, PAN {rec.get('pan_id', '?')}); all devices must be paired again."
    if t == "no_neighbours_heard":
        return "security", "The coordinator hears no neighbours at all (antenna, radio or interference problem)."
    if t == "frame_counter_unverified":
        return "security", f"Frame counter could not be verified (radio {rec.get('value', '?')}, expected at least {rec.get('needed', '?')})."
    if t == "broker_login_adopted":
        return "security", f"Broker login {rec.get('user', '?')!r} adopted from Home Assistant ({rec.get('ip', '?')})."
    if t == "definition_saved":
        return "security", f"Device definition saved{by}: {rec.get('manufacturer', '?')} / {rec.get('model', '?')}."
    if t == "definition_removed":
        return "security", f"Device definition removed{by}: {rec.get('manufacturer', '?')} / {rec.get('model', '?')}."
    if t == "egress_refused":
        return "security", f"Outbound connection refused: {rec.get('host', '?')} ({rec.get('reason', '')})."
    if t == "backup_created":
        return "security", f"Backup created{by}."
    if t == "backup_restored":
        return "security", f"Backup restored{by}; restart pending."
    if t == "previous_setup_import":
        return "security", f"Previous setup imported{by}: {rec.get('devices', '?')} devices."

    # health
    if t == "coordinator_started":
        return "health", f"Coordinator started (channel {rec.get('channel', '?')}, PAN {rec.get('pan_id', '?')})."
    if t == "restart_requested":
        return "health", f"Gateway restart requested{by}."
    if t == "neighbour_check":
        return "health", f"Neighbour check: {rec.get('neighbours', '?')} neighbours, {rec.get('routers', '?')} routers."
    if t in ("gateway_started", "gateway_stopped"):
        return "health", "Gateway started." if t == "gateway_started" else "Gateway stopping."

    if lvl == "security":  # anything else at security level is still worth a line
        fields = ", ".join(f"{k} {rec[k]}" for k in sorted(rec) if k not in ("ts", "level", "type", "prev", "ieee"))
        return "security", f"Security event {t}{(': ' + fields) if fields else ''}."
    return None


# ----------------------------------------------------------------- notifier --

class TelegramNotifier:
    def __init__(self, audit: Any, egress: EgressClient, settings: NotifySettings, secrets: Any, *,
                 resolve_name: Resolver | None = None, clock: Callable[[], float] = time.time,
                 local_time: Callable[[float], time.struct_time] = time.localtime, sleep: Callable[[float], Any] | None = None) -> None:
        self.audit = audit
        self.egress = egress
        self.settings = settings
        self.secrets = secrets
        self.resolve = resolve_name
        self.clock = clock
        self.local_time = local_time
        self._sleep = sleep or asyncio.sleep
        self._pending: list[tuple[str, str]] = []        # (category, line) waiting for the digest
        self._urgent: list[tuple[str, str]] = []
        self._first_pending: float | None = None
        self._dropped = 0
        self._sent_at: collections.deque[float] = collections.deque()
        self.recent: collections.deque[dict[str, Any]] = collections.deque(maxlen=20)
        self.sent = 0
        self.failed = 0
        self._task: asyncio.Task[None] | None = None
        self._kick: asyncio.Event | None = None
        self._lock = asyncio.Lock()
        self._subscribed = False
        self._sync_egress()

    # -- lifecycle ---------------------------------------------------------

    def _sync_egress(self) -> None:
        self.egress.enabled = bool(self.settings["enabled"])

    def start(self) -> None:
        if not self._subscribed:
            self.audit.subscribe(self.on_audit)
            self._subscribed = True
        self._kick = asyncio.Event()
        self._task = asyncio.create_task(self._worker())
        self.on_audit({"level": "event", "type": "gateway_started", "ts": self.clock()})

    async def stop(self) -> None:
        self.on_audit({"level": "event", "type": "gateway_stopped", "ts": self.clock()})
        try:  # waits for a send already in flight (the lock), then delivers whatever is still queued
            await asyncio.wait_for(self.flush(force=True), 15)
        except Exception:
            log.debug("final flush did not complete")
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    async def _worker(self) -> None:
        assert self._kick is not None
        while True:
            try:
                await asyncio.wait_for(self._kick.wait(), 1.0)
            except asyncio.TimeoutError:
                pass
            self._kick.clear()
            try:
                await self.flush()
            except Exception:
                log.exception("notification flush failed")

    # -- settings ----------------------------------------------------------

    def apply_settings(self, patch: dict[str, Any]) -> list[str]:
        changed = self.settings.apply(patch)
        self._sync_egress()
        if "enabled" in changed and not self.settings["enabled"]:
            self._pending.clear()
            self._urgent.clear()
            self._first_pending = None
        return changed

    def status(self) -> dict[str, Any]:
        return {"settings": _deep_copy(self.settings.data), "has_token": self.secrets.has_token(),
                "chat_id": self.secrets.chat_id(), "categories": dict(CATEGORIES),
                "sent": self.sent, "failed": self.failed, "dropped": self._dropped, "queued": len(self._pending) + len(self._urgent),
                "recent": list(self.recent), "egress": self.egress.snapshot()}

    def configured(self) -> bool:
        return bool(self.settings["enabled"] and self.secrets.has_token() and self.secrets.chat_id())

    # -- intake ------------------------------------------------------------

    def on_audit(self, rec: dict[str, Any]) -> None:
        if not self.settings["enabled"]:
            return
        if rec.get("type") in ("notify_failed", "notify_settings_changed", "notify_test"):
            return  # never notify about notifying
        if rec.get("type") == "egress_refused" and rec.get("host") == TELEGRAM_HOST:
            return  # our own refused send; it is already counted as a failure
        mapped = describe(rec, self.resolve, bool(self.settings["include_addresses"]))
        if mapped is None:
            return
        cat, text = mapped
        if not self.settings["categories"].get(cat, False):
            return
        stamp = self.local_time(float(rec.get("ts") or self.clock()))
        line = f"{stamp.tm_hour:02d}:{stamp.tm_min:02d} {text}"
        bucket = self._urgent if cat in IMMEDIATE else self._pending
        if len(self._pending) + len(self._urgent) >= PENDING_CAP:
            self._dropped += 1
            return
        bucket.append((cat, line))
        if bucket is self._pending and self._first_pending is None:
            self._first_pending = self.clock()
        if self._kick is not None:
            self._kick.set()

    # -- batching / sending ------------------------------------------------

    def _quiet(self) -> bool:
        return in_quiet_hours(self.settings["quiet_start"], self.settings["quiet_end"], self.local_time(self.clock()))

    def _digest_due(self) -> bool:
        if not self._pending:
            return False
        if self._quiet():
            return False
        d = int(self.settings["digest_seconds"])
        return d == 0 or self._first_pending is None or self.clock() - self._first_pending >= d

    async def flush(self, force: bool = False) -> int:
        """Send what is due; returns the number of Telegram messages sent."""
        async with self._lock:
            lines: list[str] = []
            if self._urgent:
                lines += [ln for _, ln in self._urgent]
                self._urgent.clear()
            if force or self._digest_due():
                lines += [ln for _, ln in self._pending]
                self._pending.clear()
                self._first_pending = None
            if not lines:
                return 0
            if not self.configured():
                self._dropped += len(lines)
                return 0
            return await self._send_lines(lines)

    def _allowance(self) -> int:
        now = self.clock()
        while self._sent_at and now - self._sent_at[0] >= RATE_WINDOW_S:
            self._sent_at.popleft()
        return max(0, RATE_LIMIT - len(self._sent_at))

    async def _send_lines(self, lines: list[str]) -> int:
        allowed = self._allowance()
        if allowed == 0:
            self._dropped += len(lines)
            log.warning("notification rate limit reached; %d line(s) summarised later", len(lines))
            return 0
        chunks = _chunk(lines, MAX_MESSAGE - 40)
        if len(chunks) > allowed:
            kept, rest = chunks[:allowed], chunks[allowed:]
            self._dropped += sum(c.count("\n") + 1 for c in rest)
            chunks = kept
        if self._dropped:
            suffix = f"\n… and {self._dropped} more"
            self._dropped = 0
            chunks[-1] = chunks[-1][: MAX_MESSAGE - len(suffix)] + suffix
        n = 0
        for text in chunks:
            if await self._send(text):
                n += 1
        return n

    async def send_test(self) -> dict[str, Any]:
        if not self.settings["enabled"]:
            raise ValueError("notifications are disabled")
        if not self.secrets.has_token() or not self.secrets.chat_id():
            raise ValueError("bot token and chat id are required")
        ok = await self._send("Test message from One Roof Zigbee: notifications are working.", test=True)
        return {"ok": ok, "recent": list(self.recent)[-1:] }

    async def _send(self, text: str, *, test: bool = False) -> bool:
        token, chat = self.secrets.token(), self.secrets.chat_id()
        url = f"https://{TELEGRAM_HOST}/bot{token}/sendMessage"
        body = {"chat_id": chat, "text": text, "disable_web_page_preview": True}
        err = ""
        for attempt in range(RETRIES):
            try:
                status, resp = await self.egress.post_json(url, body)
                if status == 200 and isinstance(resp, dict) and resp.get("ok"):
                    self._sent_at.append(self.clock())
                    self.sent += 1
                    self.recent.append({"ts": self.clock(), "ok": True, "chars": len(text), "lines": text.count("\n") + 1, "test": test,
                                        "preview": text[:80]})
                    return True
                desc = (resp or {}).get("description") if isinstance(resp, dict) else None
                err = f"HTTP {status}" + (f": {desc}" if desc else "")
                if status in (400, 401, 403, 404):
                    break  # bad token / chat: retrying does not help
            except EgressRefused as e:
                err = f"refused ({e})"
                break
            except Exception as e:
                err = f"{type(e).__name__}: {e}"[:160]
            if attempt + 1 < RETRIES:
                await self._sleep(BACKOFF_S[attempt])
        self.failed += 1
        self.recent.append({"ts": self.clock(), "ok": False, "chars": len(text), "lines": text.count("\n") + 1, "test": test,
                            "error": err, "preview": text[:80]})
        self.audit.event("notify_failed", channel="telegram", error=err, chars=len(text))
        return False


def _chunk(lines: list[str], limit: int) -> list[str]:
    out: list[str] = []
    cur = ""
    for ln in lines:
        ln = ln if len(ln) <= limit else ln[: limit - 1] + "…"
        if cur and len(cur) + 1 + len(ln) > limit:
            out.append(cur)
            cur = ln
        else:
            cur = f"{cur}\n{ln}" if cur else ln
    if cur:
        out.append(cur)
    return out
