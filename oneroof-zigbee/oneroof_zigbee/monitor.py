"""Liveness and anomaly monitor.

Zigbee has no per-device secure session, so a stolen network key cannot be made
harmless by the protocol. What the gateway can do is watch behaviour the way a
physical access-control line does: every device has a rhythm, and an intruder
with a radio breaks it. This module keeps a small behavioural profile per
device and raises `device_anomaly` security alerts when:

* **sequence jump** — the ZCL transaction sequence from a device skips far
  ahead or runs backwards outside the normal wrap (an impersonator keeps
  its own counter);
* **link-quality swing** — LQI differs wildly from the device's running
  average (a different radio in a different place);
* **unexpected command** — a device that has only ever *reported* suddenly
  sends cluster commands (sensors do not send on/off commands);
* **burst** — far more frames per minute than the device ever produced;
* **silence after burst** — a device goes quiet right after a burst, which is
  the signature of a replay/impersonation that stranded the real device's
  frame counter;
* **went silent** — a mains-powered device misses its expected cadence by a
  wide margin (liveness, like a supervised line).

Thresholds are deliberately conservative (no alert on a single odd frame),
profiles persist in the registry so a restart does not reset the baseline,
and every alert carries the evidence so it can be judged in Activity.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

SEQ_JUMP = 40            # ZCL seq is mod 256 and normally advances by 1..few
LQI_SWING = 80           # absolute LQI deviation from the running mean (needs >= 20 samples)
BURST_FACTOR = 5.0       # frames/minute vs. the device's highest observed minute
BURST_MIN_FRAMES = 30    # and at least this many frames in the minute
SILENCE_AFTER_BURST_S = 600
LIVENESS_FACTOR = 4.0    # mains device silent for > factor × its typical interval (min 30 min)
LIVENESS_MIN_S = 1800
ALERT_COOLDOWN_S = 900   # one alert per kind per device per 15 min


@dataclass
class Profile:
    frames: int = 0
    last_seq: int | None = None
    lqi_mean: float = 0.0
    lqi_n: int = 0
    commands_seen: bool = False
    minute: int = 0
    minute_frames: int = 0
    peak_minute_frames: int = 0
    last_seen: float = 0.0
    typical_gap: float = 0.0  # EWMA of inter-arrival seconds
    burst_at: float = 0.0
    alerts: dict[str, float] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if k != "alerts"}

    @staticmethod
    def from_json(d: dict[str, Any]) -> "Profile":
        p = Profile()
        for k, v in (d or {}).items():
            if hasattr(p, k) and k != "alerts":
                setattr(p, k, v)
        return p


class Monitor:
    def __init__(self, alert: Callable[..., None], *, now: Callable[[], float] = time.time) -> None:
        self._alert = alert  # alert(type, **fields)
        self._now = now
        self.profiles: dict[int, Profile] = {}

    # -- persistence ---------------------------------------------------------

    def export(self) -> dict[str, Any]:
        return {f"0x{k:016x}": p.to_json() for k, p in self.profiles.items()}

    def load(self, data: dict[str, Any]) -> None:
        for k, v in (data or {}).items():
            try:
                self.profiles[int(k, 16)] = Profile.from_json(v)
            except (ValueError, TypeError):
                continue

    # -- observations --------------------------------------------------------

    def observe(self, ieee: int, *, seq: int | None, lqi: int | None, is_command: bool, mains: bool,
                count: bool = True) -> list[str]:
        """Feed one received frame. Returns the anomaly kinds raised (for tests/UI).
        ``count=False`` updates link quality and last-seen only (vendor chatter frames)."""
        now = self._now()
        p = self.profiles.setdefault(ieee, Profile())
        raised: list[str] = []
        if not count:
            if lqi is not None:
                p.lqi_n += 1
                p.lqi_mean += (lqi - p.lqi_mean) / min(p.lqi_n, 50)
            p.last_seen = now
            return raised
        p.frames += 1

        if seq is not None and p.last_seq is not None and p.frames > 20:
            delta = (seq - p.last_seq) % 256
            # A counter that restarts near zero is a device reboot/resync, not an impersonator
            # (who keeps a counter of their own somewhere in the middle of the range).
            if SEQ_JUMP < delta < 256 - SEQ_JUMP and seq >= 16:
                raised += self._raise(p, ieee, "sequence_jump", now, last=p.last_seq, seen=seq)
        if seq is not None:
            p.last_seq = seq

        if lqi is not None:
            if p.lqi_n >= 20 and abs(lqi - p.lqi_mean) > LQI_SWING:
                raised += self._raise(p, ieee, "link_quality_swing", now, mean=round(p.lqi_mean), seen=lqi)
            p.lqi_n += 1
            p.lqi_mean += (lqi - p.lqi_mean) / min(p.lqi_n, 50)

        if is_command and not p.commands_seen:
            if p.frames > 50:
                raised += self._raise(p, ieee, "unexpected_command", now, frames=p.frames)
            p.commands_seen = True

        minute = int(now // 60)
        if minute != p.minute:
            p.peak_minute_frames = max(p.peak_minute_frames, p.minute_frames)
            p.minute, p.minute_frames = minute, 0
        p.minute_frames += 1
        if (p.frames > 50 and p.minute_frames >= BURST_MIN_FRAMES
                and p.minute_frames > BURST_FACTOR * max(p.peak_minute_frames, 2)):
            p.burst_at = now
            raised += self._raise(p, ieee, "burst", now, frames_this_minute=p.minute_frames, usual_peak=p.peak_minute_frames)

        if p.last_seen:
            gap = now - p.last_seen
            p.typical_gap = gap if not p.typical_gap else 0.9 * p.typical_gap + 0.1 * gap
        p.last_seen = now
        return raised

    def sweep(self, devices: list[tuple[int, bool]]) -> list[str]:
        """Periodic liveness pass over (ieee, mains) pairs."""
        now = self._now()
        raised: list[str] = []
        for ieee, mains in devices:
            p = self.profiles.get(ieee)
            if not p or not p.last_seen:
                continue
            silent = now - p.last_seen
            if p.burst_at and p.last_seen <= p.burst_at + 5 and silent > SILENCE_AFTER_BURST_S:
                raised += self._raise(p, ieee, "silence_after_burst", now, silent_s=int(silent))
                p.burst_at = 0.0
            if mains and p.typical_gap and p.frames >= 20:
                limit = max(LIVENESS_MIN_S, LIVENESS_FACTOR * p.typical_gap)
                if silent > limit:
                    raised += self._raise(p, ieee, "went_silent", now, silent_s=int(silent), typical_s=int(p.typical_gap))
        return raised

    def _raise(self, p: Profile, ieee: int, kind: str, now: float, **evidence: Any) -> list[str]:
        if now - p.alerts.get(kind, 0.0) < ALERT_COOLDOWN_S:
            return []
        p.alerts[kind] = now
        self._alert("device_anomaly", ieee=f"0x{ieee:016x}", kind=kind, **evidence)
        return [kind]
