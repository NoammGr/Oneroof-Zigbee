"""Liveness and anomaly monitor.

Zigbee has no per-device secure session, so a stolen network key cannot be made
harmless by the protocol. What the gateway can do is watch behaviour the way a
physical access-control line does: every device has a rhythm, and an intruder
with a radio breaks it. This module keeps a small behavioural profile per
device and raises `device_anomaly` security alerts when:

* **sequence jump** — the ZCL transaction sequence from a device skips far
  ahead or runs backwards outside the normal wrap (an impersonator keeps
  its own counter);
* **link-quality swing** — a frame arrives at a link quality unlike any level
  the device has been heard at (a different radio in a different place). A
  device with two routes to the coordinator is heard at two levels, and
  alternating between known levels is routing, not an anomaly: each level
  alerts once, when it first appears;
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
LQI_SWING = 80           # a frame this far from every known level is a new level (needs >= 20 samples)
LQI_LEVELS = 4           # how many distinct levels a device may be heard at before the oldest is forgotten
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
    seq_heads: list[int] = field(default_factory=list)  # devices run several independent counters (per cluster/endpoint)
    seq_pending: int = 0
    silent_alerted: bool = False
    lqi_mean: float = 0.0
    lqi_n: int = 0
    lqi_levels: list[float] = field(default_factory=list)  # the link qualities this device is heard at (routes)
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
            p.silent_alerted = False
            return raised
        p.frames += 1
        p.silent_alerted = False

        if seq is not None and p.frames > 20:
            # Devices legitimately run several independent counters (one per cluster/endpoint), so a
            # value close to ANY recent head is normal. A restart near zero is a reboot. Only a value
            # matching no head, twice in a row, is an anomaly.
            matched = False
            for i, h in enumerate(p.seq_heads):
                fwd = (seq - h) % 256
                back = (h - seq) % 256
                # Counters only advance: accept a bounded step forward, or a tiny step back (retry).
                if fwd <= SEQ_JUMP or back <= 8:
                    if fwd <= SEQ_JUMP:
                        p.seq_heads[i] = seq
                    matched = True
                    break
            if matched or seq < 16 or len(p.seq_heads) < 4:
                if not matched:
                    p.seq_heads.append(seq)
                    del p.seq_heads[:-4]
                p.seq_pending = 0
            else:
                p.seq_pending += 1
                if p.seq_pending >= 2:
                    raised += self._raise(p, ieee, "sequence_jump", now, heads=list(p.seq_heads), seen=seq)
                    p.seq_pending = 0
                p.seq_heads.append(seq)
                del p.seq_heads[:-4]
        if seq is not None:
            p.last_seq = seq

        if lqi is not None and lqi > 0:
            # Zero is "no reading" on this stack, never a real link; it must not open a level.
            raised += self._track_lqi(p, ieee, lqi, now)

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

    def sweep(self, devices: list[tuple[int, bool] | tuple[int, bool, bool]]) -> list[tuple[int, str]]:
        """Periodic liveness pass over (ieee, mains[, quiet_expected]) tuples. Returns (ieee, kind)
        per finding, so the caller can act per device (e.g. mark it offline). A device whose
        silence is expected - it is marked as switched off at the wall - is still returned
        as ``went_silent`` so the caller can show it off, but it raises no security alert:
        a lamp cut from power is not a supervised line gone quiet."""
        now = self._now()
        raised: list[tuple[int, str]] = []
        for entry in devices:
            ieee, mains = entry[0], entry[1]
            quiet_expected = bool(entry[2]) if len(entry) > 2 else False
            p = self.profiles.get(ieee)
            if not p or not p.last_seen:
                continue
            silent = now - p.last_seen
            if p.burst_at and p.last_seen <= p.burst_at + 5 and silent > SILENCE_AFTER_BURST_S:
                raised += [(ieee, k) for k in self._raise(p, ieee, "silence_after_burst", now, silent_s=int(silent))]
                p.burst_at = 0.0
            if mains and p.typical_gap and p.frames >= 20 and not p.silent_alerted:
                limit = max(LIVENESS_MIN_S, LIVENESS_FACTOR * p.typical_gap)
                if silent > limit:
                    # Once per outage: the flag clears when the device is heard again, so a bulb cut
                    # from power (wall switch) alerts once, not every sweep until eternity.
                    p.silent_alerted = True
                    if quiet_expected:
                        raised.append((ieee, "went_silent"))
                    else:
                        raised += [(ieee, k) for k in self._raise(p, ieee, "went_silent", now, silent_s=int(silent), typical_s=int(p.typical_gap))]
        return raised

    def _track_lqi(self, p: Profile, ieee: int, lqi: int, now: float) -> list[str]:
        """Link quality as a set of levels rather than one average. A router that is heard
        directly at 40 and through a neighbour at 180 is at two levels, for good; both are
        its own. Only a level no frame has been near before is worth a word, and it is said
        once, when the level appears - not every cooldown for as long as the routes alternate."""
        raised: list[str] = []
        if not p.lqi_levels and p.lqi_n:
            # A profile written before levels existed knows only its running average: that
            # average is the one level it has been heard at, not an empty history. Without
            # this, every device's first frame after an upgrade read as a new level.
            p.lqi_levels.append(p.lqi_mean)
        near = min(p.lqi_levels, key=lambda c: abs(c - lqi), default=None)
        if near is not None and abs(near - lqi) <= LQI_SWING:
            p.lqi_levels[p.lqi_levels.index(near)] = near + (lqi - near) / 20.0
        else:
            if p.lqi_n >= 20:
                raised += self._raise(p, ieee, "link_quality_swing", now, mean=round(p.lqi_mean), seen=lqi,
                                      levels=[round(c) for c in p.lqi_levels])
            p.lqi_levels.append(float(lqi))
            del p.lqi_levels[:-LQI_LEVELS]
        p.lqi_n += 1
        p.lqi_mean += (lqi - p.lqi_mean) / min(p.lqi_n, 50)
        return raised

    def _raise(self, p: Profile, ieee: int, kind: str, now: float, **evidence: Any) -> list[str]:
        if now - p.alerts.get(kind, 0.0) < ALERT_COOLDOWN_S:
            return []
        p.alerts[kind] = now
        self._alert("device_anomaly", ieee=f"0x{ieee:016x}", kind=kind, **evidence)
        return [kind]
