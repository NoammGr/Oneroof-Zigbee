"""Over-the-air network key rotation (Zigbee 3.0 network key update).

The network key is shared by every device, so a leaked key lets anyone in radio
range read and inject traffic. Rotating it used to mean re-pairing everything.
Zigbee 3.0 provides a better way: the trust centre hands the new key to each
device individually, encrypted under that device's *own* link key, and then
broadcasts a switch. Someone holding only the old network key cannot read the
per-device deliveries, so after the switch they are locked out.

Sequence
  1. new random key, sequence number = current + 1 (mod 256)
  2. for every known device: unicast key transport under its link key
     (sleepy devices receive it from their parent when they next poll, so a
     delivery window follows — configurable, default 5 minutes)
  3. broadcast "switch key"; the coordinator switches too
  4. keystore updated; the old key is gone

A device that slept through the whole window rejoins with its link key on its
next contact and receives the current key from the trust centre (secure rejoin),
so nothing needs re-pairing.

Limits, stated plainly: whoever also holds the trust-centre link-key seed (for
example from the previous setup's backup files) can follow the rotation. Only
a fresh pairing (new seed) excludes them; the UI says so.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

from .devices import Device, Registry
from .security import Audit, Keystore, NetworkSecrets
from .znp import Coordinator, ZnpError

log = logging.getLogger("oneroof_zigbee.rotation")

DEFAULT_WINDOW_S = 300


@dataclass
class RotationState:
    phase: str = "idle"  # idle | delivering | waiting | switching | done | failed
    started: float = 0.0
    window_s: int = DEFAULT_WINDOW_S
    seq: int | None = None
    delivered: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    switch_at: float = 0.0
    error: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {"phase": self.phase, "started": self.started, "window_s": self.window_s, "seq": self.seq,
                "delivered": list(self.delivered), "failed": dict(self.failed), "switch_at": self.switch_at,
                "error": self.error, "seconds_left": max(0, int(self.switch_at - time.time())) if self.phase == "waiting" else 0}


class KeyRotation:
    MIN_WINDOW_S = 30

    def __init__(self, coord: Coordinator, registry: Registry, keystore: Keystore, audit: Audit) -> None:
        self.coord = coord
        self.registry = registry
        self.keystore = keystore
        self.audit = audit
        self.state = RotationState()
        self._task: asyncio.Task[None] | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self, *, window_s: int = DEFAULT_WINDOW_S, by: str = "") -> RotationState:
        if self.running:
            raise ValueError("a key rotation is already in progress")
        window_s = max(self.MIN_WINDOW_S, min(int(window_s), 24 * 3600))
        self.state = RotationState(phase="delivering", started=time.time(), window_s=window_s)
        self._task = asyncio.create_task(self._run(by), name="key-rotation")
        return self.state

    async def _run(self, by: str) -> None:
        st = self.state
        try:
            current = self.coord.secrets
            seq = ((await self.coord.active_key_sequence()) + 1) & 0xFF
            new_key = os.urandom(16)
            st.seq = seq
            self.audit.security("network_key_rotation_started", by=by, window_s=st.window_s, seq=seq,
                                devices=len(self.registry.all()))
            for dev in self.registry.all():
                if not dev.nwk:
                    st.failed[dev.ieee_str] = "address unknown"
                    continue
                try:
                    await self.coord.deliver_network_key(dev.nwk, seq, new_key)
                    st.delivered.append(dev.ieee_str)
                except ZnpError as e:
                    st.failed[dev.ieee_str] = str(e)
                    log.info("key delivery to %s refused: %s", dev.ieee_str, e)
                await asyncio.sleep(0.2)
            self.audit.event("network_key_delivered", delivered=len(st.delivered), failed=len(st.failed))
            st.phase = "waiting"
            st.switch_at = time.time() + st.window_s
            await asyncio.sleep(st.window_s)
            st.phase = "switching"
            await self.coord.switch_network_key(seq)
            self.keystore.save(NetworkSecrets(network_key=new_key, pan_id=current.pan_id, ext_pan_id=current.ext_pan_id,
                                              channel=current.channel, tc_install_code=current.tc_install_code,
                                              frame_counter=current.frame_counter, tclk_seed=current.tclk_seed))
            self.coord.secrets = self.keystore.load()
            verified = await self.coord.active_key_matches()
            st.phase = "done"
            self.audit.security("network_key_rotated", by=by, seq=seq, delivered=len(st.delivered),
                                failed=len(st.failed), verified=verified)
            if not verified:
                log.error("key switch sent but the radio does not report the new key as active")
        except asyncio.CancelledError:
            st.phase = "failed"
            st.error = "cancelled"
            raise
        except Exception as e:
            log.exception("key rotation failed")
            st.phase = "failed"
            st.error = str(e)
            self.audit.security("network_key_rotation_failed", error=str(e))

    def cancel(self) -> None:
        if self.running and self.state.phase in ("delivering", "waiting"):
            self._task.cancel()  # type: ignore[union-attr]


def candidates(registry: Registry) -> list[Device]:
    return [d for d in registry.all() if d.nwk]
