"""Over-the-air network key rotation (Zigbee 3.0 network key update).

The network key is shared by every device, so a leaked key lets anyone in radio
range read and inject traffic. Rotating it used to mean re-pairing everything.
Zigbee 3.0 provides a better way: the trust centre hands the new key to each
device individually, encrypted under that device's *own* link key, and then
broadcasts a switch. Someone holding only the old network key cannot read the
per-device deliveries, so after the switch they are locked out.

Sequence
  1. new random key, sequence number = current + 1 (mod 256)
  2. every device gets the key with evidence: a router must first answer an
     address query on the current key (a stale short address is re-resolved),
     a battery device is handed the key the moment it is heard — it polls its
     parent right after sending, the one moment a transport reaches it. The
     window (default 5 minutes) extends itself, up to a maximum, while anyone
     is missing; failed transports are retried through it
  2b. by default the switch waits for everyone — the rotation keeps offering
     the key for as long as it takes, raises a "stalled" alert after the
     maximum wait, survives a restart (the pending rotation is kept in the
     keystore) and can be cancelled; a device that is gone for good is
     removed from the registry to unblock it. Routers are checked again
     after the switch and reported if they do not answer on the new key
  3. switch, leaves first: every sleeping device is told to switch by unicast
     the moment it is heard (a broadcast never reaches a sleeping device),
     then the routers by unicast, then the coordinator itself — with the key
     items rewritten at that sequence if the radio did not follow — and the
     new key is recorded as precommissioned so the next start does not re-form.
     Afterwards every router must answer on the new key; if none does, the
     devices did not switch and the coordinator rolls itself back to the
     previous key (nothing is lost; the rotation ends "rolled_back")
  4. keystore updated: new key + its sequence, the old key kept as the
     alternate so stragglers are still heard until they rejoin

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
    phase: str = "idle"  # idle | delivering | waiting | switching | done | cancelled | aborted | failed
    started: float = 0.0
    window_s: int = DEFAULT_WINDOW_S
    max_window_s: int = 6 * 3600
    seq: int | None = None
    delivered: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)      # ieee → why the transport failed (retried)
    pending: dict[str, str] = field(default_factory=dict)     # ieee → why we wait (asleep: handed the key when it wakes)
    switch_at: float = 0.0
    error: str | None = None
    retried: int = 0                 # deliveries that succeeded on a retry
    extended: int = 0                # how often the window was extended for stragglers
    verified: bool | None = None     # the radio reports the new key as active
    finished_on_coordinator: bool = False  # the switch needed the stack restart on the coordinator
    unreachable: list[str] = field(default_factory=list)      # routers that did not answer on the new key after the switch
    aborted: dict[str, str] = field(default_factory=dict)     # ieee → reason, when the switch was refused
    stalled: bool = False            # past the maximum wait with devices still missing (an alert was raised)
    resumed: bool = False            # picked up after a restart
    by: str = ""
    switch_pending: dict[str, str] = field(default_factory=dict)  # ieee → why the switch waits (asleep: told the moment it wakes)
    switched: list[str] = field(default_factory=list)             # devices told to switch, by unicast
    rolled_back: bool = False        # the devices did not follow the switch; the coordinator returned to the previous key

    def to_json(self) -> dict[str, Any]:
        return {"phase": self.phase, "started": self.started, "window_s": self.window_s, "max_window_s": self.max_window_s, "seq": self.seq,
                "delivered": list(self.delivered), "failed": dict(self.failed), "pending": dict(self.pending), "switch_at": self.switch_at,
                "error": self.error, "seconds_left": max(0, int(self.switch_at - time.time())) if self.phase == "waiting" else 0,
                "retried": self.retried, "extended": self.extended, "verified": self.verified,
                "finished_on_coordinator": self.finished_on_coordinator, "unreachable": list(self.unreachable), "aborted": dict(self.aborted),
                "stalled": self.stalled, "resumed": self.resumed, "by": self.by,
                "waiting_s": int(time.time() - self.started) if self.phase in ("waiting", "switching") else 0,
                "switch_pending": dict(self.switch_pending), "switched": list(self.switched), "rolled_back": self.rolled_back}


class KeyRotation:
    MIN_WINDOW_S = 30
    RETRY_EVERY_S = 30   # stragglers are offered the key again this often during the window
    AWAKE_S = 30         # a battery device heard this recently is awake: hand it the key now
    LOOKUP_TIMEOUT_S = 6.0  # how long a router gets to answer an address query

    def __init__(self, coord: Coordinator, registry: Registry, keystore: Keystore, audit: Audit, *,
                 require_all: bool = True, max_window_s: int = 6 * 3600) -> None:
        self.coord = coord
        self.registry = registry
        self.keystore = keystore
        self.audit = audit
        self.require_all = require_all
        self.max_window_s = max_window_s
        self.state = RotationState()
        self._task: asyncio.Task[None] | None = None
        self._seq = 0
        self._key = b""
        self._inflight: set[str] = set()
        self._dirty = False   # progress to write to the keystore (its KDF is slow: batched, off the event loop)

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self, *, window_s: int = DEFAULT_WINDOW_S, by: str = "") -> RotationState:
        if self.running:
            raise ValueError("a key rotation is already in progress")
        window_s = max(self.MIN_WINDOW_S, min(int(window_s), 24 * 3600))
        self.state = RotationState(phase="delivering", started=time.time(), window_s=window_s, max_window_s=max(window_s, self.max_window_s), by=by)
        self._task = asyncio.create_task(self._run(by), name="key-rotation")
        return self.state

    def resume(self, pending: dict[str, Any]) -> RotationState | None:
        """Pick up a rotation the previous run left unfinished (kept in the keystore): the devices
        that already hold the new key are not asked again; the rest are offered it until they take it."""
        if self.running:
            return None
        try:
            key = bytes.fromhex(pending["key"])
            seq = int(pending["seq"]) & 0xFF
        except (KeyError, ValueError, TypeError):
            log.warning("pending rotation record unreadable — dropped")
            self._clear_pending()
            return None
        self.state = RotationState(phase="delivering", started=float(pending.get("started") or time.time()),
                                   window_s=int(pending.get("window_s") or DEFAULT_WINDOW_S), max_window_s=self.max_window_s, seq=seq,
                                   delivered=list(pending.get("delivered") or []), retried=int(pending.get("retried") or 0),
                                   extended=int(pending.get("extended") or 0), resumed=True, by=str(pending.get("by") or ""))
        self._seq, self._key = seq, key
        self.audit.security("network_key_rotation_resumed", by=self.state.by, seq=seq, delivered=len(self.state.delivered))
        self._task = asyncio.create_task(self._run(self.state.by, resume=True), name="key-rotation")
        return self.state

    # -- persistence: a rotation must survive a restart ----------------------------------------

    async def _persist_progress(self) -> None:
        st = self.state
        record = {"key": self._key.hex(), "seq": self._seq, "started": st.started, "window_s": st.window_s, "by": st.by,
                  "delivered": list(st.delivered), "retried": st.retried, "extended": st.extended}

        def write() -> None:
            s = self.keystore.load()
            s.pending_rotation = record
            self.keystore.save(s)

        self._dirty = False
        try:
            await asyncio.to_thread(write)
        except (OSError, ValueError) as e:
            log.warning("pending rotation not saved: %s", e)

    def _clear_pending(self) -> None:
        try:
            s = self.keystore.load()
            if s.pending_rotation is not None:
                s.pending_rotation = None
                self.keystore.save(s)
        except (OSError, ValueError) as e:
            log.warning("pending rotation not cleared: %s", e)

    # -- evidence per device ------------------------------------------------------------------

    @staticmethod
    def _awake_device(dev: Device) -> bool:
        return not (dev.is_router or dev.rx_on_when_idle)

    async def _reachable(self, dev: Device) -> bool:
        """A router must answer an address query on the current key before it is handed the new
        one; a stale short address is re-resolved through the network first."""
        if dev.nwk:
            ieee = await self.coord.ieee_lookup(dev.nwk, timeout=self.LOOKUP_TIMEOUT_S)
            if ieee == dev.ieee:
                return True
        nwk = await self.coord.nwk_lookup(dev.ieee, timeout=self.LOOKUP_TIMEOUT_S)
        if nwk is None:
            return False
        if nwk != dev.nwk:
            self.registry.add_or_update(dev.ieee, nwk)
            self.audit.event("short_address_learned", ieee=dev.ieee_str, nwk=f"{nwk:#06x}", by="key rotation")
        return True

    async def _deliver(self, dev: Device, *, check: bool = True) -> bool:
        st = self.state
        if check and not self._awake_device(dev) and not await self._reachable(dev):
            st.failed[dev.ieee_str] = "unreachable — not answering on the current key (power-cycle it, or check its address on the device page)"
            return False
        if not dev.nwk:
            st.failed[dev.ieee_str] = "address unknown"
            return False
        try:
            await self.coord.deliver_network_key(dev.nwk, self._seq, self._key)
        except ZnpError as e:
            st.failed[dev.ieee_str] = str(e)
            log.info("key delivery to %s refused: %s", dev.ieee_str, e)
            return False
        st.failed.pop(dev.ieee_str, None)
        st.pending.pop(dev.ieee_str, None)
        if dev.ieee_str not in st.delivered:
            st.delivered.append(dev.ieee_str)
            self._dirty = True
        return True

    def device_heard(self, dev: Device) -> None:
        """The gateway heard a frame from this device: a sleeping device is awake right now and
        will poll its parent again within moments — the one moment a transport (the key, or the
        order to switch to it) reaches it."""
        st = self.state
        if not self.running or dev.ieee_str in self._inflight:
            return
        if st.phase in ("delivering", "waiting") and (dev.ieee_str in st.pending or dev.ieee_str in st.failed):
            job, what = self._deliver_awake, "key delivered to %s while it was awake"
        elif st.phase == "switching" and dev.ieee_str in st.switch_pending:
            job, what = self._switch_device, "%s told to switch while it was awake"
        else:
            return
        self._inflight.add(dev.ieee_str)

        async def go() -> None:
            try:
                if await job(dev):
                    log.info(what, dev.ieee_str)
            finally:
                self._inflight.discard(dev.ieee_str)

        asyncio.create_task(go(), name=f"key-rotation-{dev.ieee_str}")

    def note_new_device(self, dev: Device) -> None:
        """A device joined the network while a rotation is running: it received the CURRENT key at
        join, so it must get the new key too before anyone switches — otherwise the switch cuts it
        off minutes after it was paired. It just spoke, so it is awake right now."""
        st = self.state
        if not self.running or st.phase not in ("delivering", "waiting", "switching") or dev.ieee_str in self._inflight:
            return
        if (dev.ieee_str in st.delivered or dev.ieee_str in st.pending
                or dev.ieee_str in st.failed or dev.ieee_str in st.switch_pending):
            self.device_heard(dev)
            return
        self.audit.security("rotation_adopted_new_device", ieee=dev.ieee_str, phase=st.phase)
        if st.phase == "switching":
            st.switch_pending[dev.ieee_str] = "joined during the switch — getting the key first"
            self._inflight.add(dev.ieee_str)

            async def go() -> None:
                try:
                    if await self._deliver_awake(dev):
                        await self._switch_device(dev)
                finally:
                    self._inflight.discard(dev.ieee_str)

            asyncio.create_task(go(), name=f"key-rotation-{dev.ieee_str}")
        else:
            st.pending[dev.ieee_str] = "joined during the rotation — it gets the key the moment it speaks"
            self._dirty = True
            self.device_heard(dev)

    async def _deliver_awake(self, dev: Device) -> bool:
        if await self._deliver(dev, check=False):
            self.state.retried += 1
            return True
        return False

    async def _switch_device(self, dev: Device) -> bool:
        """Unicast switch-key. If the firmware switches itself on a unicast (some do), put the radio
        back on the current key at once so the remaining devices can still be reached."""
        st = self.state
        if not dev.nwk:
            return False
        try:
            await self.coord.switch_network_key_unicast(dev.nwk, self._seq)
        except ZnpError as e:
            log.info("switch order to %s refused: %s", dev.ieee_str, e)
            return False
        st.switch_pending.pop(dev.ieee_str, None)
        if dev.ieee_str not in st.switched:
            st.switched.append(dev.ieee_str)
        try:
            if await self.coord.active_key_sequence() == self._seq and not await self.coord.active_key_matches():
                log.warning("the radio switched itself on the unicast to %s — restoring the current key until every device is told", dev.ieee_str)
                await self.coord.restore_active_key()
        except ZnpError as e:
            log.warning("could not check the radio's key after the switch order: %s", e)
        return True

    async def _retry_failed(self) -> None:
        st = self.state
        for dev in self.registry.all():
            if dev.ieee_str not in st.failed or dev.ieee_str in self._inflight:
                continue
            if await self._deliver(dev):
                st.retried += 1
                log.info("key delivered to %s on retry", dev.ieee_str)
            await asyncio.sleep(0.2)

    # -- the rotation ---------------------------------------------------------------------------

    async def _run(self, by: str, *, resume: bool = False) -> None:
        st = self.state
        try:
            current = self.coord.secrets
            if resume:
                seq, new_key = self._seq, self._key
            else:
                seq = ((await self.coord.active_key_sequence()) + 1) & 0xFF
                new_key = os.urandom(16)
                st.seq, self._seq, self._key = seq, seq, new_key
            devices = self.registry.all()
            if not resume:
                self.audit.security("network_key_rotation_started", by=by, window_s=st.window_s, seq=seq,
                                    devices=len(devices), require_all=self.require_all)
                await self._persist_progress()
            now = time.time()
            for dev in devices:
                if dev.ieee_str in st.delivered:
                    continue
                if not dev.nwk:
                    st.failed[dev.ieee_str] = "address unknown"
                elif self._awake_device(dev):
                    if dev.last_seen and now - dev.last_seen <= self.AWAKE_S:
                        await self._deliver(dev, check=False)
                    else:
                        st.pending[dev.ieee_str] = "asleep — it gets the key the moment it wakes"
                else:
                    await self._deliver(dev)
                await asyncio.sleep(0.2)
            self.audit.event("network_key_delivered", delivered=len(st.delivered), failed=len(st.failed), pending=len(st.pending))
            await self._persist_progress()
            st.phase = "waiting"
            st.switch_at = time.time() + st.window_s
            # Nobody is left behind: the window runs until every device has the key, extending
            # itself for as long as it takes — stragglers are retried, sleepers caught awake. Past
            # the maximum wait a "stalled" alert says who is holding it up (remove a device that is
            # gone for good, or cancel); with require_all off the switch goes ahead at that point.
            while True:
                self._prune_unregistered()
                if self._dirty:
                    await self._persist_progress()
                left = st.switch_at - time.time()
                if left <= 0:
                    if not st.failed and not st.pending:
                        break
                    over_max = time.time() - st.started >= st.max_window_s
                    if over_max and not self.require_all:
                        break
                    if over_max and not st.stalled:
                        st.stalled = True
                        self.audit.security("network_key_rotation_stalled", by=by, seq=seq, waiting_s=int(time.time() - st.started),
                                            missing={**st.failed, **st.pending},
                                            hint="the key keeps being offered; remove a device that is gone, or cancel the rotation")
                        log.error("key rotation stalled: still missing %s", sorted({**st.failed, **st.pending}))
                    st.switch_at = time.time() + st.window_s
                    st.extended += 1
                    if not st.stalled:
                        self.audit.event("network_key_rotation_extended", by=by, extended=st.extended,
                                         failed=sorted(st.failed), pending=sorted(st.pending))
                    await self._persist_progress()
                    continue
                await asyncio.sleep(min(self.RETRY_EVERY_S, left))
                if st.failed and time.time() < st.switch_at:
                    await self._retry_failed()
            # --- switch, leaves first --------------------------------------------------------------
            # A broadcast never reaches a sleeping device and a router switched early would cut the
            # mesh for everyone behind it, so: sleeping devices by unicast the moment each is heard,
            # then the routers by unicast, then the coordinator itself.
            st.phase = "switching"
            now = time.time()
            sleepers = [d for d in devices if d.ieee_str in st.delivered and self._awake_device(d)]
            routers = [d for d in devices if d.ieee_str in st.delivered and not self._awake_device(d)]
            for d in sleepers:
                if d.last_seen and now - d.last_seen <= self.AWAKE_S:
                    await self._switch_device(d)
                else:
                    st.switch_pending[d.ieee_str] = "asleep — told to switch the moment it wakes"
            switch_started = time.time()
            while st.switch_pending:
                self._prune_unregistered()
                for gone in [k for k in st.switch_pending if k not in {d.ieee_str for d in self.registry.all()}]:
                    st.switch_pending.pop(gone, None)
                if time.time() - switch_started >= st.max_window_s and not st.stalled:
                    st.stalled = True
                    self.audit.security("network_key_rotation_stalled", by=by, seq=seq, waiting_s=int(time.time() - st.started),
                                        missing=dict(st.switch_pending), stage="switch",
                                        hint="these sleeping devices have not woken since; remove a device that is gone, or cancel")
                if time.time() - switch_started >= st.max_window_s and not self.require_all:
                    break
                await asyncio.sleep(1.0)
            for d in routers:
                await self._switch_device(d)
            await self.coord.switch_network_key(seq)  # broadcast as well, for whoever listens
            self.keystore.save(NetworkSecrets(network_key=new_key, pan_id=current.pan_id, ext_pan_id=current.ext_pan_id,
                                              channel=current.channel, tc_install_code=current.tc_install_code,
                                              frame_counter=current.frame_counter, tclk_seed=current.tclk_seed,
                                              key_seq=seq, previous_network_key=current.network_key,
                                              previous_key_seq=(await self.coord.active_key_sequence()) if not await self.coord.active_key_matches() else (seq - 1) & 0xFF,
                                              pending_rotation=None, last_rotation_ts=time.time()))
            self.coord.secrets = self.keystore.load()
            self.coord.keystore = self.keystore
            verified = await self.coord.active_key_matches()
            if not verified:
                # The radio did not take the broadcast switch for itself (seen on Z-Stack 3.x.0): the
                # devices are on the new key now, so the coordinator must follow — a short stack
                # restart with the key items rewritten at this sequence.
                log.warning("radio did not take the new key on the broadcast switch — finishing the switch on the coordinator")
                st.finished_on_coordinator = True
                verified = await self.coord.finish_key_switch()
            else:
                await self.coord.finish_key_switch()  # records the key as precommissioned so the next start does not re-form
            st.verified = verified
            # Ground truth after the switch: every router that was given the key (and is still
            # registered — one the owner removed meanwhile is not waited for) must answer on it.
            known = {d.ieee_str for d in self.registry.all()}
            checked = [d for d in routers if d.ieee_str in known and d.nwk]
            for dev in checked:
                if await self.coord.ieee_lookup(dev.nwk, timeout=self.LOOKUP_TIMEOUT_S) != dev.ieee:
                    st.unreachable.append(dev.ieee_str)
            if checked and len(st.unreachable) >= len(checked):
                # Nobody answers on the new key: the devices did not switch. The coordinator goes back
                # to the previous key so nothing is lost; the rotation is reported, not pretended.
                log.error("no router answers on the new key — the devices did not switch; the coordinator returns to the previous key")
                ok = await self.coord.rollback_key_switch()
                st.rolled_back = True
                st.phase = "rolled_back"
                st.error = "the devices did not switch to the new key; the coordinator returned to the previous key"
                self.audit.security("network_key_rotation_rolled_back", by=by, seq=seq, delivered=len(st.delivered), switched=len(st.switched),
                                    unreachable=sorted(st.unreachable), coordinator_restored=ok)
                return
            st.phase = "done"
            self.audit.security("network_key_rotated", by=by, seq=seq, delivered=len(st.delivered), failed=len(st.failed),
                                pending=len(st.pending), retried=st.retried, extended=st.extended, verified=verified,
                                finished_on_coordinator=st.finished_on_coordinator, unreachable=sorted(st.unreachable), switched=len(st.switched))
            if not verified:
                log.error("key switch sent but the radio does not report the new key as active — use Maintenance → Finish key switch")
            if st.unreachable:
                log.warning("after the switch %d router(s) do not answer on the new key: %s", len(st.unreachable), ", ".join(st.unreachable))
        except asyncio.CancelledError:
            st.phase = "cancelled"
            st.error = "cancelled — the old key stays in force"
            self._clear_pending()
            self.audit.security("network_key_rotation_cancelled", by=by, seq=seq, delivered=len(st.delivered),
                                missing=sorted({**st.failed, **st.pending}))
            raise
        except Exception as e:
            log.exception("key rotation failed")
            st.phase = "failed"
            st.error = str(e)
            self._clear_pending()
            self.audit.security("network_key_rotation_failed", error=str(e))

    def _prune_unregistered(self) -> None:
        """A device the owner removed no longer holds the rotation up."""
        st = self.state
        known = {d.ieee_str for d in self.registry.all()}
        for gone in [k for k in list(st.failed) + list(st.pending) if k not in known]:
            st.failed.pop(gone, None)
            st.pending.pop(gone, None)
            log.info("%s removed from the registry — no longer waited for", gone)

    def cancel(self) -> bool:
        if self.running and self.state.phase in ("delivering", "waiting", "switching"):
            self._task.cancel()  # type: ignore[union-attr]
            return True
        return False


def candidates(registry: Registry) -> list[Device]:
    return [d for d in registry.all() if d.nwk]
