"""Coordinator bring-up and high-level radio operations on Z-Stack 3.x.

Security posture applied at every start (not optional):

1. Network key, PAN id, ext PAN id are random per installation (from the
   keystore), never the Z-Stack defaults.
2. PRECFGKEYS_ENABLE = 1 only while the network is formed (that is the only
   way the firmware takes PRECFGKEY as the network key; otherwise it makes
   up a random one), then 0 again: the key is never *assumed* shared and is
   transported to a joining device encrypted under a link key.
3. TC_REQUIRE_KEY_EXCHANGE = 1 → Zigbee 3.0 devices must complete the
   TCLK update after joining or they are kicked off the network.
4. Rejoin-with-default-TCLK policy disabled → a device that lost the network
   key cannot come back using the public "ZigBeeAlliance09" key.
5. Permit-join is always 0 at startup, and capped by JoinGuard.
6. Optional "strict" mode: the default centralized link key is replaced with
   our own random key, so the *only* way to join is with an install code.
   Devices that only support the public key cannot join in strict mode — this
   is the trade-off the user opts into knowingly.
"""

from __future__ import annotations

from typing import Any

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ..security import Audit, JoinGuard, NetworkSecrets, derive_link_key
from . import commands as c
from .commands import AfCmd, NvId, SysCmd, ZdoCmd
from .transport import Transport, ZnpStatusError, ZnpTimeout
from .unpi import Frame, FrameType, Subsystem

log = logging.getLogger("oneroof_zigbee.znp.coordinator")

HA_PROFILE = 0x0104
FRAME_COUNTER_MARGIN = 1 << 20  # ~1M frames of headroom over the saved counter
# SYS_VERSION revisions are the firmware's build date (YYYYMMDD); One Roof builds
# start 2026-08-28, everything older is a stock TI/community image.
ONEROOF_MIN_REVISION = 20260828
GATEWAY_ENDPOINT = 1
# clusters we advertise on our endpoint so devices bind/report to us
GATEWAY_IN_CLUSTERS = [0x0000, 0x0003, 0x0006, 0x000A, 0x0019, 0x0500]
GATEWAY_OUT_CLUSTERS = [0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x0020, 0x0300,
                        0x0400, 0x0402, 0x0403, 0x0405, 0x0406, 0x0500, 0x0702, 0x0B04, 0x0102, 0x0201]


@dataclass(frozen=True)
class IncomingAps:
    src_addr: int
    src_ep: int
    dst_ep: int
    cluster: int
    group: int
    lqi: int
    secure: bool
    seq: int
    payload: bytes


@dataclass(frozen=True)
class JoinedDevice:
    ieee: int
    nwk: int
    parent: int | None
    capabilities: int
    plain_join: bool = False  # joined through a window without install code: the key travelled under the public key


ApsCb = Callable[[IncomingAps], Awaitable[None]]
JoinCb = Callable[[JoinedDevice], Awaitable[None]]
LeaveCb = Callable[[int, int, bool], Awaitable[None]]  # ieee, nwk, rejoin (the device is coming back)


class Coordinator:
    def __init__(self, transport: Transport, secrets: NetworkSecrets, guard: JoinGuard, audit: Audit,
                 *, strict_install_codes: bool = False) -> None:
        self.t = transport
        self.secrets = secrets
        self.guard = guard
        self.audit = audit
        self.strict = strict_install_codes
        self.keystore: Any = None  # Keystore, when the owner wants sequence/key fixes persisted (set by __main__ / rotation)
        self.version: c.Version | None = None
        self.ieee: int = 0
        self._trans_id = 0
        self._aps_cbs: list[ApsCb] = []
        self._join_cbs: list[JoinCb] = []
        self._leave_cbs: list[LeaveCb] = []
        self._pending_confirms: dict[int, asyncio.Future[int]] = {}
        self._permit_task: asyncio.Task[None] | None = None
        # IEEEs already on the network (fed by the gateway's registry). Announces from
        # these are rejoins (power cycle, parent change) and must never be judged as joins.
        self.known_ieee: set[int] = set()
        self.radio_tuning: dict[str, int] = {}  # routing/broadcast settings the operator chose
        self._wire_listeners()

    # ------------------------------------------------------------ events --

    def on_aps(self, cb: ApsCb) -> None:
        self._aps_cbs.append(cb)

    def on_device_joined(self, cb: JoinCb) -> None:
        self._join_cbs.append(cb)

    def on_device_left(self, cb: LeaveCb) -> None:
        self._leave_cbs.append(cb)

    def rebind(self, transport: Transport) -> None:
        """Point the coordinator at a fresh transport after the serial link was
        lost and reopened, and re-register the frame listeners on it. The
        registered callbacks (on_aps/on_device_joined/...) and known_ieee live
        on this object, so the gateway keeps its Coordinator reference across a
        reconnect — only the underlying transport changes. Call start() after.
        """
        self.t = transport
        self._wire_listeners()

    def _wire_listeners(self) -> None:
        self.t.on(Subsystem.AF, AfCmd.INCOMING_MSG, self._on_incoming)
        self.t.on(Subsystem.AF, AfCmd.DATA_CONFIRM, self._on_confirm)
        self.t.on(Subsystem.ZDO, ZdoCmd.END_DEVICE_ANNCE_IND, self._on_announce)
        self.t.on(Subsystem.ZDO, ZdoCmd.TC_DEV_IND, self._on_tc_dev)
        self.t.on(Subsystem.ZDO, ZdoCmd.LEAVE_IND, self._on_leave)
        self.t.on(Subsystem.ZDO, ZdoCmd.PERMIT_JOIN_IND, self._on_permit_ind)
        self.t.on(Subsystem.ZDO, ZdoCmd.MSG_CB_INCOMING, self._on_zdo_forwarded)
        self.t.on(Subsystem.SYS, SysCmd.RESET_IND, lambda f: log.warning("coordinator reset indication %s", f.data.hex()))

    async def _on_incoming(self, f: Frame) -> None:
        m = c.decode_af_incoming_msg(f.data)
        msg = IncomingAps(m.src_addr, m.src_ep, m.dst_ep, m.cluster, m.group, m.lqi, m.security_use, m.trans_seq, m.data)
        for cb in self._aps_cbs:
            try:
                await cb(msg)
            except Exception:
                log.exception("aps handler failed")

    def _on_confirm(self, f: Frame) -> None:
        d = c.decode_af_data_confirm(f.data)
        fut = self._pending_confirms.pop(d.trans_id, None)
        if fut and not fut.done():
            fut.set_result(d.status)

    def _on_zdo_forwarded(self, f: Frame) -> None:
        """Firmware that forwards ZDO responses only through the message callback (after
        MSG_CB_REGISTER) delivers them in a generic envelope; re-issue the classic indication so
        the waiters in node_descriptor()/active_endpoints()/bind()/… see them."""
        d = c.decode_msg_cb_incoming(f.data)
        if d is None:
            return
        src, cluster, payload = d
        mt = c.ZDO_RSP_CLUSTER_TO_MT.get(cluster)
        if mt is None:
            return
        self.t.inject(Frame(FrameType.AREQ, Subsystem.ZDO, mt, src.to_bytes(2, "little") + payload))

    async def _on_announce(self, f: Frame) -> None:
        a = c.decode_end_device_annce(f.data)
        if a.ieee in self.known_ieee:
            self.audit.event("device_rejoined", ieee=f"0x{a.ieee:016x}", nwk=f"{a.nwk_addr:#06x}")
            dev = JoinedDevice(a.ieee, a.nwk_addr, None, a.capabilities)
            for cb in self._join_cbs:
                await cb(dev)
            return
        expected = self.guard.on_device_joined(a.ieee, a.nwk_addr)
        if not expected:
            # Defence in depth: the firmware should not have admitted it; evict.
            log.error("evicting unexpected device 0x%016x", a.ieee)
            try:
                await self.remove_device(a.nwk_addr, a.ieee)
            except Exception:
                log.exception("eviction failed")
            return
        self.known_ieee.add(a.ieee)
        w = self.guard.window
        plain = bool(w and not w.install_code)
        if w and (self.guard.policy.close_after_first_join or w.allowed_ieee is not None):
            # One device per window: nothing else can slip in behind the one we expected.
            self.audit.event("permit_join_closed_after_join", ieee=f"0x{a.ieee:016x}")
            if self._permit_task:
                self._permit_task.cancel()
            await self._force_close_join()
        dev = JoinedDevice(a.ieee, a.nwk_addr, None, a.capabilities, plain_join=plain)
        for cb in self._join_cbs:
            await cb(dev)

    def _on_tc_dev(self, f: Frame) -> None:
        d = c.decode_tc_dev_ind(f.data)
        self.audit.event("tc_device_ind", ieee=f"0x{d.ieee:016x}", nwk=f"{d.nwk_addr:#06x}", parent=f"{d.parent_addr:#06x}")

    async def _on_leave(self, f: Frame) -> None:
        d = c.decode_leave_ind(f.data)
        self.audit.event("device_left", ieee=f"0x{d.ieee:016x}", nwk=f"{d.src_addr:#06x}", rejoin=d.rejoin)
        for cb in self._leave_cbs:
            await cb(d.ieee, d.src_addr, d.rejoin)

    def _on_permit_ind(self, f: Frame) -> None:
        d = c.decode_permit_join_ind(f.data)
        if d.duration == 0:
            self.guard.mark_closed("firmware reports closed")
        elif self.guard.window is None:
            # Someone (a router, or a bug) opened joining without going through us.
            self.audit.security("permit_join_unexpected_open", duration=d.duration)
            asyncio.create_task(self._force_close_join())

    # ------------------------------------------------------------- start --

    async def start(self) -> None:
        await self._reset()
        ver = await self.t.request(c.sys_version(), check_status=False)
        self.version = c.decode_version(ver.data)
        log.info("Z-Stack product=%d version %d.%d.%d rev=%s", self.version.product, self.version.major,
                 self.version.minor, self.version.maint, self.version.revision)
        if not self.version.is_zstack3:
            raise RuntimeError("only Z-Stack 3.x coordinators are supported (CC2652/CC1352)")

        bad = await self._config_mismatches()
        on_net = await self._nv_read(NvId.BDBNODEISONANETWORK)
        if bad and on_net and on_net[0] == 1:
            # The radio says it is on a network. The config NV items are hints, not the network:
            # a restore made outside the add-on (zigpy-znp and friends) writes the live network
            # state but not these items. Start the radio and judge by the network it is actually
            # on; re-form only when THAT disagrees — re-forming over a live matching network is
            # exactly what cuts every device off.
            log.warning("coordinator NV config differs (%s) but the radio reports a network — judging by the live network",
                        ", ".join(x.name for x in bad))
            self.audit.security("network_config_suspect", items=[x.name for x in bad])
            await self._apply_runtime_security()
            await self._startup()
            live = c.decode_ext_nwk_info((await self.t.request(c.zdo_ext_nwk_info(), check_status=False)).data)
            if live.pan_id != self.secrets.pan_id or live.channel != self.secrets.channel:
                log.warning("live network pan=%#06x channel=%d does not match the keystore (pan=%#06x channel=%d) — (re)forming",
                            live.pan_id, live.channel, self.secrets.pan_id, self.secrets.channel)
                await self._form_network()
            else:
                s = self.secrets
                for item, want in ((NvId.PANID, s.pan_id.to_bytes(2, "little")),
                                   (NvId.EXTPANID, s.ext_pan_id.to_bytes(8, "little")),
                                   (NvId.APS_USE_EXT_PANID, s.ext_pan_id.to_bytes(8, "little")),
                                   (NvId.CHANLIST, (1 << s.channel).to_bytes(4, "little")),
                                   (NvId.LOGICAL_TYPE, b"\x00")):
                    try:
                        await self._nv_write(item, want)
                    except ZnpStatusError as e:
                        log.info("config item %s not rewritten (%s)", item.name, e)
                log.warning("live network matches the keystore — config items repaired, nothing re-formed")
                self.audit.event("network_config_repaired", items=[x.name for x in bad])
                if NvId.PRECFGKEY in bad:
                    # The key story is decided by _verify_active_key below, never by re-forming.
                    self.audit.security("network_key_switch_unfinished")
        elif bad:
            log.warning("coordinator NV config does not match keystore and the radio is not on a network — (re)forming")
            await self._form_network()
        else:
            await self._apply_runtime_security()
            await self._startup()

        info = await self.t.request(c.util_get_device_info())
        di = c.decode_device_info(info.data)
        self.ieee = di.ieee
        nwk = c.decode_ext_nwk_info((await self.t.request(c.zdo_ext_nwk_info(), check_status=False)).data)
        log.info("coordinator 0x%016x up: pan=%#06x channel=%d state=%d", self.ieee, nwk.pan_id, nwk.channel, di.device_state)
        self.audit.event("coordinator_started", ieee=f"0x{self.ieee:016x}", pan_id=f"{nwk.pan_id:#06x}", channel=nwk.channel,
                         strict_install_codes=self.strict)
        if nwk.pan_id != self.secrets.pan_id or nwk.channel != self.secrets.channel:
            # The firmware kept a previous network instead of applying ours: the keystore and the
            # radio disagree, which after a key rotation means the old key is still in use.
            log.error("coordinator is on pan=%#06x channel=%d but the keystore says pan=%#06x channel=%d — "
                      "the network was not (re)formed", nwk.pan_id, nwk.channel, self.secrets.pan_id, self.secrets.channel)
            self.audit.security("network_parameters_mismatch", radio_pan_id=f"{nwk.pan_id:#06x}", radio_channel=nwk.channel,
                                keystore_pan_id=f"{self.secrets.pan_id:#06x}", keystore_channel=self.secrets.channel)

        await self._register_endpoint()
        await self._register_zdo_callbacks()
        await self._force_close_join()
        await self._verify_active_key()
        await self._reapply_radio_tuning()
        if self.secrets.frame_counter:
            await self._ensure_frame_counter(self.secrets.frame_counter + FRAME_COUNTER_MARGIN)
        asyncio.create_task(self._neighbour_check(), name="neighbour-check")

    async def _neighbour_check(self) -> None:
        """Ground truth for key/radio health: routers announce themselves every 15 s under the
        network key; a coordinator that can decrypt them lists them as neighbours."""
        await asyncio.sleep(45)
        try:
            n = await self.neighbors(0x0000)
        except (ZnpTimeout, ZnpStatusError) as e:
            log.warning("neighbour table unavailable (%s)", e)
            return
        routers = [x for x in n if x.device_type == 1]
        log.info("coordinator hears %d neighbour(s), %d router(s)%s", len(n), len(routers),
                 "" if n else " — nothing decrypts: wrong network key, or no router in range")
        self.audit.event("neighbour_check", neighbours=len(n), routers=len(routers),
                         lqi=[x.lqi for x in n][:16])
        if not n:
            self.audit.security("no_neighbours_heard")

    async def _reset(self) -> None:
        reset_ind = await self._arm(self.t.wait_for(Subsystem.SYS, SysCmd.RESET_IND, timeout=8.0))
        self.t.send(c.sys_reset(soft=True))
        try:
            await reset_ind
        except ZnpTimeout:
            # Some dongles do not echo RESET_IND over USB-CDC; a ping proves liveness.
            await asyncio.sleep(1.0)
        await self.t.request(c.sys_ping(), check_status=False)

    async def _nv_read(self, item: int) -> bytes | None:
        try:
            rsp = await self.t.request(c.nv_read(item), check_status=False)
        except ZnpTimeout:
            return None
        status, value = c.decode_nv_read(rsp.data)
        return value if status == 0 else None

    async def _nv_write(self, item: int, value: bytes) -> None:
        try:
            await self.t.request(c.nv_item_init(item, len(value), value))
        except ZnpStatusError as e:
            if e.status not in (0x00, 0x09):  # 0x09 = item already existed
                raise
        await self.t.request(c.nv_write(item, value))

    async def _config_mismatches(self) -> list[NvId]:
        """NV items that disagree with the keystore (empty = the radio is on our network)."""
        s = self.secrets
        checks = {
            NvId.PRECFGKEY: s.network_key,
            NvId.PANID: s.pan_id.to_bytes(2, "little"),
            NvId.EXTPANID: s.ext_pan_id.to_bytes(8, "little"),
            NvId.CHANLIST: (1 << s.channel).to_bytes(4, "little"),
            NvId.LOGICAL_TYPE: b"\x00",
        }
        bad: list[NvId] = []
        for item, want in checks.items():
            got = await self._nv_read(item)
            if got is None or got[: len(want)] != want:
                shown = (got[: len(want)].hex() if got else None) if item != NvId.PRECFGKEY else ("<key>" if got else None)
                log.warning("coordinator NV %s differs: dongle=%s keystore=%s", item.name, shown,
                            want.hex() if item != NvId.PRECFGKEY else "<key>")
                self.audit.event("coordinator_nv_mismatch", item=item.name)
                bad.append(item)
        on_net = await self._nv_read(NvId.BDBNODEISONANETWORK)
        if not (on_net and on_net[0] == 1):
            bad.append(NvId.BDBNODEISONANETWORK)
        return bad

    async def _config_matches(self) -> bool:
        return not await self._config_mismatches()

    async def _form_network(self) -> None:
        s = self.secrets
        # 1. wipe
        await self._nv_write(NvId.STARTUP_OPTION, bytes([c.StartupOption.CLEAR_ALL]))
        await self._reset()
        # 2. configure
        await self._nv_write(NvId.LOGICAL_TYPE, b"\x00")
        await self._nv_write(NvId.PRECFGKEYS_ENABLE, b"\x01")  # use PRECFGKEY for the network (see module doc)
        await self._nv_write(NvId.PRECFGKEY, s.network_key)
        await self._nv_write(NvId.ZDO_DIRECT_CB, b"\x01")
        await self._nv_write(NvId.PANID, s.pan_id.to_bytes(2, "little"))
        await self._nv_write(NvId.EXTPANID, s.ext_pan_id.to_bytes(8, "little"))
        await self._nv_write(NvId.APS_USE_EXT_PANID, s.ext_pan_id.to_bytes(8, "little"))
        await self._nv_write(NvId.CHANLIST, (1 << s.channel).to_bytes(4, "little"))
        if s.tclk_seed:
            # Imported network: devices hold link keys derived from the previous coordinator's seed.
            await self._nv_write(NvId.TCLK_SEED, s.tclk_seed)
            self.audit.event("tclk_seed_restored")
        await self._nv_write(NvId.STARTUP_OPTION, bytes([c.StartupOption.NONE]))
        await self._reset()
        await self._apply_runtime_security()
        if s.frame_counter:
            # The saved counter is from the last backup, the dongle may have sent many frames
            # since; devices drop anything at or below what they last saw, so jump well ahead.
            counter = min(s.frame_counter + FRAME_COUNTER_MARGIN, 0xFFFF_FFFF)
            try:
                await self.t.request(c.appcnf_set_nwk_frame_counter(counter))
                self.audit.event("frame_counter_restored", value=counter, saved=s.frame_counter)
            except ZnpStatusError as e:
                log.warning("could not set NWK frame counter (%s); devices from an imported network may ignore us until they rejoin", e)
        # 3. form
        await self.t.request(c.appcnf_set_channel(True, 1 << s.channel))
        await self.t.request(c.appcnf_set_channel(False, 0))
        coord_up = await self._arm(self._wait_coordinator_state(60.0))
        await self.t.request(c.appcnf_start_commissioning(c.CommissioningMode.NWK_FORMATION))
        await coord_up
        # The firmware built the network state; now install our key material the way a restore
        # does — stack stopped, items written, then started. Joining devices must receive the key
        # (never assume it), so PRECFGKEYS_ENABLE goes back to 0.
        await self._nv_write(NvId.PRECFGKEYS_ENABLE, b"\x00")
        await self._reset()
        await self._write_security_state_stopped()
        await self._apply_runtime_security()
        await self._startup()
        # Some firmware ignores the configured PAN/channel and forms its own (the config NV is
        # consumed by a pending CLEAR_STATE, or the stack simply picks). For a FRESH network the
        # identity is arbitrary — the keys are ours either way (verified below) — so the keystore
        # adopts what actually formed instead of running a network the radio does not have.
        live = c.decode_ext_nwk_info((await self.t.request(c.zdo_ext_nwk_info(), check_status=False)).data)
        if live.pan_id not in (0, 0xFFFF) and (live.pan_id != s.pan_id or live.channel != s.channel
                                               or (live.ext_pan_id and live.ext_pan_id != s.ext_pan_id)):
            log.warning("radio formed pan=%#06x channel=%d (asked for pan=%#06x channel=%d) — adopting the formed identity",
                        live.pan_id, live.channel, s.pan_id, s.channel)
            s.pan_id, s.channel = live.pan_id, live.channel
            if live.ext_pan_id:
                s.ext_pan_id = live.ext_pan_id
            self.audit.security("network_identity_adopted", pan_id=f"{live.pan_id:#06x}", channel=live.channel)
        self.network_was_formed = True  # the gateway marks every known device offline until it rejoins
        s.formed_ts = time.time()
        s.last_rotation_ts = time.time()  # a fresh network is a fresh key: start the rotation clock
        self._persist_secrets()
        self.audit.security("network_formed", channel=s.channel, pan_id=f"{s.pan_id:#06x}")

    async def _verify_active_key(self) -> None:
        """Compare the key the radio actually uses with the keystore (never printed)."""
        raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
        if raw is None or len(raw) < 17:
            log.warning("could not read the active network key item from the coordinator")
            return
        same = raw[1:17] == self.secrets.network_key
        log.info("active network key on the coordinator matches the keystore: %s", "yes" if same else "NO")
        if not same:
            self.audit.security("network_key_mismatch")
            s = self.secrets
            if not s.pending_rotation and s.previous_network_key == bytes(raw[1:17]):
                # The radio sits on the keystore's *previous* key and no rotation is in flight:
                # a rollback or an external restore put it there deliberately, and the devices
                # answer that key. The radio is the ground truth — the keystore follows it and
                # forgets the key that never worked, instead of "finishing" a switch nobody wants.
                from dataclasses import replace
                self.secrets = replace(s, network_key=bytes(raw[1:17]), key_seq=raw[0],
                                       previous_network_key=None, previous_key_seq=None, pending_rotation=None)
                self._persist_secrets()
                await self._record_precfgkey()
                self.audit.security("keystore_followed_radio", seq=raw[0])
                log.warning("the radio is on the keystore's previous network key and no rotation is pending — "
                            "keeping the radio's key (sequence %d); the keystore now follows it", raw[0])
                return
            if not await self._decide_sequence(raw):
                log.error("the keystore key is not the radio's and no evidence says which sequence the devices know it by — "
                          "leaving the radio as it is; use Maintenance → Finish key switch or Roll back")
                self.audit.security("network_key_mismatch_unresolved")
            else:
                try:
                    await self._repair_active_key(raw)
                except ZnpStatusError as e:
                    log.warning("key item write refused by the firmware (%s); installing the key through the ZDO key update", e)
                    await self._install_key_via_zdo(raw[0] if raw else 0)
                await self._record_precfgkey()
        if self.secrets.tclk_seed:
            seed = await self._nv_read(NvId.TCLK_SEED)
            ok = seed is not None and seed[:16] == self.secrets.tclk_seed
            log.info("trust-centre link-key seed matches the imported one: %s", "yes" if ok else "NO")
            if not ok:
                await self._nv_write(NvId.TCLK_SEED, self.secrets.tclk_seed)
                self.audit.event("tclk_seed_restored")
                log.warning("trust-centre link-key seed written from the import; takes effect on the next restart")

    # ------------------------------------------------ network key rotation --

    async def active_key_sequence(self) -> int:
        raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
        return raw[0] if raw else 0

    async def active_key_matches(self) -> bool:
        raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
        return raw is not None and len(raw) >= 17 and raw[1:17] == self.secrets.network_key

    async def _decide_sequence(self, active_raw: bytes) -> bool:
        """Which sequence do the devices know the keystore key by? Evidence only:
        * the radio's alternate key item holds the keystore key → that item's sequence (the radio
          moved past the keystore: a restored backup, or a rollback);
        * the keystore says the key is the *next* one (previous_network_key is the radio's key, or a
          rotation is pending) → active + 1;
        * the keystore already carries a sequence different from the radio's → trust it.
        Otherwise refuse: installing a key under the wrong sequence cuts every device off."""
        active_seq, active_key = active_raw[0], bytes(active_raw[1:17])
        alt = await self._nv_read(NvId.NWK_ALTERN_KEY_INFO)
        s = self.secrets
        if alt is not None and len(alt) >= 17 and bytes(alt[1:17]) == s.network_key:
            s.key_seq, s.previous_network_key, s.previous_key_seq = alt[0], active_key, active_seq
            log.warning("keystore key is the radio's alternate key (sequence %d): installing it as active, keeping the current one as alternate", alt[0])
            self._persist_secrets()
            return True
        if s.previous_network_key == active_key or s.pending_rotation:
            if s.key_seq == active_seq:
                s.key_seq = (active_seq + 1) & 0xFF
            s.previous_network_key, s.previous_key_seq = active_key, active_seq
            log.warning("keystore key is the next key (sequence %d); the radio is still on %d", s.key_seq, active_seq)
            self._persist_secrets()
            return True
        if s.key_seq != active_seq:
            if s.previous_network_key is None:
                s.previous_network_key, s.previous_key_seq = active_key, active_seq
                self._persist_secrets()
            return True
        # A radio that has sent next to nothing under its key is a fresh formation whose firmware
        # made up its own key (no device knows it): installing the keystore key is what a first
        # start must do. A radio with millions of frames behind it is a live network — refuse.
        counter = await self.nwk_frame_counter()
        if counter is None or counter < 1000:
            log.warning("radio key differs from the keystore on a freshly formed network (frame counter %s): installing the keystore key", counter)
            return True
        return False

    def _assume_rotation_sequence(self, active_raw: bytes) -> None:
        """The keystore key is not the radio's active key and the keystore knows no newer sequence
        than the radio's: the key got there by an over-the-air rotation (which counts the sequence
        up by one) that the radio never finished. Devices that took the key know it under
        active+1; installing it under any other sequence would cut them off. The key the radio is
        on now is remembered as the previous one, so it stays the alternate and devices that
        missed the switch are still heard."""
        active_seq, active_key = active_raw[0], bytes(active_raw[1:17])
        changed = False
        if self.secrets.key_seq == active_seq:
            self.secrets.key_seq = (active_seq + 1) & 0xFF
            log.warning("keystore key installed with sequence %d (the radio is on %d; an unfinished rotation)", self.secrets.key_seq, active_seq)
            changed = True
        if self.secrets.previous_network_key is None and active_key != self.secrets.network_key:
            self.secrets.previous_network_key = active_key
            changed = True
        if changed:
            self._persist_secrets()

    async def rollback_key_switch(self, previous: tuple[bytes, int] | None = None) -> bool:
        """Undo a switch the devices did not follow: the coordinator goes back to the key the devices
        use. Two shapes:
        * the keystore moved ahead but the radio never switched → the keystore follows the radio;
        * the radio switched → it returns to the previous key, taken from the keystore
          (previous_network_key) or from the radio's own alternate key item, with a short stack
          restart; the abandoned key stays as the alternate.
        Nothing is broadcast: a device that did not switch could not read it anyway."""
        from dataclasses import replace
        raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
        if raw is None or len(raw) < 17:
            log.warning("could not read the active network key item from the coordinator")
            return False
        active_seq, active_key = raw[0], bytes(raw[1:17])
        if active_key != self.secrets.network_key:
            self.secrets = replace(self.secrets, network_key=active_key, key_seq=active_seq, previous_network_key=None,
                                   previous_key_seq=None, pending_rotation=None)
            self._persist_secrets()
            await self._record_precfgkey()
            self.audit.security("network_key_switch_rolled_back", mode="keystore", seq=active_seq)
            log.warning("keystore returned to the key the radio is on (sequence %d)", active_seq)
            return True
        prev_key: bytes | None = None
        prev_seq: int | None = None
        s = self.secrets
        if previous is not None and previous[0] == active_key:
            log.info("the radio is already on the key handed in (sequence %d); nothing to roll back", active_seq)
            return True
        if previous is not None:
            prev_key, prev_seq = previous[0], previous[1] & 0xFF  # from a backup / the previous setup's files
        elif s.previous_network_key and s.previous_network_key != active_key:
            prev_key = s.previous_network_key
            prev_seq = s.previous_key_seq if s.previous_key_seq is not None else (active_seq - 1) & 0xFF
        else:
            alt = await self._nv_read(NvId.NWK_ALTERN_KEY_INFO)
            if alt is not None and len(alt) >= 17 and bytes(alt[1:17]) not in (active_key, bytes(16)):
                prev_key, prev_seq = bytes(alt[1:17]), alt[0]
        if prev_key is None:
            log.error("no previous network key is known (neither the keystore nor the radio's alternate key item has one) — "
                      "restore a backup taken before the rotation")
            self.audit.security("network_key_rollback_impossible")
            return False
        self.secrets = replace(s, network_key=prev_key, key_seq=prev_seq, previous_network_key=active_key, previous_key_seq=active_seq,
                               pending_rotation=None)
        self._persist_secrets()
        try:
            ok = await self._repair_active_key(raw)
        except ZnpStatusError as e:
            log.warning("key item write refused by the firmware (%s); installing the key through the ZDO key update", e)
            await self._install_key_via_zdo(active_seq)
            ok = await self.active_key_matches()
        await self._record_precfgkey()
        self.audit.security("network_key_switch_rolled_back", mode="radio", seq=prev_seq, ok=ok)
        log.warning("coordinator returned to the previous network key (sequence %d): %s", prev_seq, "ok" if ok else "NOT verified")
        return ok

    async def _run_discovery(self, mask: int, duration: int, timeout: float) -> tuple[int, list[c.Beacon]]:
        """Send a network discovery request with a beacon collector armed; returns (SRSP status, beacons)."""
        beacons: list[c.Beacon] = []

        def _collect(frame: Frame) -> None:
            try:
                beacons.extend(c.decode_beacon_notify_ind(frame.data))
            except Exception:  # noqa: BLE001 - a malformed beacon must not kill the scan
                log.debug("unparsable beacon indication: %s", frame.data.hex())

        self.t.on(Subsystem.ZDO, ZdoCmd.BEACON_NOTIFY_IND, _collect)
        cnf = await self._arm(self.t.wait_for(Subsystem.ZDO, ZdoCmd.NWK_DISCOVERY_CNF, timeout=timeout))
        try:
            rsp = await self.t.request(c.zdo_network_discovery(mask, duration), check_status=False)
            status = rsp.data[0] if rsp.data else 0xFF
            if status != 0:
                cnf.cancel()
                return status, []
            try:
                await cnf
            except ZnpTimeout:
                pass  # some firmware skips the confirm; whatever beacons arrived still count
            return 0, beacons
        finally:
            self.t.off(Subsystem.ZDO, ZdoCmd.BEACON_NOTIFY_IND, _collect)

    async def scan_air(self, duration: int = 3, channels: list[int] | None = None) -> dict[str, Any]:
        """Beacon survey. Beacon requests and their answers are unencrypted, so every router in
        radio range answers whatever key anyone is on: the result tells apart "the routers are
        alive but we disagree on the key or the frame counter" from "the routers are not
        transmitting at all". Some firmware refuses to scan while the network is up (0xC2); then
        the stack is paused for the scan and restarted, with the frame counter kept safe."""
        chans = channels or list(range(11, 27))
        mask = 0
        for ch in chans:
            if not 11 <= ch <= 26:
                raise ValueError("channels are 11..26")
            mask |= 1 << ch
        timeout = 5.0 + 0.5 * len(chans)
        status, beacons = await self._run_discovery(mask, duration, timeout)
        mode = "online"
        if status != 0:
            mode = "paused"
            log.info("firmware refuses to scan while the network is up (status %#04x); pausing the stack for the scan", status)
            live = await self.nwk_frame_counter()  # before the stop: the counter must not go backwards
            if live is not None and live > (self.secrets.frame_counter or 0):
                self.secrets.frame_counter = live
                self._persist_secrets()
            await self._reset()
            # With the network state (NIB) present the firmware performs the scan but reports no
            # beacons; take the NIB out for the scan and put it back — the dance zigpy-znp's scan does.
            nib = await self._nv_read(NvId.NIB)
            removed = False
            if nib is not None:
                try:
                    await self.t.request(c.nv_delete(NvId.NIB, len(nib)))
                    removed = True
                    await self._reset()
                except ZnpStatusError as e:
                    log.info("NIB not removed for the scan (%s); beacons may stay hidden", e)
            try:
                status, beacons = await self._run_discovery(mask, duration, timeout)
            finally:
                if removed:
                    try:
                        await self.t.request(c.nv_item_init(NvId.NIB, len(nib), nib), check_status=False)
                        await self._nv_write(NvId.NIB, nib)
                    except ZnpStatusError as e:
                        log.error("NIB could not be written back after the scan (%s)", e)
                    await self._reset()
                # The network comes back whatever the scan did.
                await self._apply_runtime_security()
                await self._startup()
                await self._register_endpoint()
                await self._register_zdo_callbacks()
                await self._force_close_join()
                if live is not None:
                    await self._ensure_frame_counter(live + 1024)
        if status != 0:
            self.audit.security("air_scan_refused", status=status)
            return {"ok": False, "status": status, "error": f"the firmware refused the scan (status {status:#04x})"}
        nets: dict[tuple[int, int, int], dict[str, Any]] = {}
        seen: dict[tuple[int, int, int], set[int]] = {}
        for b in beacons:
            k = (b.pan_id, b.ext_pan_id, b.channel)
            e = nets.setdefault(k, {"pan_id": f"{b.pan_id:#06x}", "ext_pan_id": f"0x{b.ext_pan_id:016x}",
                                    "channel": b.channel, "best_lqi": 0, "permit_join": False,
                                    "update_id": b.update_id,
                                    "this_network": b.ext_pan_id == self.secrets.ext_pan_id
                                    or b.pan_id == self.secrets.pan_id})
            seen.setdefault(k, set()).add(b.src_addr)
            e["best_lqi"] = max(e["best_lqi"], b.lqi)
            e["permit_join"] = e["permit_join"] or b.permit_joining
        networks = [{**e, "responders": len(seen[k])} for k, e in nets.items()]
        networks.sort(key=lambda n: (not n["this_network"], -n["responders"]))
        self.audit.event("air_scan", beacons=len(beacons), networks=len(networks), mode=mode,
                         ours_heard=sum(n["responders"] for n in networks if n["this_network"]))
        return {"ok": True, "networks": networks, "channels": chans, "mode": mode}

    # Routing and broadcast behaviour the firmware reads from NV at every boot (TI's zgItemTable:
    # "if the item exists, set the item to the value stored in NV memory"), so these can be tuned
    # on a running installation without re-flashing. Everything here is one byte.
    # NOT here, deliberately: neighbour/routing/device-table SIZES are compile-time array bounds —
    # no NV item exists for them and changing them needs a new firmware image.
    RADIO_TUNING: dict[str, tuple[int, int, int, str]] = {
        "concentrator_enable": (NvId.CONCENTRATOR_ENABLE, 0, 1,
                                "Act as a concentrator so devices route towards the coordinator"),
        "concentrator_discovery_seconds": (NvId.CONCENTRATOR_DISCOVERY, 0, 255,
                                           "How often the coordinator floods a route request to the whole network. "
                                           "0 = never (the firmware default). Frequent floods fill the air and can "
                                           "starve battery and no-neutral devices"),
        "concentrator_radius": (NvId.CONCENTRATOR_RADIUS, 1, 30, "How many hops such a flood travels"),
        "concentrator_route_cache": (NvId.CONCENTRATOR_RC, 0, 1, "Keep a source-route cache for those routes"),
        "source_route_expiry_seconds": (NvId.SRC_RTG_EXPIRY_TIME, 0, 255, "How long a learned source route is kept"),
        "route_discovery_seconds": (NvId.ROUTE_DISCOVERY_TIME, 1, 255, "How long a route discovery may take"),
        "route_expiry_seconds": (NvId.ROUTE_EXPIRY_TIME, 0, 255, "How long an unused route is kept"),
        "broadcast_retries": (NvId.BCAST_RETRIES, 0, 5, "Retries for a broadcast"),
        "passive_ack_timeout": (NvId.PASSIVE_ACK_TIMEOUT, 1, 255, "How long a broadcast waits to hear itself repeated"),
        "broadcast_delivery_seconds": (NvId.BCAST_DELIVERY_TIME, 1, 255, "How long a broadcast stays alive in the network"),
    }

    async def _reapply_radio_tuning(self) -> None:
        """Keep the radio at the settings the operator chose. The firmware reads these from NV at
        boot, and a re-formation resets them to its compiled-in defaults — so they are checked at
        every start and, if they have drifted, written and applied with one short restart."""
        want = {k: int(v) for k, v in (self.radio_tuning or {}).items() if k in self.RADIO_TUNING}
        if not want:
            return
        try:
            have = await self.read_radio_tuning()
        except (ZnpStatusError, ZnpTimeout, asyncio.TimeoutError) as e:
            log.info("radio tuning not read (%s); leaving the radio as it is", e)
            return
        drift = {k: v for k, v in want.items() if have.get(k) != v}
        if not drift:
            return
        log.warning("radio settings differ from the configured ones (%s) — applying them",
                    ", ".join(f"{k}: {have.get(k)}\u2192{v}" for k, v in drift.items()))
        try:
            await self.apply_radio_tuning(want)
        except (ZnpStatusError, ZnpTimeout, ValueError, asyncio.TimeoutError) as e:
            log.error("radio settings could not be applied (%s)", e)

    async def read_radio_tuning(self) -> dict[str, int | None]:
        """What the radio is actually set to right now (None = the item does not exist yet, so the
        firmware's compiled-in default is in force)."""
        out: dict[str, int | None] = {}
        for name, (nv, *_rest) in self.RADIO_TUNING.items():
            raw = await self._nv_read(nv)
            out[name] = raw[0] if raw else None
        return out

    async def apply_radio_tuning(self, values: dict[str, int]) -> dict[str, Any]:
        """Write routing/broadcast tunables and restart the stack so the firmware picks them up.

        This deliberately touches NOTHING else: no key items, no PAN, no channel, no startup
        option, no frame counter. The network the devices are joined to is the same one before and
        after — only how loudly the coordinator hunts for routes changes. The result is verified
        against the keystore before it is reported as done."""
        clean: dict[str, int] = {}
        for name, value in values.items():
            spec = self.RADIO_TUNING.get(name)
            if spec is None:
                raise ValueError(f"unknown radio setting {name!r}")
            nv, lo, hi, _help = spec
            v = int(value)
            if not lo <= v <= hi:
                raise ValueError(f"{name} must be {lo}..{hi}")
            clean[name] = v
        before = {"pan_id": self.secrets.pan_id, "channel": self.secrets.channel}
        await self._reset()
        written: list[str] = []
        for name, v in clean.items():
            nv = self.RADIO_TUNING[name][0]
            try:
                await self._nv_write(nv, bytes([v]))
                written.append(name)
            except ZnpStatusError as e:
                log.warning("radio setting %s refused by the firmware (%s)", name, e)
        await self._apply_runtime_security()
        await self._startup()
        await self._register_endpoint()
        await self._register_zdo_callbacks()
        await self._force_close_join()
        live = c.decode_ext_nwk_info((await self.t.request(c.zdo_ext_nwk_info(), check_status=False)).data)
        key_ok = await self.active_key_matches()
        same_network = live.pan_id == before["pan_id"] and live.channel == before["channel"]
        self.audit.security("radio_tuning_applied", settings=clean, written=written,
                            key_ok=key_ok, same_network=same_network)
        if not (key_ok and same_network):
            log.error("radio tuning left the coordinator on pan=%#06x channel=%d key_ok=%s — expected pan=%#06x channel=%d",
                      live.pan_id, live.channel, key_ok, before["pan_id"], before["channel"])
        else:
            log.warning("radio tuning applied (%s); network unchanged: pan=%#06x channel=%d, key verified",
                        ", ".join(f"{k}={v}" for k, v in clean.items()), live.pan_id, live.channel)
        asyncio.create_task(self._neighbour_check(), name="neighbour-check-after-tuning")
        return {"applied": clean, "written": written, "key_ok": key_ok, "same_network": same_network,
                "pan_id": f"{live.pan_id:#06x}", "channel": live.channel}

    async def key_slots(self) -> dict[str, Any]:
        """The two key slots' sequence numbers, and whether two different keys share one number —
        the aftermath of an interrupted rotation plus rollbacks; devices then drop everything."""
        a = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
        b = await self._nv_read(NvId.NWK_ALTERN_KEY_INFO)
        ok_a, ok_b = a is not None and len(a) >= 17, b is not None and len(b) >= 17
        return {"active_seq": a[0] if ok_a else None, "altern_seq": b[0] if ok_b else None,
                "sequence_collision": bool(ok_a and ok_b and a[0] == b[0] and a[1:17] != b[1:17])}

    async def relabel_key_sequence(self, seq: int) -> bool:
        """Write the SAME active key again under another sequence number. After an interrupted
        rotation the devices know the key by the next number; every frame is dropped until the
        label matches. Nothing else changes and nothing is re-paired."""
        raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
        if raw is None or len(raw) < 17:
            return False
        if bytes(raw[1:17]) != self.secrets.network_key:
            raise ValueError("the keystore and the radio disagree on the key itself — resolve that first (roll back or finish)")
        self.secrets.key_seq = seq & 0xFF
        self._persist_secrets()
        ok = await self._repair_active_key(raw)
        self.audit.security("network_key_sequence_relabelled", seq=seq & 0xFF, ok=ok)
        return ok

    async def refresh_frame_counter(self) -> None:
        """Remember the radio's outgoing NWK frame counter in the keystore now and then, so a
        restart, repair or backup never sets it back below what the devices last saw."""
        try:
            live = await self.nwk_frame_counter()
        except (ZnpTimeout, ZnpStatusError) as e:
            log.debug("frame counter not read: %s", e)
            return
        if live is not None and live > (self.secrets.frame_counter or 0) + 50_000:
            self.secrets.frame_counter = live
            self._persist_secrets()

    async def rollback_source(self) -> str:
        """Where a previous key could come from: "keystore" (the keystore moved ahead of the radio, or
        remembers the previous key), "radio" (the alternate key slot), or "none"."""
        raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
        if raw is None or len(raw) < 17:
            return "none"
        active_key = bytes(raw[1:17])
        if active_key != self.secrets.network_key:
            return "keystore"
        if self.secrets.previous_network_key and self.secrets.previous_network_key != active_key:
            return "keystore"
        alt = await self._nv_read(NvId.NWK_ALTERN_KEY_INFO)
        if alt is not None and len(alt) >= 17 and bytes(alt[1:17]) not in (active_key, bytes(16)):
            return "radio"
        return "none"

    async def rollback_available(self) -> bool:
        return await self.rollback_source() != "none"

    async def switch_network_key_unicast(self, nwk: int, seq: int) -> None:
        """Tell one device to start using the key with this sequence number."""
        await self.t.request(c.zdo_ext_switch_nwk_key(nwk, seq))

    async def restore_active_key(self) -> bool:
        """Put the radio back on the keystore key (stop, rewrite key items, start) — used when the
        firmware switched itself in the middle of switching the devices."""
        raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
        if raw is None or len(raw) < 17:
            return False
        if bytes(raw[1:17]) == self.secrets.network_key:
            return True
        return await self._repair_active_key(raw)

    def _persist_secrets(self) -> None:
        if self.keystore is not None:
            try:
                self.keystore.save(self.secrets)
            except OSError as e:
                log.warning("keystore not saved: %s", e)

    async def _record_precfgkey(self) -> None:
        """PRECFGKEY is what the next start compares with the keystore; keep it on the current key so a
        finished rotation is not mistaken for a foreign network."""
        try:
            await self._nv_write(NvId.PRECFGKEY, self.secrets.network_key)
        except ZnpStatusError as e:
            log.info("PRECFGKEY not updated while running (%s); the next start finishes it", e)

    async def finish_key_switch(self) -> bool:
        """The coordinator's half of a key rotation: put the radio on the keystore's key at the
        keystore's sequence (stop, write the key items, start). A no-op — apart from recording
        PRECFGKEY — when the radio already reports that key as active. Returns whether it does now."""
        raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
        if raw is None or len(raw) < 17:
            log.warning("could not read the active network key item from the coordinator")
            return False
        if raw[1:17] == self.secrets.network_key:
            await self._record_precfgkey()
            return True
        self._assume_rotation_sequence(raw)
        try:
            ok = await self._repair_active_key(raw)
        except ZnpStatusError as e:
            log.warning("key item write refused by the firmware (%s); installing the key through the ZDO key update", e)
            await self._install_key_via_zdo(raw[0])
            ok = await self.active_key_matches()
        await self._record_precfgkey()
        self.audit.security("network_key_switch_finished", ok=ok, seq=self.secrets.key_seq)
        return ok

    async def deliver_network_key(self, nwk: int, seq: int, key: bytes) -> None:
        """Hand a device the next network key, encrypted under its own link key (unicast)."""
        await self.t.request(c.zdo_ext_update_nwk_key(nwk, seq, key))

    async def switch_network_key(self, seq: int) -> None:
        """Tell everyone (and ourselves) to start using the key with this sequence number."""
        await self.t.request(c.zdo_ext_switch_nwk_key(0xFFFF, seq))

    async def _install_key_via_zdo(self, active_seq: int) -> None:
        """Install the keystore key with the network-key update/switch commands addressed to the
        coordinator itself (nothing is sent over the air). The key sequence number must stay the one
        the devices know (the imported network's, normally 0), so the same sequence is tried first."""
        key = self.secrets.network_key
        for seq in dict.fromkeys((self.secrets.key_seq & 0xFF, active_seq, (active_seq + 1) & 0xFF)):
            done = False
            for dst in (0x0000, 0xFFFF):  # self first; the broadcast form also installs locally and is
                try:                       # encrypted under the current key, so nothing usable leaves
                    await self.t.request(c.zdo_ext_update_nwk_key(dst, seq, key))
                    await self.t.request(c.zdo_ext_switch_nwk_key(dst, seq))
                    done = True
                    break
                except ZnpStatusError as e:
                    log.warning("ZDO key update (dst %#06x, sequence %d) refused (%s)", dst, seq, e)
            if not done:
                continue
            raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
            if raw is not None and len(raw) >= 17 and raw[1:17] == key:
                log.warning("network key installed through the ZDO key update (sequence %d)", seq)
                self.audit.event("network_key_repaired", method="zdo", seq=seq)
                return
            log.info("key item still differs after the ZDO key update with sequence %d", seq)
            if seq == active_seq:
                continue
        self.audit.security("network_key_unrepaired")
        log.error("network key could not be installed; the neighbour check will show whether routers are heard")

    async def _write_security_state_stopped(self, counter_floor: int | None = None) -> None:
        """Write key items, frame counter and TC seed into NV right after a reset and BEFORE the
        network is started — the order the firmware accepts for a restore (writes while the stack
        runs are refused). Caller resets first and starts the network afterwards."""
        s = self.secrets
        # The outgoing NWK frame counter must only ever go up: devices drop anything at or below the
        # last value they saw from us. Use the live counter (read before the stop) when it is ahead
        # of the saved one — the saved one dates from the import or the last refresh.
        base = max(s.frame_counter or 0, counter_floor or 0)
        counter = base + FRAME_COUNTER_MARGIN if base else None
        for item in (NvId.NWK_ACTIVE_KEY_INFO, NvId.NWK_ALTERN_KEY_INFO):
            raw = await self._nv_read(item)
            if raw is None or len(raw) < 17:
                log.info("key item %s: %s bytes, not written", item.name, None if raw is None else len(raw))
                continue
            # Keep the item's exact length: seq(1) + key(16) [+ counter(4) on firmware that has it].
            # The active item carries the sequence the devices know the key by; the alternate item
            # keeps the previous key (sequence − 1) so a device that missed a rotation is still heard.
            seq = s.key_seq & 0xFF
            if item == NvId.NWK_ALTERN_KEY_INFO and s.previous_network_key:
                prev_seq = s.previous_key_seq if s.previous_key_seq is not None else (seq - 1) & 0xFF
                value = bytes([prev_seq & 0xFF]) + s.previous_network_key + raw[17:]
            else:
                value = bytes([seq]) + s.network_key + raw[17:]
            if counter is not None and len(raw) >= 21:
                value = value[:17] + counter.to_bytes(4, "little") + value[21:]
            try:
                await self._nv_write(item, value)
                log.info("key item %s (%d bytes) written", item.name, len(value))
            except ZnpStatusError as e:
                log.warning("write of key item %s (%d bytes) refused while stopped (%s)", item.name, len(value), e)
        legacy = await self._nv_read(NvId.NWKKEY)
        if legacy is not None and len(legacy) >= 17:
            try:
                await self._nv_write(NvId.NWKKEY, bytes([s.key_seq & 0xFF]) + s.network_key + legacy[17:])
            except ZnpStatusError as e:
                log.warning("write of NWKKEY refused while stopped (%s)", e)
        await self._nv_write(NvId.PRECFGKEY, s.network_key)
        if s.tclk_seed:
            await self._nv_write(NvId.TCLK_SEED, s.tclk_seed)
        if counter is not None:
            try:
                await self._write_frame_counter_table(counter)
            except ZnpStatusError as e:
                log.warning("frame counter table write refused while stopped (%s)", e)

    async def _repair_active_key(self, active_raw: bytes) -> bool:
        """The radio formed the network with a key other than the keystore's (firmware variants
        generate their own unless the key items are written explicitly). Write the active, alternate
        and legacy key items with our key, keep the frame counter, restart the network, verify."""
        s = self.secrets
        live = await self.nwk_frame_counter()  # before the stop: the counter must not go backwards
        if live is not None and live > (s.frame_counter or 0):
            s.frame_counter = live
            self._persist_secrets()
        await self._reset()
        await self._write_security_state_stopped(counter_floor=live)
        await self._apply_runtime_security()
        await self._startup()
        await self._register_endpoint()
        await self._register_zdo_callbacks()
        await self._force_close_join()
        asyncio.create_task(self._neighbour_check(), name="neighbour-check-after-repair")  # the truthful line, 45 s later
        raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
        fixed = raw is not None and len(raw) >= 17 and raw[1:17] == s.network_key
        if fixed:
            log.warning("active network key rewritten from the keystore and network restarted")
            self.audit.event("network_key_repaired", method="nv")
        else:
            log.warning("key items could not be rewritten; installing the key through the ZDO key update")
            await self._install_key_via_zdo(raw[0] if raw else 0)
            fixed = await self.active_key_matches()
        return fixed

    async def _sec_material(self) -> list[tuple[int, int, bytes]]:
        """(subId, frameCounter, extPanId LE) entries of the security material table (Z-Stack 3.x.0);
        empty on firmware without the extended NV API."""
        out = []
        for sub in range(8):
            try:
                rsp = await self.t.request(c.exnv_read(c.EXNV_NWK_SEC_MATERIAL_TABLE, sub, 12), check_status=False)
            except ZnpTimeout:
                break
            status, value = c.decode_nv_read(rsp.data)
            if status != 0 or len(value) < 12:
                break
            out.append((sub, int.from_bytes(value[0:4], "little"), value[4:12]))
        return out

    async def nwk_frame_counter(self) -> int | None:
        """The coordinator's outgoing NWK frame counter. Z-Stack 3.x.0 keeps it in the security
        material table (entry for our extended PAN id, else the generic all-FF entry); older
        firmware in the active key item."""
        ext = self.secrets.ext_pan_id.to_bytes(8, "little")
        table = await self._sec_material()
        if table:
            for _sub, counter, pan in table:
                if pan == ext:
                    return counter
            for _sub, counter, pan in table:
                if pan == b"\xff" * 8:
                    return counter
            return max(counter for _s, counter, _p in table)
        raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
        if raw is None or len(raw) < 21:
            return None
        return int.from_bytes(raw[17:21], "little")

    async def _write_frame_counter_table(self, value: int) -> bool:
        """Write the counter into the security material table entries for our network (and the
        generic one); False when the firmware has no such table."""
        ext = self.secrets.ext_pan_id.to_bytes(8, "little")
        table = await self._sec_material()
        if not table:
            return False
        written = False
        for sub, _counter, pan in table:
            if pan in (ext, b"\xff" * 8):
                await self.t.request(c.exnv_write(c.EXNV_NWK_SEC_MATERIAL_TABLE, sub, value.to_bytes(4, "little") + pan))
                written = True
        if not written:  # no entry for us yet: take the first slot
            sub = table[0][0]
            await self.t.request(c.exnv_write(c.EXNV_NWK_SEC_MATERIAL_TABLE, sub, value.to_bytes(4, "little") + ext))
        return True

    async def _ensure_frame_counter(self, minimum: int) -> None:
        """Devices drop frames whose NWK counter is below the last one they saw from us, so after an
        import the counter must be above the previous setup's. The SET command is not always kept
        across formation/reset on every firmware; verify by reading it back and fall back to writing
        the key item directly, then restart the network."""
        minimum = min(minimum, 0xFFFF_FFFF)
        current = await self.nwk_frame_counter()
        log.info("NWK frame counter on the coordinator: %s (need at least %d)", current, minimum)
        if current is not None and current >= minimum:
            self.audit.event("frame_counter_verified", value=current)
            return
        try:
            await self.t.request(c.appcnf_set_nwk_frame_counter(minimum))
        except ZnpStatusError as e:
            log.warning("SET_NWK_FRAME_COUNTER refused (%s)", e)
        current = await self.nwk_frame_counter()
        if current is not None and current >= minimum:
            log.info("NWK frame counter set to %d", current)
            self.audit.event("frame_counter_verified", value=current)
            return
        try:
            if not await self._write_frame_counter_table(minimum):
                raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
                if raw is None or len(raw) < 21:
                    log.error("cannot read the active key item; frame counter stays at %s — devices may ignore us", current)
                    self.audit.security("frame_counter_unverified", value=current, needed=minimum)
                    return
                await self._nv_write(NvId.NWK_ACTIVE_KEY_INFO, raw[:17] + minimum.to_bytes(4, "little") + raw[21:])
                alt = await self._nv_read(NvId.NWK_ALTERN_KEY_INFO)
                if alt is not None and len(alt) >= 21:
                    await self._nv_write(NvId.NWK_ALTERN_KEY_INFO, alt[:17] + minimum.to_bytes(4, "little") + alt[21:])
        except ZnpStatusError as e:
            log.error("firmware refuses to write the frame counter (%s); it stays at %s — devices may ignore us", e, current)
            self.audit.security("frame_counter_unverified", value=current, needed=minimum)
            return
        await self._reset()
        await self._apply_runtime_security()
        await self._startup()
        await self._register_endpoint()
        current = await self.nwk_frame_counter()
        if current is not None and current >= minimum:
            log.warning("NWK frame counter written directly and restarted: now %d", current)
            self.audit.event("frame_counter_verified", value=current, method="nv")
        else:
            log.error("NWK frame counter still %s after writing it; devices may ignore this coordinator", current)
            self.audit.security("frame_counter_unverified", value=current, needed=minimum)

    async def _apply_runtime_security(self) -> None:
        """Settings the firmware forgets across resets — applied every boot."""
        await self.t.request(c.appcnf_set_tc_require_key_exchange(True))
        await self.t.request(c.appcnf_set_allow_rejoin_tc_policy(False))
        await self.t.request(c.appcnf_set_join_uses_install_code(self.strict))
        if self.strict:
            # Replace the public ZigBeeAlliance09 link key with our random one.
            await self.t.request(c.appcnf_set_default_centralized_key(False, self.secrets.tc_install_code))
        else:
            await self.t.request(c.appcnf_set_default_centralized_key(True))

    @staticmethod
    async def _arm(coro):
        """Schedule an indication waiter and let it register before we send the request."""
        task = asyncio.ensure_future(coro)
        await asyncio.sleep(0)
        return task

    async def _wait_coordinator_state(self, timeout: float) -> None:
        await self.t.wait_for(Subsystem.ZDO, ZdoCmd.STATE_CHANGE_IND, timeout=timeout,
                              predicate=lambda f: bool(f.data) and f.data[0] == c.DeviceState.ZB_COORD)

    async def _startup(self) -> None:
        coord_up = await self._arm(self._wait_coordinator_state(30.0))
        await self.t.request(c.zdo_startup_from_app(), check_status=False)
        try:
            await coord_up
        except ZnpTimeout:
            di = c.decode_device_info((await self.t.request(c.util_get_device_info())).data)
            if di.device_state != c.DeviceState.ZB_COORD:
                raise

    async def _register_zdo_callbacks(self) -> None:
        """Ask for all ZDO messages to be forwarded: some firmware builds deliver device-level
        responses (node/simple descriptors, bind, active endpoints) only this way."""
        try:
            await self.t.request(c.zdo_msg_cb_register(0xFFFF))
        except ZnpStatusError as e:
            log.info("ZDO message callback registration refused (%s); relying on direct indications", e)

    async def _register_endpoint(self) -> None:
        try:
            await self.t.request(c.af_register(GATEWAY_ENDPOINT, HA_PROFILE, 0x0005, GATEWAY_IN_CLUSTERS, GATEWAY_OUT_CLUSTERS))
        except ZnpStatusError as e:
            if e.status != 0xB8:  # already registered
                raise

    # -------------------------------------------------------------- join --

    async def permit_join(self, seconds: int, requested_by: str, *, ieee: int | None = None,
                          install_code: bytes | None = None) -> int:
        """Open a join window through the JoinGuard. Returns the effective seconds."""
        if install_code is not None and ieee is None:
            raise ValueError("install code requires the device IEEE address")
        if install_code is None and self.strict:
            raise PermissionError("strict mode: joining requires an install code")
        window = self.guard.request_open(seconds, requested_by, ieee)  # policy first: no side effects on denial
        window.install_code = install_code is not None
        if install_code is not None:
            key = derive_link_key(install_code)
            await self.t.request(c.appcnf_add_install_code(ieee, key, c.InstallCodeFormat.DERIVED_KEY))
            self.audit.event("install_code_added", ieee=f"0x{ieee:016x}", by=requested_by)
        await self.t.request(c.zdo_permit_join(window.seconds))
        if self._permit_task:
            self._permit_task.cancel()
        self._permit_task = asyncio.create_task(self._auto_close(window.seconds))
        return window.seconds

    async def _auto_close(self, seconds: int) -> None:
        await asyncio.sleep(seconds)
        await self._force_close_join()

    async def _force_close_join(self) -> None:
        try:
            await self.t.request(c.zdo_permit_join(0))
        except Exception:
            log.exception("failed to close join window — retrying in 2s")
            await asyncio.sleep(2)
            await self.t.request(c.zdo_permit_join(0))
        self.guard.mark_closed()

    async def remove_device(self, nwk: int, ieee: int) -> None:
        await self.t.request(c.zdo_mgmt_leave_req(nwk, ieee))
        self.audit.event("device_removed", ieee=f"0x{ieee:016x}")

    # --------------------------------------------------------------- aps --

    def _next_trans_id(self) -> int:
        self._trans_id = (self._trans_id % 255) + 1
        return self._trans_id

    async def send_aps(self, dst: int, dst_ep: int, cluster: int, payload: bytes, *, src_ep: int = GATEWAY_ENDPOINT,
                       wait_confirm: bool = True, timeout: float = 10.0) -> int:
        tid = self._next_trans_id()
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[int] = loop.create_future()
        self._pending_confirms[tid] = fut
        try:
            await self.t.request(c.af_data_request(dst, dst_ep, src_ep, cluster, tid, payload))
            if not wait_confirm:
                return 0
            status = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError as e:
            raise ZnpTimeout(f"no AF_DATA_CONFIRM for {dst:#06x}/{cluster:#06x}") from e
        finally:
            self._pending_confirms.pop(tid, None)
        if status != 0:
            raise ZnpStatusError(c.af_data_request(dst, dst_ep, src_ep, cluster, tid, payload), status)
        return status

    # --------------------------------------------------------------- zdo --

    async def active_endpoints(self, nwk: int, timeout: float = 10.0) -> list[int]:
        wait = self.t.wait_for(Subsystem.ZDO, ZdoCmd.ACTIVE_EP_RSP, timeout=timeout,
                               predicate=lambda f: c.decode_active_ep_rsp(f.data).nwk_addr == nwk)
        task = await self._arm(wait)
        await self.t.request(c.zdo_active_ep_req(nwk))
        rsp = c.decode_active_ep_rsp((await task).data)
        if rsp.status != 0:
            raise ZnpStatusError(c.zdo_active_ep_req(nwk), rsp.status)
        return rsp.endpoints

    async def simple_descriptor(self, nwk: int, ep: int, timeout: float = 10.0) -> c.SimpleDescRsp:
        wait = self.t.wait_for(Subsystem.ZDO, ZdoCmd.SIMPLE_DESC_RSP, timeout=timeout,
                               predicate=lambda f: (lambda d: d.nwk_addr == nwk and (d.endpoint == ep or d.status != 0))(c.decode_simple_desc_rsp(f.data)))
        task = await self._arm(wait)
        await self.t.request(c.zdo_simple_desc_req(nwk, ep))
        rsp = c.decode_simple_desc_rsp((await task).data)
        if rsp.status != 0:
            raise ZnpStatusError(c.zdo_simple_desc_req(nwk, ep), rsp.status)
        return rsp

    async def nwk_lookup(self, ieee: int, timeout: float = 6.0) -> int | None:
        """Resolve an IEEE address to its current short address via ZDO broadcast; None if silent."""
        wait = self.t.wait_for(Subsystem.ZDO, ZdoCmd.NWK_ADDR_RSP, timeout=timeout,
                               predicate=lambda f: c.decode_ieee_addr_rsp(f.data).ieee == ieee)
        task = await self._arm(wait)
        try:
            await self.t.request(c.zdo_nwk_addr_req(ieee))
            rsp = c.decode_ieee_addr_rsp((await task).data)
        except (ZnpTimeout, ZnpStatusError):
            task.cancel()
            return None
        return rsp.nwk if rsp.status == 0 else None

    async def ieee_lookup(self, nwk: int, timeout: float = 6.0) -> int | None:
        """Resolve a short address to an IEEE address via ZDO; None if nobody answers."""
        wait = self.t.wait_for(Subsystem.ZDO, ZdoCmd.IEEE_ADDR_RSP, timeout=timeout,
                               predicate=lambda f: c.decode_ieee_addr_rsp(f.data).nwk == nwk)
        task = await self._arm(wait)
        try:
            await self.t.request(c.zdo_ieee_addr_req(nwk))
            rsp = c.decode_ieee_addr_rsp((await task).data)
        except (ZnpTimeout, ZnpStatusError):
            task.cancel()
            return None
        return rsp.ieee if rsp.status == 0 else None

    async def node_descriptor(self, nwk: int, timeout: float = 10.0) -> c.NodeDescRsp:
        wait = self.t.wait_for(Subsystem.ZDO, ZdoCmd.NODE_DESC_RSP, timeout=timeout,
                               predicate=lambda f: c.decode_node_desc_rsp(f.data).nwk_addr == nwk)
        task = await self._arm(wait)
        await self.t.request(c.zdo_node_desc_req(nwk))
        return c.decode_node_desc_rsp((await task).data)

    async def bind(self, nwk: int, src_ieee: int, src_ep: int, cluster: int, timeout: float = 10.0, *,
                   dst_ieee: int | None = None, dst_ep: int = GATEWAY_ENDPOINT) -> int:
        """Bind src endpoint/cluster to dst (default: us). Returns ZDO status."""
        wait = self.t.wait_for(Subsystem.ZDO, ZdoCmd.BIND_RSP, timeout=timeout,
                               predicate=lambda f: int.from_bytes(f.data[0:2], "little") == nwk)
        task = await self._arm(wait)
        await self.t.request(c.zdo_bind_req(nwk, src_ieee, src_ep, cluster, dst_ieee if dst_ieee is not None else self.ieee, dst_ep))
        rsp = await task
        return rsp.data[2] if len(rsp.data) >= 3 else 0xFF

    async def unbind(self, nwk: int, src_ieee: int, src_ep: int, cluster: int, dst_ieee: int, dst_ep: int, timeout: float = 10.0) -> int:
        wait = self.t.wait_for(Subsystem.ZDO, ZdoCmd.UNBIND_RSP, timeout=timeout,
                               predicate=lambda f: int.from_bytes(f.data[0:2], "little") == nwk)
        task = await self._arm(wait)
        await self.t.request(c.zdo_unbind_req(nwk, src_ieee, src_ep, cluster, dst_ieee, dst_ep))
        rsp = await task
        return rsp.data[2] if len(rsp.data) >= 3 else 0xFF

    async def info(self) -> dict:
        """Live coordinator status for the UI's Coordinator page: firmware identity,
        radio state, and whether the radio agrees with the keystore — the same sync
        the gateway enforces at startup, made visible and re-checkable on demand."""
        di = c.decode_device_info((await self.t.request(c.util_get_device_info())).data)
        nwk = c.decode_ext_nwk_info((await self.t.request(c.zdo_ext_nwk_info(), check_status=False)).data)
        counter = await self.nwk_frame_counter()
        key_ok = await self.active_key_matches()
        s, v = self.secrets, self.version
        sync = {
            "pan_id": nwk.pan_id == s.pan_id,
            "ext_pan_id": nwk.ext_pan_id == s.ext_pan_id,
            "channel": nwk.channel == s.channel,
            "network_key": key_ok,
            # equal is fine right after a restore; behind the keystore means devices
            # will drop our frames (the exact failure the startup margin prevents)
            "frame_counter": counter is not None and counter >= (s.frame_counter or 0),
        }
        return {
            "firmware": {
                "product": v.product if v else None,
                "version": f"{v.major}.{v.minor}.{v.maint}" if v else None,
                "revision": v.revision if v else None,
                "oneroof": bool(v and v.revision and v.revision >= ONEROOF_MIN_REVISION),
            },
            "radio": {
                "ieee": f"0x{self.ieee:016x}",
                "device_state": di.device_state,
                "started": di.device_state == c.DeviceState.ZB_COORD,
                "pan_id": f"{nwk.pan_id:#06x}",
                "ext_pan_id": f"0x{nwk.ext_pan_id:016x}",
                "channel": nwk.channel,
                "frame_counter": counter,
            },
            "keystore": {
                "pan_id": f"{s.pan_id:#06x}",
                "ext_pan_id": f"0x{s.ext_pan_id:016x}",
                "channel": s.channel,
                "frame_counter": s.frame_counter,
            },
            "sync": {**sync, "in_sync": all(sync.values())},
        }

    async def neighbors(self, nwk: int, timeout: float = 10.0) -> list[c.Neighbor]:
        out: list[c.Neighbor] = []
        index = 0
        while True:
            wait = self.t.wait_for(Subsystem.ZDO, ZdoCmd.MGMT_LQI_RSP, timeout=timeout,
                                   predicate=lambda f: c.decode_mgmt_lqi_rsp(f.data).src_addr == nwk)
            task = await self._arm(wait)
            await self.t.request(c.zdo_mgmt_lqi_req(nwk, index))
            rsp = c.decode_mgmt_lqi_rsp((await task).data)
            if rsp.status != 0:
                break
            out.extend(rsp.neighbors)
            index += len(rsp.neighbors)
            if index >= rsp.total or not rsp.neighbors:
                break
        return out
