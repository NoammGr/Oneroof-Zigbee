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

import asyncio
import logging
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
LeaveCb = Callable[[int, int], Awaitable[None]]  # ieee, nwk


class Coordinator:
    def __init__(self, transport: Transport, secrets: NetworkSecrets, guard: JoinGuard, audit: Audit,
                 *, strict_install_codes: bool = False) -> None:
        self.t = transport
        self.secrets = secrets
        self.guard = guard
        self.audit = audit
        self.strict = strict_install_codes
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
        self._wire_listeners()

    # ------------------------------------------------------------ events --

    def on_aps(self, cb: ApsCb) -> None:
        self._aps_cbs.append(cb)

    def on_device_joined(self, cb: JoinCb) -> None:
        self._join_cbs.append(cb)

    def on_device_left(self, cb: LeaveCb) -> None:
        self._leave_cbs.append(cb)

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
            await cb(d.ieee, d.src_addr)

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

        if not await self._config_matches():
            log.warning("coordinator NV config does not match keystore — (re)forming network")
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

    async def _config_matches(self) -> bool:
        s = self.secrets
        checks = {
            NvId.PRECFGKEY: s.network_key,
            NvId.PANID: s.pan_id.to_bytes(2, "little"),
            NvId.EXTPANID: s.ext_pan_id.to_bytes(8, "little"),
            NvId.CHANLIST: (1 << s.channel).to_bytes(4, "little"),
            NvId.LOGICAL_TYPE: b"\x00",
        }
        for item, want in checks.items():
            got = await self._nv_read(item)
            if got is None or got[: len(want)] != want:
                shown = (got[: len(want)].hex() if got else None) if item != NvId.PRECFGKEY else ("<key>" if got else None)
                log.warning("coordinator NV %s differs: dongle=%s keystore=%s", item.name, shown,
                            want.hex() if item != NvId.PRECFGKEY else "<key>")
                self.audit.event("coordinator_nv_mismatch", item=item.name)
                return False
        on_net = await self._nv_read(NvId.BDBNODEISONANETWORK)
        return bool(on_net and on_net[0] == 1)

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
            try:
                await self._repair_active_key(raw)
            except ZnpStatusError as e:
                log.warning("key item write refused by the firmware (%s); installing the key through the ZDO key update", e)
                await self._install_key_via_zdo(raw[0] if raw else 0)
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
        for seq in (active_seq, (active_seq + 1) & 0xFF):
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

    async def _write_security_state_stopped(self) -> None:
        """Write key items, frame counter and TC seed into NV right after a reset and BEFORE the
        network is started — the order the firmware accepts for a restore (writes while the stack
        runs are refused). Caller resets first and starts the network afterwards."""
        s = self.secrets
        counter = (s.frame_counter or 0) + FRAME_COUNTER_MARGIN if s.frame_counter else None
        for item in (NvId.NWK_ACTIVE_KEY_INFO, NvId.NWK_ALTERN_KEY_INFO):
            raw = await self._nv_read(item)
            if raw is None or len(raw) < 17:
                log.info("key item %s: %s bytes, not written", item.name, None if raw is None else len(raw))
                continue
            # Keep the item's exact length: seq(1) + key(16) [+ counter(4) on firmware that has it].
            value = b"\x00" + s.network_key + raw[17:]
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
                await self._nv_write(NvId.NWKKEY, b"\x00" + s.network_key + legacy[17:])
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

    async def _repair_active_key(self, active_raw: bytes) -> None:
        """The radio formed the network with a key other than the keystore's (firmware variants
        generate their own unless the key items are written explicitly). Write the active, alternate
        and legacy key items with our key, keep the frame counter, restart the network, verify."""
        s = self.secrets
        await self._reset()
        await self._write_security_state_stopped()
        await self._apply_runtime_security()
        await self._startup()
        await self._register_endpoint()
        raw = await self._nv_read(NvId.NWK_ACTIVE_KEY_INFO)
        fixed = raw is not None and len(raw) >= 17 and raw[1:17] == s.network_key
        if fixed:
            log.warning("active network key rewritten from the keystore and network restarted")
            self.audit.event("network_key_repaired", method="nv")
        else:
            log.warning("key items could not be rewritten; installing the key through the ZDO key update")
            await self._install_key_via_zdo(raw[0] if raw else 0)

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
