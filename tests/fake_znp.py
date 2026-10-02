"""A scripted fake CC2652 for tests: answers SREQs, emits AREQs on cue.

It speaks real UNPI bytes through an asyncio StreamReader/StreamWriter pair,
so Transport + Coordinator run unmodified.
"""

from __future__ import annotations

import asyncio

from oneroof_zigbee.znp import commands as c
from oneroof_zigbee.znp.unpi import Frame, FrameType, Parser, Subsystem
from oneroof_zigbee.znp.wire import Writer


class _Writer:
    """Minimal StreamWriter stand-in that feeds a FakeZnp."""

    def __init__(self, fake: FakeZnp) -> None:
        self._fake = fake

    def write(self, data: bytes) -> None:
        self._fake._host_wrote(data)

    def close(self) -> None:
        self._fake.closed = True

    async def wait_closed(self) -> None:
        return None


class FakeZnp:
    def __init__(self) -> None:
        self.reader = asyncio.StreamReader()
        self.writer = _Writer(self)
        self._parser = Parser()
        self.nv: dict[int, bytes] = {}
        self.requests: list[Frame] = []
        self.permit_durations: list[int] = []
        self.install_codes: list[tuple[int, bytes]] = []
        self.device_state = 0
        self.formed = False
        self.closed = False
        self.ieee = 0x00124B0011223344
        self.frame_counter = None
        self.ignore_set_frame_counter = False
        self.active_key = None  # None = whatever PRECFGKEY holds; set to model a radio on another key
        self.local_install_on_unicast = True  # False models firmware that keeps no alternate key from per-device transports
        self.switch_local_on_unicast = False  # True models firmware that switches the coordinator itself on any unicast switch order
        self.devices_follow_broadcast_switch = True  # False: a broadcast switch order reaches no device (sleepers never, others ignore)
        self.devices_follow_unicast_switch = True
        self.device_keys: dict[int, bytes] = {}          # nwk → the key that device is on (only tracked devices are modelled)
        self.device_pending: dict[int, tuple[int, bytes]] = {}  # nwk → (seq, key) delivered but not yet switched to
        self.key_switches: list[tuple[int, int]] = []    # (dst, seq) of every switch order sent
        self.refuse_key_item_writes = False  # True = a firmware whose key items cannot be written at all
        self.pending_key = None
        self.key_deliveries: list[tuple[int, int]] = []
        self.active_seq = 0
        self.forward_zdo = True  # the firmware in the field forwards ZDO responses only via the message callback
        self.has_exnv = True  # Z-Stack 3.x.0: frame counters live in the security material table
        self.sec_material: list[tuple[int, bytes]] = [(0, b"\xff" * 8)]  # (frameCounter, extPanId LE)  # model firmware that does not keep SET_NWK_FRAME_COUNTER
        self.nwk_to_ieee: dict[int, int] = {}  # populated by emit_announce; used for IEEE_ADDR_REQ
        self.formation_ignores_config = False  # models firmware that forms its own PAN/channel
        self.nib_blocks_beacons = True  # real firmware: no beacon indications while a NIB exists
        self.live_pan_id = None        # override EXT_NWK_INFO (models a NIB that differs from the config NV items)
        self.live_channel = None
        self.net_running = False       # like the real stack: no network between RESET and STARTUP_FROM_APP
        self.scan_while_up = True      # False models firmware that answers 0xC2 while the network runs (the common case)
        self.beacons: list[tuple] = []  # (src, pan, ch, permit, router_cap, dev_cap, lqi, depth, update_id, ext_pan)
        self.refuse_scan = False
        self.on_data_request = None  # optional hook: Frame -> list[Frame] of AREQs to emit
        self.bind_status = 0x00  # ZDO status the "device" answers a bind request with (0x8C: table full)
        self.af_srsp_statuses: list[int] = []  # statuses the next AF data requests are refused with, in order
        # neighbour tables per asked address: {nwk: [(ieee, nwk, lqi, relationship, depth)]}; an
        # address not listed answers the one stock neighbour below
        self.neighbours: dict[int, list[tuple]] = {}

    # --- emit AREQ from "the radio" ---
    # MT ids of ZDO responses that the real firmware delivers only through the message callback
    _FORWARDED = {0x80: 0x8000, 0x81: 0x8001, 0x82: 0x8002, 0x84: 0x8004, 0x85: 0x8005, 0xA1: 0x8021, 0xA2: 0x8022,
                  0xB1: 0x8031, 0xB6: 0x8036}

    def emit(self, frame: Frame) -> None:
        if (self.forward_zdo and frame.type is FrameType.AREQ and frame.subsystem is Subsystem.ZDO
                and frame.command in self._FORWARDED):
            # Like the hardware: no classic indication, only the generic ZDO message envelope
            # (SrcAddr, WasBroadcast, ClusterId, SecurityUse, SeqNum, MacDstAddr, Data).
            src = frame.data[0:2]
            env = src + b"\x00" + self._FORWARDED[frame.command].to_bytes(2, "little") + b"\x00\x07" + b"\x00\x00" + frame.data[2:]
            frame = Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.MSG_CB_INCOMING, env)
        self.reader.feed_data(frame.encode())

    def emit_incoming(self, src: int, cluster: int, payload: bytes, src_ep: int = 1, seq: int = 1, lqi: int = 200) -> None:
        w = Writer().u16(0).u16(cluster).u16(src).u8(src_ep).u8(1).u8(0).u8(lqi).u8(1).u32(0).u8(seq).lv(payload)
        self.emit(Frame(FrameType.AREQ, Subsystem.AF, c.AfCmd.INCOMING_MSG, w.bytes()))

    def _radio_key(self) -> bytes:
        return self.active_key if self.active_key is not None else self.nv.get(c.NvId.PRECFGKEY, bytes(16))[:16]

    def emit_announce(self, ieee: int, nwk: int, caps: int = 0x8E) -> None:
        self.nwk_to_ieee[nwk] = ieee
        w = Writer().u16(nwk).u16(nwk).ieee(ieee).u8(caps)
        self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.END_DEVICE_ANNCE_IND, w.bytes()))

    # --- host → fake ---
    def _host_wrote(self, data: bytes) -> None:
        for f in self._parser.feed(data):
            self._handle(f)

    def _srsp(self, req: Frame, data: bytes) -> None:
        self.emit(Frame(FrameType.SRSP, req.subsystem, req.command, data))

    def _handle(self, f: Frame) -> None:
        self.requests.append(f)
        ss, cmd = f.subsystem, f.command
        if ss is Subsystem.SYS:
            if cmd == c.SysCmd.RESET_REQ:
                self.net_running = False
                self.emit(Frame(FrameType.AREQ, Subsystem.SYS, c.SysCmd.RESET_IND, bytes(6)))
            elif cmd == c.SysCmd.PING:
                self._srsp(f, b"\x79\x07")
            elif cmd == c.SysCmd.NV_READ:  # extended NV API: security material table only
                item, sub = int.from_bytes(f.data[1:3], "little"), int.from_bytes(f.data[3:5], "little")
                if not self.has_exnv or item != c.EXNV_NWK_SEC_MATERIAL_TABLE or sub >= len(self.sec_material):
                    self._srsp(f, b"\x0a")  # NV_BAD_ITEM_LEN / not found
                else:
                    counter, pan = self.sec_material[sub]
                    body = counter.to_bytes(4, "little") + pan
                    self._srsp(f, b"\x00" + bytes([len(body)]) + body)
            elif cmd == c.SysCmd.NV_WRITE:
                item, sub = int.from_bytes(f.data[1:3], "little"), int.from_bytes(f.data[3:5], "little")
                value = f.data[8:]
                if not self.has_exnv or item != c.EXNV_NWK_SEC_MATERIAL_TABLE or sub >= len(self.sec_material):
                    self._srsp(f, b"\x0a")
                else:
                    self.sec_material[sub] = (int.from_bytes(value[0:4], "little"), value[4:12])
                    self.frame_counter = self.sec_material[sub][0]
                    self._srsp(f, b"\x00")
            elif cmd == c.SysCmd.VERSION:
                self._srsp(f, bytes([2, 2, 2, 7, 1]) + (20220219).to_bytes(4, "little"))
            elif cmd == c.SysCmd.OSAL_NV_ITEM_INIT:
                item = int.from_bytes(f.data[0:2], "little")
                init = f.data[5:]
                if item in self.nv:
                    self._srsp(f, b"\x09")
                else:
                    self.nv[item] = init
                    self._srsp(f, b"\x00")
            elif cmd == c.SysCmd.OSAL_NV_WRITE:
                item = int.from_bytes(f.data[0:2], "little")
                if item in (c.NvId.NWK_ACTIVE_KEY_INFO, c.NvId.NWK_ALTERN_KEY_INFO):
                    # Like the real firmware: the item is seq(1)+key(16) = 17 bytes; any other length
                    # is refused with NV_OPER_FAILED, and so is everything while refuse_key_item_writes.
                    if self.refuse_key_item_writes or len(f.data[4:]) != 17:
                        self._srsp(f, b"\x02")
                        return
                    self.nv[item] = f.data[4:]
                    if item == c.NvId.NWK_ACTIVE_KEY_INFO:
                        self.active_key = f.data[4:][1:17]
                        self.active_seq = f.data[4]
                    self._srsp(f, b"\x00")
                    return
                self.nv[item] = f.data[4:]
                if item == c.NvId.STARTUP_OPTION and f.data[4] == 3:
                    # clear everything on next reset, like the real thing
                    self.nv = {item: f.data[4:]}
                    self.formed = False
                self._srsp(f, b"\x00")
            elif cmd == c.SysCmd.OSAL_NV_LENGTH:
                item = int.from_bytes(f.data[0:2], "little")
                v = self.nv.get(item)
                self._srsp(f, (len(v) if v else 0).to_bytes(2, "little"))
            elif cmd == c.SysCmd.OSAL_NV_DELETE:
                item = int.from_bytes(f.data[0:2], "little")
                self.nv.pop(item, None)
                self._srsp(f, b"\x00")
            elif cmd == c.SysCmd.OSAL_NV_READ:
                item = int.from_bytes(f.data[0:2], "little")
                if item == c.NvId.BDBNODEISONANETWORK:
                    self._srsp(f, b"\x00\x01" + (b"\x01" if self.formed else b"\x00"))
                elif item == c.NvId.NWK_ALTERN_KEY_INFO and item in self.nv and len(self.nv[item]) >= 17:
                    body = self.nv[item][:17]  # a distinct alternate key (written, or preset by a test)
                    self._srsp(f, b"\x00" + bytes([len(body)]) + body)
                elif item in (c.NvId.NWK_ACTIVE_KEY_INFO, c.NvId.NWK_ALTERN_KEY_INFO):
                    key = self.active_key if self.active_key is not None else self.nv.get(c.NvId.PRECFGKEY, bytes(16))[:16]
                    body = bytes([self.active_seq]) + key  # 17 bytes: the counter lives in the security material table
                    self._srsp(f, b"\x00" + bytes([len(body)]) + body)
                elif item in self.nv:
                    v = self.nv[item]
                    self._srsp(f, b"\x00" + bytes([len(v)]) + v)
                else:
                    self._srsp(f, b"\x09")
        elif ss is Subsystem.APP_CNF:
            if cmd == c.AppCnfCmd.BDB_SET_ACTIVE_DEFAULT_CENTRALIZED_KEY:
                mode = f.data[0]
                if mode == 1:
                    from oneroof_zigbee.security.installcode import crc16
                    code = f.data[1:19]
                    if len(code) != 18 or crc16(code[:16]) != int.from_bytes(code[16:18], "little"):
                        self._srsp(f, b"\x02")  # INVALID_PARAMETER, like the real firmware
                        return
                elif mode != 0:
                    self._srsp(f, b"\x02")
                    return
            if cmd == c.AppCnfCmd.SET_NWK_FRAME_COUNTER:
                if not self.ignore_set_frame_counter:
                    self.frame_counter = int.from_bytes(f.data[0:4], "little")
                    self.sec_material = [(self.frame_counter, pan) for _c, pan in self.sec_material]
            if cmd == c.AppCnfCmd.BDB_ADD_INSTALLCODE:
                self.install_codes.append((int.from_bytes(f.data[1:9], "little"), f.data[9:]))
            self._srsp(f, b"\x00")
            if cmd == c.AppCnfCmd.BDB_START_COMMISSIONING and f.data[0] == c.CommissioningMode.NWK_FORMATION:
                self.formed = True
                self.sec_material = [(0, pan) for _c, pan in self.sec_material]
                self.frame_counter = 0
                # Like the real firmware: formation always makes up its own network key; PRECFGKEY
                # and PRECFGKEYS_ENABLE do not change that. Only the key items (17 bytes, written
                # while stopped) set the key.
                self.active_key = bytes(b ^ 0x5A for b in self.nv.get(c.NvId.PRECFGKEY, bytes(16))[:16])
                if self.formation_ignores_config:
                    self.nv[c.NvId.PANID] = (0x4CD2).to_bytes(2, "little")
                    self.nv[c.NvId.CHANLIST] = (1 << 11).to_bytes(4, "little")
                self.nv[c.NvId.NIB] = bytes(110)
                self.net_running = True
                self.device_state = 9
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.STATE_CHANGE_IND, bytes([9])))
        elif ss is Subsystem.ZDO:
            if cmd == c.ZdoCmd.STARTUP_FROM_APP:
                self._srsp(f, b"\x00")
                self.net_running = True
                self.device_state = 9
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.STATE_CHANGE_IND, bytes([9])))
            elif cmd == c.ZdoCmd.MGMT_PERMIT_JOIN_REQ:
                self.permit_durations.append(f.data[3])
                self._srsp(f, b"\x00")
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.PERMIT_JOIN_IND, bytes([f.data[3]])))
            elif cmd == c.ZdoCmd.EXT_NWK_INFO:
                pan = self.live_pan_id if self.live_pan_id is not None else int.from_bytes(self.nv.get(c.NvId.PANID, b"\x00\x00"), "little")
                extpan = int.from_bytes(self.nv.get(c.NvId.EXTPANID, b"\x00" * 8), "little")
                ch_mask = int.from_bytes(self.nv.get(c.NvId.CHANLIST, b"\x00\x00\x00\x00"), "little")
                ch = self.live_channel if self.live_channel is not None else (ch_mask.bit_length() - 1 if ch_mask else 0)
                self._srsp(f, Writer().u16(0).u8(self.device_state).u16(pan).u16(0).u64(extpan).u64(0).u8(ch).bytes())
            elif cmd == c.ZdoCmd.ACTIVE_EP_REQ:
                nwk = int.from_bytes(f.data[0:2], "little")
                self._srsp(f, b"\x00")
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.ACTIVE_EP_RSP, Writer().u16(nwk).u8(0).u16(nwk).u8(1).u8(1).bytes()))
            elif cmd == c.ZdoCmd.SIMPLE_DESC_REQ:
                nwk = int.from_bytes(f.data[0:2], "little")
                ep = f.data[4]
                self._srsp(f, b"\x00")
                body = Writer().u8(ep).u16(0x0104).u16(0x0100).u8(1).u16list([0x0000, 0x0006, 0x0008]).u16list([0x0019]).bytes()
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.SIMPLE_DESC_RSP, Writer().u16(nwk).u8(0).u16(nwk).lv(body).bytes()))
            elif cmd == c.ZdoCmd.NODE_DESC_REQ:
                nwk = int.from_bytes(f.data[0:2], "little")
                self._srsp(f, b"\x00")
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.NODE_DESC_RSP,
                                Writer().u16(nwk).u8(0).u16(nwk).u8(1).u8(0x40).u8(0x8E).u16(0x1037).u8(80).u16(160).raw(bytes(6)).bytes()))
            elif cmd == c.ZdoCmd.BIND_REQ:
                self._srsp(f, b"\x00")
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.BIND_RSP, f.data[0:2] + bytes([self.bind_status])))
            elif cmd == c.ZdoCmd.UNBIND_REQ:
                self._srsp(f, b"\x00")
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.UNBIND_RSP, f.data[0:2] + b"\x00"))
            elif cmd == c.ZdoCmd.NETWORK_DISCOVERY_REQ:
                if self.refuse_scan or (self.net_running and not self.scan_while_up):
                    self._srsp(f, b"\x02")
                    return
                self._srsp(f, b"\x00")
                suppressed = self.nib_blocks_beacons and not self.net_running and c.NvId.NIB in self.nv
                if self.beacons and not suppressed:
                    w = Writer().u8(len(self.beacons))
                    for src, pan, ch, pj, rc, dc, lqi, depth, upd, ext in self.beacons:
                        w.u16(src).u16(pan).u8(ch).u8(pj).u8(rc).u8(dc).u8(2).u8(2).u8(lqi).u8(depth).u8(upd).u64(ext)
                    self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.BEACON_NOTIFY_IND, w.bytes()))
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.NWK_DISCOVERY_CNF, b"\x00"))
            elif cmd == c.ZdoCmd.MGMT_LEAVE_REQ:
                self._srsp(f, b"\x00")
            elif cmd == c.ZdoCmd.NWK_ADDR_REQ:
                ieee = int.from_bytes(f.data[0:8], "little")
                self._srsp(f, b"\x00")
                nwk = next((n for n, i in self.nwk_to_ieee.items() if i == ieee), None)
                if nwk is not None:
                    self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.NWK_ADDR_RSP, Writer().u8(0).ieee(ieee).u16(nwk).u8(0).u8(0).bytes()))
                # silent otherwise, like a sleeping or absent device
            elif cmd == c.ZdoCmd.IEEE_ADDR_REQ:
                nwk = int.from_bytes(f.data[0:2], "little")
                self._srsp(f, b"\x00")
                ieee = self.nwk_to_ieee.get(nwk)
                if ieee is not None and nwk in self.device_keys and self.device_keys[nwk] != self._radio_key():
                    ieee = None  # a device on another key cannot read the request: silence
                if ieee is not None:
                    self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.IEEE_ADDR_RSP, Writer().u8(0).ieee(ieee).u16(nwk).u8(0).u8(0).bytes()))
                else:
                    self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.IEEE_ADDR_RSP, Writer().u8(0x81).ieee(0).u16(nwk).bytes()))
            elif cmd == c.ZdoCmd.EXT_UPDATE_NWK_KEY:
                dst = int.from_bytes(f.data[0:2], "little")
                if dst == 0x0000:
                    self._srsp(f, b"\x01")  # the real firmware refuses a transport to itself
                else:
                    if self.local_install_on_unicast or dst == 0xFFFF:
                        self.pending_key = (f.data[2], f.data[3:19])
                    if dst in self.device_keys:
                        self.device_pending[dst] = (f.data[2], bytes(f.data[3:19]))
                    self.key_deliveries.append((dst, f.data[2]))
                    self._srsp(f, b"\x00")
            elif cmd == c.ZdoCmd.EXT_SWITCH_NWK_KEY:
                dst = int.from_bytes(f.data[0:2], "little")
                seq = f.data[2]
                self.key_switches.append((dst, seq))
                targets = list(self.device_keys) if dst == 0xFFFF else [dst]
                follow = self.devices_follow_broadcast_switch if dst == 0xFFFF else self.devices_follow_unicast_switch
                if follow:
                    for n in targets:
                        p = self.device_pending.get(n)
                        if p and p[0] == seq:
                            self.device_keys[n] = p[1]
                if (dst == 0xFFFF or self.switch_local_on_unicast) and self.pending_key and self.pending_key[0] == seq:
                    self.active_key = self.pending_key[1]
                    self.active_seq = seq
                self._srsp(f, b"\x00")
            elif cmd == c.ZdoCmd.MGMT_LQI_REQ:
                nwk = int.from_bytes(f.data[0:2], "little")
                self._srsp(f, b"\x00")
                # by default one neighbour: a router 0x5678 with lqi 180, relationship child(1), depth 1
                rows = self.neighbours.get(nwk, [(0x00124B00DEADBEEF, 0x5678, 180, 1, 1)])
                w = Writer().u16(nwk).u8(0).u8(len(rows)).u8(0).u8(len(rows))
                for ieee, n_nwk, lqi, rel, depth in rows:
                    w.raw(Writer().u64(0).ieee(ieee).u16(n_nwk).u8(0x01 | (0x01 << 2) | (rel << 4)).u8(0x02).u8(depth).u8(lqi).bytes())
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.MGMT_LQI_RSP, w.bytes()))
            else:
                self._srsp(f, b"\x00")
        elif ss is Subsystem.UTIL:
            if cmd == c.UtilCmd.GET_DEVICE_INFO:
                self._srsp(f, Writer().u8(0).ieee(self.ieee).u16(0).u8(0).u8(self.device_state).u8(0).bytes())
            else:
                self._srsp(f, b"\x00")
        elif ss is Subsystem.AF:
            if cmd == c.AfCmd.REGISTER:
                self._srsp(f, b"\x00")
            elif cmd == c.AfCmd.DATA_REQUEST:
                if self.af_srsp_statuses:
                    # the coordinator momentarily refusing to queue a frame (BUFFER_FULL and the like)
                    self._srsp(f, bytes([self.af_srsp_statuses.pop(0)]))
                    return
                self._srsp(f, b"\x00")
                tid = f.data[6]
                self.emit(Frame(FrameType.AREQ, Subsystem.AF, c.AfCmd.DATA_CONFIRM, bytes([0, f.data[3], tid])))
                if self.on_data_request:
                    for areq in self.on_data_request(f):
                        self.emit(areq)
        else:
            self._srsp(f, b"\x00")
