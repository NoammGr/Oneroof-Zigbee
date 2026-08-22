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
        self.nwk_to_ieee: dict[int, int] = {}  # populated by emit_announce; used for IEEE_ADDR_REQ
        self.on_data_request = None  # optional hook: Frame -> list[Frame] of AREQs to emit

    # --- emit AREQ from "the radio" ---
    def emit(self, frame: Frame) -> None:
        self.reader.feed_data(frame.encode())

    def emit_incoming(self, src: int, cluster: int, payload: bytes, src_ep: int = 1, seq: int = 1, lqi: int = 200) -> None:
        w = Writer().u16(0).u16(cluster).u16(src).u8(src_ep).u8(1).u8(0).u8(lqi).u8(1).u32(0).u8(seq).lv(payload)
        self.emit(Frame(FrameType.AREQ, Subsystem.AF, c.AfCmd.INCOMING_MSG, w.bytes()))

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
                self.emit(Frame(FrameType.AREQ, Subsystem.SYS, c.SysCmd.RESET_IND, bytes(6)))
            elif cmd == c.SysCmd.PING:
                self._srsp(f, b"\x79\x07")
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
                self.nv[item] = f.data[4:]
                if item == c.NvId.STARTUP_OPTION and f.data[4] == 3:
                    # clear everything on next reset, like the real thing
                    self.nv = {item: f.data[4:]}
                    self.formed = False
                self._srsp(f, b"\x00")
            elif cmd == c.SysCmd.OSAL_NV_READ:
                item = int.from_bytes(f.data[0:2], "little")
                if item == c.NvId.BDBNODEISONANETWORK:
                    self._srsp(f, b"\x00\x01" + (b"\x01" if self.formed else b"\x00"))
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
                self.frame_counter = int.from_bytes(f.data[0:4], "little")
            if cmd == c.AppCnfCmd.BDB_ADD_INSTALLCODE:
                self.install_codes.append((int.from_bytes(f.data[1:9], "little"), f.data[9:]))
            self._srsp(f, b"\x00")
            if cmd == c.AppCnfCmd.BDB_START_COMMISSIONING and f.data[0] == c.CommissioningMode.NWK_FORMATION:
                self.formed = True
                self.device_state = 9
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.STATE_CHANGE_IND, bytes([9])))
        elif ss is Subsystem.ZDO:
            if cmd == c.ZdoCmd.STARTUP_FROM_APP:
                self._srsp(f, b"\x00")
                self.device_state = 9
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.STATE_CHANGE_IND, bytes([9])))
            elif cmd == c.ZdoCmd.MGMT_PERMIT_JOIN_REQ:
                self.permit_durations.append(f.data[3])
                self._srsp(f, b"\x00")
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.PERMIT_JOIN_IND, bytes([f.data[3]])))
            elif cmd == c.ZdoCmd.EXT_NWK_INFO:
                pan = int.from_bytes(self.nv.get(c.NvId.PANID, b"\x00\x00"), "little")
                ch_mask = int.from_bytes(self.nv.get(c.NvId.CHANLIST, b"\x00\x00\x00\x00"), "little")
                ch = ch_mask.bit_length() - 1 if ch_mask else 0
                self._srsp(f, Writer().u16(0).u8(self.device_state).u16(pan).u16(0).u64(0).u64(0).u8(ch).bytes())
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
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.BIND_RSP, f.data[0:2] + b"\x00"))
            elif cmd == c.ZdoCmd.UNBIND_REQ:
                self._srsp(f, b"\x00")
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.UNBIND_RSP, f.data[0:2] + b"\x00"))
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
                if ieee is not None:
                    self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.IEEE_ADDR_RSP, Writer().u8(0).ieee(ieee).u16(nwk).u8(0).u8(0).bytes()))
                else:
                    self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.IEEE_ADDR_RSP, Writer().u8(0x81).ieee(0).u16(nwk).bytes()))
            elif cmd == c.ZdoCmd.MGMT_LQI_REQ:
                nwk = int.from_bytes(f.data[0:2], "little")
                self._srsp(f, b"\x00")
                # one neighbour: a router 0x5678 with lqi 180, relationship child(1), depth 1
                entry = Writer().u64(0).ieee(0x00124B00DEADBEEF).u16(0x5678).u8(0x01 | (0x01 << 2) | (0x01 << 4)).u8(0x02).u8(1).u8(180).bytes()
                self.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.MGMT_LQI_RSP, Writer().u16(nwk).u8(0).u8(1).u8(0).u8(1).raw(entry).bytes()))
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
                self._srsp(f, b"\x00")
                tid = f.data[6]
                self.emit(Frame(FrameType.AREQ, Subsystem.AF, c.AfCmd.DATA_CONFIRM, bytes([0, f.data[3], tid])))
                if self.on_data_request:
                    for areq in self.on_data_request(f):
                        self.emit(areq)
        else:
            self._srsp(f, b"\x00")
