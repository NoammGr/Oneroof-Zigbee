"""Simulated Zigbee devices behind the FakeZnp, used by the end-to-end tests.

Each SimDevice answers ZCL like a real product would: Basic attributes,
cluster reads, write/configure-reporting acks, IAS enrol, OTA client
behaviour (query → blocks → upgrade end).  This is what makes the e2e tests
meaningful: the gateway talks to "devices", not to stubs of itself.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from oneroof_zigbee.znp import commands as c
from oneroof_zigbee.znp.unpi import Frame, FrameType, Subsystem
from oneroof_zigbee.znp.wire import Writer
from tests.fake_znp import FakeZnp


def zcl_string(s: str) -> bytes:
    b = s.encode()
    return bytes([len(b)]) + b


@dataclass
class SimDevice:
    ieee: int
    nwk: int
    manufacturer: str
    model: str
    in_clusters: list[int]
    out_clusters: list[int]
    device_id: int = 0x0100
    router: bool = True
    power_source: int = 1
    sw_build: str = "1.0.0"
    date_code: str = "20240101"
    attrs: dict[tuple[int, int], tuple[int, bytes]] = field(default_factory=dict)  # (cluster, attr) → (dtype, raw)
    # OTA client state
    ota_manufacturer: int = 0x1037
    ota_image_type: int = 0x0001
    ota_version: int = 3
    ota_received: bytearray = field(default_factory=bytearray)
    ota_expected: int = 0
    ota_done: bool = False
    received_commands: list[tuple[int, int, bytes]] = field(default_factory=list)  # (cluster, cmd, payload)
    written: list[tuple[int, int, int]] = field(default_factory=list)              # (cluster, attr, value)

    def capabilities(self) -> int:
        return 0x8E if self.router else 0x80

    def basic_records(self) -> list[tuple[int, int, bytes]]:
        return [(0x0000, 0x20, b"\x03"), (0x0001, 0x20, b"\x45"), (0x0002, 0x20, b"\x02"), (0x0003, 0x20, b"\x01"),
                (0x0004, 0x42, zcl_string(self.manufacturer)), (0x0005, 0x42, zcl_string(self.model)),
                (0x0006, 0x42, zcl_string(self.date_code)), (0x0007, 0x30, bytes([self.power_source])),
                (0x4000, 0x42, zcl_string(self.sw_build))]


def plug(ieee: int, nwk: int) -> SimDevice:
    d = SimDevice(ieee, nwk, "_TZ3000_ko6v90pg", "TS011F", [0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0702, 0x0B04], [0x0019], 0x0051)
    d.attrs.update({
        (0x0006, 0x0000): (0x10, b"\x01"), (0x0006, 0x4003): (0x30, b"\xff"),
        (0x0B04, 0x0600): (0x21, b"\x01\x00"), (0x0B04, 0x0601): (0x21, b"\x01\x00"), (0x0B04, 0x0602): (0x21, b"\x01\x00"),
        (0x0B04, 0x0603): (0x21, b"\xe8\x03"), (0x0B04, 0x0604): (0x21, b"\x01\x00"), (0x0B04, 0x0605): (0x21, b"\x01\x00"),
        (0x0B04, 0x0505): (0x21, b"\xec\x00"), (0x0B04, 0x0508): (0x21, b"\x2c\x01"), (0x0B04, 0x050b): (0x29, b"\x47\x00"),
        (0x0702, 0x0301): (0x22, b"\x01\x00\x00"), (0x0702, 0x0302): (0x22, b"\xe8\x03\x00"), (0x0702, 0x0000): (0x25, (193080).to_bytes(6, "little")),
    })
    return d


def climate_sensor(ieee: int, nwk: int) -> SimDevice:
    d = SimDevice(ieee, nwk, "LUMI", "lumi.weather", [0x0000, 0x0001, 0x0003, 0x0402, 0x0405], [], 0x0302, router=False, power_source=3)
    d.attrs.update({(0x0402, 0x0000): (0x29, (2135).to_bytes(2, "little", signed=True)), (0x0405, 0x0000): (0x21, (4512).to_bytes(2, "little")),
                    (0x0001, 0x0020): (0x20, b"\x1e"), (0x0001, 0x0021): (0x20, b"\xb4")})
    return d


def contact_sensor(ieee: int, nwk: int) -> SimDevice:
    d = SimDevice(ieee, nwk, "LUMI", "lumi.sensor_magnet", [0x0000, 0x0001, 0x0003, 0x0500], [], 0x0402, router=False, power_source=3)
    d.attrs.update({(0x0500, 0x0001): (0x31, (0x0015).to_bytes(2, "little")), (0x0500, 0x0002): (0x19, b"\x00\x00"),
                    (0x0001, 0x0021): (0x20, b"\xc8")})
    return d


class World:
    """Attaches SimDevices to a FakeZnp and answers the gateway's traffic."""

    def __init__(self, fake: FakeZnp) -> None:
        self.fake = fake
        self.devices: dict[int, SimDevice] = {}
        self.pending_ota: list[tuple[SimDevice, int]] = []
        orig = fake._handle
        fake._handle = self._handle_znp
        self._orig_handle = orig
        fake.on_data_request = self._on_data_request

    def add(self, d: SimDevice) -> SimDevice:
        self.devices[d.nwk] = d
        return d

    def announce(self, d: SimDevice) -> None:
        self.fake.emit_announce(d.ieee, d.nwk, caps=d.capabilities())

    # -- ZDO answers with the device's real descriptors --
    def _handle_znp(self, f: Frame) -> None:
        if f.subsystem is Subsystem.ZDO and f.command == c.ZdoCmd.SIMPLE_DESC_REQ:
            nwk = int.from_bytes(f.data[0:2], "little")
            ep = f.data[4]
            d = self.devices.get(nwk)
            self.fake.requests.append(f)
            self.fake._srsp(f, b"\x00")
            if d:
                body = Writer().u8(ep).u16(0x0104).u16(d.device_id).u8(1).u16list(d.in_clusters).u16list(d.out_clusters).bytes()
                self.fake.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.SIMPLE_DESC_RSP, Writer().u16(nwk).u8(0).u16(nwk).lv(body).bytes()))
            else:
                self.fake.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.SIMPLE_DESC_RSP, Writer().u16(nwk).u8(0x81).u16(nwk).u8(0).bytes()))
            return
        self._orig_handle(f)

    # -- ZCL answers --
    def _on_data_request(self, f: Frame) -> list[Frame]:
        dst = int.from_bytes(f.data[0:2], "little")
        dst_ep, src_ep = f.data[2], f.data[3]
        cluster = int.from_bytes(f.data[4:6], "little")
        z = f.data[10:]
        d = self.devices.get(dst)
        if d is None or not z:
            return []
        fc = z[0]
        manuf_specific = bool(fc & 0x04)
        seq = z[3] if manuf_specific else z[1]
        cmd = z[4] if manuf_specific else z[2]
        payload = z[5:] if manuf_specific else z[3:]
        global_cmd = (fc & 0x03) == 0
        out: list[Frame] = []

        def reply(p: bytes, lqi: int = 200) -> None:
            w = Writer().u16(0).u16(cluster).u16(dst).u8(dst_ep).u8(src_ep).u8(0).u8(lqi).u8(1).u32(0).u8(seq).lv(p)
            out.append(Frame(FrameType.AREQ, Subsystem.AF, c.AfCmd.INCOMING_MSG, w.bytes()))

        if global_cmd and cmd == 0x00:  # read attributes
            attrs = [int.from_bytes(payload[i:i + 2], "little") for i in range(0, len(payload), 2)]
            body = b""
            for a in attrs:
                if cluster == 0x0000:
                    rec = next(((dt, raw) for aid, dt, raw in d.basic_records() if aid == a), None)
                else:
                    rec = d.attrs.get((cluster, a))
                if rec:
                    body += a.to_bytes(2, "little") + b"\x00" + bytes([rec[0]]) + rec[1]
                else:
                    body += a.to_bytes(2, "little") + b"\x86"  # unsupported attribute
            reply(bytes([0x18, seq, 0x01]) + body)
        elif global_cmd and cmd == 0x02:  # write attributes
            a = int.from_bytes(payload[0:2], "little")
            dt = payload[2]
            val = payload[3:]
            d.written.append((cluster, a, int.from_bytes(val, "little")))
            d.attrs[(cluster, a)] = (dt, val)
            reply(bytes([0x18, seq, 0x04, 0x00]))
        elif global_cmd and cmd == 0x06:  # configure reporting
            reply(bytes([0x18, seq, 0x07, 0x00]))
        elif not global_cmd:
            d.received_commands.append((cluster, cmd, payload))
            if cluster == 0x0006 and cmd in (0x00, 0x01, 0x02, 0x42):
                cur = d.attrs.get((0x0006, 0x0000), (0x10, b"\x00"))[1] == b"\x01"
                new = {0x00: False, 0x01: True, 0x02: not cur, 0x42: True}[cmd]
                d.attrs[(0x0006, 0x0000)] = (0x10, b"\x01" if new else b"\x00")
                # devices report the change back
                reply(bytes([0x18, (seq + 100) & 0xFF, 0x0A, 0x00, 0x00, 0x10, 0x01 if new else 0x00]))
            elif cluster == 0x0008 and cmd in (0x00, 0x04):
                d.attrs[(0x0008, 0x0000)] = (0x20, payload[0:1])
            elif cluster == 0x0019 and cmd == 0x00:  # ImageNotify → QueryNextImage
                q = bytes([0x01, (seq + 1) & 0xFF, 0x01]) + struct.pack("<BHHI", 0, d.ota_manufacturer, d.ota_image_type, d.ota_version)
                w = Writer().u16(0).u16(0x0019).u16(dst).u8(dst_ep).u8(src_ep).u8(0).u8(200).u8(1).u32(0).u8(seq + 1).lv(q)
                out.append(Frame(FrameType.AREQ, Subsystem.AF, c.AfCmd.INCOMING_MSG, w.bytes()))
            elif cluster == 0x0019 and cmd == 0x02:  # QueryNextImageResponse
                if payload[0] == 0x00:
                    d.ota_expected = struct.unpack_from("<I", payload, 9)[0]
                    d.ota_received = bytearray()
                    out.extend(self._ota_block_request(d, dst, dst_ep, src_ep, seq + 2))
            elif cluster == 0x0019 and cmd == 0x05:  # ImageBlockResponse
                if payload[0] == 0x00:
                    off, n = struct.unpack_from("<IB", payload, 9)
                    d.ota_received += payload[14:14 + n]
                    if len(d.ota_received) < d.ota_expected:
                        out.extend(self._ota_block_request(d, dst, dst_ep, src_ep, seq + 2))
                    else:
                        end = bytes([0x01, (seq + 3) & 0xFF, 0x06]) + struct.pack("<BHHI", 0x00, d.ota_manufacturer, d.ota_image_type, 5)
                        w = Writer().u16(0).u16(0x0019).u16(dst).u8(dst_ep).u8(src_ep).u8(0).u8(200).u8(1).u32(0).u8(seq + 3).lv(end)
                        out.append(Frame(FrameType.AREQ, Subsystem.AF, c.AfCmd.INCOMING_MSG, w.bytes()))
            elif cluster == 0x0019 and cmd == 0x07:  # UpgradeEndResponse
                d.ota_done = True
        return out

    def _ota_block_request(self, d: SimDevice, dst: int, dst_ep: int, src_ep: int, seq: int) -> list[Frame]:
        req = bytes([0x01, seq & 0xFF, 0x03]) + struct.pack("<BHHIIB", 0, d.ota_manufacturer, d.ota_image_type, 5, len(d.ota_received), 64)
        w = Writer().u16(0).u16(0x0019).u16(dst).u8(dst_ep).u8(src_ep).u8(0).u8(200).u8(1).u32(0).u8(seq & 0xFF).lv(req)
        return [Frame(FrameType.AREQ, Subsystem.AF, c.AfCmd.INCOMING_MSG, w.bytes())]

    # -- spontaneous traffic --
    def report(self, d: SimDevice, cluster: int, attr: int, dtype: int, raw: bytes, seq: int = 0x50) -> None:
        d.attrs[(cluster, attr)] = (dtype, raw)
        self.fake.emit_incoming(d.nwk, cluster, bytes([0x18, seq, 0x0A]) + attr.to_bytes(2, "little") + bytes([dtype]) + raw)

    def ias_notify(self, d: SimDevice, zone_status: int) -> None:
        p = bytes([0x19, 0x60, 0x00]) + struct.pack("<HBBH", zone_status, 0, 1, 0)
        self.fake.emit_incoming(d.nwk, 0x0500, p)
