"""ZNP command identifiers and payload codecs (Z-Stack 3.x, CC2652/CC1352).

Only the commands the gateway needs are defined.  Each request has an
encoder; each response / indication has a decoder returning a dataclass.
Command numbers come from TI's "Z-Stack Monitor and Test API" document.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from .unpi import Frame, FrameType, Subsystem
from .wire import Reader, Writer

# ---------------------------------------------------------------- SYS ----


class SysCmd(IntEnum):
    RESET_REQ = 0x00          # AREQ
    PING = 0x01
    VERSION = 0x02
    OSAL_NV_ITEM_INIT = 0x07
    OSAL_NV_READ = 0x08
    OSAL_NV_WRITE = 0x09
    OSAL_NV_DELETE = 0x12
    OSAL_NV_LENGTH = 0x13
    RESET_IND = 0x80          # AREQ


class NvId(IntEnum):
    """ZCD_NV_* item ids."""
    STARTUP_OPTION = 0x0003
    EXTPANID = 0x002D
    APS_USE_EXT_PANID = 0x0047
    PRECFGKEY = 0x0062
    PRECFGKEYS_ENABLE = 0x0063
    SECURITY_MODE = 0x0064
    NWKKEY = 0x0082
    PANID = 0x0083
    CHANLIST = 0x0084
    LOGICAL_TYPE = 0x0087
    ZDO_DIRECT_CB = 0x008F
    BDBNODEISONANETWORK = 0x0055


class StartupOption(IntEnum):
    NONE = 0x00
    CLEAR_CONFIG = 0x01
    CLEAR_STATE = 0x02
    CLEAR_ALL = 0x03


@dataclass(frozen=True)
class Version:
    transport_rev: int
    product: int
    major: int
    minor: int
    maint: int
    revision: int | None = None

    @property
    def is_zstack3(self) -> bool:
        # product 1 = zstack 3.0.x, 2 = zstack 3.x.0 (CC26x2/CC13x2)
        return self.product in (1, 2)


def sys_reset(soft: bool = True) -> Frame:
    return Frame(FrameType.AREQ, Subsystem.SYS, SysCmd.RESET_REQ, bytes([1 if soft else 0]))


def sys_ping() -> Frame:
    return Frame(FrameType.SREQ, Subsystem.SYS, SysCmd.PING)


def sys_version() -> Frame:
    return Frame(FrameType.SREQ, Subsystem.SYS, SysCmd.VERSION)


def decode_version(data: bytes) -> Version:
    r = Reader(data)
    transport, product, major, minor, maint = r.u8(), r.u8(), r.u8(), r.u8(), r.u8()
    revision = r.u32() if r.remaining >= 4 else None
    return Version(transport, product, major, minor, maint, revision)


def nv_item_init(item: int, length: int, init: bytes = b"") -> Frame:
    w = Writer().u16(item).u16(length).lv(init)
    return Frame(FrameType.SREQ, Subsystem.SYS, SysCmd.OSAL_NV_ITEM_INIT, w.bytes())


def nv_write(item: int, value: bytes, offset: int = 0) -> Frame:
    w = Writer().u16(item).u8(offset).lv(value)
    return Frame(FrameType.SREQ, Subsystem.SYS, SysCmd.OSAL_NV_WRITE, w.bytes())


def nv_read(item: int, offset: int = 0) -> Frame:
    w = Writer().u16(item).u8(offset)
    return Frame(FrameType.SREQ, Subsystem.SYS, SysCmd.OSAL_NV_READ, w.bytes())


def decode_nv_read(data: bytes) -> tuple[int, bytes]:
    r = Reader(data)
    status = r.u8()
    return status, r.lv() if r.remaining else b""


def nv_length(item: int) -> Frame:
    return Frame(FrameType.SREQ, Subsystem.SYS, SysCmd.OSAL_NV_LENGTH, Writer().u16(item).bytes())


# ----------------------------------------------------------------- AF ----


class AfCmd(IntEnum):
    REGISTER = 0x00
    DATA_REQUEST = 0x01
    DATA_CONFIRM = 0x80   # AREQ
    INCOMING_MSG = 0x81   # AREQ


def af_register(ep: int, profile: int, device_id: int, in_clusters: list[int], out_clusters: list[int]) -> Frame:
    w = (
        Writer()
        .u8(ep).u16(profile).u16(device_id).u8(0)  # app dev version
        .u8(0)  # latency: no latency
        .u16list(in_clusters)
        .u16list(out_clusters)
    )
    return Frame(FrameType.SREQ, Subsystem.AF, AfCmd.REGISTER, w.bytes())


class AfOptions(IntEnum):
    NONE = 0x00
    ACK_REQUEST = 0x10
    DISCOVER_ROUTE = 0x20
    SKIP_ROUTING = 0x80


def af_data_request(
    dst: int, dst_ep: int, src_ep: int, cluster: int, trans_id: int, payload: bytes,
    options: int = AfOptions.ACK_REQUEST | AfOptions.DISCOVER_ROUTE, radius: int = 30,
) -> Frame:
    if len(payload) > 230:
        raise ValueError("APS payload too large for AF_DATA_REQUEST")
    w = (
        Writer().u16(dst).u8(dst_ep).u8(src_ep).u16(cluster)
        .u8(trans_id).u8(options).u8(radius).lv(payload)
    )
    return Frame(FrameType.SREQ, Subsystem.AF, AfCmd.DATA_REQUEST, w.bytes())


@dataclass(frozen=True)
class AfDataConfirm:
    status: int
    endpoint: int
    trans_id: int


def decode_af_data_confirm(data: bytes) -> AfDataConfirm:
    r = Reader(data)
    return AfDataConfirm(r.u8(), r.u8(), r.u8())


@dataclass(frozen=True)
class AfIncomingMsg:
    group: int
    cluster: int
    src_addr: int
    src_ep: int
    dst_ep: int
    was_broadcast: bool
    lqi: int
    security_use: bool
    timestamp: int
    trans_seq: int
    data: bytes


def decode_af_incoming_msg(data: bytes) -> AfIncomingMsg:
    r = Reader(data)
    return AfIncomingMsg(
        group=r.u16(), cluster=r.u16(), src_addr=r.u16(), src_ep=r.u8(), dst_ep=r.u8(),
        was_broadcast=bool(r.u8()), lqi=r.u8(), security_use=bool(r.u8()),
        timestamp=r.u32(), trans_seq=r.u8(), data=r.lv(),
    )


# ---------------------------------------------------------------- ZDO ----


class ZdoCmd(IntEnum):
    NODE_DESC_REQ = 0x02
    SIMPLE_DESC_REQ = 0x04
    ACTIVE_EP_REQ = 0x05
    BIND_REQ = 0x21
    UNBIND_REQ = 0x22
    MGMT_LQI_REQ = 0x31
    MGMT_LEAVE_REQ = 0x34
    MGMT_PERMIT_JOIN_REQ = 0x36
    STARTUP_FROM_APP = 0x40
    EXT_NWK_INFO = 0x50
    # indications
    NODE_DESC_RSP = 0x82
    SIMPLE_DESC_RSP = 0x84
    ACTIVE_EP_RSP = 0x85
    BIND_RSP = 0xA1
    UNBIND_RSP = 0xA2
    MGMT_LQI_RSP = 0xB1
    MGMT_LEAVE_RSP = 0xB4
    MGMT_PERMIT_JOIN_RSP = 0xB6
    STATE_CHANGE_IND = 0xC0
    END_DEVICE_ANNCE_IND = 0xC1
    SRC_RTG_IND = 0xC4
    LEAVE_IND = 0xC9
    TC_DEV_IND = 0xCA
    PERMIT_JOIN_IND = 0xCB


class DeviceState(IntEnum):
    HOLD = 0
    INIT = 1
    NWK_DISC = 2
    NWK_JOINING = 3
    NWK_REJOIN = 4
    END_DEVICE_UNAUTH = 5
    END_DEVICE = 6
    ROUTER = 7
    COORD_STARTING = 8
    ZB_COORD = 9
    NWK_ORPHAN = 10


BROADCAST_ROUTERS_AND_COORD = 0xFFFC
ADDR_MODE_BROADCAST = 0x0F
ADDR_MODE_SHORT = 0x02
ADDR_MODE_IEEE = 0x03


def zdo_startup_from_app(delay_ms: int = 100) -> Frame:
    return Frame(FrameType.SREQ, Subsystem.ZDO, ZdoCmd.STARTUP_FROM_APP, Writer().u16(delay_ms).bytes())


def zdo_permit_join(seconds: int, dst: int = BROADCAST_ROUTERS_AND_COORD) -> Frame:
    seconds = max(0, min(254, seconds))  # 255 = forever, deliberately unreachable
    mode = ADDR_MODE_BROADCAST if dst == BROADCAST_ROUTERS_AND_COORD else ADDR_MODE_SHORT
    w = Writer().u8(mode).u16(dst).u8(seconds).u8(0)  # tc significance 0
    return Frame(FrameType.SREQ, Subsystem.ZDO, ZdoCmd.MGMT_PERMIT_JOIN_REQ, w.bytes())


def zdo_node_desc_req(nwk: int) -> Frame:
    return Frame(FrameType.SREQ, Subsystem.ZDO, ZdoCmd.NODE_DESC_REQ, Writer().u16(nwk).u16(nwk).bytes())


def zdo_active_ep_req(nwk: int) -> Frame:
    return Frame(FrameType.SREQ, Subsystem.ZDO, ZdoCmd.ACTIVE_EP_REQ, Writer().u16(nwk).u16(nwk).bytes())


def zdo_simple_desc_req(nwk: int, ep: int) -> Frame:
    return Frame(FrameType.SREQ, Subsystem.ZDO, ZdoCmd.SIMPLE_DESC_REQ, Writer().u16(nwk).u16(nwk).u8(ep).bytes())


def zdo_mgmt_leave_req(nwk: int, ieee: int, rejoin: bool = False, remove_children: bool = False) -> Frame:
    flags = (0x01 if rejoin else 0) | (0x02 if remove_children else 0)
    return Frame(FrameType.SREQ, Subsystem.ZDO, ZdoCmd.MGMT_LEAVE_REQ, Writer().u16(nwk).ieee(ieee).u8(flags).bytes())


def zdo_bind_req(nwk: int, src_ieee: int, src_ep: int, cluster: int, dst_ieee: int, dst_ep: int) -> Frame:
    w = (
        Writer().u16(nwk).ieee(src_ieee).u8(src_ep).u16(cluster)
        .u8(ADDR_MODE_IEEE).ieee(dst_ieee).u8(dst_ep)
    )
    return Frame(FrameType.SREQ, Subsystem.ZDO, ZdoCmd.BIND_REQ, w.bytes())


def zdo_unbind_req(nwk: int, src_ieee: int, src_ep: int, cluster: int, dst_ieee: int, dst_ep: int) -> Frame:
    w = (
        Writer().u16(nwk).ieee(src_ieee).u8(src_ep).u16(cluster)
        .u8(ADDR_MODE_IEEE).ieee(dst_ieee).u8(dst_ep)
    )
    return Frame(FrameType.SREQ, Subsystem.ZDO, ZdoCmd.UNBIND_REQ, w.bytes())


def zdo_mgmt_lqi_req(nwk: int, start_index: int = 0) -> Frame:
    return Frame(FrameType.SREQ, Subsystem.ZDO, ZdoCmd.MGMT_LQI_REQ, Writer().u16(nwk).u8(start_index).bytes())


def zdo_ext_nwk_info() -> Frame:
    return Frame(FrameType.SREQ, Subsystem.ZDO, ZdoCmd.EXT_NWK_INFO)


@dataclass(frozen=True)
class NwkInfo:
    short_addr: int
    device_state: int
    pan_id: int
    parent_addr: int
    ext_pan_id: int
    parent_ext_addr: int
    channel: int


def decode_ext_nwk_info(data: bytes) -> NwkInfo:
    r = Reader(data)
    return NwkInfo(r.u16(), r.u8(), r.u16(), r.u16(), r.u64(), r.u64(), r.u8())


@dataclass(frozen=True)
class DeviceAnnounce:
    src_addr: int
    nwk_addr: int
    ieee: int
    capabilities: int

    @property
    def is_router(self) -> bool:
        return bool(self.capabilities & 0x02)

    @property
    def mains_powered(self) -> bool:
        return bool(self.capabilities & 0x04)

    @property
    def rx_on_when_idle(self) -> bool:
        return bool(self.capabilities & 0x08)


def decode_end_device_annce(data: bytes) -> DeviceAnnounce:
    r = Reader(data)
    return DeviceAnnounce(r.u16(), r.u16(), r.ieee(), r.u8())


@dataclass(frozen=True)
class TcDeviceInd:
    nwk_addr: int
    ieee: int
    parent_addr: int


def decode_tc_dev_ind(data: bytes) -> TcDeviceInd:
    r = Reader(data)
    return TcDeviceInd(r.u16(), r.ieee(), r.u16())


@dataclass(frozen=True)
class LeaveInd:
    src_addr: int
    ieee: int
    request: bool
    remove_children: bool
    rejoin: bool


def decode_leave_ind(data: bytes) -> LeaveInd:
    r = Reader(data)
    return LeaveInd(r.u16(), r.ieee(), bool(r.u8()), bool(r.u8()), bool(r.u8()))


@dataclass(frozen=True)
class PermitJoinInd:
    duration: int


def decode_permit_join_ind(data: bytes) -> PermitJoinInd:
    return PermitJoinInd(Reader(data).u8())


@dataclass(frozen=True)
class ActiveEpRsp:
    src_addr: int
    status: int
    nwk_addr: int
    endpoints: list[int]


def decode_active_ep_rsp(data: bytes) -> ActiveEpRsp:
    r = Reader(data)
    src, status, nwk = r.u16(), r.u8(), r.u16()
    n = r.u8()
    return ActiveEpRsp(src, status, nwk, [r.u8() for _ in range(n)])


@dataclass(frozen=True)
class SimpleDescRsp:
    src_addr: int
    status: int
    nwk_addr: int
    endpoint: int
    profile: int
    device_id: int
    device_version: int
    in_clusters: list[int]
    out_clusters: list[int]


def decode_simple_desc_rsp(data: bytes) -> SimpleDescRsp:
    r = Reader(data)
    src, status, nwk = r.u16(), r.u8(), r.u16()
    length = r.u8()
    if status != 0 or length == 0:
        return SimpleDescRsp(src, status, nwk, 0, 0, 0, 0, [], [])
    ep, profile, dev_id, ver = r.u8(), r.u16(), r.u16(), r.u8()
    ins = r.u16list()
    outs = r.u16list()
    return SimpleDescRsp(src, status, nwk, ep, profile, dev_id, ver, ins, outs)


@dataclass(frozen=True)
class NodeDescRsp:
    src_addr: int
    status: int
    nwk_addr: int
    logical_type: int
    manufacturer_code: int
    max_buffer: int
    max_in_transfer: int


def decode_node_desc_rsp(data: bytes) -> NodeDescRsp:
    r = Reader(data)
    src, status, nwk = r.u16(), r.u8(), r.u16()
    if status != 0:
        return NodeDescRsp(src, status, nwk, 0, 0, 0, 0)
    b0 = r.u8()
    r.u8()  # aps flags / freq band
    r.u8()  # mac capability flags
    manuf = r.u16()
    max_buf = r.u8()
    max_in = r.u16()
    return NodeDescRsp(src, status, nwk, b0 & 0x07, manuf, max_buf, max_in)


@dataclass(frozen=True)
class Neighbor:
    ext_pan_id: int
    ieee: int
    nwk_addr: int
    device_type: int
    rx_on_when_idle: int
    relationship: int
    permit_joining: int
    depth: int
    lqi: int


@dataclass(frozen=True)
class MgmtLqiRsp:
    src_addr: int
    status: int
    total: int
    start_index: int
    neighbors: list[Neighbor] = field(default_factory=list)


def decode_mgmt_lqi_rsp(data: bytes) -> MgmtLqiRsp:
    r = Reader(data)
    src, status, total, start, count = r.u16(), r.u8(), r.u8(), r.u8(), r.u8()
    items: list[Neighbor] = []
    for _ in range(count):
        ext_pan, ieee, nwk = r.u64(), r.u64(), r.u16()
        b = r.u8()
        b2 = r.u8()
        depth, lqi = r.u8(), r.u8()
        items.append(Neighbor(ext_pan, ieee, nwk, b & 0x03, (b >> 2) & 0x03, (b >> 4) & 0x07, b2 & 0x03, depth, lqi))
    return MgmtLqiRsp(src, status, total, start, items)


# --------------------------------------------------------------- UTIL ----


class UtilCmd(IntEnum):
    GET_DEVICE_INFO = 0x00
    LED_CONTROL = 0x0A


@dataclass(frozen=True)
class DeviceInfo:
    status: int
    ieee: int
    short_addr: int
    device_type: int
    device_state: int
    assoc_devices: list[int]


def util_get_device_info() -> Frame:
    return Frame(FrameType.SREQ, Subsystem.UTIL, UtilCmd.GET_DEVICE_INFO)


def decode_device_info(data: bytes) -> DeviceInfo:
    r = Reader(data)
    status, ieee, short, dtype, dstate = r.u8(), r.ieee(), r.u16(), r.u8(), r.u8()
    n = r.u8()
    return DeviceInfo(status, ieee, short, dtype, dstate, [r.u16() for _ in range(n)])


def util_led(led: int, on: bool) -> Frame:
    return Frame(FrameType.SREQ, Subsystem.UTIL, UtilCmd.LED_CONTROL, Writer().u8(led).u8(1 if on else 0).bytes())


# ------------------------------------------------------------ APP_CNF ----


class AppCnfCmd(IntEnum):
    SET_NWK_FRAME_COUNTER = 0xFF
    SET_DEFAULT_REMOTE_ENDDEVICE_TIMEOUT = 0x01
    SET_ENDDEVICE_TIMEOUT = 0x02
    SET_ALLOWREJOIN_TC_POLICY = 0x03
    BDB_ADD_INSTALLCODE = 0x04
    BDB_START_COMMISSIONING = 0x05
    BDB_SET_JOINUSESINSTALLCODE = 0x06
    BDB_SET_ACTIVE_DEFAULT_CENTRALIZED_KEY = 0x07
    BDB_SET_CHANNEL = 0x08
    BDB_SET_TC_REQUIRE_KEY_EXCHANGE = 0x09
    BDB_COMMISSIONING_NOTIFICATION = 0x80  # AREQ


class CommissioningMode(IntEnum):
    INITIALIZATION = 0x00
    TOUCHLINK = 0x01
    NWK_STEERING = 0x02
    NWK_FORMATION = 0x04
    FINDING_BINDING = 0x08


class InstallCodeFormat(IntEnum):
    CODE_WITH_CRC = 0x01   # 16 bytes install code + 2 byte CRC
    DERIVED_KEY = 0x02     # 16 byte key already derived via AES-MMO


def appcnf_set_nwk_frame_counter(value: int) -> Frame:
    """Set the outgoing NWK frame counter (used when re-forming an imported network so devices
    do not drop our frames as replays). Must be sent before the network starts."""
    return Frame(FrameType.SREQ, Subsystem.APP_CNF, AppCnfCmd.SET_NWK_FRAME_COUNTER, Writer().u32(value & 0xFFFFFFFF).bytes())


def appcnf_set_channel(primary: bool, channel_mask: int) -> Frame:
    w = Writer().u8(1 if primary else 0).u32(channel_mask)
    return Frame(FrameType.SREQ, Subsystem.APP_CNF, AppCnfCmd.BDB_SET_CHANNEL, w.bytes())


def appcnf_start_commissioning(mode: int) -> Frame:
    return Frame(FrameType.SREQ, Subsystem.APP_CNF, AppCnfCmd.BDB_START_COMMISSIONING, bytes([mode]))


def appcnf_add_install_code(ieee: int, data: bytes, fmt: InstallCodeFormat) -> Frame:
    w = Writer().u8(int(fmt)).ieee(ieee).raw(data)
    return Frame(FrameType.SREQ, Subsystem.APP_CNF, AppCnfCmd.BDB_ADD_INSTALLCODE, w.bytes())


def appcnf_set_join_uses_install_code(enabled: bool) -> Frame:
    return Frame(FrameType.SREQ, Subsystem.APP_CNF, AppCnfCmd.BDB_SET_JOINUSESINSTALLCODE, bytes([1 if enabled else 0]))


def appcnf_set_tc_require_key_exchange(enabled: bool) -> Frame:
    return Frame(FrameType.SREQ, Subsystem.APP_CNF, AppCnfCmd.BDB_SET_TC_REQUIRE_KEY_EXCHANGE, bytes([1 if enabled else 0]))


def appcnf_set_default_centralized_key(use_default: bool, install_code_with_crc: bytes = bytes(18)) -> Frame:
    """useGlobal=1 → firmware uses the public ZigBeeAlliance09 key.
    useGlobal=0 → firmware derives the centralized TCLK (AES-MMO) from the given
    18-byte install code + CRC. The firmware validates the CRC itself."""
    if len(install_code_with_crc) != 18:
        raise ValueError("install code must be 16 bytes + 2 byte CRC")
    w = Writer().u8(1 if use_default else 0).raw(install_code_with_crc)
    return Frame(FrameType.SREQ, Subsystem.APP_CNF, AppCnfCmd.BDB_SET_ACTIVE_DEFAULT_CENTRALIZED_KEY, w.bytes())


def appcnf_set_allow_rejoin_tc_policy(allow: bool) -> Frame:
    return Frame(FrameType.SREQ, Subsystem.APP_CNF, AppCnfCmd.SET_ALLOWREJOIN_TC_POLICY, bytes([1 if allow else 0]))


@dataclass(frozen=True)
class CommissioningNotification:
    status: int
    mode: int
    remaining_modes: int


def decode_commissioning_notification(data: bytes) -> CommissioningNotification:
    r = Reader(data)
    return CommissioningNotification(r.u8(), r.u8(), r.u8())


# ------------------------------------------------------------- status ----


def status_of(data: bytes) -> int:
    """Most SRSPs start with a status byte; 0 = success."""
    return data[0] if data else 0xFF


ZSTACK_STATUS = {
    0x00: "SUCCESS", 0x01: "FAILURE", 0x02: "INVALID_PARAMETER", 0x09: "NV_ITEM_UNINIT",
    0x0A: "NV_OPER_FAILED", 0x0C: "NV_BAD_ITEM_LEN", 0x10: "MEM_ERROR", 0x11: "BUFFER_FULL",
    0xA1: "NWK_INVALID_REQUEST", 0xB1: "APS_FAIL", 0xB3: "APS_ILLEGAL_REQUEST",
    0xB7: "APS_NO_ACK", 0xC1: "NWK_INVALID_REQ", 0xCD: "NWK_NO_ROUTE", 0xE9: "MAC_NO_ACK",
}
