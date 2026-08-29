"""ZCL general (profile-wide) commands — ZCL spec chapter 2.5.

Each command is a dataclass with ``encode() -> bytes`` (payload only) and a
``decode(payload) -> cls`` classmethod.  Builder helpers at the bottom wrap
a payload in a full :class:`ZclFrame`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .frame import (
    DIRECTION_CLIENT_TO_SERVER,
    FRAME_TYPE_CLUSTER,
    FRAME_TYPE_GLOBAL,
    ZclFrame,
    encode_frame,
)
from .types import DataType, ZclDecodeError, decode_value, encode_value, is_analog

# Global command ids
CMD_READ_ATTRIBUTES = 0x00
CMD_READ_ATTRIBUTES_RSP = 0x01
CMD_WRITE_ATTRIBUTES = 0x02
CMD_WRITE_ATTRIBUTES_UNDIVIDED = 0x03
CMD_WRITE_ATTRIBUTES_RSP = 0x04
CMD_WRITE_ATTRIBUTES_NO_RSP = 0x05
CMD_CONFIGURE_REPORTING = 0x06
CMD_CONFIGURE_REPORTING_RSP = 0x07
CMD_READ_REPORTING_CONFIG = 0x08
CMD_READ_REPORTING_CONFIG_RSP = 0x09
CMD_REPORT_ATTRIBUTES = 0x0A
CMD_DEFAULT_RESPONSE = 0x0B
CMD_DISCOVER_ATTRIBUTES = 0x0C
CMD_DISCOVER_ATTRIBUTES_RSP = 0x0D

# Common status codes (ZCL 2.6.3)
STATUS_SUCCESS = 0x00
STATUS_FAILURE = 0x01
STATUS_MALFORMED_COMMAND = 0x80
STATUS_UNSUP_CLUSTER_COMMAND = 0x81
STATUS_UNSUP_GENERAL_COMMAND = 0x82
STATUS_UNSUPPORTED_ATTRIBUTE = 0x86
STATUS_INVALID_VALUE = 0x87
STATUS_READ_ONLY = 0x88
STATUS_INVALID_DATA_TYPE = 0x8D
STATUS_UNREPORTABLE_ATTRIBUTE = 0x8C
STATUS_TIMEOUT = 0x94


def _u8(b: bytes, o: int) -> int:
    if o + 1 > len(b):
        raise ZclDecodeError("truncated")
    return b[o]


def _u16(b: bytes, o: int) -> int:
    if o + 2 > len(b):
        raise ZclDecodeError("truncated")
    return int.from_bytes(b[o : o + 2], "little")


def _p16(v: int) -> bytes:
    return int(v).to_bytes(2, "little")


# ---------------------------------------------------------------------------
# Read Attributes
# ---------------------------------------------------------------------------


@dataclass
class ReadAttributes:
    attrs: list[int]

    def encode(self) -> bytes:
        return b"".join(_p16(a) for a in self.attrs)

    @classmethod
    def decode(cls, payload: bytes) -> "ReadAttributes":
        if len(payload) % 2:
            raise ZclDecodeError("ReadAttributes payload length must be even")
        return cls([_u16(payload, o) for o in range(0, len(payload), 2)])


@dataclass
class ReadAttributeRecord:
    attr: int
    status: int
    dtype: int | None = None
    value: Any = None
    raw: bytes | None = None  # undecoded value bytes (vendor TLV payloads arrive as "strings")


@dataclass
class ReadAttributesResponse:
    records: list[ReadAttributeRecord]

    def encode(self) -> bytes:
        out = bytearray()
        for r in self.records:
            out += _p16(r.attr)
            out.append(r.status)
            if r.status == STATUS_SUCCESS:
                if r.dtype is None:
                    raise ValueError("successful record requires dtype")
                out.append(r.dtype)
                out += encode_value(r.dtype, r.value)
        return bytes(out)

    @classmethod
    def decode(cls, payload: bytes) -> "ReadAttributesResponse":
        """Tolerant: a record with an unknown data type or a truncated tail ends
        parsing but keeps every record decoded so far (real devices do send
        oddities; one bad attribute must not sink an interview)."""
        records: list[ReadAttributeRecord] = []
        o = 0
        while o < len(payload):
            try:
                attr = _u16(payload, o)
                status = _u8(payload, o + 2)
                o += 3
                if status == STATUS_SUCCESS:
                    dtype = _u8(payload, o)
                    o += 1
                    start = o
                    value, o = decode_value(dtype, payload, o)
                    records.append(ReadAttributeRecord(attr, status, dtype, value, bytes(payload[start:o])))
                else:
                    records.append(ReadAttributeRecord(attr, status))
            except ZclDecodeError:
                break
        return cls(records)

    def successful(self) -> list[tuple[int, Any]]:
        return [(r.attr, r.value) for r in self.records if r.status == STATUS_SUCCESS]


# ---------------------------------------------------------------------------
# Write Attributes
# ---------------------------------------------------------------------------


@dataclass
class WriteAttributeRecord:
    attr: int
    dtype: int
    value: Any


@dataclass
class WriteAttributes:
    records: list[WriteAttributeRecord]

    def encode(self) -> bytes:
        out = bytearray()
        for r in self.records:
            out += _p16(r.attr)
            out.append(r.dtype)
            out += encode_value(r.dtype, r.value)
        return bytes(out)

    @classmethod
    def decode(cls, payload: bytes) -> "WriteAttributes":
        records: list[WriteAttributeRecord] = []
        o = 0
        while o < len(payload):
            attr = _u16(payload, o)
            dtype = _u8(payload, o + 2)
            o += 3
            value, o = decode_value(dtype, payload, o)
            records.append(WriteAttributeRecord(attr, dtype, value))
        return cls(records)


@dataclass
class WriteAttributeStatus:
    status: int
    attr: int | None = None  # absent when the whole write succeeded


@dataclass
class WriteAttributesResponse:
    records: list[WriteAttributeStatus]

    def encode(self) -> bytes:
        if len(self.records) == 1 and self.records[0].attr is None:
            return bytes([self.records[0].status])
        out = bytearray()
        for r in self.records:
            if r.attr is None:
                raise ValueError("attr required in multi-record response")
            out.append(r.status)
            out += _p16(r.attr)
        return bytes(out)

    @classmethod
    def decode(cls, payload: bytes) -> "WriteAttributesResponse":
        if len(payload) == 1:
            return cls([WriteAttributeStatus(payload[0])])
        records: list[WriteAttributeStatus] = []
        o = 0
        while o < len(payload):
            status = _u8(payload, o)
            attr = _u16(payload, o + 1)
            o += 3
            records.append(WriteAttributeStatus(status, attr))
        return cls(records)

    @property
    def all_ok(self) -> bool:
        return all(r.status == STATUS_SUCCESS for r in self.records)


# ---------------------------------------------------------------------------
# Configure Reporting
# ---------------------------------------------------------------------------


@dataclass
class ReportingConfigRecord:
    attr: int
    direction: int = 0  # 0 = "send reports", 1 = "receive reports"
    dtype: int | None = None
    min_interval: int = 0
    max_interval: int = 0
    reportable_change: Any = None  # analog types only
    timeout: int = 0  # direction == 1 only

    def encode(self) -> bytes:
        out = bytearray([self.direction & 0xFF])
        out += _p16(self.attr)
        if self.direction == 0:
            if self.dtype is None:
                raise ValueError("dtype required for direction 0")
            out.append(self.dtype)
            out += _p16(self.min_interval)
            out += _p16(self.max_interval)
            if is_analog(self.dtype):
                out += encode_value(self.dtype, 0 if self.reportable_change is None else self.reportable_change)
        else:
            out += _p16(self.timeout)
        return bytes(out)


@dataclass
class ConfigureReporting:
    records: list[ReportingConfigRecord]

    def encode(self) -> bytes:
        return b"".join(r.encode() for r in self.records)

    @classmethod
    def decode(cls, payload: bytes) -> "ConfigureReporting":
        records: list[ReportingConfigRecord] = []
        o = 0
        while o < len(payload):
            direction = _u8(payload, o)
            attr = _u16(payload, o + 1)
            o += 3
            if direction == 0:
                dtype = _u8(payload, o)
                mn = _u16(payload, o + 1)
                mx = _u16(payload, o + 3)
                o += 5
                change: Any = None
                if is_analog(dtype):
                    change, o = decode_value(dtype, payload, o)
                records.append(ReportingConfigRecord(attr, 0, dtype, mn, mx, change))
            else:
                timeout = _u16(payload, o)
                o += 2
                records.append(ReportingConfigRecord(attr, 1, timeout=timeout))
        return cls(records)


@dataclass
class ReportingConfigStatus:
    status: int
    direction: int | None = None
    attr: int | None = None


@dataclass
class ConfigureReportingResponse:
    records: list[ReportingConfigStatus]

    def encode(self) -> bytes:
        if len(self.records) == 1 and self.records[0].attr is None:
            return bytes([self.records[0].status])
        out = bytearray()
        for r in self.records:
            if r.attr is None or r.direction is None:
                raise ValueError("attr/direction required in multi-record response")
            out.append(r.status)
            out.append(r.direction)
            out += _p16(r.attr)
        return bytes(out)

    @classmethod
    def decode(cls, payload: bytes) -> "ConfigureReportingResponse":
        if len(payload) == 1:
            return cls([ReportingConfigStatus(payload[0])])
        records: list[ReportingConfigStatus] = []
        o = 0
        while o < len(payload):
            status = _u8(payload, o)
            direction = _u8(payload, o + 1)
            attr = _u16(payload, o + 2)
            o += 4
            records.append(ReportingConfigStatus(status, direction, attr))
        return cls(records)

    @property
    def all_ok(self) -> bool:
        return all(r.status == STATUS_SUCCESS for r in self.records)


# ---------------------------------------------------------------------------
# Report Attributes
# ---------------------------------------------------------------------------


@dataclass
class AttributeReport:
    attr: int
    dtype: int
    value: Any
    raw: bytes | None = None  # undecoded value bytes (vendor TLV payloads arrive as "strings")


@dataclass
class ReportAttributes:
    records: list[AttributeReport]

    def encode(self) -> bytes:
        out = bytearray()
        for r in self.records:
            out += _p16(r.attr)
            out.append(r.dtype)
            out += encode_value(r.dtype, r.value)
        return bytes(out)

    @classmethod
    def decode(cls, payload: bytes) -> "ReportAttributes":
        records: list[AttributeReport] = []
        o = 0
        while o < len(payload):
            try:
                attr = _u16(payload, o)
                dtype = _u8(payload, o + 2)
                o += 3
                start = o
                value, o = decode_value(dtype, payload, o)
                records.append(AttributeReport(attr, dtype, value, bytes(payload[start:o])))
            except ZclDecodeError:
                break  # keep what we have; see ReadAttributesResponse.decode
        return cls(records)

    def pairs(self) -> list[tuple[int, Any]]:
        return [(r.attr, r.value) for r in self.records]


# ---------------------------------------------------------------------------
# Default Response
# ---------------------------------------------------------------------------


@dataclass
class DefaultResponse:
    cmd: int
    status: int

    def encode(self) -> bytes:
        return bytes([self.cmd & 0xFF, self.status & 0xFF])

    @classmethod
    def decode(cls, payload: bytes) -> "DefaultResponse":
        if len(payload) < 2:
            raise ZclDecodeError("DefaultResponse needs 2 bytes")
        return cls(payload[0], payload[1])


# ---------------------------------------------------------------------------
# Discover Attributes
# ---------------------------------------------------------------------------


@dataclass
class DiscoverAttributes:
    start_attr: int = 0
    max_count: int = 0xFF

    def encode(self) -> bytes:
        return _p16(self.start_attr) + bytes([self.max_count & 0xFF])

    @classmethod
    def decode(cls, payload: bytes) -> "DiscoverAttributes":
        return cls(_u16(payload, 0), _u8(payload, 2))


@dataclass
class AttributeInfo:
    attr: int
    dtype: int


@dataclass
class DiscoverAttributesResponse:
    complete: bool
    attributes: list[AttributeInfo] = field(default_factory=list)

    def encode(self) -> bytes:
        out = bytearray([1 if self.complete else 0])
        for a in self.attributes:
            out += _p16(a.attr)
            out.append(a.dtype)
        return bytes(out)

    @classmethod
    def decode(cls, payload: bytes) -> "DiscoverAttributesResponse":
        complete = bool(_u8(payload, 0))
        attrs: list[AttributeInfo] = []
        o = 1
        while o < len(payload):
            attrs.append(AttributeInfo(_u16(payload, o), _u8(payload, o + 2)))
            o += 3
        return cls(complete, attrs)


# ---------------------------------------------------------------------------
# Generic dispatch
# ---------------------------------------------------------------------------

_DECODERS: dict[int, Any] = {
    CMD_READ_ATTRIBUTES: ReadAttributes,
    CMD_READ_ATTRIBUTES_RSP: ReadAttributesResponse,
    CMD_WRITE_ATTRIBUTES: WriteAttributes,
    CMD_WRITE_ATTRIBUTES_UNDIVIDED: WriteAttributes,
    CMD_WRITE_ATTRIBUTES_NO_RSP: WriteAttributes,
    CMD_WRITE_ATTRIBUTES_RSP: WriteAttributesResponse,
    CMD_CONFIGURE_REPORTING: ConfigureReporting,
    CMD_CONFIGURE_REPORTING_RSP: ConfigureReportingResponse,
    CMD_REPORT_ATTRIBUTES: ReportAttributes,
    CMD_DEFAULT_RESPONSE: DefaultResponse,
    CMD_DISCOVER_ATTRIBUTES: DiscoverAttributes,
    CMD_DISCOVER_ATTRIBUTES_RSP: DiscoverAttributesResponse,
}


def decode_global_command(frame: ZclFrame) -> Any:
    """Decode the payload of a global frame into its command dataclass.

    Returns ``None`` for global commands we do not model.
    """
    if frame.frame_type != FRAME_TYPE_GLOBAL:
        raise ValueError("not a global frame")
    cls = _DECODERS.get(frame.command)
    if cls is None:
        return None
    return cls.decode(frame.payload)


# ---------------------------------------------------------------------------
# Builders (return full ZCL frames as bytes)
# ---------------------------------------------------------------------------


def build_global_command(
    seq: int,
    cmd: int,
    payload: bytes,
    *,
    direction: int = DIRECTION_CLIENT_TO_SERVER,
    manufacturer: int | None = None,
    disable_default_response: bool = True,
) -> bytes:
    return encode_frame(
        ZclFrame(
            frame_type=FRAME_TYPE_GLOBAL,
            manufacturer=manufacturer,
            direction=direction,
            disable_default_response=disable_default_response,
            seq=seq,
            command=cmd,
            payload=payload,
        )
    )


def build_read_attributes(seq: int, attrs: Iterable[int], manufacturer: int | None = None) -> bytes:
    return build_global_command(
        seq, CMD_READ_ATTRIBUTES, ReadAttributes(list(attrs)).encode(), manufacturer=manufacturer
    )


def build_write_attributes(
    seq: int, records: Iterable[WriteAttributeRecord], manufacturer: int | None = None
) -> bytes:
    return build_global_command(
        seq,
        CMD_WRITE_ATTRIBUTES,
        WriteAttributes(list(records)).encode(),
        manufacturer=manufacturer,
        disable_default_response=False,
    )


def build_configure_reporting(
    seq: int, records: Iterable[ReportingConfigRecord], manufacturer: int | None = None
) -> bytes:
    return build_global_command(
        seq,
        CMD_CONFIGURE_REPORTING,
        ConfigureReporting(list(records)).encode(),
        manufacturer=manufacturer,
    )


def build_default_response(
    seq: int, cmd: int, status: int, direction: int, manufacturer: int | None = None
) -> bytes:
    """A Default Response always has disable-default-response set."""
    return build_global_command(
        seq,
        CMD_DEFAULT_RESPONSE,
        DefaultResponse(cmd, status).encode(),
        direction=direction,
        manufacturer=manufacturer,
        disable_default_response=True,
    )


def build_discover_attributes(
    seq: int, start: int = 0, max_count: int = 0xFF, manufacturer: int | None = None
) -> bytes:
    return build_global_command(
        seq,
        CMD_DISCOVER_ATTRIBUTES,
        DiscoverAttributes(start, max_count).encode(),
        manufacturer=manufacturer,
    )


def build_cluster_command(
    seq: int,
    cmd: int,
    payload: bytes,
    direction: int = DIRECTION_CLIENT_TO_SERVER,
    manufacturer: int | None = None,
    disable_default_response: bool = True,
) -> bytes:
    return encode_frame(
        ZclFrame(
            frame_type=FRAME_TYPE_CLUSTER,
            manufacturer=manufacturer,
            direction=direction,
            disable_default_response=disable_default_response,
            seq=seq,
            command=cmd,
            payload=payload,
        )
    )


__all__ = [
    "CMD_READ_ATTRIBUTES",
    "CMD_READ_ATTRIBUTES_RSP",
    "CMD_WRITE_ATTRIBUTES",
    "CMD_WRITE_ATTRIBUTES_RSP",
    "CMD_CONFIGURE_REPORTING",
    "CMD_CONFIGURE_REPORTING_RSP",
    "CMD_REPORT_ATTRIBUTES",
    "CMD_DEFAULT_RESPONSE",
    "CMD_DISCOVER_ATTRIBUTES",
    "CMD_DISCOVER_ATTRIBUTES_RSP",
    "STATUS_SUCCESS",
    "STATUS_FAILURE",
    "STATUS_UNSUPPORTED_ATTRIBUTE",
    "ReadAttributes",
    "ReadAttributeRecord",
    "ReadAttributesResponse",
    "WriteAttributeRecord",
    "WriteAttributes",
    "WriteAttributeStatus",
    "WriteAttributesResponse",
    "ReportingConfigRecord",
    "ConfigureReporting",
    "ReportingConfigStatus",
    "ConfigureReportingResponse",
    "AttributeReport",
    "ReportAttributes",
    "DefaultResponse",
    "DiscoverAttributes",
    "AttributeInfo",
    "DiscoverAttributesResponse",
    "decode_global_command",
    "build_global_command",
    "build_read_attributes",
    "build_write_attributes",
    "build_configure_reporting",
    "build_default_response",
    "build_discover_attributes",
    "build_cluster_command",
    "DataType",
]
