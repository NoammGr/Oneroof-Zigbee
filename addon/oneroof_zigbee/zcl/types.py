"""ZCL data types and value (de)serialisation.

Written from the ZCL specification (chapter 2.6, "Data Types").
All multi-byte values are little-endian.  "Invalid"/"unknown" sentinel
values defined by the spec are decoded as ``None``; encoding ``None``
produces the sentinel again where one exists.
"""

from __future__ import annotations

import math
import struct
from enum import IntEnum
from typing import Any


class DataType(IntEnum):
    nodata = 0x00
    data8 = 0x08
    data16 = 0x09
    data24 = 0x0A
    data32 = 0x0B
    data40 = 0x0C
    data48 = 0x0D
    data56 = 0x0E
    data64 = 0x0F
    bool_ = 0x10
    bitmap8 = 0x18
    bitmap16 = 0x19
    bitmap24 = 0x1A
    bitmap32 = 0x1B
    bitmap40 = 0x1C
    bitmap48 = 0x1D
    bitmap56 = 0x1E
    bitmap64 = 0x1F
    uint8 = 0x20
    uint16 = 0x21
    uint24 = 0x22
    uint32 = 0x23
    uint40 = 0x24
    uint48 = 0x25
    uint56 = 0x26
    uint64 = 0x27
    int8 = 0x28
    int16 = 0x29
    int24 = 0x2A
    int32 = 0x2B
    int40 = 0x2C
    int48 = 0x2D
    int56 = 0x2E
    int64 = 0x2F
    enum8 = 0x30
    enum16 = 0x31
    semi = 0x38
    single = 0x39
    double = 0x3A
    octstr = 0x41
    string = 0x42
    long_octstr = 0x43
    long_string = 0x44
    array = 0x48
    struct_ = 0x4C
    tod = 0xE0
    date = 0xE1
    utc = 0xE2
    cluster_id = 0xE8
    attr_id = 0xE9
    bac_oid = 0xEA
    eui64 = 0xF0
    key128 = 0xF1
    unk = 0xFF


class ZclDecodeError(ValueError):
    """Raised when a buffer is too short or malformed."""


# ---------------------------------------------------------------------------
# Size tables
# ---------------------------------------------------------------------------

_FIXED_SIZE: dict[int, int] = {DataType.nodata: 0, DataType.bool_: 1}
for _i in range(8):
    _FIXED_SIZE[0x08 + _i] = _i + 1  # dataN
    _FIXED_SIZE[0x18 + _i] = _i + 1  # bitmapN
    _FIXED_SIZE[0x20 + _i] = _i + 1  # uintN
    _FIXED_SIZE[0x28 + _i] = _i + 1  # intN
_FIXED_SIZE.update(
    {
        DataType.enum8: 1,
        DataType.enum16: 2,
        DataType.semi: 2,
        DataType.single: 4,
        DataType.double: 8,
        DataType.tod: 4,
        DataType.date: 4,
        DataType.utc: 4,
        DataType.cluster_id: 2,
        DataType.attr_id: 2,
        DataType.bac_oid: 4,
        DataType.eui64: 8,
        DataType.key128: 16,
    }
)


def _is_uint(dtype: int) -> bool:
    return 0x20 <= dtype <= 0x27


def _is_int(dtype: int) -> bool:
    return 0x28 <= dtype <= 0x2F


def _is_raw(dtype: int) -> bool:
    """dataN / bitmapN: raw bit patterns, no invalid sentinel."""
    return 0x08 <= dtype <= 0x0F or 0x18 <= dtype <= 0x1F


def is_analog(dtype: int) -> bool:
    """True for analog types (which carry a reportable-change field)."""
    return (
        _is_uint(dtype)
        or _is_int(dtype)
        or dtype in (DataType.semi, DataType.single, DataType.double)
        or dtype in (DataType.tod, DataType.date, DataType.utc)
    )


def fixed_size(dtype: int) -> int | None:
    """Byte size of a fixed-width type, or None for variable-width types."""
    return _FIXED_SIZE.get(dtype)


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def _need(data: bytes, offset: int, n: int) -> None:
    if offset + n > len(data):
        raise ZclDecodeError(f"need {n} bytes at offset {offset}, have {len(data) - offset}")


def decode_value(dtype: int, data: bytes, offset: int = 0) -> tuple[Any, int]:
    """Decode one value of type ``dtype`` from ``data`` at ``offset``.

    Returns ``(value, new_offset)``.  Invalid sentinels decode to ``None``.
    """
    size = _FIXED_SIZE.get(dtype)
    if size is not None:
        _need(data, offset, size)
        raw = data[offset : offset + size]
        end = offset + size

        if dtype == DataType.nodata:
            return None, end
        if dtype == DataType.bool_:
            if raw[0] == 0xFF:
                return None, end
            return bool(raw[0]), end
        if _is_raw(dtype) or dtype in (DataType.bac_oid, DataType.key128):
            # dataN/bitmapN decode as unsigned int; key128/bacOID kept raw.
            if dtype == DataType.key128:
                return bytes(raw), end
            return int.from_bytes(raw, "little"), end
        if _is_uint(dtype) or dtype in (
            DataType.enum8,
            DataType.enum16,
            DataType.cluster_id,
            DataType.attr_id,
            DataType.tod,
            DataType.date,
            DataType.utc,
            DataType.eui64,
        ):
            v = int.from_bytes(raw, "little")
            if v == (1 << (8 * size)) - 1:
                return None, end
            return v, end
        if _is_int(dtype):
            v = int.from_bytes(raw, "little", signed=True)
            if v == -(1 << (8 * size - 1)):
                return None, end
            return v, end
        if dtype == DataType.semi:
            v = struct.unpack("<e", raw)[0]
        elif dtype == DataType.single:
            v = struct.unpack("<f", raw)[0]
        else:  # double
            v = struct.unpack("<d", raw)[0]
        return (None if math.isnan(v) else float(v)), end

    # Variable-width types
    if dtype in (DataType.octstr, DataType.string):
        _need(data, offset, 1)
        n = data[offset]
        offset += 1
        if n == 0xFF:
            return None, offset
        _need(data, offset, n)
        raw = bytes(data[offset : offset + n])
        offset += n
        if dtype == DataType.string:
            return raw.decode("utf-8", errors="replace"), offset
        return raw, offset

    if dtype in (DataType.long_octstr, DataType.long_string):
        _need(data, offset, 2)
        n = int.from_bytes(data[offset : offset + 2], "little")
        offset += 2
        if n == 0xFFFF:
            return None, offset
        _need(data, offset, n)
        raw = bytes(data[offset : offset + n])
        offset += n
        if dtype == DataType.long_string:
            return raw.decode("utf-8", errors="replace"), offset
        return raw, offset

    if dtype == DataType.array:
        # element type u8, count u16, then `count` elements of that type
        _need(data, offset, 3)
        elem_type = data[offset]
        count = int.from_bytes(data[offset + 1 : offset + 3], "little")
        offset += 3
        if count == 0xFFFF:
            return None, offset
        items: list[Any] = []
        for _ in range(count):
            v, offset = decode_value(elem_type, data, offset)
            items.append(v)
        return items, offset

    if dtype == DataType.struct_:
        # count u16, then `count` × (type u8, value)
        _need(data, offset, 2)
        count = int.from_bytes(data[offset : offset + 2], "little")
        offset += 2
        if count == 0xFFFF:
            return None, offset
        items = []
        for _ in range(count):
            _need(data, offset, 1)
            elem_type = data[offset]
            offset += 1
            v, offset = decode_value(elem_type, data, offset)
            items.append(v)
        return items, offset

    if dtype == DataType.unk:
        return None, offset

    raise ZclDecodeError(f"unsupported ZCL data type 0x{dtype:02x}")


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------


def encode_value(dtype: int, value: Any) -> bytes:
    """Encode ``value`` as ZCL type ``dtype``.  ``None`` encodes the invalid sentinel."""
    size = _FIXED_SIZE.get(dtype)
    if size is not None:
        if dtype == DataType.nodata:
            return b""
        if dtype == DataType.bool_:
            if value is None:
                return b"\xff"
            return b"\x01" if value else b"\x00"
        if dtype == DataType.key128:
            if not isinstance(value, (bytes, bytearray)) or len(value) != 16:
                raise ValueError("key128 requires 16 bytes")
            return bytes(value)
        if _is_int(dtype):
            if value is None:
                value = -(1 << (8 * size - 1))
            return int(value).to_bytes(size, "little", signed=True)
        if dtype == DataType.semi:
            return struct.pack("<e", math.nan if value is None else float(value))
        if dtype == DataType.single:
            return struct.pack("<f", math.nan if value is None else float(value))
        if dtype == DataType.double:
            return struct.pack("<d", math.nan if value is None else float(value))
        # everything else fixed-size is an unsigned int pattern
        if value is None:
            value = (1 << (8 * size)) - 1
        return int(value).to_bytes(size, "little", signed=False)

    if dtype in (DataType.octstr, DataType.string):
        if value is None:
            return b"\xff"
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        if len(raw) > 0xFE:
            raise ValueError("string too long for short string type")
        return bytes([len(raw)]) + raw

    if dtype in (DataType.long_octstr, DataType.long_string):
        if value is None:
            return b"\xff\xff"
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        if len(raw) > 0xFFFE:
            raise ValueError("string too long for long string type")
        return len(raw).to_bytes(2, "little") + raw

    if dtype == DataType.array:
        # value: (elem_type, [items]) or None
        if value is None:
            return b"\x00\xff\xff"
        elem_type, items = value
        out = bytes([elem_type]) + len(items).to_bytes(2, "little")
        for item in items:
            out += encode_value(elem_type, item)
        return out

    if dtype == DataType.struct_:
        # value: [(elem_type, item), ...] or None
        if value is None:
            return b"\xff\xff"
        out = len(value).to_bytes(2, "little")
        for elem_type, item in value:
            out += bytes([elem_type]) + encode_value(elem_type, item)
        return out

    if dtype == DataType.unk:
        return b""

    raise ValueError(f"unsupported ZCL data type 0x{dtype:02x}")
