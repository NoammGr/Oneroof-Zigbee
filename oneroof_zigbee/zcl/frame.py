"""ZCL frame header codec (ZCL spec chapter 2.4).

Frame control byte:
    bits 0-1  frame type (0 = global/profile-wide, 1 = cluster-specific)
    bit  2    manufacturer specific (manufacturer code u16 follows)
    bit  3    direction (0 client→server, 1 server→client)
    bit  4    disable default response
    bits 5-7  reserved
"""

from __future__ import annotations

from dataclasses import dataclass

FRAME_TYPE_GLOBAL = 0
FRAME_TYPE_CLUSTER = 1

DIRECTION_CLIENT_TO_SERVER = 0
DIRECTION_SERVER_TO_CLIENT = 1


class ZclFrameError(ValueError):
    """Malformed ZCL frame header."""


@dataclass
class ZclFrame:
    frame_type: int  # 0 = global, 1 = cluster-specific
    manufacturer: int | None
    direction: int  # 0 client→server, 1 server→client
    disable_default_response: bool
    seq: int
    command: int
    payload: bytes

    @property
    def is_global(self) -> bool:
        return self.frame_type == FRAME_TYPE_GLOBAL

    @property
    def is_cluster_specific(self) -> bool:
        return self.frame_type == FRAME_TYPE_CLUSTER


def decode_frame(data: bytes) -> ZclFrame:
    """Parse a raw APS payload into a :class:`ZclFrame`."""
    if len(data) < 3:
        raise ZclFrameError("frame too short")
    fc = data[0]
    frame_type = fc & 0x03
    mfg_specific = bool(fc & 0x04)
    direction = (fc >> 3) & 0x01
    disable_default_response = bool(fc & 0x10)
    offset = 1
    manufacturer: int | None = None
    if mfg_specific:
        if len(data) < 5:
            raise ZclFrameError("frame too short for manufacturer code")
        manufacturer = int.from_bytes(data[1:3], "little")
        offset = 3
    seq = data[offset]
    command = data[offset + 1]
    payload = bytes(data[offset + 2 :])
    return ZclFrame(
        frame_type=frame_type,
        manufacturer=manufacturer,
        direction=direction,
        disable_default_response=disable_default_response,
        seq=seq,
        command=command,
        payload=payload,
    )


def encode_frame(frame: ZclFrame) -> bytes:
    """Serialise a :class:`ZclFrame` into bytes ready for AF_DATA_REQUEST."""
    if not 0 <= frame.frame_type <= 3:
        raise ZclFrameError("frame_type must be 0..3")
    if frame.direction not in (0, 1):
        raise ZclFrameError("direction must be 0 or 1")
    if not 0 <= frame.seq <= 0xFF:
        raise ZclFrameError("seq must fit in a byte")
    if not 0 <= frame.command <= 0xFF:
        raise ZclFrameError("command must fit in a byte")
    fc = frame.frame_type & 0x03
    if frame.manufacturer is not None:
        fc |= 0x04
    if frame.direction:
        fc |= 0x08
    if frame.disable_default_response:
        fc |= 0x10
    out = bytearray([fc])
    if frame.manufacturer is not None:
        if not 0 <= frame.manufacturer <= 0xFFFF:
            raise ZclFrameError("manufacturer code must fit in u16")
        out += frame.manufacturer.to_bytes(2, "little")
    out.append(frame.seq)
    out.append(frame.command)
    out += frame.payload
    return bytes(out)
