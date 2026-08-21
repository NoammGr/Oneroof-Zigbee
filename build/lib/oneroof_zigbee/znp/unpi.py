"""TI Unified Network Processor Interface (UNPI) framing.

Wire format (all little-endian):

    SOF(0xFE) | LEN(1) | CMD0(1) | CMD1(1) | DATA(LEN) | FCS(1)

CMD0 = (type << 5) | subsystem.  FCS = XOR of every byte from LEN through the
last DATA byte.  This module is a pure codec; it never touches a serial port.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

SOF = 0xFE
MAX_PAYLOAD = 250


class FrameType(IntEnum):
    POLL = 0
    SREQ = 1  # synchronous request (host → NP)
    AREQ = 2  # asynchronous request / indication
    SRSP = 3  # synchronous response (NP → host)


class Subsystem(IntEnum):
    RPC_ERR = 0
    SYS = 1
    MAC = 2
    NWK = 3
    AF = 4
    ZDO = 5
    SAPI = 6
    UTIL = 7
    DEBUG = 8
    APP = 9
    APP_CNF = 15
    GREENPOWER = 21


class FrameError(ValueError):
    """Raised on a corrupt or impossible frame."""


@dataclass(frozen=True, slots=True)
class Frame:
    type: FrameType
    subsystem: Subsystem
    command: int
    data: bytes = b""

    @property
    def cmd0(self) -> int:
        return (int(self.type) << 5) | int(self.subsystem)

    def encode(self) -> bytes:
        if len(self.data) > MAX_PAYLOAD:
            raise FrameError(f"payload too large: {len(self.data)} > {MAX_PAYLOAD}")
        body = bytes([len(self.data), self.cmd0, self.command]) + self.data
        return bytes([SOF]) + body + bytes([fcs(body)])

    def is_response_to(self, other: Frame) -> bool:
        return (
            self.type is FrameType.SRSP
            and other.type is FrameType.SREQ
            and self.subsystem is other.subsystem
            and self.command == other.command
        )


def fcs(body: bytes) -> int:
    acc = 0
    for b in body:
        acc ^= b
    return acc


class Parser:
    """Incremental parser: feed bytes, pull complete frames.

    Resynchronises on SOF after any error, so one corrupt byte on the line
    costs at most one frame, never the whole session.
    """

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[Frame]:
        self._buf.extend(data)
        out: list[Frame] = []
        while True:
            frame = self._try_parse_one()
            if frame is None:
                break
            out.append(frame)
        return out

    def _try_parse_one(self) -> Frame | None:
        buf = self._buf
        # discard garbage before SOF
        sof = buf.find(SOF)
        if sof < 0:
            buf.clear()
            return None
        if sof > 0:
            del buf[:sof]
        if len(buf) < 5:
            return None
        length = buf[1]
        total = 1 + 1 + 2 + length + 1
        if len(buf) < total:
            return None
        body = bytes(buf[1 : total - 1])
        expected = buf[total - 1]
        if fcs(body) != expected:
            # Bad checksum: this SOF was probably noise. Drop ONE byte and resync,
            # so a stray 0xFE cannot swallow the valid frames behind it.
            del buf[:1]
            return self._try_parse_one()
        del buf[:total]
        cmd0, cmd1 = body[1], body[2]
        try:
            ftype = FrameType(cmd0 >> 5)
            subsys = Subsystem(cmd0 & 0x1F)
        except ValueError:
            return self._try_parse_one()
        return Frame(ftype, subsys, cmd1, body[3:])
