"""Tiny little-endian struct helpers shared by the ZNP command layer."""

from __future__ import annotations

import struct


class Writer:
    __slots__ = ("_parts",)

    def __init__(self) -> None:
        self._parts: list[bytes] = []

    def u8(self, v: int) -> Writer:
        self._parts.append(struct.pack("<B", v))
        return self

    def u16(self, v: int) -> Writer:
        self._parts.append(struct.pack("<H", v))
        return self

    def u32(self, v: int) -> Writer:
        self._parts.append(struct.pack("<I", v))
        return self

    def u64(self, v: int) -> Writer:
        self._parts.append(struct.pack("<Q", v))
        return self

    def ieee(self, v: int) -> Writer:
        """IEEE/EUI64 address, transmitted little-endian."""
        return self.u64(v)

    def raw(self, b: bytes) -> Writer:
        self._parts.append(bytes(b))
        return self

    def lv(self, b: bytes) -> Writer:
        """u8 length-prefixed bytes."""
        return self.u8(len(b)).raw(b)

    def u16list(self, items: list[int]) -> Writer:
        self.u8(len(items))
        for i in items:
            self.u16(i)
        return self

    def bytes(self) -> bytes:
        return b"".join(self._parts)


class Reader:
    __slots__ = ("_d", "pos")

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self._d = data
        self.pos = pos

    def _take(self, fmt: str):
        size = struct.calcsize(fmt)
        if self.pos + size > len(self._d):
            raise ValueError("truncated ZNP payload")
        (v,) = struct.unpack_from(fmt, self._d, self.pos)
        self.pos += size
        return v

    def u8(self) -> int:
        return self._take("<B")

    def u16(self) -> int:
        return self._take("<H")

    def u32(self) -> int:
        return self._take("<I")

    def u64(self) -> int:
        return self._take("<Q")

    def ieee(self) -> int:
        return self.u64()

    def raw(self, n: int) -> bytes:
        if self.pos + n > len(self._d):
            raise ValueError("truncated ZNP payload")
        out = self._d[self.pos : self.pos + n]
        self.pos += n
        return bytes(out)

    def lv(self) -> bytes:
        return self.raw(self.u8())

    def u16list(self) -> list[int]:
        n = self.u8()
        return [self.u16() for _ in range(n)]

    def rest(self) -> bytes:
        out = self._d[self.pos :]
        self.pos = len(self._d)
        return bytes(out)

    @property
    def remaining(self) -> int:
        return len(self._d) - self.pos


def ieee_str(ieee: int) -> str:
    return f"0x{ieee:016x}"


def ieee_int(s: str) -> int:
    s = s.lower().removeprefix("0x").replace(":", "")
    if len(s) != 16:
        raise ValueError(f"bad IEEE address: {s!r}")
    return int(s, 16)
