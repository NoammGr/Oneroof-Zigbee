"""MQTT 3.1.1 control packet codec (pure functions + dataclasses).

Implements section 2 (packet format) and section 3 (control packets) of the
MQTT 3.1.1 specification for the packet types this project needs. Every
decoder is strict: anything that violates a MUST in the spec raises
:class:`MalformedPacket`. Nothing here touches the network.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAX_REMAINING_LENGTH = 256 * 1024  # project hard cap (spec allows 268 435 455)
MAX_PACKET_ID = 0xFFFF

# Control packet types (fixed header bits 7-4)
CONNECT = 1
CONNACK = 2
PUBLISH = 3
PUBACK = 4
PUBREC = 5
PUBREL = 6
PUBCOMP = 7
SUBSCRIBE = 8
SUBACK = 9
UNSUBSCRIBE = 10
UNSUBACK = 11
PINGREQ = 12
PINGRESP = 13
DISCONNECT = 14

# CONNACK return codes
CONNACK_ACCEPTED = 0
CONNACK_UNACCEPTABLE_PROTOCOL = 1
CONNACK_IDENTIFIER_REJECTED = 2
CONNACK_SERVER_UNAVAILABLE = 3
CONNACK_BAD_CREDENTIALS = 4
CONNACK_NOT_AUTHORIZED = 5

SUBACK_FAILURE = 0x80


class MalformedPacket(ValueError):
    """Raised for any protocol violation; the broker MUST close the connection."""


class NeedMoreData(Exception):
    """Raised by :func:`decode_fixed_header` when the buffer is incomplete."""


# ---------------------------------------------------------------------------
# Primitive encoders / decoders
# ---------------------------------------------------------------------------


def encode_remaining_length(n: int) -> bytes:
    """Variable-length integer, 7 bits per byte, continuation bit 0x80 (2.2.3)."""
    if n < 0 or n > MAX_REMAINING_LENGTH:
        raise MalformedPacket(f"remaining length {n} out of range")
    out = bytearray()
    while True:
        digit = n % 128
        n //= 128
        if n > 0:
            digit |= 0x80
        out.append(digit)
        if n == 0:
            return bytes(out)


def decode_remaining_length(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Return ``(value, bytes_consumed)``; raises NeedMoreData if truncated."""
    multiplier = 1
    value = 0
    consumed = 0
    while True:
        if offset + consumed >= len(data):
            raise NeedMoreData
        byte = data[offset + consumed]
        consumed += 1
        value += (byte & 0x7F) * multiplier
        if byte & 0x80 == 0:
            break
        multiplier *= 128
        if consumed == 4:
            raise MalformedPacket("remaining length exceeds 4 bytes")
    if value > MAX_REMAINING_LENGTH:
        raise MalformedPacket(f"remaining length {value} exceeds cap {MAX_REMAINING_LENGTH}")
    return value, consumed


def encode_string(s: str) -> bytes:
    """UTF-8 string prefixed with a 2-byte big-endian length (1.5.3)."""
    data = s.encode("utf-8")
    if len(data) > 0xFFFF:
        raise MalformedPacket("string longer than 65535 bytes")
    if "\x00" in s:
        raise MalformedPacket("string contains U+0000")
    return struct.pack("!H", len(data)) + data


def _check_utf8(s: str) -> None:
    for ch in s:
        cp = ord(ch)
        if cp == 0 or 0xD800 <= cp <= 0xDFFF:
            raise MalformedPacket("string contains forbidden code point")


class _Reader:
    """Cursor over a bytes object with bounds-checked reads."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise MalformedPacket("packet truncated")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def string(self) -> str:
        n = self.u16()
        raw = self.take(n)
        try:
            s = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise MalformedPacket("invalid UTF-8") from exc
        _check_utf8(s)
        return s

    def binary(self) -> bytes:
        return self.take(self.u16())

    def done(self) -> None:
        if self.pos != len(self.data):
            raise MalformedPacket("trailing bytes in packet")


# ---------------------------------------------------------------------------
# Packet dataclasses
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Connect:
    client_id: str
    clean_session: bool = True
    keepalive: int = 60
    username: str | None = None
    password: bytes | None = None
    will_topic: str | None = None
    will_payload: bytes = b""
    will_qos: int = 0
    will_retain: bool = False


@dataclass(slots=True)
class Connack:
    session_present: bool
    return_code: int


@dataclass(slots=True)
class Publish:
    topic: str
    payload: bytes = b""
    qos: int = 0
    retain: bool = False
    dup: bool = False
    packet_id: int | None = None


@dataclass(slots=True)
class Puback:
    packet_id: int


@dataclass(slots=True)
class Subscribe:
    packet_id: int
    topics: list[tuple[str, int]] = field(default_factory=list)


@dataclass(slots=True)
class Suback:
    packet_id: int
    return_codes: list[int] = field(default_factory=list)


@dataclass(slots=True)
class Unsubscribe:
    packet_id: int
    topics: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Unsuback:
    packet_id: int


@dataclass(slots=True)
class Pingreq:
    pass


@dataclass(slots=True)
class Pingresp:
    pass


@dataclass(slots=True)
class Disconnect:
    pass


Packet = (
    Connect
    | Connack
    | Publish
    | Puback
    | Subscribe
    | Suback
    | Unsubscribe
    | Unsuback
    | Pingreq
    | Pingresp
    | Disconnect
)


# ---------------------------------------------------------------------------
# Topic validation and matching (4.7)
# ---------------------------------------------------------------------------


def validate_topic(topic: str) -> None:
    """A topic *name* (for PUBLISH): non-empty, no wildcards, no U+0000."""
    if not topic:
        raise MalformedPacket("empty topic name")
    if "+" in topic or "#" in topic:
        raise MalformedPacket("wildcard in topic name")
    _check_utf8(topic)
    if len(topic.encode("utf-8")) > 0xFFFF:
        raise MalformedPacket("topic too long")


def validate_filter(topic_filter: str) -> None:
    """A topic *filter* (for SUBSCRIBE): wildcards only as whole levels,
    '#' only as the last level."""
    if not topic_filter:
        raise MalformedPacket("empty topic filter")
    _check_utf8(topic_filter)
    if len(topic_filter.encode("utf-8")) > 0xFFFF:
        raise MalformedPacket("topic filter too long")
    levels = topic_filter.split("/")
    for i, level in enumerate(levels):
        if "#" in level:
            if level != "#" or i != len(levels) - 1:
                raise MalformedPacket("'#' must be the whole last level")
        if "+" in level and level != "+":
            raise MalformedPacket("'+' must occupy a whole level")


def topic_matches(topic_filter: str, topic: str) -> bool:
    """Return True if ``topic`` matches ``topic_filter`` (4.7.1, 4.7.2).

    A filter starting with a wildcard never matches a topic starting with
    '$' so that '$SYS/...' is never delivered to '#' or '+/...' subscribers.
    """
    if topic.startswith("$") and topic_filter[:1] in ("+", "#"):
        return False
    f_levels = topic_filter.split("/")
    t_levels = topic.split("/")
    i = 0
    for i, f in enumerate(f_levels):
        if f == "#":
            return True  # matches the parent and any number of children
        if i >= len(t_levels):
            return False
        if f != "+" and f != t_levels[i]:
            return False
    return len(f_levels) == len(t_levels)


# ---------------------------------------------------------------------------
# Encoders
# ---------------------------------------------------------------------------


def _frame(ptype: int, flags: int, body: bytes) -> bytes:
    return bytes([(ptype << 4) | (flags & 0x0F)]) + encode_remaining_length(len(body)) + body


def _check_packet_id(pid: int | None) -> int:
    if pid is None or not 1 <= pid <= MAX_PACKET_ID:
        raise MalformedPacket("packet identifier must be 1..65535")
    return pid


def encode(packet: Packet) -> bytes:
    """Serialise a packet dataclass to bytes."""
    match packet:
        case Connect():
            return _encode_connect(packet)
        case Connack(session_present=sp, return_code=rc):
            if not 0 <= rc <= 5:
                raise MalformedPacket("invalid CONNACK return code")
            return _frame(CONNACK, 0, bytes([1 if sp else 0, rc]))
        case Publish():
            return _encode_publish(packet)
        case Puback(packet_id=pid):
            return _frame(PUBACK, 0, struct.pack("!H", _check_packet_id(pid)))
        case Subscribe(packet_id=pid, topics=topics):
            if not topics:
                raise MalformedPacket("SUBSCRIBE needs at least one filter")
            body = bytearray(struct.pack("!H", _check_packet_id(pid)))
            for tf, qos in topics:
                validate_filter(tf)
                if qos not in (0, 1, 2):
                    raise MalformedPacket("invalid requested QoS")
                body += encode_string(tf) + bytes([qos])
            return _frame(SUBSCRIBE, 0x2, bytes(body))
        case Suback(packet_id=pid, return_codes=codes):
            for c in codes:
                if c not in (0, 1, 2, SUBACK_FAILURE):
                    raise MalformedPacket("invalid SUBACK return code")
            return _frame(SUBACK, 0, struct.pack("!H", _check_packet_id(pid)) + bytes(codes))
        case Unsubscribe(packet_id=pid, topics=topics):
            if not topics:
                raise MalformedPacket("UNSUBSCRIBE needs at least one filter")
            body = bytearray(struct.pack("!H", _check_packet_id(pid)))
            for tf in topics:
                validate_filter(tf)
                body += encode_string(tf)
            return _frame(UNSUBSCRIBE, 0x2, bytes(body))
        case Unsuback(packet_id=pid):
            return _frame(UNSUBACK, 0, struct.pack("!H", _check_packet_id(pid)))
        case Pingreq():
            return _frame(PINGREQ, 0, b"")
        case Pingresp():
            return _frame(PINGRESP, 0, b"")
        case Disconnect():
            return _frame(DISCONNECT, 0, b"")
    raise MalformedPacket(f"cannot encode {type(packet).__name__}")


def _encode_connect(p: Connect) -> bytes:
    flags = 0
    if p.clean_session:
        flags |= 0x02
    if p.will_topic is not None:
        validate_topic(p.will_topic)
        if p.will_qos not in (0, 1, 2):
            raise MalformedPacket("invalid will QoS")
        flags |= 0x04 | (p.will_qos << 3)
        if p.will_retain:
            flags |= 0x20
    elif p.will_qos or p.will_retain:
        raise MalformedPacket("will flags set without will topic")
    if p.username is not None:
        flags |= 0x80
    if p.password is not None:
        if p.username is None:
            raise MalformedPacket("password without username")
        flags |= 0x40
    if not 0 <= p.keepalive <= 0xFFFF:
        raise MalformedPacket("keepalive out of range")
    body = bytearray(encode_string("MQTT"))
    body += bytes([4, flags]) + struct.pack("!H", p.keepalive)
    body += encode_string(p.client_id)
    if p.will_topic is not None:
        if len(p.will_payload) > 0xFFFF:
            raise MalformedPacket("will payload too long")
        body += encode_string(p.will_topic) + struct.pack("!H", len(p.will_payload)) + p.will_payload
    if p.username is not None:
        body += encode_string(p.username)
    if p.password is not None:
        if len(p.password) > 0xFFFF:
            raise MalformedPacket("password too long")
        body += struct.pack("!H", len(p.password)) + p.password
    return _frame(CONNECT, 0, bytes(body))


def _encode_publish(p: Publish) -> bytes:
    validate_topic(p.topic)
    if p.qos not in (0, 1, 2):
        raise MalformedPacket("invalid QoS")
    flags = (p.qos << 1) | (0x01 if p.retain else 0)
    if p.dup:
        if p.qos == 0:
            raise MalformedPacket("DUP must be 0 for QoS 0")
        flags |= 0x08
    body = bytearray(encode_string(p.topic))
    if p.qos > 0:
        body += struct.pack("!H", _check_packet_id(p.packet_id))
    elif p.packet_id is not None:
        raise MalformedPacket("packet identifier present for QoS 0")
    body += p.payload
    return _frame(PUBLISH, flags, bytes(body))


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------


def decode_fixed_header(buf: bytes) -> tuple[int, int, int, int]:
    """Parse the fixed header at the start of ``buf``.

    Returns ``(packet_type, flags, remaining_length, header_size)``.
    Raises :class:`NeedMoreData` if the buffer does not yet hold the full
    fixed header, :class:`MalformedPacket` on bad input.
    """
    if not buf:
        raise NeedMoreData
    first = buf[0]
    ptype = first >> 4
    flags = first & 0x0F
    if ptype == 0 or ptype == 15:
        raise MalformedPacket(f"reserved packet type {ptype}")
    length, consumed = decode_remaining_length(buf, 1)
    return ptype, flags, length, 1 + consumed


def decode(ptype: int, flags: int, body: bytes) -> Packet:
    """Decode a packet given its type, fixed-header flags and variable body."""
    if ptype == PUBLISH:
        return _decode_publish(flags, body)
    if ptype in (SUBSCRIBE, UNSUBSCRIBE):
        if flags != 0x2:
            raise MalformedPacket("SUBSCRIBE/UNSUBSCRIBE flags must be 0010")
    elif flags != 0:
        raise MalformedPacket(f"reserved flags must be 0 for type {ptype}")
    r = _Reader(body)
    if ptype == CONNECT:
        return _decode_connect(r)
    if ptype == CONNACK:
        ack_flags = r.u8()
        rc = r.u8()
        r.done()
        if ack_flags & 0xFE or rc > 5:
            raise MalformedPacket("invalid CONNACK")
        return Connack(bool(ack_flags & 1), rc)
    if ptype == PUBACK:
        pid = _check_packet_id(r.u16())
        r.done()
        return Puback(pid)
    if ptype == SUBSCRIBE:
        pid = _check_packet_id(r.u16())
        topics: list[tuple[str, int]] = []
        while r.remaining():
            tf = r.string()
            validate_filter(tf)
            qos = r.u8()
            if qos > 2:
                raise MalformedPacket("requested QoS > 2")
            topics.append((tf, qos))
        if not topics:
            raise MalformedPacket("SUBSCRIBE with no filters")
        return Subscribe(pid, topics)
    if ptype == SUBACK:
        pid = _check_packet_id(r.u16())
        codes = list(r.take(r.remaining()))
        if not codes or any(c not in (0, 1, 2, SUBACK_FAILURE) for c in codes):
            raise MalformedPacket("invalid SUBACK return codes")
        return Suback(pid, codes)
    if ptype == UNSUBSCRIBE:
        pid = _check_packet_id(r.u16())
        filters: list[str] = []
        while r.remaining():
            tf = r.string()
            validate_filter(tf)
            filters.append(tf)
        if not filters:
            raise MalformedPacket("UNSUBSCRIBE with no filters")
        return Unsubscribe(pid, filters)
    if ptype == UNSUBACK:
        pid = _check_packet_id(r.u16())
        r.done()
        return Unsuback(pid)
    if ptype in (PINGREQ, PINGRESP, DISCONNECT):
        r.done()
        return {PINGREQ: Pingreq, PINGRESP: Pingresp, DISCONNECT: Disconnect}[ptype]()
    if ptype in (PUBREC, PUBREL, PUBCOMP):
        raise MalformedPacket("QoS 2 flow is not supported")
    raise MalformedPacket(f"unknown packet type {ptype}")


def _decode_connect(r: _Reader) -> Connect:
    if r.string() != "MQTT":
        raise MalformedPacket("bad protocol name")
    level = r.u8()
    if level != 4:
        # Caller should answer CONNACK 0x01; we signal via a dedicated subclass.
        raise UnacceptableProtocol(f"protocol level {level}")
    flags = r.u8()
    if flags & 0x01:
        raise MalformedPacket("CONNECT reserved flag set")
    clean = bool(flags & 0x02)
    has_will = bool(flags & 0x04)
    will_qos = (flags >> 3) & 0x03
    will_retain = bool(flags & 0x20)
    has_pass = bool(flags & 0x40)
    has_user = bool(flags & 0x80)
    if not has_will and (will_qos or will_retain):
        raise MalformedPacket("will QoS/retain set without will flag")
    if will_qos == 3:
        raise MalformedPacket("will QoS 3")
    if has_pass and not has_user:
        raise MalformedPacket("password flag without username flag")
    keepalive = r.u16()
    client_id = r.string()
    if not client_id and not clean:
        raise MalformedPacket("empty client id requires clean session")
    will_topic: str | None = None
    will_payload = b""
    if has_will:
        will_topic = r.string()
        validate_topic(will_topic)
        will_payload = r.binary()
    username = r.string() if has_user else None
    password = r.binary() if has_pass else None
    r.done()
    return Connect(
        client_id=client_id,
        clean_session=clean,
        keepalive=keepalive,
        username=username,
        password=password,
        will_topic=will_topic,
        will_payload=will_payload,
        will_qos=will_qos,
        will_retain=will_retain,
    )


class UnacceptableProtocol(MalformedPacket):
    """CONNECT with a protocol level other than 4 (answer CONNACK 0x01)."""


def _decode_publish(flags: int, body: bytes) -> Publish:
    dup = bool(flags & 0x08)
    qos = (flags >> 1) & 0x03
    retain = bool(flags & 0x01)
    if qos == 3:
        raise MalformedPacket("PUBLISH QoS 3")
    if dup and qos == 0:
        raise MalformedPacket("DUP set on QoS 0 PUBLISH")
    r = _Reader(body)
    topic = r.string()
    validate_topic(topic)
    pid: int | None = None
    if qos > 0:
        pid = _check_packet_id(r.u16())
    payload = r.take(r.remaining())
    return Publish(topic=topic, payload=payload, qos=qos, retain=retain, dup=dup, packet_id=pid)


def decode_one(buf: bytes) -> tuple[Packet, int]:
    """Decode the first complete packet in ``buf``.

    Returns ``(packet, bytes_consumed)``; raises NeedMoreData if incomplete.
    """
    ptype, flags, length, hsize = decode_fixed_header(buf)
    total = hsize + length
    if len(buf) < total:
        raise NeedMoreData
    return decode(ptype, flags, bytes(buf[hsize:total])), total
