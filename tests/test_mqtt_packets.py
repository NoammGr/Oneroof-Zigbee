from __future__ import annotations

import pytest

from oneroof_zigbee.mqtt import packets as pk

# --- remaining length varint -------------------------------------------------


@pytest.mark.parametrize(
    "value,encoded",
    [
        (0, b"\x00"),
        (1, b"\x01"),
        (127, b"\x7f"),
        (128, b"\x80\x01"),
        (16_383, b"\xff\x7f"),
        (16_384, b"\x80\x80\x01"),
        (pk.MAX_REMAINING_LENGTH, b"\x80\x80\x10"),
    ],
)
def test_remaining_length_roundtrip(value: int, encoded: bytes) -> None:
    assert pk.encode_remaining_length(value) == encoded
    assert pk.decode_remaining_length(encoded) == (value, len(encoded))


def test_remaining_length_truncated_and_too_long() -> None:
    with pytest.raises(pk.NeedMoreData):
        pk.decode_remaining_length(b"\x80")
    with pytest.raises(pk.MalformedPacket):
        pk.decode_remaining_length(b"\xff\xff\xff\xff\x01")
    with pytest.raises(pk.MalformedPacket):
        pk.decode_remaining_length(pk.encode_remaining_length(pk.MAX_REMAINING_LENGTH)[:-1] + b"\x11")
    with pytest.raises(pk.MalformedPacket):
        pk.encode_remaining_length(pk.MAX_REMAINING_LENGTH + 1)
    with pytest.raises(pk.MalformedPacket):
        pk.encode_remaining_length(-1)


def test_remaining_length_decode_with_offset() -> None:
    assert pk.decode_remaining_length(b"\x30\x80\x01", 1) == (128, 2)


# --- strings -----------------------------------------------------------------


def test_string_roundtrip() -> None:
    data = pk.encode_string("héllo/wörld")
    r = pk._Reader(data)
    assert r.string() == "héllo/wörld"
    r.done()


def test_string_rejects_nul_and_bad_utf8() -> None:
    with pytest.raises(pk.MalformedPacket):
        pk.encode_string("a\x00b")
    with pytest.raises(pk.MalformedPacket):
        pk._Reader(b"\x00\x02\xff\xfe").string()
    assert pk._Reader(b"\x00\x05hello").string() == "hello"
    with pytest.raises(pk.MalformedPacket):
        pk._Reader(b"\x00\x06hello").string()  # declared 6, only 5 present


# --- packet roundtrips -------------------------------------------------------


def roundtrip(packet: pk.Packet) -> pk.Packet:
    raw = pk.encode(packet)
    decoded, consumed = pk.decode_one(raw + b"junk")
    assert consumed == len(raw)
    return decoded


def test_connect_roundtrip_full() -> None:
    c = pk.Connect(
        client_id="cid",
        clean_session=False,
        keepalive=120,
        username="u",
        password=b"p\x00\xff",
        will_topic="oz/bridge/state",
        will_payload=b"offline",
        will_qos=1,
        will_retain=True,
    )
    assert roundtrip(c) == c
    raw = pk.encode(c)
    assert raw[0] == 0x10
    assert raw[2:9] == b"\x00\x04MQTT\x04"


def test_connect_minimal() -> None:
    c = pk.Connect(client_id="", clean_session=True, keepalive=0)
    assert roundtrip(c) == c


def test_connect_rejects_bad_things() -> None:
    good = pk.encode(pk.Connect(client_id="x", username="u", password=b"p"))
    # flip reserved flag bit 0 of connect flags
    body = bytearray(good)
    flags_idx = 2 + 7  # fixed(2) + "MQTT"(6) + level(1)
    body[flags_idx] |= 0x01
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(bytes(body))
    # password without username
    body = bytearray(good)
    body[flags_idx] = (body[flags_idx] & ~0x80) & 0xFF
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(bytes(body))
    # wrong protocol level
    body = bytearray(good)
    body[flags_idx - 1] = 3
    with pytest.raises(pk.UnacceptableProtocol):
        pk.decode_one(bytes(body))
    # empty client id with clean_session=0
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(pk.encode(pk.Connect(client_id="", clean_session=False)))
    with pytest.raises(pk.MalformedPacket):
        pk.encode(pk.Connect(client_id="x", password=b"p"))


@pytest.mark.parametrize("sp,rc", [(False, 0), (True, 0), (False, 4), (False, 5)])
def test_connack_roundtrip(sp: bool, rc: int) -> None:
    assert roundtrip(pk.Connack(sp, rc)) == pk.Connack(sp, rc)


def test_connack_invalid() -> None:
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x20\x02\x00\x06")
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x20\x02\x02\x00")
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x21\x02\x00\x00")  # reserved flags


def test_publish_qos0_roundtrip() -> None:
    p = pk.Publish(topic="oz/x/state", payload=b"{}", qos=0, retain=True)
    assert roundtrip(p) == p
    assert pk.encode(p)[0] == 0x31


def test_publish_qos1_roundtrip_with_dup() -> None:
    p = pk.Publish(topic="a/b", payload=b"\x00" * 300, qos=1, retain=False, dup=True, packet_id=0x1234)
    assert roundtrip(p) == p
    raw = pk.encode(p)
    assert raw[0] == 0x3A
    assert raw[1:3] == b"\xb3\x02"  # remaining length 2+3+2+300 = 307
    assert pk.decode_remaining_length(raw, 1)[0] == 307


def test_publish_empty_payload_and_large() -> None:
    assert roundtrip(pk.Publish("t")) == pk.Publish("t")
    big = pk.Publish("t", b"x" * (pk.MAX_REMAINING_LENGTH - 3))
    assert roundtrip(big) == big
    with pytest.raises(pk.MalformedPacket):
        pk.encode(pk.Publish("t", b"x" * (pk.MAX_REMAINING_LENGTH - 2)))


def test_publish_invalid() -> None:
    with pytest.raises(pk.MalformedPacket):
        pk.encode(pk.Publish("a/+", b""))
    with pytest.raises(pk.MalformedPacket):
        pk.encode(pk.Publish("", b""))
    with pytest.raises(pk.MalformedPacket):
        pk.encode(pk.Publish("a", qos=1))  # missing packet id
    with pytest.raises(pk.MalformedPacket):
        pk.encode(pk.Publish("a", qos=1, packet_id=0))
    with pytest.raises(pk.MalformedPacket):
        pk.encode(pk.Publish("a", qos=0, dup=True))
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x36\x03\x00\x01a")  # QoS 3
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x32\x03\x00\x01a")  # QoS 1 without packet id
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x30\x03\x00\x01#")  # wildcard in topic name


def test_puback_roundtrip() -> None:
    assert roundtrip(pk.Puback(65535)) == pk.Puback(65535)
    assert pk.encode(pk.Puback(1)) == b"\x40\x02\x00\x01"
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x40\x02\x00\x00")
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x40\x03\x00\x01\x00")


def test_subscribe_suback_roundtrip() -> None:
    s = pk.Subscribe(10, [("a/#", 1), ("+/b", 0), ("c", 2)])
    assert roundtrip(s) == s
    assert pk.encode(s)[0] == 0x82
    a = pk.Suback(10, [1, 0, 0x80])
    assert roundtrip(a) == a
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x80\x02\x00\x01")  # wrong flags, no payload
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x82\x02\x00\x01")  # no filters
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x82\x06\x00\x01\x00\x01a\x03")  # qos 3
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x82\x08\x00\x01\x00\x03a/#b\x00")  # bad filter
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x90\x03\x00\x01\x03")  # bad suback code


def test_unsubscribe_unsuback_roundtrip() -> None:
    u = pk.Unsubscribe(7, ["a/b", "#"])
    assert roundtrip(u) == u
    assert pk.encode(u)[0] == 0xA2
    assert roundtrip(pk.Unsuback(7)) == pk.Unsuback(7)
    with pytest.raises(pk.MalformedPacket):
        pk.encode(pk.Unsubscribe(7, []))


def test_ping_disconnect() -> None:
    assert pk.encode(pk.Pingreq()) == b"\xc0\x00"
    assert pk.encode(pk.Pingresp()) == b"\xd0\x00"
    assert pk.encode(pk.Disconnect()) == b"\xe0\x00"
    assert isinstance(roundtrip(pk.Pingreq()), pk.Pingreq)
    assert isinstance(roundtrip(pk.Pingresp()), pk.Pingresp)
    assert isinstance(roundtrip(pk.Disconnect()), pk.Disconnect)
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\xc0\x01\x00")
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\xc1\x00")


def test_reserved_types_and_qos2_flow_rejected() -> None:
    for first in (0x00, 0xF0):
        with pytest.raises(pk.MalformedPacket):
            pk.decode_one(bytes([first, 0]))
    with pytest.raises(pk.MalformedPacket):
        pk.decode_one(b"\x62\x02\x00\x01")  # PUBREL


def test_decode_one_need_more_data() -> None:
    raw = pk.encode(pk.Publish("abc", b"payload"))
    for n in range(len(raw)):
        with pytest.raises(pk.NeedMoreData):
            pk.decode_one(raw[:n])
    with pytest.raises(pk.NeedMoreData):
        pk.decode_one(b"")


def test_stream_of_packets() -> None:
    stream = pk.encode(pk.Pingreq()) + pk.encode(pk.Publish("t", b"x")) + pk.encode(pk.Puback(3))
    out = []
    while stream:
        p, n = pk.decode_one(stream)
        out.append(p)
        stream = stream[n:]
    assert [type(p) for p in out] == [pk.Pingreq, pk.Publish, pk.Puback]


# --- topics ------------------------------------------------------------------


@pytest.mark.parametrize(
    "flt,topic,expected",
    [
        ("a/b/c", "a/b/c", True),
        ("a/b/c", "a/b", False),
        ("a/b", "a/b/c", False),
        ("a/+/c", "a/b/c", True),
        ("a/+/c", "a/b/d", False),
        ("a/+/c", "a//c", True),
        ("+", "a", True),
        ("+", "a/b", False),
        ("+", "/a", False),
        ("+/+", "/a", True),
        ("/+", "/a", True),
        ("#", "a", True),
        ("#", "a/b/c", True),
        ("#", "", True),
        ("a/#", "a", True),
        ("a/#", "a/", True),
        ("a/#", "a/b/c", True),
        ("a/#", "b/a", False),
        ("a/b/#", "a/b", True),
        ("a/b/#", "a", False),
        ("+/#", "a/b/c", True),
        ("sport/+", "sport", False),
        ("sport/+", "sport/", True),
        ("a/B", "a/b", False),
        # $ topics are hidden from wildcard-led filters
        ("#", "$SYS/broker/clients", False),
        ("+/broker/clients", "$SYS/broker/clients", False),
        ("+/#", "$SYS/x", False),
        ("$SYS/#", "$SYS/broker/clients", True),
        ("$SYS/+/clients", "$SYS/broker/clients", True),
        ("$SYS/broker/clients", "$SYS/broker/clients", True),
        ("a/$b", "a/$b", True),
        ("a/+", "a/$b", True),
    ],
)
def test_topic_matches(flt: str, topic: str, expected: bool) -> None:
    assert pk.topic_matches(flt, topic) is expected


@pytest.mark.parametrize("flt", ["a/b", "+", "#", "a/+/b", "a/#", "+/#", "/", "a//b", "$SYS/#", "+/+/+"])
def test_validate_filter_ok(flt: str) -> None:
    pk.validate_filter(flt)


@pytest.mark.parametrize("flt", ["", "a#", "#/a", "a/#/b", "a+", "+a", "a/b+", "##", "a\x00b"])
def test_validate_filter_bad(flt: str) -> None:
    with pytest.raises(pk.MalformedPacket):
        pk.validate_filter(flt)


@pytest.mark.parametrize("topic", ["", "a/+", "#", "a/b#", "x\x00"])
def test_validate_topic_bad(topic: str) -> None:
    with pytest.raises(pk.MalformedPacket):
        pk.validate_topic(topic)


def test_validate_topic_ok() -> None:
    for t in ("a", "a/b", "/", "a//b", "$SYS/x", "ünïcode/topic"):
        pk.validate_topic(t)
