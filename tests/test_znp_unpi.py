from oneroof_zigbee.znp import commands as c
from oneroof_zigbee.znp.unpi import Frame, FrameType, Parser, Subsystem, fcs


def test_encode_ping():
    f = c.sys_ping()
    assert f.encode() == bytes([0xFE, 0x00, 0x21, 0x01, 0x20])


def test_roundtrip_with_payload():
    f = Frame(FrameType.SREQ, Subsystem.ZDO, 0x36, bytes([0x0F, 0xFC, 0xFF, 0x3C, 0x00]))
    raw = f.encode()
    assert raw[0] == 0xFE and raw[-1] == fcs(raw[1:-1])
    (parsed,) = Parser().feed(raw)
    assert parsed == f


def test_parser_resyncs_after_garbage_and_bad_fcs():
    good = c.sys_ping().encode()
    bad = bytearray(good)
    bad[-1] ^= 0xFF
    p = Parser()
    frames = p.feed(b"\x00\x11garbage" + bytes(bad) + good[:3])
    assert frames == []
    frames = p.feed(good[3:] + good)
    assert frames == [c.sys_ping(), c.sys_ping()]


def test_parser_handles_split_frames():
    raw = c.zdo_permit_join(60).encode()
    p = Parser()
    out = []
    for b in raw:
        out += p.feed(bytes([b]))
    assert len(out) == 1 and out[0].command == 0x36


def test_permit_join_never_forever():
    f = c.zdo_permit_join(255)
    assert f.data[3] == 254
    f = c.zdo_permit_join(-5)
    assert f.data[3] == 0


def test_decode_af_incoming():
    payload = bytes.fromhex("0000 0204 3412 01 01 00 c8 01 00000000 07 03 aabbcc".replace(" ", ""))
    m = c.decode_af_incoming_msg(payload)
    assert m.cluster == 0x0402 and m.src_addr == 0x1234 and m.src_ep == 1 and m.lqi == 200
    assert m.data == bytes.fromhex("aabbcc") and m.trans_seq == 7


def test_decode_simple_desc_rsp():
    # src 0x1234, status 0, nwk 0x1234, len, ep 1, profile 0x0104, dev 0x0100, ver 1, in [0,6], out [0x19]
    d = bytes.fromhex("3412 00 3412 0e 01 0401 0001 01 02 0000 0600 01 1900".replace(" ", ""))
    r = c.decode_simple_desc_rsp(d)
    assert r.endpoint == 1 and r.profile == 0x0104 and r.in_clusters == [0, 6] and r.out_clusters == [0x19]


def test_decode_device_announce():
    d = bytes.fromhex("3412 3412 efbeadde004b1200 8e".replace(" ", ""))
    a = c.decode_end_device_annce(d)
    assert a.ieee == 0x00124B00DEADBEEF and a.is_router and a.mains_powered and a.rx_on_when_idle


def test_install_code_frame_uses_derived_key_format():
    f = c.appcnf_add_install_code(0x00124B00DEADBEEF, bytes(16), c.InstallCodeFormat.DERIVED_KEY)
    assert f.data[0] == 2 and len(f.data) == 1 + 8 + 16


def test_stray_sof_does_not_swallow_following_frames():
    good = c.sys_ping().encode()
    # a stray SOF with a large length byte right before two valid frames
    out = Parser().feed(b"\xfe\xf0" + good * 60)
    assert out == [c.sys_ping()] * 60
