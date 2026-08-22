import json
import os

import pytest

from oneroof_zigbee.security import (
    Audit, InstallCodeError, JoinGuard, JoinPolicy, JoinPolicyError, Keystore, NetworkSecrets,
    aes_mmo_hash, crc16, derive_link_key, parse_install_code,
)


def test_install_code_spec_vector():
    code = parse_install_code("83FE D340 7A93 9723 A5C6 39B2 6916 D505")
    assert code[-2:].hex() == "c3b5"
    assert derive_link_key(code).hex() == "66b6900981e1ee3ca4206b6b861c02bb"


def test_install_code_with_crc_and_bad_crc():
    ok = parse_install_code("83FED3407A939723A5C639B26916D505C3B5")
    assert len(ok) == 18
    with pytest.raises(InstallCodeError):
        parse_install_code("83FED3407A939723A5C639B26916D505C3B6")
    with pytest.raises(InstallCodeError):
        parse_install_code("83FED3")
    with pytest.raises(InstallCodeError):
        parse_install_code("zz")


def test_crc16_x25_known():
    assert crc16(b"123456789") == 0x906E


def test_mmo_hash_empty_and_length():
    assert len(aes_mmo_hash(b"")) == 16
    assert aes_mmo_hash(b"a") != aes_mmo_hash(b"b")


def test_keystore_roundtrip_and_permissions(tmp_path, monkeypatch):
    monkeypatch.delenv("ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE", raising=False)
    ks = Keystore(tmp_path / "net.keystore")
    s = ks.load_or_create(channel=20)
    assert (tmp_path / "net.keystore.pass").exists()
    assert oct(os.stat(ks.path).st_mode & 0o777) == "0o600"
    assert oct(os.stat(ks.path.with_name(ks.path.name + ".pass")).st_mode & 0o777) == "0o600"
    again = Keystore(tmp_path / "net.keystore").load()
    assert again.network_key == s.network_key and again.pan_id == s.pan_id and again.channel == 20
    assert "redacted" in repr(s) and s.network_key.hex() not in repr(s)
    # plaintext must not be on disk
    assert s.network_key not in ks.path.read_bytes()
    assert s.network_key.hex().encode() not in ks.path.read_bytes()


def test_keystore_wrong_passphrase_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE", "one")
    ks = Keystore(tmp_path / "k")
    ks.load_or_create(11)
    monkeypatch.setenv("ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE", "two")
    from cryptography.exceptions import InvalidTag
    with pytest.raises(InvalidTag):
        Keystore(tmp_path / "k").load()


def test_generated_secrets_are_random():
    a, b = NetworkSecrets.generate(11), NetworkSecrets.generate(11)
    assert a.network_key != b.network_key and a.pan_id != b.pan_id
    assert a.network_key != bytes.fromhex("01030507090b0d0f00020406080a0c0d")  # z-stack default


def test_audit_chain_verifies_and_detects_tamper(tmp_path):
    p = tmp_path / "audit.log"
    a = Audit(p)
    a.event("one", x=1)
    a.security("two", y=2)
    Audit(p).event("three")  # reopened instance continues the chain
    assert Audit.verify(p) == (True, 0)
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["y"] = 99
    lines[1] = json.dumps(rec, separators=(",", ":"), sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    ok, bad = Audit.verify(p)
    assert not ok and bad == 3  # line 3's prev no longer matches


def test_join_guard_policy():
    g = JoinGuard(JoinPolicy(max_seconds=60, cooldown_seconds=0), Audit(None))
    w = g.request_open(600, "me")
    assert w.seconds == 60 and g.window is w
    assert g.on_device_joined(1, 2) is True
    g.mark_closed()
    assert g.window is None
    assert g.on_device_joined(1, 2) is False
    with pytest.raises(JoinPolicyError):
        g.request_open(0, "me")


def test_join_guard_ieee_pinning_and_cooldown():
    g = JoinGuard(JoinPolicy(cooldown_seconds=30), Audit(None))
    g.request_open(10, "me", allowed_ieee=0xAA)
    assert g.on_device_joined(0xBB, 1) is False
    assert g.on_device_joined(0xAA, 1) is True
    g.mark_closed()
    with pytest.raises(JoinPolicyError):
        g.request_open(10, "me")


def test_join_guard_require_install_code():
    g = JoinGuard(JoinPolicy(require_install_code=True, cooldown_seconds=0), Audit(None))
    with pytest.raises(JoinPolicyError):
        g.request_open(10, "me")
    g.request_open(10, "me", allowed_ieee=0x1)


def test_local_ca_and_server_cert(tmp_path):
    import os
    import ssl
    from oneroof_zigbee.security.tls import client_context, ensure_server_cert, fingerprint, server_context
    cert, key, ca = ensure_server_cert(tmp_path, ["myhost.local"])
    assert oct(os.stat(key).st_mode & 0o777) == "0o600" and oct(os.stat(tmp_path / "tls" / "ca.key").st_mode & 0o777) == "0o600"
    assert len(fingerprint(ca).split(":")) == 32
    # second call reuses (no renewal)
    mtime = cert.stat().st_mtime
    assert ensure_server_cert(tmp_path, ["myhost.local"])[0].stat().st_mtime == mtime
    # new hostname → reissued, CA unchanged
    ca_mtime = ca.stat().st_mtime
    ensure_server_cert(tmp_path, ["myhost.local", "other.local"])
    assert ca.stat().st_mtime == ca_mtime
    srv = server_context(cert, key)
    assert srv.minimum_version == ssl.TLSVersion.TLSv1_2
    cli = client_context(ca)
    assert cli.verify_mode == ssl.CERT_REQUIRED


def test_join_guard_first_window_allowed_right_after_boot(monkeypatch):
    """monotonic() is uptime on Linux: a freshly booted host must not be in 'cooldown'."""
    import time as _t
    monkeypatch.setattr(_t, "monotonic", lambda: 2.0)
    g = JoinGuard(JoinPolicy(cooldown_seconds=1000), Audit(None))
    assert g.request_open(10, "me").seconds == 10


async def test_transport_debug_log_never_shows_key_material(caplog):
    """Key reads/writes and install codes are redacted even at DEBUG (logs get pasted into tickets)."""
    import logging
    from tests.fake_znp import FakeZnp
    from oneroof_zigbee.znp import commands as c
    from oneroof_zigbee.znp.transport import Transport
    fake = FakeZnp()
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    caplog.set_level(logging.DEBUG, logger="oneroof_zigbee.znp.transport")
    key = bytes(range(0x10, 0x20))
    await t.request(c.nv_item_init(c.NvId.PRECFGKEY, 16, key))
    await t.request(c.nv_write(c.NvId.PRECFGKEY, key))
    await t.request(c.nv_read(c.NvId.PRECFGKEY), check_status=False)
    from oneroof_zigbee.security.installcode import crc16
    await t.request(c.appcnf_set_default_centralized_key(False, key + crc16(key).to_bytes(2, "little")))
    await t.request(c.nv_read(c.NvId.PANID), check_status=False)  # harmless items stay readable
    text = caplog.text
    assert key.hex() not in text and "<redacted>" in text
    assert "RX SRSP SYS:0x08 <redacted>" in text
    assert any(line for line in text.splitlines() if "TX SYS:0x08 " in line and "<redacted>" not in line), "PANID read not redacted"
    await t.close()
