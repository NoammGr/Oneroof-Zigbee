"""Telegram notifications and the outbound (egress) policy."""

import asyncio
import json
import logging
import ssl
import time

import pytest

from oneroof_zigbee.notify import CATEGORIES, EgressClient, EgressRefused, NotifySecrets, NotifySettings, TelegramNotifier, describe
from oneroof_zigbee.notify.egress import default_ssl_context
from oneroof_zigbee.notify.telegram import in_quiet_hours
from oneroof_zigbee.security import Audit
from oneroof_zigbee.security.tls import ensure_server_cert, server_context
from tests.test_ui import http, ui as ui_fixture  # noqa: F401  (fixture re-used)

TOKEN = "123456789:AAFakeTokenForTestsOnly_abcdefghijklmnop"
CHAT = "-1001234567890"
IEEE_A = "0x0000000000000001"
NAMES = {IEEE_A: "Kitchen plug"}


# ----------------------------------------------------------------- helpers --

class FakeTelegram:
    """A local HTTPS endpoint that speaks just enough of the Bot API."""

    def __init__(self):
        self.requests: list[tuple[str, dict]] = []
        self.fail_next = 0          # answer 500 this many times
        self.status = 200
        self.server = None
        self.port = 0

    async def start(self, tmp_path):
        cert, key, ca = ensure_server_cert(tmp_path, ["api.telegram.org"])
        self.ca = ca
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=server_context(cert, key))
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            line = head.split(b"\r\n")[0].decode()
            method, path, _ = line.split(" ")
            n = 0
            for h in head.decode().split("\r\n")[1:]:
                if h.lower().startswith("content-length:"):
                    n = int(h.split(":")[1])
            body = json.loads(await reader.readexactly(n)) if n else {}
            self.requests.append((path, body))
            if self.fail_next > 0:
                self.fail_next -= 1
                status, payload = 500, {"ok": False, "description": "boom"}
            else:
                status, payload = self.status, ({"ok": True, "result": {"message_id": len(self.requests)}} if self.status == 200
                                                else {"ok": False, "description": "Unauthorized"})
            raw = json.dumps(payload).encode()
            writer.write(f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\nConnection: close\r\n\r\n".encode() + raw)
            await writer.drain()
        finally:
            writer.close()


def trust_ctx(ca):
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


@pytest.fixture
async def fake_tg(tmp_path):
    f = FakeTelegram()
    await f.start(tmp_path / "tg")
    yield f
    await f.stop()


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def make(tmp_path, fake_tg=None, *, enabled=True, clock=None, local=None, **settings):
    audit = Audit(tmp_path / "audit.log")
    egress = EgressClient(audit, ssl_context=trust_ctx(fake_tg.ca) if fake_tg else None,
                          connect_to={"api.telegram.org": ("127.0.0.1", fake_tg.port)} if fake_tg else None)
    st = NotifySettings(tmp_path / "notify.yaml")
    st.apply({"enabled": enabled, "digest_seconds": 0, **settings})
    sec = NotifySecrets(tmp_path / "notify.secrets")
    if fake_tg:
        sec.update(bot_token=TOKEN, chat_id=CHAT)
    slept: list[float] = []

    async def fake_sleep(s):
        slept.append(s)

    n = TelegramNotifier(audit, egress, st, sec, resolve_name=NAMES.get, clock=clock or Clock(),
                         local_time=local or time.localtime, sleep=fake_sleep)
    n.slept = slept
    return n, audit, egress


# ------------------------------------------------------------------ egress --

async def test_egress_refuses_unlisted_hosts_and_records_ledger(tmp_path):
    audit = Audit(tmp_path / "audit.log")
    seen = []
    audit.subscribe(seen.append)
    c = EgressClient(audit, enabled=True)
    with pytest.raises(EgressRefused):
        await c.post_json("https://example.org/x", {})
    with pytest.raises(EgressRefused):
        await c.post_json("http://api.telegram.org/x", {})  # plaintext is refused even for the allowed host
    c.enabled = False
    with pytest.raises(EgressRefused):
        await c.post_json("https://api.telegram.org/x", {})
    led = c.snapshot()
    assert led["allowed_hosts"] == ["api.telegram.org"]
    assert led["hosts"]["example.org"]["refused"] == 1 and led["hosts"]["example.org"]["count"] == 1
    assert led["hosts"]["api.telegram.org"]["refused"] == 2 and "disabled" in led["hosts"]["api.telegram.org"]["last_error"]
    refused = [r for r in seen if r["type"] == "egress_refused"]
    assert len(refused) == 3 and all(r["level"] == "security" for r in refused)
    assert refused[0]["host"] == "example.org" and "allow-list" in refused[0]["reason"]
    assert not any("/x" in json.dumps(r) for r in refused)  # never the path


def test_default_tls_context_is_strict():
    ctx = default_ssl_context()
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
    c = EgressClient(None)
    assert c.enabled is False and c.allowed_hosts == frozenset({"api.telegram.org"})


async def test_egress_post_against_local_https_endpoint(tmp_path, fake_tg):
    c = EgressClient(Audit(None), enabled=True, ssl_context=trust_ctx(fake_tg.ca), connect_to={"api.telegram.org": ("127.0.0.1", fake_tg.port)})
    status, body = await c.post_json("https://api.telegram.org/botX/sendMessage", {"chat_id": "1", "text": "hi"})
    assert status == 200 and body["ok"] is True
    assert fake_tg.requests == [("/botX/sendMessage", {"chat_id": "1", "text": "hi"})]
    e = c.snapshot()["hosts"]["api.telegram.org"]
    assert e["count"] == 1 and e["refused"] == 0 and e["last_error"] is None


async def test_egress_rejects_untrusted_certificate(tmp_path, fake_tg):
    # the system trust store does not know the test CA → the handshake fails, nothing is sent
    c = EgressClient(Audit(None), enabled=True, connect_to={"api.telegram.org": ("127.0.0.1", fake_tg.port)})
    with pytest.raises(ssl.SSLError):
        await c.post_json("https://api.telegram.org/botX/sendMessage", {})
    assert fake_tg.requests == []
    assert "SSL" in c.snapshot()["hosts"]["api.telegram.org"]["last_error"]


# ---------------------------------------------------------------- mapping --

def test_describe_every_category_uses_names_not_addresses():
    res = NAMES.get
    cases = {
        "join_window": [{"type": "permit_join_opened", "seconds": 60, "by": "ui:admin"}, {"type": "permit_join_closed", "reason": "timeout"},
                        {"type": "permit_join_closed_after_join", "ieee": IEEE_A}],
        "devices": [{"type": "device_joined", "ieee": IEEE_A}, {"type": "device_left", "ieee": IEEE_A}, {"type": "device_removed", "ieee": IEEE_A},
                    {"type": "device_rejoined", "ieee": IEEE_A}, {"type": "interview_done", "ieee": IEEE_A, "manufacturer": "Acme", "model": "Plug-1"}],
        "security": [{"type": "unexpected_join", "ieee": "0x00000000000000ff", "level": "security", "reason": "no window"},
                     {"type": "traffic_from_unknown_device", "ieee": "0x00000000000000ff", "cluster": "0x0006", "level": "security"},
                     {"type": "unknown_device_adopted", "ieee": IEEE_A, "by": "ui:admin"}, {"type": "unknown_device_evicted", "ieee": IEEE_A, "by": "ui:admin"},
                     {"type": "request_denied", "action": "permit_join", "by": "ha", "reason": "not control"},
                     {"type": "key_rotation_after_plain_join", "ieee": IEEE_A}, {"type": "network_key_rotated", "by": "ui:admin", "delivered": 3, "failed": 0},
                     {"type": "network_key_mismatch"}, {"type": "network_key_repaired", "method": "nv"}, {"type": "network_parameters_mismatch", "radio_channel": 11, "radio_pan_id": "0x1234"},
                     {"type": "no_neighbours_heard"}, {"type": "frame_counter_unverified", "value": 1, "needed": 2},
                     {"type": "broker_login_adopted", "user": "ha", "ip": "172.30.32.2"}, {"type": "definition_saved", "manufacturer": "Acme", "model": "Plug-1"},
                     {"type": "definition_removed", "manufacturer": "Acme", "model": "Plug-1"}, {"type": "permit_join_unexpected_open", "duration": 254},
                     {"type": "something_new", "level": "security", "detail": 1}],
        "anomalies": [{"type": "device_anomaly", "ieee": IEEE_A, "kind": "sequence_jump", "jump": 120}],
        "health": [{"type": "coordinator_started", "channel": 15, "pan_id": "0x1a2b"}, {"type": "restart_requested", "by": "ui:admin"},
                   {"type": "neighbour_check", "neighbours": 4, "routers": 2}, {"type": "gateway_started"}],
        "liveness": [{"type": "device_anomaly", "ieee": IEEE_A, "kind": "went_silent", "silent_s": 900, "typical_s": 60}],
    }
    assert set(cases) == set(CATEGORIES)
    for cat, recs in cases.items():
        for rec in recs:
            got = describe(rec, res, False)
            assert got is not None and got[0] == cat, rec
            assert "0x0000" not in got[1], got
            if rec.get("ieee") == IEEE_A:
                assert "Kitchen plug" in got[1], got
    # unknown device without addresses stays anonymous; with addresses the IEEE appears
    assert "unregistered device" in describe({"type": "unexpected_join", "ieee": "0x00000000000000ff"}, res, False)[1]
    assert "0x00000000000000ff" in describe({"type": "unexpected_join", "ieee": "0x00000000000000ff"}, res, True)[1]
    assert "Kitchen plug (0x0000000000000001)" in describe({"type": "device_joined", "ieee": IEEE_A}, res, True)[1]
    assert describe({"type": "command", "ieee": IEEE_A}, res, False) is None  # routine events are not notifications
    assert "sequence jump" in describe(cases["anomalies"][0], res, False)[1] and "jump 120" in describe(cases["anomalies"][0], res, False)[1]
    # coordinator link loss/recovery: immediate ("anomalies"), on by default
    off = describe({"type": "coordinator_offline", "reason": "serial link closed"}, res, False)
    assert off is not None and off[0] == "anomalies" and "OFFLINE" in off[1] and "serial link closed" in off[1]
    on = describe({"type": "coordinator_online"}, res, False)
    assert on is not None and on[0] == "anomalies" and "back online" in on[1]
    from oneroof_zigbee.notify.telegram import IMMEDIATE
    assert "anomalies" in IMMEDIATE


# ---------------------------------------------------------------- batching --

async def test_security_immediate_and_digest_batched(tmp_path, fake_tg):
    clock = Clock()
    n, audit, _ = make(tmp_path, fake_tg, clock=clock, digest_seconds=30)
    n.audit.subscribe(n.on_audit)
    audit.event("device_joined", ieee=IEEE_A)
    audit.event("permit_join_closed", reason="first join")
    assert await n.flush() == 0                          # digest not due yet
    audit.security("unexpected_join", ieee="0x00000000000000ff", reason="no window")
    assert await n.flush() == 1                          # security goes out now, alone
    path, body = fake_tg.requests[-1]
    assert path == f"/bot{TOKEN}/sendMessage" and body["chat_id"] == CHAT and body["disable_web_page_preview"] is True
    assert "parse_mode" not in body and "UNEXPECTED JOIN" in body["text"] and "Kitchen" not in body["text"]
    clock.t += 31
    assert await n.flush() == 1                          # one message with both routine lines
    text = fake_tg.requests[-1][1]["text"]
    assert "Kitchen plug" in text and "Join window closed" in text and text.count("\n") == 1
    assert n.sent == 2 and n.failed == 0 and n.status()["recent"][-1]["ok"] is True


async def test_category_toggle_and_disabled(tmp_path, fake_tg):
    n, audit, egress = make(tmp_path, fake_tg, categories={"devices": False})
    n.audit.subscribe(n.on_audit)
    audit.event("device_joined", ieee=IEEE_A)
    assert await n.flush() == 0 and fake_tg.requests == []
    n.apply_settings({"enabled": False})
    assert egress.enabled is False
    audit.security("unexpected_join", ieee=IEEE_A)
    assert await n.flush() == 0 and fake_tg.requests == []


async def test_rate_limit_and_more_suffix(tmp_path, fake_tg):
    clock = Clock()
    n, audit, _ = make(tmp_path, fake_tg, clock=clock)
    for i in range(25):
        n.on_audit({"type": "unexpected_join", "level": "security", "ieee": IEEE_A, "reason": f"r{i}", "ts": clock.t})
        await n.flush()
    assert len(fake_tg.requests) == 20
    assert n.status()["dropped"] == 5
    clock.t += 61
    n.on_audit({"type": "unexpected_join", "level": "security", "ieee": IEEE_A, "reason": "later", "ts": clock.t})
    await n.flush()
    assert len(fake_tg.requests) == 21 and fake_tg.requests[-1][1]["text"].endswith("… and 5 more")


async def test_long_batches_are_split_at_4096(tmp_path, fake_tg):
    n, audit, _ = make(tmp_path, fake_tg)
    for _i in range(60):
        n.on_audit({"type": "device_joined", "ieee": IEEE_A, "by": "x" * 150, "ts": 0})
    await n.flush()
    assert len(fake_tg.requests) >= 2 and all(len(b["text"]) <= 4096 for _, b in fake_tg.requests)


def test_quiet_hours_math():
    lt = lambda h, m: time.struct_time((2026, 1, 1, h, m, 0, 0, 1, 0))  # noqa: E731
    assert in_quiet_hours("22:00", "07:00", lt(23, 0)) and in_quiet_hours("22:00", "07:00", lt(6, 59))
    assert not in_quiet_hours("22:00", "07:00", lt(7, 0)) and not in_quiet_hours("22:00", "07:00", lt(12, 0))
    assert in_quiet_hours("09:00", "17:00", lt(12, 0)) and not in_quiet_hours("09:00", "17:00", lt(18, 0))
    assert not in_quiet_hours(None, None, lt(12, 0))


async def test_quiet_hours_hold_routine_but_not_security(tmp_path, fake_tg):
    hour = [23]
    local = lambda t: time.struct_time((2026, 1, 1, hour[0], 0, 0, 0, 1, 0))  # noqa: E731
    n, audit, _ = make(tmp_path, fake_tg, local=local, quiet_start="22:00", quiet_end="07:00")
    n.on_audit({"type": "device_joined", "ieee": IEEE_A, "ts": 0})
    assert await n.flush() == 0
    n.on_audit({"type": "unexpected_join", "level": "security", "ieee": IEEE_A, "ts": 0})
    assert await n.flush() == 1 and "UNEXPECTED" in fake_tg.requests[-1][1]["text"]
    hour[0] = 8
    assert await n.flush() == 1 and "Kitchen plug" in fake_tg.requests[-1][1]["text"]


async def test_retries_with_backoff_and_failure_audit(tmp_path, fake_tg):
    n, audit, _ = make(tmp_path, fake_tg)
    seen = []
    audit.subscribe(seen.append)
    fake_tg.fail_next = 2
    n.on_audit({"type": "unexpected_join", "level": "security", "ieee": IEEE_A, "ts": 0})
    assert await n.flush() == 1 and len(fake_tg.requests) == 3 and n.slept == [1.0, 3.0]
    fake_tg.fail_next = 3
    n.on_audit({"type": "unexpected_join", "level": "security", "ieee": IEEE_A, "ts": 0})
    assert await n.flush() == 0 and n.failed == 1
    rec = [r for r in seen if r["type"] == "notify_failed"][-1]
    assert rec["level"] == "event" and "HTTP 500" in rec["error"] and TOKEN not in json.dumps(rec)
    fake_tg.status = 401  # bad token: no retry
    before = len(fake_tg.requests)
    n.on_audit({"type": "unexpected_join", "level": "security", "ieee": IEEE_A, "ts": 0})
    await n.flush()
    assert len(fake_tg.requests) == before + 1 and n.failed == 2


async def test_send_test_and_start_stop(tmp_path, fake_tg):
    n, audit, _ = make(tmp_path, fake_tg, categories={"health": True})
    n.start()
    await asyncio.sleep(0)
    await n.stop()
    texts = [b["text"] for _, b in fake_tg.requests]
    assert any("Gateway started" in t for t in texts) and any("Gateway stopping" in t for t in texts)
    r = await n.send_test()
    assert r["ok"] is True and "Test message" in fake_tg.requests[-1][1]["text"]
    n.secrets.clear_token()
    with pytest.raises(ValueError):
        await n.send_test()


# ----------------------------------------------------------------- secrets --

def test_secrets_roundtrip_permissions_and_no_leak(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    s = NotifySecrets(tmp_path / "notify.secrets")
    assert not s.has_token()
    s.update(bot_token=TOKEN, chat_id=CHAT)
    assert (tmp_path / "notify.secrets").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "notify.secrets.pass").stat().st_mode & 0o777 == 0o600
    assert TOKEN.encode() not in (tmp_path / "notify.secrets").read_bytes()
    s2 = NotifySecrets(tmp_path / "notify.secrets")
    assert s2.token() == TOKEN and s2.chat_id() == CHAT and s2.has_token()
    assert "has_token=True" in repr(s2) and TOKEN not in repr(s2)
    s2.clear_token()
    assert not NotifySecrets(tmp_path / "notify.secrets").has_token() and s2.chat_id() == CHAT
    # settings file holds no secret, is private
    st = NotifySettings(tmp_path / "notify.yaml")
    st.apply({"enabled": True, "quiet_start": "22:00", "quiet_end": "07:00"})
    text = (tmp_path / "notify.yaml").read_text()
    assert "token" not in text and (tmp_path / "notify.yaml").stat().st_mode & 0o777 == 0o600
    assert NotifySettings(tmp_path / "notify.yaml")["quiet_start"] == "22:00"
    with pytest.raises(ValueError):
        st.apply({"quiet_start": "25:00", "quiet_end": "07:00"})
    with pytest.raises(ValueError):
        st.apply({"categories": {"nope": True}})
    with pytest.raises(ValueError):
        st.apply({"bot_token": "x"})
    assert TOKEN not in caplog.text and CHAT not in caplog.text


async def test_token_never_in_logs_or_audit(tmp_path, fake_tg, caplog):
    caplog.set_level(logging.DEBUG)
    n, audit, _ = make(tmp_path, fake_tg)
    fake_tg.fail_next = 3
    n.on_audit({"type": "unexpected_join", "level": "security", "ieee": IEEE_A, "ts": 0})
    await n.flush()
    n.on_audit({"type": "unexpected_join", "level": "security", "ieee": IEEE_A, "ts": 0})
    await n.flush()
    assert TOKEN not in caplog.text
    assert TOKEN not in (tmp_path / "audit.log").read_text()
    assert TOKEN not in json.dumps(n.status())


# --------------------------------------------------------------------- API --

@pytest.fixture
async def ui_notify(ui_fixture, tmp_path, fake_tg):  # noqa: F811
    fake, gw, server, api = ui_fixture
    n, audit, egress = make(tmp_path / "n", None)
    n.egress = EgressClient(gw.audit, ssl_context=trust_ctx(fake_tg.ca), connect_to={"api.telegram.org": ("127.0.0.1", fake_tg.port)})
    n.audit = gw.audit
    n.apply_settings({"enabled": False})
    api.notifier = n
    yield fake, gw, server, api, n


async def test_api_notify_roundtrip(ui_notify, fake_tg):
    fake, gw, server, api, n = ui_notify
    st, _, body = await http(server.port, "GET", "/api/notify")
    j = json.loads(body)
    assert st == 200 and j["has_token"] is False and j["settings"]["enabled"] is False and set(j["categories"]) == set(CATEGORIES)
    assert "bot_token" not in json.dumps(j)
    st, _, body = await http(server.port, "PUT", "/api/notify",
                             {"enabled": True, "bot_token": TOKEN, "chat_id": CHAT, "digest_seconds": 5, "categories": {"health": True}}, )
    j = json.loads(body)
    assert st == 200 and j["has_token"] is True and j["chat_id"] == CHAT and j["settings"]["digest_seconds"] == 5 and j["settings"]["categories"]["health"] is True
    assert TOKEN not in body.decode()
    assert sorted(j["changed"]) == ["bot_token", "categories", "chat_id", "digest_seconds", "enabled"]
    st, _, body = await http(server.port, "GET", "/api/audit")
    rec = [r for r in json.loads(body) if r["type"] == "notify_settings_changed"][-1]
    assert rec["by"] == "ui:admin" and TOKEN not in json.dumps(rec)
    # token is not required on later saves
    st, _, body = await http(server.port, "PUT", "/api/notify", {"include_addresses": True})
    assert st == 200 and json.loads(body)["has_token"] is True
    st, _, body = await http(server.port, "PUT", "/api/notify", {"digest_seconds": "lots"})
    assert st == 400
    st, _, body = await http(server.port, "PUT", "/api/notify", {"bot_token": "no colon"})
    assert st == 400
    # test message through the local endpoint
    st, _, body = await http(server.port, "POST", "/api/notify/test", {})
    assert st == 200 and json.loads(body)["ok"] is True and fake_tg.requests[-1][1]["chat_id"] == CHAT
    st, _, body = await http(server.port, "GET", "/api/egress")
    j = json.loads(body)
    assert j["allowed_hosts"] == ["api.telegram.org"] and j["hosts"]["api.telegram.org"]["count"] == 1 and "no outbound connection" in j["policy"]
    st, _, body = await http(server.port, "GET", "/api/notify")
    assert json.loads(body)["recent"][-1]["ok"] is True and json.loads(body)["sent"] == 1
    st, _, body = await http(server.port, "DELETE", "/api/notify/token", {})
    assert st == 200 and json.loads(body)["has_token"] is False, body
    st, _, body = await http(server.port, "POST", "/api/notify/test", {})
    assert st == 400


async def test_api_notify_control_gating(ui_notify):
    fake, gw, server, api, n = ui_notify
    api.acts_as = "homeassistant"
    st, _, _ = await http(server.port, "GET", "/api/notify")
    assert st == 200
    st, _, _ = await http(server.port, "PUT", "/api/notify", {"enabled": True})
    assert st == 403
    st, _, _ = await http(server.port, "POST", "/api/notify/test", {})
    assert st == 403
    st, _, _ = await http(server.port, "DELETE", "/api/notify/token", {})
    assert st == 403
    assert n.settings["enabled"] is False


async def test_the_same_worry_reaches_the_phone_once_per_window(tmp_path):
    """A wall-switched bulb 'goes silent' every evening; a marginal plug drops hourly. The audit
    records every event — the phone hears each (kind, device) once per cooldown window, other
    devices and other kinds unaffected."""
    clock = Clock()
    n, audit, egress = make(tmp_path, enabled=True, clock=clock)
    silent = {"type": "device_anomaly", "ieee": IEEE_A, "kind": "went_silent",
              "silent_s": 1800, "typical_s": 9, "level": "event"}

    n.on_audit(dict(silent))
    assert len(n._pending) + len(n._urgent) == 1, "the first alert goes out"

    clock.t += 3600                                   # an hour later, same device, same story
    n.on_audit(dict(silent))
    assert len(n._pending) + len(n._urgent) == 1, "the repeat within the window is kept off the phone"

    n.on_audit({**silent, "ieee": "0x0000000000000002"})  # a different device is its own story
    n.on_audit({**silent, "kind": "sequence_jump"})   # a different kind of worry too
    assert len(n._pending) + len(n._urgent) == 3

    clock.t += 6 * 3600 + 1                           # the window passes — the reminder is fair
    n.on_audit(dict(silent))
    assert len(n._pending) + len(n._urgent) == 4
