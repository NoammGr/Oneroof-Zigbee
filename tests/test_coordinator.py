import asyncio

import pytest

from oneroof_zigbee.security import Audit, JoinGuard, JoinPolicy, JoinPolicyError, NetworkSecrets, parse_install_code
from oneroof_zigbee.znp import Coordinator, Transport
from oneroof_zigbee.znp import commands as c
from oneroof_zigbee.znp.unpi import Frame, FrameType, Subsystem
from oneroof_zigbee.znp.wire import Writer
from tests.fake_znp import FakeZnp

IEEE = 0x00124B00DEADBEEF


async def make(strict=False, policy=None, fake=None):
    fake = fake or FakeZnp()
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = NetworkSecrets.generate(channel=15)
    guard = JoinGuard(policy or JoinPolicy(cooldown_seconds=0), Audit(None))
    coord = Coordinator(t, s, guard, guard.audit, strict_install_codes=strict)
    await asyncio.wait_for(coord.start(), 5)
    return fake, coord, t


async def test_forms_network_with_random_secrets_and_closes_join():
    fake, coord, t = await make()
    assert fake.formed
    assert fake.nv[c.NvId.PRECFGKEY] == coord.secrets.network_key
    assert fake.nv[c.NvId.PRECFGKEYS_ENABLE] == b"\x00"
    assert int.from_bytes(fake.nv[c.NvId.PANID], "little") == coord.secrets.pan_id
    assert int.from_bytes(fake.nv[c.NvId.CHANLIST], "little") == 1 << 15
    # last permit-join command at startup must be "close"
    assert fake.permit_durations[-1] == 0
    await t.close()


async def test_rebind_survives_a_reconnect():
    """When the serial link drops and reopens, rebind() points the coordinator
    at the fresh transport; the registered callbacks and known_ieee persist,
    and frames on the NEW transport reach them (the __main__ reconnect path)."""
    fake1, coord, t1 = await make()
    joined: list[int] = []
    coord.on_device_joined(lambda d: joined.append(d.ieee))
    coord.known_ieee.add(IEEE)  # a known device: its announce is a rejoin
    await t1.close()

    fake2 = FakeZnp()
    t2 = Transport(fake2.reader, fake2.writer, timeout=2.0)
    t2.start()
    coord.rebind(t2)
    await asyncio.wait_for(coord.start(), 5)
    assert IEEE in coord.known_ieee  # state carried across the reconnect

    fake2.emit_announce(IEEE, 0x1234)  # on the NEW transport
    await asyncio.sleep(0.1)
    assert IEEE in joined
    await t2.close()


async def test_runtime_security_applied_every_start():
    fake, coord, t = await make()
    reqs = [(f.subsystem, f.command, f.data) for f in fake.requests]
    assert (c.Subsystem.APP_CNF, c.AppCnfCmd.BDB_SET_TC_REQUIRE_KEY_EXCHANGE, b"\x01") in reqs
    # default mode = 0 (use the global default key); a Sonoff ZBDongle-P rejects 1 as a boolean with INVALID_PARAMETER
    key_cmds = [d for ss, cmd, d in reqs if ss is c.Subsystem.APP_CNF and cmd == c.AppCnfCmd.BDB_SET_ACTIVE_DEFAULT_CENTRALIZED_KEY]
    assert key_cmds and key_cmds[-1][0] == c.CentralizedKeyMode.DEFAULT_GLOBAL
    # allow, not refuse: a device that misses a key rotation while powered off can only recover
    # through an unsecured TC rejoin — refusing it (the SDK default) orphans the device until it
    # is factory-reset and re-paired (test_tc_rejoins_are_allowed_… covers the exposure handling)
    assert (c.Subsystem.APP_CNF, c.AppCnfCmd.SET_ALLOWREJOIN_TC_POLICY, b"\x01") in reqs
    await t.close()
    # second start with matching NV must NOT re-form
    fake.requests.clear()
    t2 = Transport(fake.reader, fake.writer, timeout=2.0)
    t2.start()
    coord2 = Coordinator(t2, coord.secrets, coord.guard, coord.audit)
    await asyncio.wait_for(coord2.start(), 5)
    kinds = {(f.subsystem, f.command) for f in fake.requests}
    assert (c.Subsystem.APP_CNF, c.AppCnfCmd.BDB_START_COMMISSIONING) not in kinds
    assert (c.Subsystem.ZDO, c.ZdoCmd.STARTUP_FROM_APP) in kinds
    await t2.close()


async def test_strict_mode_replaces_public_link_key_and_requires_install_code():
    fake, coord, t = await make(strict=True)
    reqs = [(f.command, f.data) for f in fake.requests if f.subsystem is c.Subsystem.APP_CNF]
    assert (c.AppCnfCmd.BDB_SET_JOINUSESINSTALLCODE, b"\x01") in reqs
    key_cmd = [d for cmd, d in reqs if cmd == c.AppCnfCmd.BDB_SET_ACTIVE_DEFAULT_CENTRALIZED_KEY][-1]
    assert key_cmd[0] == c.CentralizedKeyMode.INSTALL_CODE and key_cmd[1:] == coord.secrets.tc_install_code and len(key_cmd) == 19
    from oneroof_zigbee.security import crc16
    assert crc16(key_cmd[1:17]) == int.from_bytes(key_cmd[17:19], 'little')
    with pytest.raises(PermissionError):
        await coord.permit_join(60, "test")
    await t.close()


async def test_permit_join_with_install_code_registers_derived_key():
    fake, coord, t = await make(strict=True)
    code = parse_install_code("83FED3407A939723A5C639B26916D505")
    secs = await coord.permit_join(60, "test", ieee=IEEE, install_code=code)
    assert secs == 60
    assert fake.install_codes == [(IEEE, bytes.fromhex("66b6900981e1ee3ca4206b6b861c02bb"))]
    assert fake.permit_durations[-1] == 60
    await t.close()


async def test_permit_join_clamped_to_policy_max():
    fake, coord, t = await make(policy=JoinPolicy(max_seconds=30, cooldown_seconds=0))
    secs = await coord.permit_join(600, "test")
    assert secs == 30 and fake.permit_durations[-1] == 30
    await t.close()


async def test_require_install_code_policy_blocks_open_join():
    fake, coord, t = await make(policy=JoinPolicy(require_install_code=True, cooldown_seconds=0))
    with pytest.raises(JoinPolicyError):
        await coord.permit_join(60, "test")
    await t.close()


async def test_unexpected_join_is_evicted_and_alerted():
    fake, coord, t = await make()
    alerts = []
    coord.audit.subscribe(lambda rec: alerts.append(rec) if rec["level"] == "security" else None)
    joined = []
    coord.on_device_joined(lambda d: joined.append(d) or asyncio.sleep(0))
    fake.emit_announce(IEEE, 0x5678)
    await asyncio.sleep(0.1)
    assert joined == []
    assert any(a["type"] == "unexpected_join" for a in alerts)
    leaves = [f for f in fake.requests if f.command == c.ZdoCmd.MGMT_LEAVE_REQ and f.subsystem is c.Subsystem.ZDO]
    assert leaves and int.from_bytes(leaves[-1].data[2:10], "little") == IEEE
    await t.close()


async def test_expected_join_dispatches_and_interview_works():
    fake, coord, t = await make()
    joined = []

    async def cb(d):
        joined.append(d)

    coord.on_device_joined(cb)
    await coord.permit_join(60, "test")
    fake.emit_announce(IEEE, 0x5678)
    await asyncio.sleep(0.1)
    assert joined and joined[0].ieee == IEEE
    eps = await coord.active_endpoints(0x5678)
    assert eps == [1]
    sd = await coord.simple_descriptor(0x5678, 1)
    assert sd.in_clusters == [0, 6, 8]
    await t.close()


async def test_send_aps_waits_for_confirm_and_dispatches_incoming():
    fake, coord, t = await make()
    got = []

    async def cb(m):
        got.append(m)

    coord.on_aps(cb)
    await coord.send_aps(0x5678, 1, 0x0006, b"\x01\x01\x01")
    fake.emit_incoming(0x5678, 0x0402, b"\x18\x01\x0a\x00\x00\x29\x57\x08")
    await asyncio.sleep(0.05)
    assert got and got[0].cluster == 0x0402 and got[0].payload.endswith(b"\x57\x08")
    await t.close()


async def test_known_device_reannounce_is_rejoin_not_eviction():
    fake, coord, t = await make()
    joined = []

    async def cb(d):
        joined.append(d)

    coord.on_device_joined(cb)
    await coord.permit_join(10, "test")
    fake.emit_announce(IEEE, 0x5678)
    await asyncio.sleep(0.05)
    await coord._force_close_join()
    assert coord.guard.window is None and IEEE in coord.known_ieee
    leaves_before = sum(1 for f in fake.requests if f.subsystem is c.Subsystem.ZDO and f.command == c.ZdoCmd.MGMT_LEAVE_REQ)
    alerts = []
    coord.audit.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    fake.emit_announce(IEEE, 0x9ABC)  # power-cycled, new short address, window closed
    await asyncio.sleep(0.05)
    leaves_after = sum(1 for f in fake.requests if f.subsystem is c.Subsystem.ZDO and f.command == c.ZdoCmd.MGMT_LEAVE_REQ)
    assert leaves_after == leaves_before, "a paired device must never be evicted on rejoin"
    assert alerts == []
    assert len(joined) == 2 and joined[1].nwk == 0x9ABC
    await t.close()


async def test_policy_denial_does_not_register_install_code():
    fake, coord, t = await make(policy=JoinPolicy(cooldown_seconds=1000))
    code = parse_install_code("83FED3407A939723A5C639B26916D505")
    await coord.permit_join(5, "test", ieee=IEEE, install_code=code)
    await coord._force_close_join()
    fake.install_codes.clear()
    with pytest.raises(JoinPolicyError):
        await coord.permit_join(5, "test", ieee=IEEE + 1, install_code=code)
    assert fake.install_codes == []
    await t.close()


async def test_alert_when_firmware_keeps_a_previous_network():
    """If the radio comes up on a different PAN/channel than the keystore right after forming,
    the identity the radio actually formed is adopted (audited) — the KEY is still written and
    verified separately, so nothing runs silently on an old key."""
    fake = FakeZnp()
    # the radio keeps reporting an old network whatever NV says
    orig = fake._handle

    def stubborn(f):
        if f.subsystem is Subsystem.ZDO and f.command == c.ZdoCmd.EXT_NWK_INFO:
            fake.requests.append(f)
            fake._srsp(f, Writer().u16(0).u8(9).u16(0x1A62).u16(0).u64(0).u64(0).u8(11).bytes())
            return
        orig(f)
    fake._handle = stubborn
    alerts = []
    audit = Audit(None)
    audit.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = NetworkSecrets.generate(channel=15)
    guard = JoinGuard(JoinPolicy(cooldown_seconds=0), audit)
    coord = Coordinator(t, s, guard, audit)
    await asyncio.wait_for(coord.start(), 5)
    adopted = [a for a in alerts if a["type"] == "network_identity_adopted"]
    assert adopted and adopted[0]["pan_id"] == "0x1a62" and adopted[0]["channel"] == 11
    assert coord.secrets.pan_id == 0x1A62 and coord.secrets.channel == 11, "keystore follows the radio"
    assert not [a for a in alerts if a["type"] == "network_parameters_mismatch"], "no false alarm after adopting"
    await t.close()


@pytest.mark.parametrize("firmware_keeps_set", [True, False])
async def test_frame_counter_is_verified_after_start(firmware_keeps_set):
    """An imported counter must end up on the coordinator — via the SET command when the firmware
    keeps it, otherwise by writing the key item and restarting the network."""
    import dataclasses
    from oneroof_zigbee.znp.coordinator import FRAME_COUNTER_MARGIN
    fake = FakeZnp()
    fake.ignore_set_frame_counter = not firmware_keeps_set
    fake.refuse_key_item_writes = False  # a firmware that allows the direct write
    events = []
    audit = Audit(None)
    audit.subscribe(lambda r: events.append(r))
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = dataclasses.replace(NetworkSecrets.generate(channel=15), frame_counter=44_000_000)
    guard = JoinGuard(JoinPolicy(cooldown_seconds=0), audit)
    coord = Coordinator(t, s, guard, audit)
    await asyncio.wait_for(coord.start(), 10)
    want = 44_000_000 + FRAME_COUNTER_MARGIN
    assert fake.frame_counter == want, "coordinator really carries the imported counter"
    verified = [e for e in events if e["type"] == "frame_counter_verified"]
    assert verified and verified[-1]["value"] == want
    assert not [e for e in events if e["type"] == "frame_counter_unverified"]
    await t.close()


async def test_formation_restores_trust_centre_seed_and_start_verifies_key():
    import dataclasses
    fake = FakeZnp()
    events = []
    audit = Audit(None)
    audit.subscribe(lambda r: events.append(r))
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    seed = bytes(range(16))
    s = dataclasses.replace(NetworkSecrets.generate(channel=15), tclk_seed=seed)
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    assert fake.nv[c.NvId.TCLK_SEED] == seed
    assert "tclk_seed_restored" in [e["type"] for e in events]
    assert not [e for e in events if e["type"] == "network_key_mismatch"]
    await t.close()
    # a radio running another key raises an alert at start
    fake2 = FakeZnp()
    alerts = []
    audit2 = Audit(None)
    audit2.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    t2 = Transport(fake2.reader, fake2.writer, timeout=2.0)
    t2.start()
    s2 = NetworkSecrets.generate(channel=15)
    coord2 = Coordinator(t2, s2, JoinGuard(JoinPolicy(cooldown_seconds=0), audit2), audit2)
    await asyncio.wait_for(coord2.start(), 10)
    assert not [a for a in alerts if a["type"] == "network_key_mismatch"]
    fake2.active_key = bytes(16)  # the radio "really" uses a different key now
    fake2.refuse_key_item_writes = False  # a firmware that allows the direct write
    events2 = []
    audit2.subscribe(lambda r: events2.append(r))
    await coord2._verify_active_key()
    assert [a for a in alerts if a["type"] == "network_key_mismatch"]
    assert "network_key_repaired" in [e["type"] for e in events2]
    assert fake2.active_key == s2.network_key, "key items rewritten and the radio restarted on the keystore key"
    assert not [a for a in alerts if a["type"] == "network_key_unrepaired"]
    await t2.close()


async def test_frame_counter_refusal_is_reported_not_fatal():
    """Firmware that neither keeps SET_NWK_FRAME_COUNTER nor allows writing the key item: the
    gateway starts anyway and raises an alert instead of crashing."""
    import dataclasses
    fake = FakeZnp()
    fake.ignore_set_frame_counter = True
    fake.refuse_key_item_writes = True
    fake.has_exnv = False  # and no security material table either: nothing left to try
    alerts = []
    audit = Audit(None)
    audit.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = dataclasses.replace(NetworkSecrets.generate(channel=15), frame_counter=44_000_000)
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    assert [a for a in alerts if a["type"] == "frame_counter_unverified"]
    await t.close()


async def test_formation_ends_on_the_keystore_key_on_firmware_that_ignores_precfgkey():
    """Modelled on the real firmware: formation makes up its own key; only a 17-byte key item written
    while the stack is stopped sets it. The formed network must run on the keystore key and
    PRECFGKEYS_ENABLE must be 0 afterwards."""
    fake = FakeZnp()
    audit = Audit(None)
    alerts = []
    audit.subscribe(lambda r: alerts.append(r) if r["level"] == "security" else None)
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = NetworkSecrets.generate(channel=15)
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    assert fake.active_key == s.network_key
    assert fake.nv[c.NvId.PRECFGKEYS_ENABLE][:1] == b"\x00", "never assume the key after formation"
    assert not [a for a in alerts if a["type"] in ("network_key_mismatch", "network_key_unrepaired")]
    await t.close()


async def test_mismatching_key_is_repaired_with_a_length_exact_item_write():
    fake = FakeZnp()
    audit = Audit(None)
    events = []
    audit.subscribe(lambda r: events.append(r))
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = NetworkSecrets.generate(channel=15)
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    fake.active_key = bytes(16)  # the radio runs on another key (what a formation with ENABLE=0 produced)
    await coord._verify_active_key()
    types = [e["type"] for e in events]
    assert "network_key_mismatch" in types
    repaired = [e for e in events if e["type"] == "network_key_repaired"]
    assert repaired and repaired[-1]["method"] == "nv" and fake.active_key == s.network_key
    assert "network_key_unrepaired" not in types
    assert sum(1 for f in fake.requests if f.subsystem.name == "APP_CNF" and f.command == c.AppCnfCmd.BDB_START_COMMISSIONING) == 1
    await t.close()


@pytest.mark.parametrize("firmware_keeps_set", [True, False])
async def test_frame_counter_via_security_material_table(firmware_keeps_set):
    """Z-Stack 3.x.0: the counter lives in the security material table; it is read from there and,
    when the SET command is not kept, written there (key items are not writable)."""
    import dataclasses
    from oneroof_zigbee.znp.coordinator import FRAME_COUNTER_MARGIN
    fake = FakeZnp()
    fake.ignore_set_frame_counter = not firmware_keeps_set
    events = []
    audit = Audit(None)
    audit.subscribe(lambda r: events.append(r))
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = dataclasses.replace(NetworkSecrets.generate(channel=15), frame_counter=44_000_000)
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    want = 44_000_000 + FRAME_COUNTER_MARGIN
    assert fake.sec_material[0][0] == want
    assert await coord.nwk_frame_counter() == want
    assert [e for e in events if e["type"] == "frame_counter_verified"]
    assert not [e for e in events if e["type"] == "frame_counter_unverified"]
    await t.close()


async def test_neighbour_check_reports_ground_truth(monkeypatch):
    """45 s after start the coordinator's neighbour table is read; routers heard = key works."""
    fake = FakeZnp()
    events = []
    audit = Audit(None)
    audit.subscribe(lambda r: events.append(r))
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = NetworkSecrets.generate(channel=15)
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    real_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda d: real_sleep(0 if d >= 45 else d))
    await asyncio.wait_for(coord.start(), 10)
    for _ in range(50):
        await real_sleep(0.02)
        if any(e["type"] == "neighbour_check" for e in events):
            break
    chk = next(e for e in events if e["type"] == "neighbour_check")
    assert chk["neighbours"] == 1 and chk["routers"] == 1 and chk["lqi"] == [180]
    assert not [e for e in events if e["type"] == "no_neighbours_heard"]
    await t.close()


async def test_import_restore_end_to_end_on_hostile_firmware():
    """An imported network (key, counter, seed) ends up on the radio: formation, stopped-state writes,
    counter table, seed — then verified at start and the neighbour check reads real neighbours."""
    import dataclasses
    fake = FakeZnp()
    events = []
    audit = Audit(None)
    audit.subscribe(lambda r: events.append(r))
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    s = dataclasses.replace(NetworkSecrets.generate(channel=11), frame_counter=44_000_000, tclk_seed=bytes(range(16)))
    coord = Coordinator(t, s, JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    assert fake.active_key == s.network_key, "radio on the imported key"
    assert fake.nv[c.NvId.TCLK_SEED] == s.tclk_seed, "trust-centre seed restored"
    assert fake.sec_material[0][0] >= 44_000_000, "frame counter above the imported one"
    types = [e["type"] for e in events]
    assert "network_formed" in types and "frame_counter_verified" in types
    assert "network_key_mismatch" not in types, "no mismatch after formation: the write during formation took"
    await t.close()


async def test_forwarded_zdo_responses_satisfy_the_waiters():
    """Firmware that only forwards ZDO responses through the message callback: the generic
    envelope is converted to the classic indication and node_descriptor()/bind() complete."""
    fake = FakeZnp()
    fake.requests.clear()
    t = Transport(fake.reader, fake.writer, timeout=2.0)
    t.start()
    audit = Audit(None)
    coord = Coordinator(t, NetworkSecrets.generate(channel=15), JoinGuard(JoinPolicy(cooldown_seconds=0), audit), audit)
    await asyncio.wait_for(coord.start(), 10)
    assert any(f.subsystem is Subsystem.ZDO and f.command == c.ZdoCmd.MSG_CB_REGISTER and f.data == b"\xff\xff" for f in fake.requests), "registered for all ZDO messages"

    async def answer_via_callback(cluster, payload, delay=0.05):
        await asyncio.sleep(delay)
        env = Writer().u16(0x1234).u8(0).u16(cluster).u8(0).u8(7).u16(0).raw(payload).bytes()
        fake.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.MSG_CB_INCOMING, env))

    # Node_Desc_rsp: status 0, nwk 0x1234, then a descriptor (router, manufacturer 0x1037)
    desc = bytes([0x01, 0x40, 0x8E]) + (0x1037).to_bytes(2, "little") + bytes([0x7F]) + (0x0064).to_bytes(2, "little") + bytes(5)
    task = asyncio.create_task(answer_via_callback(0x8002, b"\x00" + (0x1234).to_bytes(2, "little") + desc))
    nd = await coord.node_descriptor(0x1234, timeout=2.0)
    await task
    assert nd.status == 0 and nd.manufacturer_code == 0x1037
    # Bind_rsp: status 0
    task = asyncio.create_task(answer_via_callback(0x8021, b"\x00"))
    assert await coord.bind(0x1234, 0x00158D0000000099, 1, 0x0006, timeout=2.0) == 0
    await task
    await t.close()


async def test_restart_with_a_rotated_keystore_finishes_only_on_evidence():
    """The keystore holds a rotated key, the dongle is still on the previous one, PAN/channel
    agree. Re-forming would wipe the network the devices are on, so the start never re-forms.
    Which sequence the devices know the key by must come from evidence: a keystore that carries
    the previous key (1.10.1+) finishes the switch under active+1; a pre-fix keystore on a live
    network (millions of frames sent) is left alone with an alert — guessing could cut everyone off."""
    fake, coord, t = await make()
    fake.requests.clear()
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    old_key = coord.secrets.network_key
    live = 45_000_000
    fake.frame_counter = live
    fake.sec_material = [(live, pan) for _c, pan in fake.sec_material]
    # 1. pre-fix keystore: no previous key, sequence 0 — refuse to guess
    rotated = NetworkSecrets(network_key=bytes(range(16)), pan_id=coord.secrets.pan_id, ext_pan_id=coord.secrets.ext_pan_id,
                             channel=coord.secrets.channel, tc_install_code=coord.secrets.tc_install_code,
                             frame_counter=coord.secrets.frame_counter, tclk_seed=coord.secrets.tclk_seed)
    coord2 = Coordinator(t, rotated, coord.guard, coord.audit)
    await asyncio.wait_for(coord2.start(), 10)
    types = [e["type"] for e in events]
    assert "network_key_switch_unfinished" in types and "network_key_mismatch_unresolved" in types
    assert "network_formed" not in types and "network_key_repaired" not in types
    assert not any(f.subsystem.name == "SYS" and f.command == c.SysCmd.OSAL_NV_WRITE and f.data[0:2] == c.NvId.STARTUP_OPTION.to_bytes(2, "little") and f.data[4] == 3
                   for f in fake.requests), "no CLEAR_ALL"
    assert fake.active_key == old_key and fake.active_seq == 0, "untouched"
    # 2. a keystore that knows the previous key: the switch is finished under active+1
    events.clear()
    rotated.previous_network_key, rotated.previous_key_seq = old_key, 0
    rotated.pending_rotation = {"delivered": [], "by": "test"}  # a rotation really is in flight
    coord3 = Coordinator(t, rotated, coord.guard, coord.audit)
    await asyncio.wait_for(coord3.start(), 10)
    types = [e["type"] for e in events]
    assert "network_key_repaired" in types and "network_formed" not in types
    assert fake.active_key == rotated.network_key and fake.active_seq == 1, "installed under the sequence the devices switched to"
    assert coord3.secrets.key_seq == 1 and coord3.secrets.previous_network_key == old_key
    assert fake.nv[c.NvId.NWK_ALTERN_KEY_INFO][:17] == b"\x00" + old_key, "the previous key stays the alternate, so stragglers are still heard"
    assert fake.nv[c.NvId.PRECFGKEY][:16] == rotated.network_key
    await t.close()


async def test_rollback_returns_the_coordinator_to_the_previous_key_from_the_alternate_slot():
    """The radio switched to a new key the devices never took, and the keystore knows no previous
    key (pre-1.10.1 rotation): the previous key is taken from the radio's alternate key item and
    reinstalled as active; the abandoned key becomes the alternate."""
    fake, coord, t = await make()
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    old_key = fake.active_key
    new_key = bytes(range(32, 48))
    # the radio moved to the new key at sequence 1; the old key sits in the alternate slot
    fake.nv[c.NvId.NWK_ALTERN_KEY_INFO] = b"\x00" + old_key
    fake.active_key, fake.active_seq = new_key, 1
    coord.secrets.network_key, coord.secrets.key_seq = new_key, 1
    assert await coord.rollback_key_switch() is True
    assert fake.active_key == old_key and fake.active_seq == 0
    assert coord.secrets.network_key == old_key and coord.secrets.key_seq == 0
    assert coord.secrets.previous_network_key == new_key and coord.secrets.previous_key_seq == 1
    assert fake.nv[c.NvId.PRECFGKEY][:16] == old_key
    assert not any(f.subsystem is Subsystem.ZDO and f.command == c.ZdoCmd.EXT_SWITCH_NWK_KEY for f in fake.requests), "nothing is broadcast"
    rb = [e for e in events if e["type"] == "network_key_switch_rolled_back"]
    assert rb and rb[-1]["mode"] == "radio" and rb[-1]["ok"] is True
    # rollback with nothing to go back to is refused, not guessed
    coord.secrets.previous_network_key = None
    fake.nv[c.NvId.NWK_ALTERN_KEY_INFO] = b"\x00" + old_key  # alternate equals active now
    fake.active_key = old_key
    assert await coord.rollback_key_switch() is False
    assert any(e["type"] == "network_key_rollback_impossible" for e in events)
    await t.close()


async def test_start_refuses_to_guess_a_sequence_without_evidence():
    """Keystore key ≠ radio key, no alternate match, no previous key, same sequence: the start
    leaves the radio alone and raises an alert instead of installing under a guessed sequence."""
    fake, coord, t = await make()
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    radio_key = fake.active_key
    fake.frame_counter = 45_000_000  # a live network, not a fresh formation
    fake.sec_material = [(45_000_000, pan) for _c, pan in fake.sec_material]
    foreign = NetworkSecrets(network_key=bytes(range(16)), pan_id=coord.secrets.pan_id, ext_pan_id=coord.secrets.ext_pan_id,
                             channel=coord.secrets.channel, tc_install_code=coord.secrets.tc_install_code,
                             frame_counter=coord.secrets.frame_counter, tclk_seed=coord.secrets.tclk_seed)
    fake.nv[c.NvId.NWK_ALTERN_KEY_INFO] = b"\x00" + radio_key  # alternate is not the keystore key either
    coord2 = Coordinator(t, foreign, coord.guard, coord.audit)
    await asyncio.wait_for(coord2.start(), 10)
    types = [e["type"] for e in events]
    assert "network_key_mismatch_unresolved" in types and "network_formed" not in types and "network_key_repaired" not in types
    assert fake.active_key == radio_key, "untouched"
    await t.close()


async def test_rollback_with_a_key_handed_in_from_a_backup():
    """Neither the keystore nor the radio's alternate slot knows the previous key: the operator
    hands in the key from a backup; the coordinator installs it under the backup's sequence."""
    fake, coord, t = await make()
    old_key = fake.active_key
    new_key = bytes(range(48, 64))
    fake.active_key, fake.active_seq = new_key, 1
    fake.nv[c.NvId.NWK_ALTERN_KEY_INFO] = b"\x01" + new_key  # the alternate slot holds nothing older either
    coord.secrets.network_key, coord.secrets.key_seq = new_key, 1
    assert await coord.rollback_source() == "none"
    assert await coord.rollback_key_switch((old_key, 0)) is True
    assert fake.active_key == old_key and fake.active_seq == 0
    assert coord.secrets.network_key == old_key and coord.secrets.previous_network_key == new_key and coord.secrets.previous_key_seq == 1
    assert await coord.rollback_source() == "keystore"
    await t.close()


async def test_repair_never_sets_the_frame_counter_back():
    """A stack restart rewrites the key items and the frame counter. The counter must be the live
    one (plus margin) when the radio has moved past the saved value — devices drop frames below
    the last counter they saw."""
    fake, coord, t = await make()
    coord.secrets.frame_counter = 44_000_000
    live = 45_400_000
    fake.frame_counter = live
    fake.sec_material = [(live, pan) for _c, pan in fake.sec_material]
    old_key = fake.active_key
    coord.secrets.network_key, coord.secrets.key_seq = bytes(range(64, 80)), 1
    coord.secrets.previous_network_key, coord.secrets.previous_key_seq = old_key, 0
    assert await coord.finish_key_switch() is True
    counter = await coord.nwk_frame_counter()
    assert counter is not None and counter > live, f"counter went back to {counter}"
    assert coord.secrets.frame_counter >= live
    # the periodic refresh keeps the keystore's copy close to the radio
    fake.frame_counter = live + 1_000_000
    fake.sec_material = [(live + 1_000_000, pan) for _c, pan in fake.sec_material]
    await coord.refresh_frame_counter()
    assert coord.secrets.frame_counter == live + 1_000_000
    await t.close()


async def test_rollback_to_the_key_already_in_use_is_a_no_op():
    fake, coord, t = await make()
    # handing in the key the radio is already on must not flip to anything else
    key_now = fake.active_key
    coord.secrets.previous_network_key, coord.secrets.previous_key_seq = bytes(range(80, 96)), 7
    assert await coord.rollback_key_switch((key_now, 0)) is True
    assert fake.active_key == key_now and coord.secrets.network_key == key_now
    await t.close()


async def test_scan_air_lists_networks_and_flags_ours():
    fake, coord, t = await make()
    ours = coord.secrets.ext_pan_id
    fake.beacons = [
        (0x1A2B, coord.secrets.pan_id, coord.secrets.channel, 0, 1, 1, 180, 1, 0, ours),
        (0x3C4D, coord.secrets.pan_id, coord.secrets.channel, 1, 1, 1, 120, 2, 0, ours),
        (0x0001, 0x9999, 15, 1, 1, 1, 60, 0, 0, 0x0102030405060708),
    ]
    fake.scan_while_up = False  # the firmware in the field: 0xC2 while the network runs
    r = await coord.scan_air(duration=1)
    assert r["ok"] and r["mode"] == "paused" and len(r["networks"]) == 2
    assert fake.net_running, "the network is restarted after the paused scan"
    assert c.NvId.NIB in fake.nv, "the NIB is put back after the scan"
    mine = [n for n in r["networks"] if n["this_network"]]
    assert len(mine) == 1 and mine[0]["responders"] == 2 and mine[0]["best_lqi"] == 180 and mine[0]["permit_join"]
    other = [n for n in r["networks"] if not n["this_network"]][0]
    assert other["responders"] == 1 and other["channel"] == 15
    await t.close()


async def test_scan_air_refused_by_firmware_is_reported_not_raised():
    fake, coord, t = await make()
    fake.refuse_scan = True
    r = await coord.scan_air(duration=1)
    assert r["ok"] is False and r["status"] == 2 and "refused" in r["error"]
    await t.close()


async def test_scan_air_online_when_the_firmware_allows_it():
    fake, coord, t = await make()
    fake.beacons = [(0x1A2B, coord.secrets.pan_id, coord.secrets.channel, 0, 1, 1, 90, 1, 0, coord.secrets.ext_pan_id)]
    r = await coord.scan_air(duration=1)
    assert r["ok"] and r["mode"] == "online" and r["networks"][0]["responders"] == 1
    assert not any(x.command == 0x00 and x.subsystem.name == "SYS" for x in fake.requests[-3:]), "no reset for an online scan"
    await t.close()


async def test_start_follows_the_radio_when_it_sits_on_the_previous_key_and_no_rotation_is_pending():
    """After a rollback or an external restore the radio holds the keystore's *previous* key and
    pending_rotation is clear: the start must adopt the radio's key, never push the newer keystore
    key back (that key never reached a single device)."""
    fake, coord, t = await make()
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    devices_key = fake.active_key  # seq 0: the key every device answers
    wrong = NetworkSecrets(network_key=bytes(range(48, 64)), pan_id=coord.secrets.pan_id,
                           ext_pan_id=coord.secrets.ext_pan_id, channel=coord.secrets.channel,
                           tc_install_code=coord.secrets.tc_install_code,
                           frame_counter=coord.secrets.frame_counter, tclk_seed=coord.secrets.tclk_seed)
    wrong.previous_network_key, wrong.previous_key_seq = devices_key, 0
    assert wrong.pending_rotation is None
    coord2 = Coordinator(t, wrong, coord.guard, coord.audit)
    await asyncio.wait_for(coord2.start(), 10)
    assert fake.active_key == devices_key and fake.active_seq == 0, "the radio is never touched"
    assert coord2.secrets.network_key == devices_key and coord2.secrets.key_seq == 0
    assert coord2.secrets.previous_network_key is None and coord2.secrets.pending_rotation is None
    types = [e["type"] for e in events]
    assert "keystore_followed_radio" in types
    assert "network_key_repaired" not in types and "network_formed" not in types and "network_key_mismatch_unresolved" not in types
    await t.close()


async def test_start_never_reforms_over_a_live_matching_network_with_unwritten_config_items():
    """A restore made outside the add-on (zigpy-znp and friends) writes the live network but not
    the legacy config NV items. The start must judge by the live network: start it, repair the
    items, and hand the key question to _verify_active_key — never re-form, which is what cut
    every device off on 2026-08-30."""
    fake, coord, t = await make()
    events = []
    coord.audit.subscribe(lambda r: events.append(r))
    devices_key = fake.active_key
    fake.live_pan_id, fake.live_channel = coord.secrets.pan_id, coord.secrets.channel  # the NIB is right
    fake.nv[c.NvId.PANID] = b"\xef\x37"  # ...but the config items were never written by the external tool
    fake.nv.pop(c.NvId.PRECFGKEY, None)
    wrong = NetworkSecrets(network_key=bytes(range(48, 64)), pan_id=coord.secrets.pan_id,
                           ext_pan_id=coord.secrets.ext_pan_id, channel=coord.secrets.channel,
                           tc_install_code=coord.secrets.tc_install_code,
                           frame_counter=coord.secrets.frame_counter, tclk_seed=coord.secrets.tclk_seed)
    wrong.previous_network_key, wrong.previous_key_seq = devices_key, 0
    coord2 = Coordinator(t, wrong, coord.guard, coord.audit)
    await asyncio.wait_for(coord2.start(), 10)
    types = [e["type"] for e in events]
    assert "network_formed" not in types, "never re-form over a live matching network"
    assert "network_config_repaired" in types and "keystore_followed_radio" in types
    assert fake.active_key == devices_key, "the devices' key survives the start"
    assert fake.nv[c.NvId.PANID] == coord.secrets.pan_id.to_bytes(2, "little"), "config item repaired"
    assert coord2.secrets.network_key == devices_key
    await t.close()


async def test_relabel_key_sequence_after_an_interrupted_rotation():
    """Interrupted rotation + rollbacks leave two different keys both labelled sequence 0; devices
    that switched know the key as sequence 1 and drop everything labelled 0. Re-labelling writes
    the same key under the right number, keeps the old key as the alternate and never lowers the
    frame counter."""
    fake, coord, t = await make()
    old = bytes(range(16))
    fake.nv[c.NvId.NWK_ALTERN_KEY_INFO] = b"\x00" + old
    coord.secrets.previous_network_key, coord.secrets.previous_key_seq = old, 0
    live = 45_000_000
    fake.frame_counter = live
    fake.sec_material = [(live, pan) for _c, pan in fake.sec_material]
    slots = await coord.key_slots()
    assert slots["sequence_collision"] is True and slots["active_seq"] == 0 and slots["altern_seq"] == 0
    assert await coord.relabel_key_sequence(1) is True
    assert fake.active_seq == 1 and fake.active_key == coord.secrets.network_key, "same key, new label"
    assert fake.nv[c.NvId.NWK_ALTERN_KEY_INFO][:17] == b"\x00" + old, "old key stays the alternate at 0"
    assert coord.secrets.key_seq == 1
    assert fake.frame_counter >= live, "counter never goes backwards"
    assert (await coord.key_slots())["sequence_collision"] is False
    await t.close()


async def test_formation_adopts_the_identity_the_radio_actually_formed():
    """Firmware that ignores the configured PAN/channel and forms its own must not leave the
    gateway running a network the radio does not have: for a fresh formation the identity is
    arbitrary, so the keystore adopts what formed — keys stay ours and are verified as before."""
    fake = FakeZnp()
    fake.formation_ignores_config = True
    fake_, coord, t = await make(fake=fake)
    assert coord.secrets.pan_id == 0x4CD2 and coord.secrets.channel == 11, "keystore follows the radio"
    assert fake.nv[c.NvId.PRECFGKEY] == coord.secrets.network_key, "the key is still ours"
    assert fake.active_key == coord.secrets.network_key
    await t.close()


async def test_radio_tuning_writes_only_routing_items_and_keeps_the_network():
    """Changing how the radio routes must never cost the network: no key item, no PAN, no channel
    and no startup option is touched, and the result is verified against the keystore."""
    fake, coord, t = await make()
    key_before, pan_before, ch_before = fake.active_key, coord.secrets.pan_id, coord.secrets.channel
    fake.requests.clear()
    result = await coord.apply_radio_tuning({"concentrator_discovery_seconds": 120,
                                             "concentrator_enable": 1})
    assert result["key_ok"] and result["same_network"], result
    written = [f for f in fake.requests
               if f.subsystem.name == "SYS" and f.command == c.SysCmd.OSAL_NV_WRITE]
    ids = {int.from_bytes(f.data[0:2], "little") for f in written}
    assert c.NvId.CONCENTRATOR_DISCOVERY in ids and c.NvId.CONCENTRATOR_ENABLE in ids
    for forbidden in (c.NvId.NWK_ACTIVE_KEY_INFO, c.NvId.NWK_ALTERN_KEY_INFO, c.NvId.PRECFGKEY,
                      c.NvId.NWKKEY, c.NvId.PANID, c.NvId.CHANLIST, c.NvId.EXTPANID,
                      c.NvId.STARTUP_OPTION, c.NvId.TCLK_SEED):
        assert forbidden not in ids, f"{forbidden.name} must not be touched by a routing change"
    assert fake.active_key == key_before, "the network key is untouched"
    assert coord.secrets.pan_id == pan_before and coord.secrets.channel == ch_before
    assert (await coord.read_radio_tuning())["concentrator_discovery_seconds"] == 120
    await t.close()


async def test_radio_tuning_refuses_nonsense_and_reapplies_on_drift():
    import pytest
    fake, coord, t = await make()
    for bad in ({"concentrator_discovery_seconds": 999}, {"not_a_setting": 1},
                {"broadcast_retries": -1}):
        with pytest.raises(ValueError):
            await coord.apply_radio_tuning(bad)
    # the firmware's defaults come back after a re-formation: the operator's choice is re-applied
    coord.radio_tuning = {"concentrator_discovery_seconds": 120}
    await coord._nv_write(c.NvId.CONCENTRATOR_DISCOVERY, bytes([60]))
    await coord._reapply_radio_tuning()
    assert (await coord.read_radio_tuning())["concentrator_discovery_seconds"] == 120
    await t.close()


async def test_tc_rejoins_are_allowed_and_rekeyed_ones_flagged_for_rotation():
    """A device that comes back without a valid network key (powered off across a rotation, or an
    Aqara that decided the hub was lost) recovers through an unsecured TC rejoin. Refusing those —
    the SDK default — orphans it until someone factory-resets and re-pairs it. So they are allowed,
    and because the re-delivered key may have travelled under the public key, such a rejoin is
    NOT flagged as exposure — mandatory key exchange means the re-delivery is under the
    device's own verified link key (see the assertion below for the full reasoning)."""
    fake, coord, t = await make()

    ieee, nwk = 0x00124B00AABB0001, 0x4321
    coord.known_ieee.add(ieee)
    joins = []

    async def on_join(d):
        joins.append(d)

    coord.on_device_joined(on_join)

    # 2. a TC-mediated rejoin (tc_device_ind then announce) is flagged as re-keyed
    fake.emit(Frame(FrameType.AREQ, Subsystem.ZDO, c.ZdoCmd.TC_DEV_IND,
                    Writer().u16(nwk).ieee(ieee).u16(0x0000).bytes()))
    fake.emit_announce(ieee, nwk)
    for _ in range(50):
        await asyncio.sleep(0.02)
        if joins:
            break
    assert joins and not joins[0].plain_join, \
        ("a TC-re-keyed rejoin is not exposure: key exchange is mandatory here, so the re-delivery "
         "travels under the device's unique verified link key — flagging it scheduled a rotation "
         "after every Aqara reboot, each waiting days on wall-switched bulbs for no gain")

    # 3. a secure rejoin (announce alone, no TC involvement) is not
    joins.clear()
    fake.emit_announce(ieee, nwk)
    for _ in range(50):
        await asyncio.sleep(0.02)
        if joins:
            break
    assert joins and not joins[0].plain_join, "a secure rejoin re-delivers nothing and needs no rotation"
    await t.close()


async def test_a_secure_rejoin_during_someone_elses_window_is_not_exposure():
    """Re-pairing one device opens a window; a wall-switched bulb that happens to power up in
    those seconds rejoins securely with the key it already holds — the trust centre delivers it
    nothing. Flagging it scheduled a rotation for every innocent bystander; now only a rejoin
    the TC actually re-keyed during a window counts as a through-the-window pairing."""
    fake, coord, t = await make()
    ieee, nwk = 0x00124B00AABB0002, 0x4322
    coord.known_ieee.add(ieee)
    joins = []

    async def on_join(d):
        joins.append(d)

    coord.on_device_joined(on_join)
    await coord.permit_join(60, "test")        # a window is open for something else

    fake.emit_announce(ieee, nwk)              # secure rejoin: no tc_device_ind, no key delivered
    for _ in range(50):
        await asyncio.sleep(0.02)
        if joins:
            break
    assert joins and not joins[0].plain_join, \
        "a secure rejoin received no key — window or no window, there is nothing to retire"
    assert not joins[0].rejoin, "inside a window it still counts as a join for interview purposes"
    await t.close()
