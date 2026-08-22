import asyncio

import pytest

from oneroof_zigbee.security import Audit, JoinGuard, JoinPolicy, JoinPolicyError, NetworkSecrets, parse_install_code
from oneroof_zigbee.znp import Coordinator, Transport
from oneroof_zigbee.znp import commands as c
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


async def test_runtime_security_applied_every_start():
    fake, coord, t = await make()
    reqs = [(f.subsystem, f.command, f.data) for f in fake.requests]
    assert (c.Subsystem.APP_CNF, c.AppCnfCmd.BDB_SET_TC_REQUIRE_KEY_EXCHANGE, b"\x01") in reqs
    assert (c.Subsystem.APP_CNF, c.AppCnfCmd.SET_ALLOWREJOIN_TC_POLICY, b"\x00") in reqs
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
    assert key_cmd[0] == 0 and key_cmd[1:] == coord.secrets.tc_install_code and len(key_cmd) == 19
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
