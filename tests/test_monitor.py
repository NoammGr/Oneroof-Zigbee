"""Liveness / anomaly monitor: behavioural profiles per device and conservative alerts."""

from __future__ import annotations

from oneroof_zigbee import monitor as mon


class Clock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


def make():
    alerts: list[dict] = []
    clock = Clock()
    m = mon.Monitor(lambda t, **f: alerts.append({"type": t, **f}), now=clock)
    return m, alerts, clock


def feed(m, clock, ieee, n, *, gap=30.0, seq0=0, lqi=120, cmd=False, mains=True):
    seq = seq0
    for _ in range(n):
        clock.t += gap
        m.observe(ieee, seq=seq & 0xFF, lqi=lqi, is_command=cmd, mains=mains)
        seq += 1
    return seq


def test_normal_traffic_never_alerts():
    m, alerts, clock = make()
    feed(m, clock, 1, 500, gap=20.0)  # 500 frames, steady seq and LQI
    m.sweep([(1, True)])
    assert alerts == []


def test_sequence_jump_and_lqi_swing_are_reported_once_per_cooldown():
    m, alerts, clock = make()
    seq = feed(m, clock, 1, 60, lqi=120)
    clock.t += 30
    m.observe(1, seq=(seq + 120) & 0xFF, lqi=20, is_command=False, mains=True)  # impersonator: own counter, far away
    kinds = sorted(a["kind"] for a in alerts)
    assert kinds == ["link_quality_swing", "sequence_jump"]
    assert alerts[0]["ieee"] == "0x0000000000000001"
    clock.t += 30
    m.observe(1, seq=5, lqi=25, is_command=False, mains=True)  # still odd, but within the cooldown
    assert len(alerts) == 2


def test_sensor_that_never_commanded_suddenly_sends_a_command():
    m, alerts, clock = make()
    feed(m, clock, 2, 80, mains=False)
    clock.t += 30
    m.observe(2, seq=80, lqi=120, is_command=True, mains=False)
    assert [a["kind"] for a in alerts] == ["unexpected_command"]
    # a device that commanded from the start (a remote) is not an anomaly
    m2, alerts2, clock2 = make()
    feed(m2, clock2, 3, 80, cmd=True, mains=False)
    assert alerts2 == []


def test_burst_then_silence():
    m, alerts, clock = make()
    feed(m, clock, 4, 100, gap=60.0)  # about one frame a minute
    clock.t = (int(clock.t // 60) + 1) * 60.0
    for i in range(40):  # 40 frames within one minute
        clock.t += 1.0
        m.observe(4, seq=(100 + i) & 0xFF, lqi=120, is_command=False, mains=True)
    assert [a["kind"] for a in alerts] == ["burst"]
    clock.t += 700  # then nothing for >10 min
    m.sweep([(4, True)])
    assert [a["kind"] for a in alerts] == ["burst", "silence_after_burst"]


def test_mains_device_liveness():
    m, alerts, clock = make()
    feed(m, clock, 5, 50, gap=120.0, mains=True)  # reports every 2 min
    clock.t += 1000  # ~17 min: above 4× typical but below the 30 min floor
    assert m.sweep([(5, True)]) == []
    clock.t += 1000
    assert m.sweep([(5, True)]) == ["went_silent"]
    assert alerts[-1]["kind"] == "went_silent" and alerts[-1]["typical_s"] == 120
    # battery devices are exempt from liveness
    feed(m, clock, 6, 50, gap=120.0, mains=False)
    clock.t += 100_000
    assert m.sweep([(6, False)]) == []


def test_profiles_round_trip():
    m, alerts, clock = make()
    feed(m, clock, 7, 30)
    data = m.export()
    m2, _, _ = make()
    m2.load(data)
    assert m2.profiles[7].frames == 30 and m2.profiles[7].last_seq == 29


def test_counter_restart_near_zero_is_not_an_anomaly():
    m, alerts, clock = make()
    feed(m, clock, 9, 60)
    clock.t += 30
    m.observe(9, seq=4, lqi=120, is_command=False, mains=True)  # device rebooted: counter restarted
    assert alerts == []
    clock.t += 30
    m.observe(9, seq=130, lqi=120, is_command=False, mains=True)  # a jump into the middle is still one
    assert [a["kind"] for a in alerts] == ["sequence_jump"]
