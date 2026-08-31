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


def test_sequence_jump_needs_two_unmatched_values_and_lqi_swing_alerts():
    m, alerts, clock = make()
    # fill all four stream heads first (a device may run several counters)
    feed(m, clock, 1, 60, lqi=120)  # head ~59
    for s0 in (120, 180, 240):
        clock.t += 5
        m.observe(1, seq=s0, lqi=120, is_command=False, mains=True)
    assert alerts == [], "new streams within capacity are not anomalies"
    clock.t += 30
    m.observe(1, seq=110, lqi=20, is_command=False, mains=True)  # 1st unmatched: pending only
    assert sorted(a["kind"] for a in alerts) == ["link_quality_swing"]
    clock.t += 5
    m.observe(1, seq=30, lqi=120, is_command=False, mains=True)  # 2nd unmatched in a row → anomaly
    assert sorted(a["kind"] for a in alerts) == ["link_quality_swing", "sequence_jump"]
    assert alerts[0]["ieee"] == "0x0000000000000001"


def test_multiple_counter_streams_never_alert():
    """Tuya plugs interleave counters (time requests vs. reports): ping-ponging between streams is
    normal and must stay quiet."""
    m, alerts, clock = make()
    feed(m, clock, 8, 40, seq0=80, lqi=120)   # stream A around 80..119
    a, b = 120, 20
    for _ in range(200):
        clock.t += 10
        a = (a + 1) & 0xFF
        m.observe(8, seq=a, lqi=120, is_command=False, mains=True)
        clock.t += 10
        b = (b + 1) & 0xFF
        m.observe(8, seq=b, lqi=120, is_command=False, mains=True)
    assert alerts == []


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
    assert m.sweep([(5, True)]) == [(5, "went_silent")]
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
    feed(m, clock, 9, 60)  # head ~59
    for s0 in (130, 190, 250):
        clock.t += 5
        m.observe(9, seq=s0, lqi=120, is_command=False, mains=True)  # heads full
    clock.t += 30
    m.observe(9, seq=4, lqi=120, is_command=False, mains=True)  # device rebooted: counter restarted
    assert alerts == []
    clock.t += 30
    m.observe(9, seq=115, lqi=120, is_command=False, mains=True)
    clock.t += 5
    m.observe(9, seq=60, lqi=120, is_command=False, mains=True)  # two unmatched in a row
    assert [a["kind"] for a in alerts] == ["sequence_jump"]


def test_uncounted_chatter_never_raises():
    m, alerts, clock = make()
    feed(m, clock, 10, 60, gap=60.0)
    clock.t = (int(clock.t // 60) + 1) * 60.0
    for _ in range(300):  # vendor heartbeat every 200 ms
        clock.t += 0.2
        m.observe(10, seq=None, lqi=120, is_command=False, mains=True, count=False)
    assert alerts == [] and m.profiles[10].last_seen == clock.t


def test_went_silent_alerts_once_per_outage():
    m, alerts, clock = make()
    feed(m, clock, 11, 50, gap=120.0, mains=True)
    clock.t += 100_000
    assert m.sweep([(11, True)]) == [(11, "went_silent")]
    for _ in range(10):
        clock.t += 900
        assert m.sweep([(11, True)]) == [], "no repeat while still silent"
    clock.t += 30
    m.observe(11, seq=1, lqi=120, is_command=False, mains=True)  # heard again
    clock.t += 100_000
    assert m.sweep([(11, True)]) == [(11, "went_silent")], "a new outage alerts again"
