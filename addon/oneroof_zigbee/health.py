"""Is my network healthy? One question, answered from what the gateway already knows.

Findings, each naming a device and saying why in plain words:
* offline      — the gateway cannot reach it right now
* weak_link    — its best hop to a relay is under LQI 80. For a battery device a router in
                 between would give it a parent next door; a router has no parent to switch
                 to, so the advice is to move it, raise its transmit power, or add a router
                 between; an extender the coordinator can barely hear helps nobody, and
                 belongs midway between the coordinator and the devices it should serve
* flapping     — went offline/online four times or more in the last day
* quiet        — not heard for far longer than its kind should be (mains 6 h, battery 26 h)
* busy_router  — a router carrying more children than is comfortable
* battery      — at or under 15 %, or about two weeks from empty on its own trend
* wall_off     — (info) a device marked "switched off at the wall" is off right now
* wall_hint    — (info) a router that went silent while ON several times: probably a wall switch

The same numbers feed the health line every One Roof add-on publishes to Home Assistant
(`oneroof/zigbee/health`, discovered by itself), so one card shows the family.
"""
from __future__ import annotations

import time
from typing import Any

WEAK_LQI = 80
FLAPS_PER_DAY = 4
QUIET_MAINS_S = 6 * 3600
QUIET_BATTERY_S = 26 * 3600
BUSY_CHILDREN = 10
WALL_PATTERN_HINT = 3             # went silent while ON this many times: probably a wall switch


BATTERY_REPLACE_PCT = 10          # what "empty" means: most devices stop reporting around here
BATTERY_WARN_DAYS = 14
BATTERY_LOW_PCT = 15


def battery_forecast(log: list[list[float]] | None, now: float | None = None) -> dict[str, Any] | None:
    """From a device's [[ts, pct], ...] history: how long until it needs a new battery.
    A straight line through the last 120 days of readings; honest about thin data ("low"
    confidence under two weeks of history, none under three points or five days)."""
    now = now or time.time()
    pts = [(float(t), float(p)) for t, p in (log or []) if now - float(t) <= 120 * 86400]
    if not pts:
        return None
    pct = pts[-1][1]
    out: dict[str, Any] = {"pct": pct, "days_left": None, "per_day": None, "confidence": "none", "points": len(pts)}
    if len(pts) < 3:
        return out
    span = pts[-1][0] - pts[0][0]
    if span < 5 * 86400:
        return out
    n = len(pts)
    mx = sum(t for t, _ in pts) / n
    my = sum(p for _, p in pts) / n
    sxx = sum((t - mx) ** 2 for t, _ in pts)
    if sxx == 0:
        return out
    slope = sum((t - mx) * (p - my) for t, p in pts) / sxx        # pct per second
    per_day = slope * 86400
    out["per_day"] = round(per_day, 3)
    out["confidence"] = "ok" if span >= 14 * 86400 else "low"
    if per_day >= -0.001:
        out["days_left"] = None                                     # flat or charging: no forecast
        return out
    out["days_left"] = max(0, int((pct - BATTERY_REPLACE_PCT) / -per_day))
    return out


def best_parents(devices: list[dict[str, Any]], links: list[dict[str, Any]]) -> dict[str, tuple[str, int]]:
    """{ieee: (relay ieee, lqi)} — the strongest link each device has to a router or the
    coordinator, from the walked neighbour tables. `devices`: [{ieee, kind}] with kind
    coordinator|router|end_device."""
    kind = {d["ieee"].lower(): d["kind"] for d in devices}
    best: dict[str, tuple[str, int]] = {}
    for link in links:
        a, b, lqi = str(link.get("source", "")).lower(), str(link.get("target", "")).lower(), int(link.get("lqi") or 0)
        if a not in kind or b not in kind or a == b:
            continue
        for me, other in ((a, b), (b, a)):
            if kind[me] == "coordinator" or kind[other] == "end_device":
                continue
            if me not in best or lqi > best[me][1]:
                best[me] = (other, lqi)
    return best


def network_health(devices: list[dict[str, Any]], links: list[dict[str, Any]],
                   flaps: dict[str, list[float]] | None = None, now: float | None = None) -> dict[str, Any]:
    """`devices`: [{ieee, name, kind, available, last_seen, battery(bool)}]. `links`: the map's
    links (may be empty: then link findings are skipped and `walked` says so).
    `flaps`: {ieee: [ts of availability changes]}."""
    now = now or time.time()
    flaps = flaps or {}
    names = {d["ieee"].lower(): d.get("name") or d["ieee"] for d in devices}
    findings: list[dict[str, Any]] = []

    def add(kind: str, severity: str, ieee: str, detail: str) -> None:
        findings.append({"kind": kind, "severity": severity, "ieee": ieee, "name": names.get(ieee.lower(), ieee), "detail": detail})

    wall_off: list[dict[str, Any]] = []
    for d in devices:
        if d["kind"] == "coordinator":
            continue
        ieee = d["ieee"]
        if d.get("wall_switched"):
            # silence is the wall switch, not the radio: no offline / flapping / quiet for it
            if d.get("wall_off"):
                wall_off.append(d)
            continue
        if d.get("wall_pattern", 0) >= WALL_PATTERN_HINT and d["kind"] == "router":
            add("wall_hint", "info", ieee, f"went silent while ON {d['wall_pattern']} times — looks switched off at the wall; mark it so on its page and it shows as off, not offline")
        if not d.get("available", True):
            add("offline", "bad", ieee, "the gateway cannot reach it right now")
        changes = [t for t in flaps.get(ieee.lower(), []) if now - t <= 86400]
        if len(changes) >= FLAPS_PER_DAY:
            add("flapping", "warn", ieee, f"went offline and back {len(changes)} times in the last day")
        seen = float(d.get("last_seen") or 0)
        limit = QUIET_BATTERY_S if d.get("battery") else QUIET_MAINS_S
        if seen and now - seen > limit and d.get("available", True):
            hours = int((now - seen) // 3600)
            add("quiet", "warn", ieee, f"not heard for {hours} h" + (" — a battery device should report within a day" if d.get("battery") else " — a mains device should speak within hours"))

    for d in devices:
        if d["kind"] == "coordinator" or not d.get("battery"):
            continue
        fc = battery_forecast(d.get("battery_log"), now)
        pct = fc["pct"] if fc else d.get("battery_pct")
        if pct is not None and pct <= BATTERY_LOW_PCT:
            add("battery", "bad" if pct <= BATTERY_REPLACE_PCT else "warn", d["ieee"], f"battery at {int(pct)} % — time for a new one")
        elif fc and fc.get("days_left") is not None and fc["days_left"] <= BATTERY_WARN_DAYS:
            add("battery", "warn", d["ieee"], f"about {fc['days_left']} days of battery left ({int(pct)} % now)")

    parents = best_parents(devices, links) if links else {}
    children: dict[str, int] = {}
    wall_ieees = {d["ieee"].lower() for d in devices if d.get("wall_switched")}
    roles = {d["ieee"].lower(): ("extender" if d.get("extender") else d["kind"]) for d in devices}
    for ieee, (relay, lqi) in parents.items():
        children[relay] = children.get(relay, 0) + 1
        if lqi < WEAK_LQI and ieee not in wall_ieees:
            role = roles.get(ieee, "end_device")
            if role == "extender":
                advice = ("an extender the coordinator can barely hear helps nobody — place it midway between "
                          "the coordinator and the devices it should serve, and raise its transmit power")
            elif role == "router":
                advice = ("a router has no parent to switch to — move it closer, raise its transmit power "
                          "if it has that setting, or put a router in between")
            else:
                advice = "a router in between would give it a parent next door"
            add("weak_link", "bad" if lqi < 50 else "warn", ieee, f"reaches {names.get(relay, relay)} at LQI {lqi} — {advice}")
    for relay, n in children.items():
        if n > BUSY_CHILDREN:
            add("busy_router", "warn", relay, f"carries {n} devices — another router nearby would share the load")
    for d in wall_off:
        kids = children.get(d["ieee"].lower(), 0)
        add("wall_off", "info", d["ieee"], "off at the wall" + (f" — while it is off, {kids} device{'s' if kids != 1 else ''} lose their parent and look for another" if kids else ""))

    order = {"bad": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["name"].lower()))
    counts = {k: sum(1 for f in findings if f["kind"] == k) for k in ("offline", "weak_link", "flapping", "quiet", "busy_router", "battery", "wall_off", "wall_hint")}
    real = [f for f in findings if f["severity"] != "info"]
    verdict = "bad" if any(f["severity"] == "bad" for f in real) else "warn" if real else "ok"
    return {"verdict": verdict, "findings": findings, "counts": counts,
            "devices": sum(1 for d in devices if d["kind"] != "coordinator"),
            "walked": bool(links), "checked_at": now}


def health_line(report: dict[str, Any], version: str, uptime_s: int, coordinator_online: bool,
                extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """The family shape: status ok|degraded, reasons, and the counts."""
    reasons: list[str] = []
    if not coordinator_online:
        reasons.append("coordinator offline")
    c = report["counts"]
    if c["offline"]:
        reasons.append(f"{c['offline']} device{'s' if c['offline'] != 1 else ''} offline")
    if c["weak_link"]:
        reasons.append(f"{c['weak_link']} weak link{'s' if c['weak_link'] != 1 else ''}")
    if c["flapping"]:
        reasons.append(f"{c['flapping']} flapping")
    if c["quiet"]:
        reasons.append(f"{c['quiet']} quiet")
    if c.get("battery"):
        reasons.append(f"{c['battery']} batter{'y' if c['battery'] == 1 else 'ies'} to replace")
    out = {"status": "degraded" if reasons else "ok", "reasons": reasons, "version": version, "uptime_s": uptime_s,
           "coordinator": "ok" if coordinator_online else "offline", "devices": report["devices"], **c}
    if extra:
        out.update(extra)
    return out
