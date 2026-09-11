"""Is my network healthy? One question, answered from what the gateway already knows.

Findings, each naming a device and saying why in plain words:
* offline      — the gateway cannot reach it right now
* weak_link    — its best hop to a relay is under LQI 80 (a router in between would help)
* flapping     — went offline/online four times or more in the last day
* quiet        — not heard for far longer than its kind should be (mains 6 h, battery 26 h)
* busy_router  — a router carrying more children than is comfortable

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

    for d in devices:
        if d["kind"] == "coordinator":
            continue
        ieee = d["ieee"]
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

    parents = best_parents(devices, links) if links else {}
    children: dict[str, int] = {}
    for ieee, (relay, lqi) in parents.items():
        children[relay] = children.get(relay, 0) + 1
        if lqi < WEAK_LQI:
            add("weak_link", "bad" if lqi < 50 else "warn", ieee,
                f"reaches {names.get(relay, relay)} at LQI {lqi} — a router in between would give it a parent next door")
    for relay, n in children.items():
        if n > BUSY_CHILDREN:
            add("busy_router", "warn", relay, f"carries {n} devices — another router nearby would share the load")

    order = {"bad": 0, "warn": 1}
    findings.sort(key=lambda f: (order[f["severity"]], f["name"].lower()))
    counts = {k: sum(1 for f in findings if f["kind"] == k) for k in ("offline", "weak_link", "flapping", "quiet", "busy_router")}
    verdict = "bad" if any(f["severity"] == "bad" for f in findings) else "warn" if findings else "ok"
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
    out = {"status": "degraded" if reasons else "ok", "reasons": reasons, "version": version, "uptime_s": uptime_s,
           "coordinator": "ok" if coordinator_online else "offline", "devices": report["devices"], **c}
    if extra:
        out.update(extra)
    return out
