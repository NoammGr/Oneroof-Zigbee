"""The gateway: glue between Coordinator (radio), ZCL, the device registry,
the MQTT broker and Home Assistant discovery.

Security-relevant behaviour lives here too:
* every MQTT control request carries the *authenticated broker username* of
  the publisher; the audit log records who asked for what;
* `permit_join` and `rotate_network_key` requests are additionally gated by
  an allow-list of usernames (`control_users`), so a compromised HA token
  that can publish to `oz/+/set` still cannot open the network;
* incoming ZCL that does not parse is logged and dropped — never crashes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from collections.abc import Callable
from typing import Any

from . import quirks, quirks_tuya, zcl
from .config import Config
from .definitions import Definitions
from .devices import Device, Registry
from .ha import Topics, bridge_discovery, discovery_messages, removal_messages
from .mqtt import Broker
from .security import Audit, InstallCodeError, JoinPolicyError, parse_install_code
from .zcl import global_commands as gc
from .zcl.types import DataType
from .zcl import vendor as vz
from .znp import Coordinator, IncomingAps, JoinedDevice, ZnpError
from .znp.wire import ieee_int, ieee_str

log = logging.getLogger("oneroof_zigbee.gateway")

TIME_CLUSTER = 0x000A
ZIGBEE_EPOCH = 946684800          # 2000-01-01 UTC, the zero of Zigbee time
# global commands that need no reply of their own: they either are replies, or the device
# explicitly asked for silence
_QUIET_GLOBALS = frozenset({gc.CMD_DEFAULT_RESPONSE, gc.CMD_REPORT_ATTRIBUTES,
                            gc.CMD_READ_ATTRIBUTES_RSP, gc.CMD_WRITE_ATTRIBUTES_RSP,
                            gc.CMD_CONFIGURE_REPORTING_RSP, gc.CMD_READ_REPORTING_CONFIG_RSP,
                            gc.CMD_DISCOVER_ATTRIBUTES_RSP})

# attributes we ask every device for during interview
_BASIC_ATTRS = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x4000]
# (cluster, attr, dtype, min, max, change) we configure reporting for
_REPORTING: dict[int, list[tuple[int, zcl.DataType, int, int, Any]]] = {
    0x0006: [(0x0000, zcl.DataType.bool_, 0, 3600, None)],
    0x0008: [(0x0000, zcl.DataType.uint8, 1, 3600, 1)],
    0x0300: [(0x0003, zcl.DataType.uint16, 1, 3600, 10), (0x0004, zcl.DataType.uint16, 1, 3600, 10), (0x0007, zcl.DataType.uint16, 1, 3600, 1)],
    0x0001: [(0x0021, zcl.DataType.uint8, 3600, 43200, 1)],
    0x0402: [(0x0000, zcl.DataType.int16, 30, 3600, 20)],
    0x0405: [(0x0000, zcl.DataType.uint16, 30, 3600, 100)],
    0x0403: [(0x0000, zcl.DataType.int16, 30, 3600, 1)],
    0x0400: [(0x0000, zcl.DataType.uint16, 10, 3600, 100)],
    0x0406: [(0x0000, zcl.DataType.bitmap8, 0, 3600, None)],
    0x0B04: [(0x050B, zcl.DataType.int16, 5, 3600, 5), (0x0505, zcl.DataType.uint16, 5, 3600, 5), (0x0508, zcl.DataType.uint16, 5, 3600, 50)],
    0x0702: [(0x0000, zcl.DataType.uint48, 10, 3600, 1)],
    0x0102: [(0x0008, zcl.DataType.uint8, 1, 3600, 1)],
    0x0201: [(0x0000, zcl.DataType.int16, 30, 3600, 20), (0x0012, zcl.DataType.int16, 1, 3600, 10), (0x0011, zcl.DataType.int16, 1, 3600, 10),
             (0x001C, zcl.DataType.enum8, 1, 3600, None)],
    0x0202: [(0x0000, zcl.DataType.enum8, 1, 3600, None)],
}
_READ_ON_JOIN: dict[int, list[int]] = {
    0x0006: [0x0000, 0x4003], 0x0008: [0x0000], 0x0300: [0x0003, 0x0004, 0x0007, 0x0008], 0x0001: [0x0020, 0x0021],
    0x0402: [0x0000], 0x0405: [0x0000], 0x0403: [0x0000], 0x0400: [0x0000], 0x0406: [0x0000],
    0x0500: [0x0001, 0x0002], 0x0B04: [0x0600, 0x0601, 0x0602, 0x0603, 0x0604, 0x0605, 0x0505, 0x0508, 0x050B],
    0x0702: [0x0301, 0x0302, 0x0000], 0x0102: [0x0008],
    # thermostat: both setpoints, the limits and ControlSequenceOfOperation decide which controls a
    # device gets (a 4-pipe air conditioner is not a radiator valve); a TRV simply lacks the rest
    0x0201: [0x0000, 0x0012, 0x0011, 0x0015, 0x0016, 0x0017, 0x0018, 0x001B, 0x001C],
    0x0202: [0x0000, 0x0001],
}


class Gateway:
    def __init__(self, cfg: Config, coord: Coordinator, broker: Broker, audit: Audit, registry: Registry,
                 *, control_users: set[str] | None = None) -> None:
        self.cfg = cfg
        self.coord = coord
        self.broker = broker
        self.audit = audit
        self.registry = registry
        self.base = cfg.mqtt.base_topic
        self.legacy = cfg.compat.legacy_layout
        self.topics = Topics(self.base, cfg.homeassistant.discovery_prefix, self.legacy)
        self.control_users = control_users if control_users is not None else {cfg.mqtt.gateway_user}
        self._seq = 0
        self._pending_rsp: dict[tuple[int, int, int], asyncio.Future[zcl.ZclFrame]] = {}
        self._answered: set[tuple[int, int]] = set()   # (ieee, cluster) we have already answered once
        self._interview_tasks: dict[int, asyncio.Task[None]] = {}
        self._lookup_times: dict[int, float] = {}
        self._locate_task: asyncio.Task[None] | None = None
        self._settled: set[int] = set()  # Tuya devices given their settle read this run
        self._dirty = False  # a state / last-seen change not yet written to the registry file
        # When a device last gave evidence of what it IS (an on/off, level or thermostat read or
        # report) — the silent-router poll goes by this, not by any frame: a plug that reports its
        # power every ten seconds says nothing about whether someone pressed its button.
        self._state_evidence: dict[int, float] = {}
        self._poll_failures: dict[int, int] = {}  # consecutive polls a mains device did not answer
        self._poll_first_miss: dict[int, float] = {}  # when the current run of unanswered polls began
        self._unanswering_noted: set[int] = set()  # devices already written up as "talks, never answers" this run
        self._set_locks: dict[int, asyncio.Lock] = {}  # commands to one device run in order
        self._poll_not_before: dict[int, float] = {}  # a device already marked offline is asked less often
        self._refresh_tasks: dict[int, asyncio.Task] = {}  # one pending "ask it what it is" per device
        self._refresh_task: asyncio.Task | None = None  # the sweep of every device after a (re)start
        self.unknown_devices: dict[int, dict[str, Any]] = {}  # ieee -> what we know about an unregistered device on our network
        self._rotation: Any = None  # KeyRotation, created on first use
        from .rotation import RotationPolicy
        # When the key rotates by itself: the owner's live decision, kept in the data folder;
        # the configured values only seed it (see RotationPolicy).
        self.rotation_policy = RotationPolicy.load(self._rotation_policy_file(), after_plain_join=self.cfg.zigbee.rotate_key_after_plain_join,
                                                   every_days=self.cfg.zigbee.rotation_interval_days)
        from .monitor import Monitor
        self.monitor = Monitor(lambda t, **f: self.audit.security(t, **f))
        self._monitor_task: asyncio.Task[None] | None = None
        self._timers: dict[tuple[int, str], asyncio.Task[None]] = {}
        self._started = False
        # Serial link health, driven by the connection supervisor in __main__:
        # False while the dongle is disconnected/reconnecting. Surfaced in the UI.
        self.coordinator_online = True
        # optional observers (the UI attaches here); called synchronously, must not raise
        self.on_state_change: Callable[[int, dict[str, Any]], None] | None = None
        self.on_device_event: Callable[[str, Device], None] | None = None
        self.on_activity: Callable[[int, dict[str, Any]], None] | None = None
        # global activity feed (state changes across all devices), newest last; also appended to activity.log
        import collections
        self.activity: collections.deque[dict[str, Any]] = collections.deque(maxlen=5000)
        self._activity_path = (cfg.data_dir / "activity.log") if cfg.data_dir else None
        from .ota import OtaServer
        self.ota = OtaServer(cfg.data_dir / "firmware", audit)
        # user device definitions take precedence over the built-in model table; installed process-wide
        self.definitions = Definitions((cfg.data_dir / "definitions.yaml") if cfg.data_dir else None)
        quirks.set_definitions(self.definitions)

    # ------------------------------------------------------------- start --

    async def start(self) -> None:
        for d in self.registry.all():
            if d.interviewed and d.endpoints and not any(e.in_clusters or e.out_clusters for e in d.endpoints.values()):
                d.interviewed = False  # imported without cluster information: interview it on contact
                d.context.pop("reporting_done", None)
                self.registry.save()
            if d.nwk == 0 and (d.interviewed or d.endpoints):
                # Interviewed at address 0 = the coordinator's own descriptors; discard them.
                d.endpoints.clear()
                d.interviewed = False
                d.context.pop("reporting_done", None)
                self.registry.save()
        for d in self.registry.all():
            d.state = self._json_safe(d.state)  # heal records written before state sanitising existed
            lq = d.state.get("linkquality")
            if d.lqi is None and isinstance(lq, int) and 0 <= lq <= 255:
                d.lqi = lq  # last known value from the imported state until the device talks
        self.coord.known_ieee.update(d.ieee for d in self.registry.all())
        self.coord.on_aps(self._on_aps)
        self.coord.on_device_joined(self._on_joined)
        self.coord.on_device_left(self._on_left)
        self.audit.subscribe(self._on_audit)

        b = self.base
        self.broker.subscribe(f"{b}/+/set", self._on_set)
        # both layouts: consumers (the Apple Home bridge among them) ask for a state refresh at
        # startup and when a device returns from an outage — a /get that nobody answers turns
        # every such refresh into silence
        self.broker.subscribe(f"{b}/+/get", self._on_get)
        self.broker.subscribe(f"{b}/bridge/request/+", self._on_request)
        self.broker.subscribe("homeassistant/status", self._on_ha_status)

        self._load_activity()
        self._load_profiles()
        self._monitor_task = asyncio.create_task(self._monitor_loop(), name="monitor")
        self._refresh_task = asyncio.create_task(self._refresh_all_states(), name="state-refresh")
        self._resume_rotation()
        await self.broker.publish(f"{b}/bridge/state", self.topics.bridge_state_payload(True), retain=True)
        # Availability is evidence, not memory. The registry remembers what was true when the
        # gateway last ran, and that memory used to be restored as fact — devices that were never
        # re-paired kept a green badge for days. At start a badge is only kept for a device we
        # actually heard from recently, or one that has spoken since this network was formed;
        # everything else starts offline and turns green the moment it is heard again.
        formed_now = getattr(self.coord, "network_was_formed", False)
        born = getattr(self.coord.secrets, "formed_ts", None) or 0
        now = time.time()
        stale = []
        for d in self.registry.all():
            if not d.available:
                continue
            heard = d.last_seen or 0
            grace = self.STARTUP_ONLINE_MAINS_S if (d.is_router or d.rx_on_when_idle) else self.STARTUP_ONLINE_BATTERY_S
            if formed_now or heard < born or now - heard > grace:
                stale.append(d)
        for d in stale:
            d.available = False
            await self._publish_availability(d, False)
        if stale:
            self.registry.save()
            self.audit.event("devices_marked_offline_at_start", count=len(stale))
        await self._publish_bridge_info()
        if self.cfg.homeassistant.discovery:
            for topic, payload in bridge_discovery(b, self.cfg.homeassistant.discovery_prefix, legacy=self.legacy):
                await self.broker.publish(topic, payload, retain=True)
            for dev in self.registry.all():
                await self._announce(dev)
                await self._publish_state(dev)
        await self._publish_permit_join()
        self._started = True
        log.info("gateway ready on base topic %r", b)
        pending = [d for d in self.registry.all()
                   if d.context.get("imported_from") and not d.context.get("reporting_done")]
        if pending:
            self._locate_task = asyncio.create_task(self._locate_imported(pending), name="locate-imported")

    async def _locate_imported(self, devices: list[Device]) -> None:
        """Imported devices are on our network but have not talked to us yet. Ask each one for its
        address (a ZDO broadcast it answers itself); whoever answers is awake, so interview or
        configure it now instead of waiting for its first report. Sleepy devices stay silent and
        are handled when they next wake (see _on_aps)."""
        await asyncio.sleep(5.0)  # let routers settle after (re)start
        self.audit.event("imported_devices_lookup", count=len(devices))
        for dev in devices:
            if dev.context.get("reporting_done") or dev.ieee in self._interview_tasks:
                continue
            known_sleepy = (not (dev.is_router or dev.rx_on_when_idle)
                            and (str(dev.power_source or "").lower() == "battery" or bool(dev.endpoints)))
            if dev.nwk and known_sleepy and not dev.interviewed:
                continue  # answers only when awake — interviewed on its next report (unknown types are tried)
            if dev.nwk:
                # Address known from the previous setup's backup: talk to the device directly.
                nwk = dev.nwk
            else:
                try:
                    nwk = await self.coord.nwk_lookup(dev.ieee)
                except Exception as e:  # transport hiccup: keep going with the next device
                    log.info("%s: address lookup failed (%s)", dev.ieee_str, e)
                    nwk = None
                if nwk is None:
                    continue
            if nwk != dev.nwk:
                self.registry.add_or_update(dev.ieee, nwk)
            dev.available = True
            dev.last_seen = time.time()
            dev.context["reporting_done"] = True
            if dev.endpoints and dev.interviewed:
                self._interview_tasks[dev.ieee] = asyncio.create_task(self._post_import_setup(dev), name=f"post-import-{dev.ieee_str}")
            else:
                self._start_interview(dev)
            await asyncio.sleep(1.0)  # one broadcast per second keeps the mesh calm

    # ----------------------------------------------------------- monitor --

    def _profiles_path(self):
        return self.cfg.data_dir / "profiles.json"

    def _load_profiles(self) -> None:
        try:
            if self._profiles_path().exists():
                self.monitor.load(json.loads(self._profiles_path().read_text()))
        except (OSError, ValueError):
            log.debug("profiles.json unreadable", exc_info=True)

    def _save_profiles(self) -> None:
        try:
            tmp = self._profiles_path().with_suffix(".tmp")
            tmp.write_text(json.dumps(self.monitor.export()))
            tmp.replace(self._profiles_path())
        except OSError:
            log.debug("profiles.json not saved", exc_info=True)

    ROUTER_POLL_AFTER_S = 900  # a mains device that has not said what it is for this long is asked
    # A mains device that fails this many polls in a row is offline until it is heard again: a bulb
    # cut from power at the wall must not keep showing the last thing it reported.
    OFFLINE_AFTER_FAILED_POLLS = 2
    # After that many misses a device is asked again after 5, 10, 15, 30 minutes - not every
    # minute: each unanswered read holds the radio for its full timeout, and a device that never
    # answers (a plug whose route back to us is broken while its own reports still arrive) would
    # otherwise cost the whole network that time all night long.
    POLL_BACKOFF_S = (300, 600, 900, 1800)
    REPORTING_RETRY_S = 600  # a reporting setup that failed (timeout, refused bind) is tried again on contact after this
    # A device that joins still called by its address is kept out of Home Assistant this long, or
    # until it is named: HA turns the first name it sees into the entity id and never changes it.
    HA_NAME_HOLD_S = 600
    # A device whose firmware refused to configure reporting cannot announce a physical press.
    # Ask it often enough that its tile still follows the wall switch within about a minute.
    UNREPORTED_POLL_AFTER_S = 60

    async def _monitor_loop(self) -> None:
        tick = 0
        while True:
            await asyncio.sleep(60)
            tick += 1
            try:
                gone = self.monitor.sweep([(d.ieee, bool(d.is_router or d.rx_on_when_idle)) for d in self.registry.all()])
                for ieee, kind in gone:
                    if kind != "went_silent":
                        continue
                    dev = self.registry.get(ieee)
                    if dev and dev.available:
                        # The green badge must tell the truth: silent past its own typical
                        # rhythm means offline until it is heard again.
                        dev.available = False
                        self._dirty = True
                        await self._publish_availability(dev, False)
                self._save_profiles()
                self._save_if_dirty()
                await self._poll_silent_routers()  # cheap: it only acts on devices past their own interval
                await self._release_name_holds()
                if tick % 5 == 0:
                    await self.coord.refresh_frame_counter()
                    self._maybe_scheduled_rotation()
            except Exception:
                log.debug("monitor sweep failed", exc_info=True)

    _REFRESH_CLUSTERS = (0x0006, 0x0008, 0x0102, 0x0201, 0x0202, 0x0300)  # what a device IS, not what it measures

    def _save_if_dirty(self) -> None:
        """The registry file is what the next start publishes before it can ask anyone: a state
        or an online/offline change that never reached the file comes back as yesterday's truth."""
        if not self._dirty:
            return
        self._dirty = False
        try:
            self.registry.save()
        except OSError:
            self._dirty = True
            log.debug("registry not saved", exc_info=True)

    def _note_state_evidence(self, dev: Device, cluster: int, state: dict[str, Any]) -> None:
        if state and (cluster in self._REFRESH_CLUSTERS or cluster == vz.TUYA_CLUSTER):
            self._state_evidence[dev.ieee] = time.time()

    async def _refresh_state(self, dev: Device) -> bool:
        """Ask a device what it actually is right now — switched on or off, how bright, which
        setpoint, where the cover sits — and publish the answer. A device keeps its own state
        across our restarts and its own power cuts; the gateway must not carry a remembered one
        around as if it were true. Returns whether the device answered at all."""
        heard = False
        extra = quirks.extra_reads(dev)  # what the model table holds on this device (a router's radio power)
        for ep in dev.endpoints.values():
            for cluster in sorted(set(self._REFRESH_CLUSTERS) | set(extra)):
                if cluster not in ep.in_clusters:
                    continue
                attrs = list(_READ_ON_JOIN.get(cluster, ()) if cluster in self._REFRESH_CLUSTERS else ()) + \
                    [a for a in extra.get(cluster, ()) if a not in _READ_ON_JOIN.get(cluster, ())]
                if not attrs:
                    continue
                try:
                    state = await self.read_attributes(dev, ep.id, cluster, attrs)
                except (ZnpError, asyncio.TimeoutError):
                    return heard  # asleep or gone: leave the rest alone
                heard = True
                self._note_state_evidence(dev, cluster, state)
                if state:
                    self._apply_changes(dev, quirks.translate_state(dev, ep.id, state))
        if not heard and dev.endpoints:
            # Nothing above applies to it (a pure relay, a device that only measures): ask for its
            # name so it has been heard once - that is what the link-quality figure and the
            # silent-router poll go by. Left alone, a restart would show "—" for a quarter hour.
            ep = dev.primary_endpoint()
            if ep is not None and 0x0000 in ep.in_clusters:
                try:
                    await self.read_attributes(dev, ep.id, 0x0000, [0x0004])
                    heard = True
                except (ZnpError, asyncio.TimeoutError):
                    return heard
        if heard:
            dev.last_seen = time.time()
            self._poll_failures.pop(dev.ieee, None)
            self._poll_first_miss.pop(dev.ieee, None)
            self._poll_not_before.pop(dev.ieee, None)
            self._unanswering_noted.discard(dev.ieee)
            if not dev.available:
                dev.available = True
                self._dirty = True
                await self._publish_availability(dev, True)
            await self._publish_state(dev)
        return heard

    def _schedule_refresh(self, dev: Device, delay: float = 3.0) -> None:
        """Ask a device what it is in a moment: after it rejoined (a power cut leaves a bulb ON at
        the wall and OFF in our memory), after a command it may not have carried out, after a
        toggle whose outcome only the device knows. One pending refresh per device."""
        if not dev.nwk or not dev.endpoints or dev.ieee in self._refresh_tasks:
            return

        async def run() -> None:
            try:
                await asyncio.sleep(delay)
                if dev.ieee in self._interview_tasks:
                    return
                await self._refresh_state(dev)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - a refresh is best effort
                log.debug("%s: state refresh failed", dev.ieee_str, exc_info=True)
            finally:
                self._refresh_tasks.pop(dev.ieee, None)

        self._refresh_tasks[dev.ieee] = asyncio.get_running_loop().create_task(run(), name=f"refresh-{dev.ieee_str}")

    async def _refresh_all_states(self) -> None:
        """After a restart of ours, ask every device that can answer where it stands. Sleepy
        battery devices cannot answer and are left to report in their own time."""
        await asyncio.sleep(8.0)  # let the network settle first
        asked = 0
        for dev in self.registry.all():
            if not (dev.is_router or dev.rx_on_when_idle) or not dev.nwk or not dev.endpoints:
                continue
            if dev.ieee in self._interview_tasks:
                continue
            try:
                await self._refresh_state(dev)
                asked += 1
            except Exception:  # noqa: BLE001 - one difficult device must not stop the sweep
                log.debug("%s: state refresh failed", dev.ieee_str, exc_info=True)
            await asyncio.sleep(0.4)  # a queue, not a burst
        if asked:
            self.audit.event("device_states_refreshed", devices=asked)

    def _poll_after(self, dev: Device) -> float:
        """How long a device may stay silent before we ask it for an attribute. A device whose
        reporting the firmware refused cannot tell us about a physical press, so it is asked far
        more often than one that reports for itself."""
        if any(not str(r.get("status", "")).startswith("ok") for r in (dev.reporting or [])):
            return self.UNREPORTED_POLL_AFTER_S
        return self.ROUTER_POLL_AFTER_S

    def _has_state_cluster(self, dev: Device) -> bool:
        return any(c in ep.in_clusters for ep in dev.endpoints.values() for c in (*self._REFRESH_CLUSTERS, vz.TUYA_CLUSTER))

    async def _poll_silent_routers(self) -> None:
        """Mains devices that have not said what they ARE for a while are asked. Not "heard from":
        a plug that reports its power every ten seconds is heard constantly and says nothing about
        whether someone pressed its button; a device whose binding failed never says. The poll
        goes by the last on/off, level, cover, thermostat or colour evidence, reads every endpoint
        that carries such a cluster (a two-gang switch has two answers), and a device that fails
        two polls in a row is offline until it is heard again — a bulb cut from power at the wall
        must not keep showing ON. Their pending binding/reporting setup runs on that contact."""
        now = time.time()
        for dev in self.registry.all():
            if not (dev.is_router or dev.rx_on_when_idle) or not dev.nwk or not dev.endpoints:
                continue
            if dev.ieee in self._interview_tasks or dev.ieee in self._refresh_tasks:
                continue
            if now < self._poll_not_before.get(dev.ieee, 0.0):
                continue
            # A device with nothing to switch is asked for its name when silent: that keeps its
            # last-seen and link quality honest, which is all there is to know about it.
            since = self._state_evidence.get(dev.ieee, 0.0) if self._has_state_cluster(dev) else (dev.last_seen or 0.0)
            if since and now - since < self._poll_after(dev):
                continue
            heard = await self._refresh_state(dev)
            if not heard:
                n = self._poll_failures[dev.ieee] = self._poll_failures.get(dev.ieee, 0) + 1
                first_miss = self._poll_first_miss.setdefault(dev.ieee, now)
                log.debug("%s: poll %d unanswered", dev.ieee_str, n)
                if n >= self.OFFLINE_AFTER_FAILED_POLLS:
                    backoff = self.POLL_BACKOFF_S[min(n - self.OFFLINE_AFTER_FAILED_POLLS, len(self.POLL_BACKOFF_S) - 1)]
                    self._poll_not_before[dev.ieee] = now + backoff
                    if (dev.last_seen or 0.0) >= first_miss:
                        # It has been heard since the first miss: alive, just not answering what
                        # we ask (its reports reach us, our unicasts do not reach it). Offline
                        # would be a lie that flips back on its next report - and every flip
                        # makes the consumers ask for its state again. It stays online with the
                        # state it last reported, and is asked less and less often.
                        if dev.ieee not in self._unanswering_noted:
                            self._unanswering_noted.add(dev.ieee)
                            log.info("%s: reports but does not answer reads (%d misses) - kept online, asked again in %d min; "
                                     "check its link quality and route", dev.friendly_name, n, backoff // 60)
                            self.audit.event("device_not_answering_reads", ieee=dev.ieee_str, polls=n, next_poll_s=backoff)
                    elif dev.available:
                        dev.available = False
                        self._dirty = True
                        await self._publish_availability(dev, False)
                        self._emit_device_event("offline", dev)
                        self.audit.event("device_unanswering", ieee=dev.ieee_str, polls=n)
            await asyncio.sleep(0.5)

    def _load_activity(self) -> None:
        if not self._activity_path or not self._activity_path.exists():
            return
        try:
            import collections
            with open(self._activity_path, "rb") as f:
                tail = collections.deque(f, maxlen=5000)
            for line in tail:
                try:
                    self.activity.append(json.loads(line))
                except ValueError:
                    continue
        except OSError:
            log.debug("activity.log unreadable", exc_info=True)

    def query_activity(self, *, device: str | None = None, key: str | None = None, n: int = 200) -> list[dict[str, Any]]:
        out = []
        for rec in reversed(self.activity):
            if device and rec.get("ieee") != device and rec.get("friendly_name") != device:
                continue
            if key and rec.get("key") != key:
                continue
            out.append(rec)
            if len(out) >= n:
                break
        out.reverse()
        return out

    async def stop(self) -> None:
        if self._locate_task:
            self._locate_task.cancel()
        if self._monitor_task:
            self._monitor_task.cancel()
        self._save_profiles()
        for t in self._interview_tasks.values():
            t.cancel()
        for t in self._timers.values():
            t.cancel()
        for t in self._refresh_tasks.values():
            t.cancel()
        self._save_if_dirty()
        await self.broker.publish(f"{self.base}/bridge/state", self.topics.bridge_state_payload(False), retain=True)

    async def coordinator_lost(self) -> None:
        """The radio is gone: nothing we show can be trusted from here on. Say so on bridge/state
        (Home Assistant marks every device unavailable) rather than keep the last word of each."""
        await self.broker.publish(f"{self.base}/bridge/state", self.topics.bridge_state_payload(False), retain=True)

    async def coordinator_back(self) -> None:
        """The radio is back: everything may have happened meanwhile. Go online and ask."""
        await self.broker.publish(f"{self.base}/bridge/state", self.topics.bridge_state_payload(True), retain=True)
        if self._refresh_task is None or self._refresh_task.done():
            self._refresh_task = asyncio.create_task(self._refresh_all_states(), name="state-refresh")

    # ------------------------------------------------------------ events --

    def _on_audit(self, rec: dict[str, Any]) -> None:
        topic = f"{self.base}/bridge/{'security' if rec['level'] == 'security' else 'event'}"
        payload = json.dumps({k: v for k, v in rec.items() if k != "prev"}).encode()
        asyncio.create_task(self.broker.publish(topic, payload, retain=rec["level"] == "security"))
        if rec["type"] in ("permit_join_opened", "permit_join_closed"):
            asyncio.create_task(self._publish_permit_join())

    async def _on_joined(self, j: JoinedDevice) -> None:
        dev = self.registry.add_or_update(j.ieee, j.nwk, is_router=bool(j.capabilities & 0x02),
                                          rx_on_when_idle=bool(j.capabilities & 0x08))
        dev.available = True
        dev.last_seen = time.time()
        if dev.friendly_name == dev.ieee_str and "discovery_topics" not in dev.context:
            # New to Home Assistant and nameless: wait for a name before it is announced there,
            # so the entity id HA creates once - from the first name it sees - is the friendly one
            # (binary_sensor.back_door_contact, not binary_sensor.0x00158d00000000d3_contact).
            dev.context["ha_name_hold"] = time.time()
        await self._publish_availability(dev, True)
        self._emit_device_event("joined", dev)
        if self._rotation is not None and self._rotation.running:
            self._rotation.note_new_device(dev)
        if j.plain_join and self.rotation_policy.after_plain_join:
            dev.context["rotate_after_join"] = True
        # A device that JOINS through a pairing window was factory-reset or re-paired: its
        # reporting, bindings and IAS enrolment died with its old life, so the interview re-runs.
        # A REJOIN is different: the device merely came back (power cut, parent change, a wobble)
        # with its configuration intact. Re-interviewing those turned every stumble into a storm —
        # the interview's burst of reads and writes is real load, a marginal device reboots under
        # it, reboots rejoin, and each rejoin used to start the next interview. A rejoining device
        # that was never interviewed is still completed.
        if not (j.rejoin and dev.interviewed):
            self._start_interview(dev)
        elif dev.is_router or dev.rx_on_when_idle:
            # It came back from something - most often a power cut - and may well have come back
            # in another state than it left (a bulb switched at the wall is ON when power returns).
            self._schedule_refresh(dev)

    async def _maybe_rotate_after_join(self, dev: Device) -> None:
        """A device paired without an install code received the network key under the public key,
        so a sniffer present at that moment may hold it. Now that the device has its own link key
        (trust-centre key exchange is mandatory here), rotate the network key over the air: the new
        key reaches every device under per-device keys and the exposed one dies within minutes."""
        if not dev.context.pop("rotate_after_join", False) or not self.rotation_policy.after_plain_join:
            return
        # One rotation per pairing session: every plain join re-arms the timer; the rotation
        # starts once the session has been quiet for a while and no join window is open. A device
        # that joins while a rotation already runs is adopted by it (note_new_device), so nobody
        # ends up on the wrong side of the switch.
        if self._rotate_debounce is not None:
            self._rotate_debounce.cancel()
        self.audit.event("key_rotation_scheduled", ieee=dev.ieee_str, quiet_s=self.ROTATE_AFTER_JOIN_QUIET_S)
        self._rotate_debounce = asyncio.create_task(self._rotate_when_quiet(), name="rotate-after-join")

    async def _rotate_when_quiet(self) -> None:
        while True:
            await asyncio.sleep(self.ROTATE_AFTER_JOIN_QUIET_S)
            if self.coord.guard.window is None:
                break
        self._rotate_debounce = None
        self._start_policy_rotation()

    def _maybe_scheduled_rotation(self) -> None:
        """Rotate on a schedule, not only after joins: an old key is a standing target. Same
        evidence engine; skipped while a pairing session or another rotation is active."""
        days = self.rotation_policy.every_days
        if not days or not self._started:
            return
        s = self.coord.secrets
        if s.last_rotation_ts is None:
            # No birthdate on record (imported network, older keystore): start the clock now.
            s.last_rotation_ts = time.time()
            self.coord._persist_secrets()
            return
        if time.time() - s.last_rotation_ts < days * 86400:
            return
        if self.coord.guard.window is not None or self._rotate_debounce is not None:
            return
        if self._rotation is not None and self._rotation.running:
            return
        self.audit.security("scheduled_key_rotation_due", days=days)
        self._start_policy_rotation(by="policy:scheduled")

    def _rotation_policy_file(self) -> Path:
        return self.cfg.data_dir / "rotation_policy.json"

    async def _req_rotation_policy(self, body: dict[str, Any], who: str) -> dict[str, Any]:
        """Read or change when the key rotates by itself. Live: no restart. Switching an automatic
        rotation off also stops the one it may be running right now — a rotation nobody asked for
        any more should not keep knocking on sleeping devices for hours."""
        from .rotation import RotationPolicy
        patch = body.get("policy")
        if patch is not None:
            # anyone may read the policy (the UI shows it); changing it is a control action
            bare = who.split(":", 1)[1] if who.startswith("ui:") else who
            if bare not in self.control_users:
                self.audit.security("request_denied", action="rotation_policy", by=who, reason="user not in control_users")
                raise PermissionError("not authorized")
            new = RotationPolicy.from_json(patch, self.rotation_policy)
            if new != self.rotation_policy:
                try:
                    new.save(self._rotation_policy_file())
                except OSError as e:
                    raise ValueError(f"policy not saved: {e}") from e
                self.rotation_policy = new
                self.audit.security("key_rotation_policy_changed", by=who, **new.to_json())
                stopped = None
                if not new.after_plain_join and self._rotate_debounce is not None:
                    self._rotate_debounce.cancel()
                    self._rotate_debounce = None
                running = self._rotation is not None and self._rotation.running
                if running and ((not new.after_plain_join and self._rotation.state.by == "policy:rotate_after_plain_join")
                                or (not new.every_days and self._rotation.state.by == "policy:scheduled")):
                    stopped = self._rotation.state.by
                    self._rotation.cancel()
                    self.audit.security("network_key_rotation_cancelled_by_policy", by=who, was=stopped)
                return {"policy": self.rotation_policy.to_json(), "stopped": stopped, **self._rotation_policy_facts()}
        return {"policy": self.rotation_policy.to_json(), **self._rotation_policy_facts()}

    def _rotation_policy_facts(self) -> dict[str, Any]:
        running = self._rotation is not None and self._rotation.running
        return {"last_rotation_ts": getattr(self.coord.secrets, "last_rotation_ts", None),
                "running_by": self._rotation.state.by if running else None,
                "configured": {"after_plain_join": self.cfg.zigbee.rotate_key_after_plain_join, "every_days": self.cfg.zigbee.rotation_interval_days}}

    def _start_policy_rotation(self, by: str = "policy:rotate_after_plain_join") -> None:
        from .rotation import KeyRotation
        from .security import Keystore
        if self._rotation is None:
            self._rotation = KeyRotation(self.coord, self.registry, Keystore(self.cfg.data_dir / "network.keystore"), self.audit,
                                         require_all=self.cfg.zigbee.rotation_require_all, max_window_s=self.cfg.zigbee.rotation_max_window_seconds)
        if self._rotation.running:
            return
        try:
            self._rotation.start(window_s=300, by=by)
            if by == "policy:rotate_after_plain_join":
                self.audit.security("key_rotation_after_plain_join")
        except ValueError as e:
            log.info("policy rotation not started: %s", e)

    async def _on_left(self, ieee: int, nwk: int, rejoin: bool = False) -> None:
        """A device announced that it is leaving. That is routine Zigbee life, not a goodbye: a
        leave with the rejoin flag IS how a device re-attaches (new parent, recovered link, a key
        change), and even a plain leave is usually someone resetting a device that will come back
        wanting its name and its room. So the device is kept and marked offline. Forgetting one is
        the user's decision (Remove), never a side effect of a frame on the air — and because it
        stays known, its rejoin is recognised instead of being evicted as an intruder."""
        dev = self.registry.get(ieee)
        if dev is None:
            return
        was = dev.available
        dev.available = False
        self.registry.save()
        if was:
            await self._publish_availability(dev, False)
        self.audit.event("device_offline_after_leave", ieee=dev.ieee_str, rejoin=rejoin)
        self._emit_device_event("offline", dev)

    def _start_interview(self, dev: Device) -> None:
        old = self._interview_tasks.get(dev.ieee)
        if old is not None and not old.done():
            # one interview at a time: announces arrive in pairs and every restart used to cancel
            # the running interview and begin again, so a flapping device was interviewed forever
            return
        self._interview_tasks[dev.ieee] = asyncio.create_task(self._interview(dev), name=f"interview-{dev.ieee_str}")

    # --------------------------------------------------------- interview --

    async def _interview(self, dev: Device) -> None:
        try:
            if dev.nwk == 0:
                # Short address unknown (imported without its database): 0 is the coordinator
                # itself, so never interview it — resolve the device's real address first.
                nwk = await self.coord.nwk_lookup(dev.ieee)
                if nwk is None:
                    raise ZnpError("device did not answer the address lookup (asleep or out of reach); "
                                   "it is interviewed automatically when it next reports")
                self.registry.add_or_update(dev.ieee, nwk)
            self.audit.event("interview_started", ieee=dev.ieee_str, nwk=f"{dev.nwk:#06x}")
            nd = await self.coord.node_descriptor(dev.nwk)
            if nd.status == 0:
                dev.context["manufacturer_code"] = nd.manufacturer_code
            eps = await self.coord.active_endpoints(dev.nwk)
            dev.endpoints.clear()
            for ep in eps:
                sd = await self.coord.simple_descriptor(dev.nwk, ep)
                desc = zcl.describe_endpoint(sd.in_clusters, sd.out_clusters, sd.device_id, sd.profile)
                from .devices import Endpoint
                dev.endpoints[ep] = Endpoint(ep, sd.profile, sd.device_id, sd.in_clusters, sd.out_clusters, desc["category"])
            prim = dev.primary_endpoint()
            basic_ep = next((e.id for e in dev.endpoints.values() if 0x0000 in e.in_clusters), prim.id if prim else 1)
            try:
                attrs = await self.read_attributes(dev, basic_ep, 0x0000, _BASIC_ATTRS)
            except (ZnpError, asyncio.TimeoutError) as e:
                log.info("%s: basic cluster read failed (%s); continuing without identity", dev.ieee_str, e)
                attrs = {}
            dev.manufacturer = attrs.get("manufacturer_name") or dev.manufacturer
            dev.model = attrs.get("model_id") or dev.model
            dev.sw_build = attrs.get("sw_build_id") or dev.sw_build
            dev.power_source = attrs.get("power_source") if isinstance(attrs.get("power_source"), str) else dev.power_source
            dev.hw_version = attrs.get("hw_version", dev.hw_version)
            dev.date_code = attrs.get("date_code", dev.date_code)
            dev.zcl_version = attrs.get("zcl_version", dev.zcl_version)
            dev.app_version = attrs.get("app_version", dev.app_version)
            dev.stack_version = attrs.get("stack_version", dev.stack_version)
            dev.interview_error = None

            policy = quirks.binding_policy(dev)  # None = default clusters, () = the model rejects binds
            reads, reports = quirks.extra_reads(dev), quirks.extra_reporting(dev)
            for ep in dev.endpoints.values():
                for cluster in ep.in_clusters:
                    if cluster == 0x0500:
                        await self._enroll_ias(dev, ep.id)
                    attrs = list(_READ_ON_JOIN.get(cluster, [])) + [a for a in reads.get(cluster, ()) if a not in _READ_ON_JOIN.get(cluster, [])]
                    if attrs:
                        try:
                            state = await self.read_attributes(dev, ep.id, cluster, attrs)
                            self._apply_changes(dev, quirks.translate_state(dev, ep.id, state))
                        except (ZnpError, asyncio.TimeoutError):
                            log.info("%s: read %s failed (sleepy device?)", dev.ieee_str, zcl.cluster_name(cluster))
                    if (cluster in _REPORTING or cluster in reports) and self._may_bind(policy, cluster):
                        await self._setup_reporting(dev, ep.id, cluster)
                if vz.TUYA_CLUSTER in ep.in_clusters:
                    await self._tuya_query(dev, ep.id)
            dev.interviewed = True
            dev.last_seen = time.time()
            self.registry.save()
            await self._vendor_settle(dev)
            self.audit.event("interview_done", ieee=dev.ieee_str, manufacturer=dev.manufacturer, model=dev.model,
                             endpoints={str(e.id): e.category for e in dev.endpoints.values()})
            await self._announce(dev)
            await self._publish_state(dev)
            await self._publish_bridge_info()
            self._emit_device_event("interviewed", dev)
            await self._maybe_rotate_after_join(dev)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            sleepy = not (dev.is_router or dev.rx_on_when_idle)
            known = bool(dev.model) and quirks.describe(dev).quirk is not None
            if sleepy and known and isinstance(e, (ZnpError, asyncio.TimeoutError)):
                # A battery device answers one request and sleeps again; its features come from model
                # knowledge, so the descriptors add nothing. Consider it described and stop retrying.
                dev.interviewed = True
                dev.interview_error = None
                dev.context["described_by"] = "model"
                self.audit.event("interview_done", ieee=dev.ieee_str, manufacturer=dev.manufacturer, model=dev.model,
                                 described_by="model knowledge", note=f"descriptors not read ({e})")
                self.registry.save()
                await self._announce(dev)
                self._emit_device_event("interviewed", dev)
                return
            log.warning("interview of %s failed: %s", dev.ieee_str, e)
            dev.interview_error = str(e)
            dev.context.pop("reporting_done", None)  # try again when the device next talks …
            dev.context["interview_retry_at"] = time.time() + 600  # … but not before 10 minutes have passed
            self.audit.event("interview_failed", ieee=dev.ieee_str, error=str(e))
            self.registry.save()
        finally:
            self._interview_tasks.pop(dev.ieee, None)

    async def _post_import_setup(self, dev: Device) -> None:
        """Imported devices kept their pairing but never bound to us; bind + configure reporting
        the first time they talk, and fill in any missing identity."""
        try:
            if not dev.manufacturer or not dev.model:
                prim = dev.primary_endpoint()
                if prim:
                    attrs = await self.read_attributes(dev, prim.id, 0x0000, _BASIC_ATTRS)
                    dev.manufacturer = attrs.get("manufacturer_name") or dev.manufacturer
                    dev.model = attrs.get("model_id") or dev.model
            policy = quirks.binding_policy(dev)
            reports = quirks.extra_reporting(dev)
            for ep in dev.endpoints.values():
                for cluster in ep.in_clusters:
                    if (cluster in _REPORTING or cluster in reports) and self._may_bind(policy, cluster):
                        await self._setup_reporting(dev, ep.id, cluster)
            self.registry.save()
            await self._vendor_settle(dev)
            self.audit.event("imported_device_configured", ieee=dev.ieee_str)
            await self._announce(dev)
        except (ZnpError, asyncio.TimeoutError) as e:
            dev.context["reporting_done"] = False  # try again next time it talks
            log.info("%s: post-import setup deferred: %s", dev.ieee_str, e)
        finally:
            self._interview_tasks.pop(dev.ieee, None)

    @staticmethod
    def _may_bind(policy: tuple[int, ...] | None, cluster: int) -> bool:
        return policy is None or cluster in policy

    @staticmethod
    def _reporting_to_retry(dev: Device) -> list[tuple[int, int]]:
        """(endpoint, cluster) pairs whose reporting setup failed for a reason worth retrying: a
        timeout or a refused bind. A ZCL status from the device ("unreportable attribute") is its
        final word and is not asked again."""
        out: list[tuple[int, int]] = []
        for r in dev.reporting or []:
            st = str(r.get("status", ""))
            if (st.startswith("failed") or st.startswith("bind failed")) and (r["endpoint"], r["cluster"]) not in out:
                out.append((r["endpoint"], r["cluster"]))
        return out

    async def _retry_reporting(self, dev: Device) -> None:
        try:
            policy = quirks.binding_policy(dev)
            done = 0
            for ep, cluster in self._reporting_to_retry(dev):
                if ep not in dev.endpoints or not self._may_bind(policy, cluster):
                    continue
                await self._setup_reporting(dev, ep, cluster)
                done += 1
            if done:
                still = self._reporting_to_retry(dev)
                self.audit.event("reporting_retried", ieee=dev.ieee_str, clusters=done, remaining=len(still))
                self.registry.save()
        finally:
            self._interview_tasks.pop(dev.ieee, None)

    async def _tuya_query(self, dev: Device, ep: int) -> None:
        """Ask a Tuya datapoint device to report every datapoint (dataQuery)."""
        try:
            await self.coord.send_aps(dev.nwk, ep, vz.TUYA_CLUSTER, gc.build_cluster_command(self._next_seq(), vz.TUYA_CMD_QUERY, b"", disable_default_response=True), wait_confirm=False)
        except (ZnpError, asyncio.TimeoutError) as e:
            log.info("%s: datapoint query failed: %s", dev.ieee_str, e)

    _TUYA_SETTLE_ATTRS = [0x0004, 0x0000, 0x0001, 0x0005, 0x0007, 0xFFFE]

    async def _vendor_settle(self, dev: Device) -> None:
        """Vendor-specific one-off after configuration.

        Tuya mains devices keep reporting a Basic cluster attribute every 200 ms until the
        coordinator has read this attribute set once. Aqara/Xiaomi devices carry their private
        cluster (0xFCC0) and need ``mode = 1`` written there with the LUMI manufacturer code —
        the same write zigbee2mqtt performs on every configure. It tells the device it lives on
        a Zigbee hub: without it, some models keep waiting for the proprietary Mi Home presence
        protocol, decide no hub is there, and say so on their indicator LED — while still
        answering commands perfectly."""
        manufacturer = str(dev.manufacturer or "")
        if manufacturer.startswith("_TZ"):
            prim = dev.primary_endpoint()
            ep = next((e.id for e in dev.endpoints.values() if 0x0000 in e.in_clusters), prim.id if prim else 1)
            try:
                await self.read_attributes(dev, ep, 0x0000, self._TUYA_SETTLE_ATTRS)
                self._settled.add(dev.ieee)
            except (ZnpError, asyncio.TimeoutError) as e:
                log.info("%s: Tuya settle read failed (%s)", dev.ieee_str, e)
            return
        lumi = manufacturer.upper() in ("LUMI", "AQARA") or str(dev.model or "").startswith("lumi.")
        if lumi:
            # Xiaomi devices answer on their private cluster without declaring it in the simple
            # descriptor, so the endpoint list cannot be trusted as a gate — zigbee2mqtt writes to
            # endpoint 1 unconditionally, and so do we when the cluster is not declared anywhere.
            prim = dev.primary_endpoint()
            lumi_ep = next((e.id for e in dev.endpoints.values() if 0xFCC0 in e.in_clusters),
                           prim.id if prim else 1)
            try:
                await self._write_attr(dev, lumi_ep, 0xFCC0, 0x0009, zcl.DataType.uint8, 1,
                                       manufacturer=vz.LUMI_MANUFACTURER_CODE)
                self.audit.event("lumi_zigbee_mode_set", ieee=dev.ieee_str)
            except (ZnpError, asyncio.TimeoutError) as e:
                # not every model has the attribute; a refusal is fine, silence was the problem
                log.info("%s: lumi mode write not accepted (%s)", dev.ieee_str, e)

    @staticmethod
    def _reporting_records(dev: Device, cluster: int) -> list[tuple[int, zcl.DataType, int, int, Any]]:
        """Standard-cluster defaults plus whatever the model table adds (device-specific clusters)."""
        rows = list(_REPORTING.get(cluster, []))
        have = {r[0] for r in rows}
        rows += [r for r in quirks.extra_reporting(dev).get(cluster, ()) if r[0] not in have]
        return rows

    async def _configure_reporting(self, dev: Device, ep: int, cluster: int,
                                   rows: list[tuple[int, Any, int, int, Any]]) -> str:
        records = [gc.ReportingConfigRecord(attr=a, dtype=int(dt), min_interval=mn, max_interval=mx, reportable_change=ch)
                   for a, dt, mn, mx, ch in rows]
        seq = self._next_seq()
        rsp = await self._request(dev, ep, cluster, gc.build_configure_reporting(seq, records), seq, gc.CMD_CONFIGURE_REPORTING_RSP)
        try:
            dec = gc.decode_global_command(rsp)
            bad = [r for r in getattr(dec, "records", []) if getattr(r, "status", 0) != 0]
            if bad:
                return f"status {bad[0].status:#04x}"
        except Exception:
            pass
        return "ok"

    async def _setup_reporting(self, dev: Device, ep: int, cluster: int) -> None:
        rows = self._reporting_records(dev, cluster)
        try:
            bound = await self.coord.bind(dev.nwk, dev.ieee, ep, cluster)
            if bound != 0:
                # The device said no (a full binding table, an endpoint that does not bind). It
                # will never tell us about a physical press: say so, so it is polled instead, and
                # never call this "ok" - that is how a light shows ON hours after the wall switch.
                log.info("%s: bind of endpoint %d %s refused by the device (ZDO status %#04x)",
                         dev.ieee_str, ep, zcl.cluster_name(cluster), bound)
                for a, _dt, mn, mx, ch in rows:
                    self._record_reporting(dev, ep, cluster, a, mn, mx, ch, f"bind failed ({bound:#04x})")
                return
            status = await self._configure_reporting(dev, ep, cluster, rows)
            if status != "ok":
                # Some firmware refuses a zero minimum interval with a generic failure — Aqara wall
                # switches do it on their secondary gang. One second between reports is immediate
                # in practice and is accepted where zero is not, so it is worth one retry before
                # the device is written off as unable to report.
                retry = [(a, dt, max(1, mn), mx, ch) for a, dt, mn, mx, ch in rows]
                if retry != rows:
                    again = await self._configure_reporting(dev, ep, cluster, retry)
                    log.info("%s: reporting on endpoint %d %s refused (%s); retry with a one second minimum: %s",
                             dev.ieee_str, ep, zcl.cluster_name(cluster), status, again)
                    if again == "ok":
                        rows, status = retry, "ok"
                    else:
                        status = f"{status} (retry {again})"
            self._record_bindings(dev, ep, cluster, "coordinator", 1)
            for a, _dt, mn, mx, ch in rows:
                self._record_reporting(dev, ep, cluster, a, mn, mx, ch, status)
        except (ZnpError, asyncio.TimeoutError) as e:
            log.info("%s: reporting setup for %s failed: %s", dev.ieee_str, zcl.cluster_name(cluster), e)
            for a, _dt, mn, mx, ch in rows:
                self._record_reporting(dev, ep, cluster, a, mn, mx, ch, f"failed: {e}")

    def _record_reporting(self, dev: Device, ep: int, cluster: int, attr: int, mn: int, mx: int, ch: Any, status: str) -> None:
        dev.reporting = [r for r in dev.reporting if not (r["endpoint"] == ep and r["cluster"] == cluster and r["attribute"] == attr)]
        c = zcl.get_cluster(cluster)
        a = c.attributes.get(attr) if c else None
        dev.reporting.append({"endpoint": ep, "cluster": cluster, "cluster_name": zcl.cluster_name(cluster), "attribute": attr,
                              "attribute_name": a.name if a else f"0x{attr:04x}", "min": mn, "max": mx, "change": ch, "status": status})

    def _record_bindings(self, dev: Device, ep: int, cluster: int, target: str, target_ep: int) -> None:
        if not any(b["endpoint"] == ep and b["cluster"] == cluster and b["target"] == target for b in dev.bindings):
            dev.bindings.append({"endpoint": ep, "cluster": cluster, "cluster_name": zcl.cluster_name(cluster), "target": target, "target_endpoint": target_ep})

    async def _enroll_ias(self, dev: Device, ep: int) -> None:
        """Write our IEEE as CIE address and send an enroll response (zone id = 1)."""
        try:
            seq = self._next_seq()
            frame = gc.build_write_attributes(seq, [gc.WriteAttributeRecord(0x0010, int(zcl.DataType.eui64), self.coord.ieee)])
            await self._request(dev, ep, 0x0500, frame, seq, gc.CMD_WRITE_ATTRIBUTES_RSP)
        except (ZnpError, asyncio.TimeoutError) as e:
            log.info("%s: IAS CIE write failed: %s", dev.ieee_str, e)
        try:
            cmd, payload = zcl.encode_command(0x0500, "zone_enroll_response", {"enroll_response_code": 0, "zone_id": 1})
            await self.coord.send_aps(dev.nwk, ep, 0x0500, gc.build_cluster_command(self._next_seq(), cmd, payload))
        except (ZnpError, asyncio.TimeoutError) as e:
            log.info("%s: IAS enroll response failed: %s", dev.ieee_str, e)

    # ------------------------------------------------------------ zcl io --

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) % 256
        return self._seq

    async def _request(self, dev: Device, ep: int, cluster: int, frame: bytes, seq: int, expect_cmd: int,
                       timeout: float = 10.0) -> zcl.ZclFrame:
        key = (dev.nwk, seq, cluster)
        fut: asyncio.Future[zcl.ZclFrame] = asyncio.get_running_loop().create_future()
        fut.expect_cmd = expect_cmd  # type: ignore[attr-defined]
        self._pending_rsp[key] = fut
        try:
            await self.coord.send_aps(dev.nwk, ep, cluster, frame)
            rsp = await asyncio.wait_for(fut, timeout)
        finally:
            self._pending_rsp.pop(key, None)
        if rsp.frame_type == zcl.FRAME_TYPE_GLOBAL and rsp.command == gc.CMD_DEFAULT_RESPONSE and expect_cmd != gc.CMD_DEFAULT_RESPONSE:
            dr = gc.decode_global_command(rsp)
            raise ZnpError(f"device answered default response status {dr.status:#04x}")
        return rsp

    async def read_attributes(self, dev: Device, ep: int, cluster: int, attrs: list[int]) -> dict[str, Any]:
        seq = self._next_seq()
        rsp = await self._request(dev, ep, cluster, gc.build_read_attributes(seq, attrs), seq, gc.CMD_READ_ATTRIBUTES_RSP)
        decoded = gc.decode_global_command(rsp)
        return self._decode_records(dev, ep, cluster, [r for r in decoded.records if r.status == gc.STATUS_SUCCESS])

    def _decode_records(self, dev: Device, ep: int, cluster: int, records: list[Any]) -> dict[str, Any]:
        """Vendor-private attributes first (Aqara reports, Tuya private attrs), the standard cluster decoders for the rest."""
        pairs = [(r.attr, r.value) for r in records]
        self._track_raw(dev, cluster, pairs)
        state, used = quirks.decode_vendor_attributes(dev, ep, cluster, [(r.attr, getattr(r, "dtype", None), r.value, getattr(r, "raw", None)) for r in records])
        rest = [(a, v) for a, v in pairs if a not in used]
        if rest:
            state = {**zcl.decode_attributes(cluster, rest, dev.context), **state}
        return state

    def _track_raw(self, dev: Device, cluster: int, pairs: list[tuple[int, Any]]) -> None:
        c = zcl.get_cluster(cluster)
        bucket = dev.raw.setdefault(str(cluster), {})
        for attr, value in pairs:
            a = c.attributes.get(attr) if c else None
            if isinstance(value, (bytes, bytearray)):
                value = value.hex()
            bucket[str(attr)] = {"name": a.name if a else f"0x{attr:04x}", "value": value, "ts": time.time()}


    async def _on_aps(self, m: IncomingAps) -> None:
        dev = self.registry.by_nwk(m.src_addr)
        if dev is None:
            dev = await self._resolve_unknown_short(m.src_addr)
        if dev is None:
            # Traffic from a short address we do not know: the firmware authenticated it (it is on
            # our network), but we have no record. Remember it so the owner can adopt or evict it.
            known = next((r for r in self.unknown_devices.values() if r.get("nwk") == f"{m.src_addr:#06x}"), None)
            if known is not None:
                known["frames"] += 1
                known["last_seen"] = time.time()
                known["lqi"] = m.lqi
                if f"{m.cluster:#06x}" not in known["clusters"]:
                    known["clusters"].append(f"{m.cluster:#06x}")
                if known["frames"] in (1, 10, 100, 1000):  # one alert, then decreasingly often
                    self.audit.security("traffic_from_unknown_device", ieee=known["ieee"], nwk=known["nwk"], vendor=known.get("vendor"),
                                        cluster=f"{m.cluster:#06x}", frames=known["frames"],
                                        hint="see Pair → Unknown devices to adopt or evict")
            else:
                self.audit.security("traffic_from_unknown_device", nwk=f"{m.src_addr:#06x}", cluster=f"{m.cluster:#06x}")
            return
        dev.last_seen = time.time()
        dev.lqi = m.lqi
        if self._rotation is not None and self._rotation.running:
            self._rotation.device_heard(dev)  # a sleeping device is awake: hand it the new key now
        if not dev.available:
            # Heard from it: it is online, whatever its import/registry state said. Its poll
            # bookkeeping starts over and it is asked what it IS now - a device that was cut from
            # power came back in whatever state its firmware chose. A device that is online and
            # merely fails our reads keeps its backoff: this frame is one more report, not an
            # answer, and clearing the backoff on every report is what made such a device flap
            # offline/online all night.
            dev.available = True
            self._dirty = True
            self._poll_failures.pop(dev.ieee, None)
            self._poll_first_miss.pop(dev.ieee, None)
            self._poll_not_before.pop(dev.ieee, None)
            await self._publish_availability(dev, True)
            self._emit_device_event("online", dev)
            if dev.is_router or dev.rx_on_when_idle:
                self._schedule_refresh(dev)
        if (str(dev.manufacturer or "").startswith("_TZ") and dev.ieee not in self._settled
                and dev.ieee not in self._interview_tasks and dev.context.get("reporting_done")):
            self._settled.add(dev.ieee)  # once per device per start (the device forgets it on its own power cycle)
            asyncio.create_task(self._vendor_settle(dev), name=f"settle-{dev.ieee_str}")
        if (dev.context.get("imported_from") and not dev.context.get("reporting_done") and dev.ieee not in self._interview_tasks
                and time.time() >= dev.context.get("interview_retry_at", 0)):
            dev.context["reporting_done"] = True  # set first so a burst of frames schedules it once
            if dev.endpoints and dev.interviewed:
                self._interview_tasks[dev.ieee] = asyncio.create_task(self._post_import_setup(dev), name=f"post-import-{dev.ieee_str}")
            else:
                self._start_interview(dev)  # no endpoints, or never marked interviewed: learn/confirm now
        elif (dev.interviewed and dev.endpoints and dev.ieee not in self._interview_tasks
              and time.time() >= dev.context.get("reporting_retry_at", 0) and self._reporting_to_retry(dev)):
            # Its reporting setup did not get through last time (it fell asleep mid-interview, the
            # radio timed out, the bind was refused). It is talking now, so it is listening now:
            # the only moment a battery device can be configured at all.
            dev.context["reporting_retry_at"] = time.time() + self.REPORTING_RETRY_S
            self._interview_tasks[dev.ieee] = asyncio.create_task(self._retry_reporting(dev), name=f"reporting-retry-{dev.ieee_str}")
        # m.secure is the *APS-layer* flag; ordinary ZCL traffic is NWK-encrypted only,
        # so it is informational, not an alert. NWK security is enforced by the firmware.
        try:
            frame = zcl.decode_frame(m.payload)
        except zcl.ZclFrameError as e:
            log.debug("%s: undecodable ZCL on %#06x: %s", dev.ieee_str, m.cluster, e)
            return

        if log.isEnabledFor(logging.DEBUG):
            # the wire, one line per frame: with `log_level: debug` the Logs page (filtered to a
            # device) shows exactly what it sends and asks — which decides between "it wants an
            # answer we do not give" and "it is not transmitting at all"
            log.debug("%s: <- ep%d cluster %#06x cmd %#04x %s dir=%d%s seq=%d lqi=%d len=%d",
                      dev.friendly_name or dev.ieee_str, m.src_ep, m.cluster, frame.command,
                      "cluster" if frame.frame_type == zcl.FRAME_TYPE_CLUSTER else "global",
                      frame.direction, "" if frame.disable_default_response else " wants-rsp",
                      frame.seq, m.lqi, len(frame.payload))
        if m.cluster == 0x0000:
            # Basic-cluster chatter (vendor heartbeats, identity reads) says nothing about behaviour;
            # only its link quality is worth keeping.
            self.monitor.observe(dev.ieee, seq=None, lqi=m.lqi, is_command=False,
                                 mains=bool(dev.is_router or dev.rx_on_when_idle), count=False)
        else:
            self.monitor.observe(dev.ieee, seq=frame.seq, lqi=m.lqi, is_command=bool(frame.is_cluster_specific and frame.direction == 0),
                                 mains=bool(dev.is_router or dev.rx_on_when_idle))
        fut = self._pending_rsp.get((m.src_addr, frame.seq, m.cluster))
        if (fut and not fut.done() and frame.direction == zcl.DIRECTION_SERVER_TO_CLIENT
                and frame.frame_type == zcl.FRAME_TYPE_GLOBAL
                and frame.command in (getattr(fut, "expect_cmd", -1), gc.CMD_DEFAULT_RESPONSE)):
            fut.set_result(frame)
            return

        changed: dict[str, Any] = {}
        if frame.frame_type == zcl.FRAME_TYPE_GLOBAL:
            if frame.command in (gc.CMD_REPORT_ATTRIBUTES, gc.CMD_READ_ATTRIBUTES_RSP):
                decoded = gc.decode_global_command(frame)
                changed = self._decode_records(dev, m.src_ep, m.cluster, [r for r in decoded.records if getattr(r, "status", 0) == 0])
                self._note_state_evidence(dev, m.cluster, changed)
                changed = quirks.translate_state(dev, m.src_ep, changed)
                if (frame.command == gc.CMD_REPORT_ATTRIBUTES
                        and not frame.disable_default_response and not m.group):
                    # The spec's receipt for a report that asked for one. Xiaomi and Aqara devices
                    # send reports with the default response requested and judge the hub by whether
                    # it arrives: a hub that stays silent is marked lost on the indicator LED even
                    # while commands keep working.
                    asyncio.create_task(self._default_response(dev, m, frame))
            elif frame.command == gc.CMD_READ_ATTRIBUTES:
                # A device asking us something. Silence is not an answer: it retries, decides the
                # gateway is unreachable and (Aqara, Xiaomi) says so on its indicator light.
                asyncio.create_task(self._answer_read(dev, m, frame))
                return
            elif frame.command not in _QUIET_GLOBALS and not frame.disable_default_response:
                # Anything else we do not implement gets the spec's answer, once, instead of
                # nothing at all — the device stops asking rather than escalating.
                asyncio.create_task(self._default_response(dev, m, frame,
                                                           status=gc.STATUS_UNSUP_GENERAL_COMMAND))
                return
        elif m.cluster == 0x0019 and frame.direction == zcl.DIRECTION_CLIENT_TO_SERVER:
            rsp = self.ota.handle(dev.ieee, dev.nwk, m.src_ep, frame.command, frame.payload)
            if rsp is not None:
                cmd_id, body = rsp
                out = gc.build_cluster_command(frame.seq, cmd_id, body, direction=zcl.DIRECTION_SERVER_TO_CLIENT,
                                               disable_default_response=True)
                asyncio.create_task(self.coord.send_aps(dev.nwk, m.src_ep, 0x0019, out, wait_confirm=False))
            return
        elif (m.cluster == 0x0020 and frame.frame_type == zcl.FRAME_TYPE_CLUSTER
              and frame.direction == zcl.DIRECTION_SERVER_TO_CLIENT and frame.command == 0x00):
            # Poll Control check-in: the device asks "hub, are you there?" on a timer and the
            # spec's answer is a Check-in Response (no fast polling). zigbee2mqtt's stack sends
            # it automatically; a device whose check-ins go unanswered concludes the hub is gone
            # — some say so on their indicator LED while still obeying every command.
            out = gc.build_cluster_command(frame.seq, 0x00, b"\x00\x00\x00",
                                           direction=zcl.DIRECTION_CLIENT_TO_SERVER,
                                           disable_default_response=True)
            asyncio.create_task(self.coord.send_aps(dev.nwk, m.src_ep, 0x0020, out, wait_confirm=False))
            first = (dev.ieee, 0x0020) not in self._answered
            self._answered.add((dev.ieee, 0x0020))
            (log.info if first else log.debug)("%s: answered a poll-control check-in",
                                               dev.friendly_name or dev.ieee_str)
            return
        elif m.cluster == vz.TUYA_CLUSTER and frame.direction == zcl.DIRECTION_SERVER_TO_CLIENT:
            changed = await self._tuya_report(dev, frame)
            self._note_state_evidence(dev, m.cluster, changed)
            if not frame.disable_default_response:
                asyncio.create_task(self._default_response(dev, m, frame))
        else:
            changed = zcl.decode_cluster_command(m.cluster, frame.command, frame.direction, frame.payload, dev.context)
            if m.cluster == 0x0500 and changed.get("command") == "zone_enroll_request":
                asyncio.create_task(self._enroll_ias(dev, m.src_ep))
            if not frame.disable_default_response and frame.direction == zcl.DIRECTION_SERVER_TO_CLIENT:
                asyncio.create_task(self._default_response(dev, m, frame))
            changed = {k: v for k, v in changed.items() if k not in ("command", "cluster") and not k.startswith("zone_")}
            if frame.direction == zcl.DIRECTION_CLIENT_TO_SERVER or m.cluster in (0xFC00, 0xFC80):
                # the device acts as a *client*: a remote, button or motion sensor sending commands to us
                changed.update(self._remote_event(dev, m, frame))
            changed = quirks.translate_state(dev, m.src_ep, changed)
        if changed:
            self._apply_changes(dev, changed)
            await self._publish_state(dev)
            if changed.get("action"):
                # an action is an event, not a state: publish it once more cleared so HA's sensor resets
                dev.state["action"] = ""
                await self._publish_state(dev)

    async def _tuya_report(self, dev: Device, frame: zcl.ZclFrame) -> dict[str, Any]:
        """Decode a datapoint report, remembering every datapoint id and wire type the device has shown
        (``context["tuya_seen"]``). A datapoint seen for the first time may change the feature list
        (inference, raw ``dp_<n>`` values), so the layout is refreshed and re-announced then."""
        if frame.command not in (vz.TUYA_CMD_DATA_RESPONSE, vz.TUYA_CMD_DATA_REPORT, vz.TUYA_CMD_STATUS_REPORT):
            return {}
        dps = vz.decode_tuya_datapoints(frame.payload)
        seen = dev.context.get(quirks_tuya.SEEN_KEY) or {}
        new = any(not isinstance(seen.get(str(dp)), dict) or seen[str(dp)].get("type") != t for dp, t, _ in dps)
        before = self._layout_of(dev) if new else None
        quirks_tuya.record_datapoints(dev, dps, time.time())
        changed = quirks.decode_tuya_values(dev, dps)
        if new:
            self.registry.save()
            await self._refresh_layout(dev, before)
        return changed

    def _layout_of(self, dev: Device) -> tuple[set[str], set[str]]:
        """``(discovery topics, feature keys)`` — what Home Assistant and the state payload currently see."""
        topics = {t for t, _ in discovery_messages(dev, self.base, self.cfg.homeassistant.discovery_prefix, legacy=self.legacy)} if self.cfg.homeassistant.discovery else set()
        return topics, {f["key"] for f in self._features(dev)}

    def layout_snapshot(self) -> dict[int, tuple[set[str], set[str]]]:
        return {d.ieee: self._layout_of(d) for d in self.registry.all()}

    async def _refresh_layout(self, dev: Device, before: tuple[set[str], set[str]] | None) -> bool:
        """Re-shape features after the model knowledge for a device changed: rebuild the datapoint-derived
        state from the last seen values, drop stale keys and entities, re-announce and republish."""
        feats = self._features(dev)
        keys = {f["key"] for f in feats}
        mapped = {f["dp"] for f in feats if "dp" in f and not f["key"].startswith("dp_")}
        seen = quirks_tuya.seen_datapoints(dev)
        rebuilt = quirks.decode_tuya_values(dev, [(dp, info["type"], info.get("last")) for dp, info in sorted(seen.items())]) if seen else {}
        stale = {f"dp_{dp}" for dp in mapped} | ((before[1] - keys) if before else set())
        for k in stale:
            dev.state.pop(k, None)
        moved = bool(stale & set(before[1])) if before else bool(stale)
        events = self._apply_changes(dev, rebuilt) if rebuilt else []
        topics, _ = self._layout_of(dev)
        if before is not None and before == (topics, keys) and not events and not moved:
            return False
        if before is not None:
            for t in before[0] - topics:
                await self.broker.publish(t, b"", retain=True)  # entity no longer exists: blank the retained config
        await self._announce(dev)
        await self._publish_state(dev)
        self._emit_device_event("interviewed", dev)
        return True

    async def apply_layout_changes(self, before: dict[int, tuple[set[str], set[str]]]) -> list[str]:
        """After definitions changed: refresh every device whose layout differs from ``before``."""
        refreshed: list[str] = []
        for dev in self.registry.all():
            if await self._refresh_layout(dev, before.get(dev.ieee)):
                refreshed.append(dev.ieee_str)
        self.registry.save()
        await self._publish_bridge_info()
        return refreshed

    def _remote_event(self, dev: Device, m: IncomingAps, frame: zcl.ZclFrame) -> dict[str, Any]:
        out: dict[str, Any] = {}
        info = quirks.describe(dev)
        action = quirks.remote_action(dev, m.src_ep, m.cluster, frame.command, frame.payload, frame.manufacturer)
        if info.quirk and info.quirk.on_off_as == "occupancy" and m.cluster == 0x0006 and frame.command in (0x01, 0x42):
            # on-with-timed-off from a motion sensor: occupied now, clear after on_time (1/10 s)
            out["occupancy"] = True
            secs = int.from_bytes(frame.payload[1:3], "little") / 10 if frame.command == 0x42 and len(frame.payload) >= 3 else 60
            self._schedule_clear(dev, "occupancy", max(1.0, min(secs, 3600.0)))
            return out
        if action and (info.category == "remote" or any(f["base"] == "action" for f in self._features(dev))):
            out["action"] = action
        return out

    def _features(self, dev: Device) -> list[dict[str, Any]]:
        from .features import features_for
        return features_for(dev)

    def _schedule_clear(self, dev: Device, key: str, secs: float) -> None:
        old = self._timers.pop((dev.ieee, key), None)
        if old:
            old.cancel()

        async def clear() -> None:
            await asyncio.sleep(secs)
            self._timers.pop((dev.ieee, key), None)
            self._apply_changes(dev, {key: False})
            await self._publish_state(dev)

        self._timers[(dev.ieee, key)] = asyncio.create_task(clear(), name=f"clear-{key}-{dev.ieee_str}")

    # Basic-cluster identity fields and vendor heartbeat attributes describe the device, not its
    # state: they go to the device record (About tab) and never into state/Activity/Home Assistant.
    _IDENTITY_KEYS = {"manufacturer_name", "model_id", "date_code", "sw_build_id", "zcl_version", "app_version",
                      "stack_version", "hw_version", "power_source", "battery_backup"}

    @staticmethod
    def _json_safe(v: Any) -> Any:
        """State must always be JSON-serializable: one bytes value would break the device list,
        state publishing and backups for every device."""
        if isinstance(v, (bytes, bytearray)):
            return bytes(v).hex()
        if isinstance(v, dict):
            return {k: Gateway._json_safe(x) for k, x in v.items()}
        if isinstance(v, (list, tuple)):
            return [Gateway._json_safe(x) for x in v]
        return v

    def _apply_changes(self, dev: Device, changed: dict[str, Any]) -> list[dict[str, Any]]:
        changed = {k: self._json_safe(v) for k, v in changed.items()}
        now = time.time()
        identity = {k: v for k, v in changed.items() if k in self._IDENTITY_KEYS or k.startswith("basic_0x")}
        if identity:
            changed = {k: v for k, v in changed.items() if k not in identity}
            for k, v in identity.items():
                if k == "sw_build_id":
                    dev.sw_build = v or dev.sw_build
                elif k == "model_id":
                    dev.model = v or dev.model
                elif k == "manufacturer_name":
                    dev.manufacturer = v or dev.manufacturer
                elif k in ("date_code", "hw_version", "zcl_version", "app_version", "stack_version", "power_source"):
                    setattr(dev, k, v)
                else:
                    dev.context.setdefault("basic_extra", {})[k] = v
            if not changed:
                return []
        events = dev.record_changes(changed, now)
        if events:
            self._dirty = True
        if dev.lqi is not None:
            dev.record_changes({"linkquality": dev.lqi}, now)
        for ev in events:
            rec = {"ieee": dev.ieee_str, "friendly_name": dev.friendly_name, **ev}
            self.activity.append(rec)
            if self._activity_path:
                try:
                    with open(self._activity_path, "a") as f:
                        f.write(json.dumps(rec, separators=(",", ":")) + "\n")
                except OSError:
                    log.debug("activity.log not writable", exc_info=True)
            if self.on_activity:
                try:
                    self.on_activity(dev.ieee, ev)
                except Exception:
                    log.exception("on_activity observer failed")
        return events

    async def _resolve_unknown_short(self, nwk: int) -> Device | None:
        """A known device (e.g. imported without its short address, or re-addressed after a
        rejoin we missed) may talk from a short address we have not seen. Ask the network once
        per minute per address; adopt it only if the IEEE is already registered."""
        now = time.monotonic()
        last = self._lookup_times.get(nwk, 0.0)
        if now - last < 60:
            return None
        self._lookup_times[nwk] = now
        try:
            ieee = await self.coord.ieee_lookup(nwk)
        except Exception:
            return None
        if ieee is None:
            return None
        dev = self.registry.get(ieee)
        if dev is None:
            from .oui import vendor_of
            rec = self.unknown_devices.setdefault(ieee, {"ieee": ieee_str(ieee), "vendor": vendor_of(ieee), "first_seen": time.time(),
                                                         "frames": 0, "clusters": []})
            rec["nwk"] = f"{nwk:#06x}"
            return None
        self.registry.add_or_update(ieee, nwk)
        self.audit.event("short_address_learned", ieee=dev.ieee_str, nwk=f"{nwk:#06x}")
        return dev

    def list_unknown(self) -> list[dict[str, Any]]:
        return sorted(self.unknown_devices.values(), key=lambda r: r.get("last_seen", 0), reverse=True)

    async def adopt_unknown(self, ieee: int, who: str) -> Device:
        """Register a device that is on our network but unknown to us, and interview it."""
        rec = self.unknown_devices.pop(ieee, None)
        if rec is None:
            raise ValueError("no such unknown device")
        nwk = int(rec["nwk"], 16)
        dev = self.registry.add_or_update(ieee, nwk)
        self.coord.known_ieee.add(ieee)
        dev.available = True
        dev.last_seen = time.time()
        self.audit.security("unknown_device_adopted", ieee=dev.ieee_str, nwk=rec["nwk"], by=who)
        self._emit_device_event("joined", dev)
        if self._rotation is not None and self._rotation.running:
            self._rotation.note_new_device(dev)
        self._start_interview(dev)
        return dev

    async def evict_unknown(self, ieee: int, who: str) -> None:
        rec = self.unknown_devices.pop(ieee, None)
        if rec is None:
            raise ValueError("no such unknown device")
        await self.coord.remove_device(int(rec["nwk"], 16), ieee)
        self.audit.security("unknown_device_evicted", ieee=rec["ieee"], nwk=rec["nwk"], by=who)

    async def _default_response(self, dev: Device, m: IncomingAps, frame: zcl.ZclFrame,
                                status: int = gc.STATUS_SUCCESS) -> None:
        try:
            # a reply always travels the other way round the client/server pair
            payload = gc.build_default_response(frame.seq, frame.command, status,
                                                1 - frame.direction, frame.manufacturer)
            await self.coord.send_aps(dev.nwk, m.src_ep, m.cluster, payload, wait_confirm=False)
        except Exception:
            log.debug("default response to %s failed", dev.ieee_str, exc_info=True)

    # ------------------------------------------------ answering the devices --

    def _gateway_attribute(self, cluster: int, attr: int) -> tuple[int, Any] | None:
        """What the coordinator can say about itself, as (ZCL type, value).

        Devices read two things from a gateway: the time (Xiaomi/Aqara do it after every
        rejoin, and repeat until answered) and its identity."""
        if cluster == TIME_CLUSTER:
            now = time.time()
            zigbee_now = int(now - ZIGBEE_EPOCH)
            offset = int(-(time.altzone if time.localtime().tm_isdst else time.timezone))
            return {
                0x0000: (DataType.utc, zigbee_now),          # Time
                0x0001: (DataType.bitmap8, 0x03),                    # TimeStatus: master, synchronised
                0x0002: (DataType.int32, offset),                 # TimeZone
                0x0007: (DataType.uint32, zigbee_now + offset),   # LocalTime
                0x0008: (DataType.utc, zigbee_now),          # LastSetTime
                0x0009: (DataType.utc, zigbee_now + 86400),  # ValidUntilTime
            }.get(attr)
        if cluster == 0x0000:
            return {
                0x0000: (DataType.uint8, 3),                      # ZCLVersion
                0x0001: (DataType.uint8, 1),                      # ApplicationVersion
                0x0003: (DataType.uint8, 1),                      # HWVersion
                0x0004: (DataType.string, "One Roof"),            # ManufacturerName
                0x0005: (DataType.string, "One Roof Gateway"),    # ModelIdentifier
                0x0007: (DataType.enum8, 0x01),                   # PowerSource: mains
            }.get(attr)
        return None

    async def _answer_read(self, dev: Device, m: IncomingAps, frame: zcl.ZclFrame) -> None:
        """Reply to a device's Read Attributes — with the value where we have one, and with
        'unsupported attribute' where we do not. Either way it is an answer."""
        try:
            asked = gc.decode_global_command(frame).attrs
            records = []
            for attr in asked:
                known = self._gateway_attribute(m.cluster, attr)
                if known is None:
                    records.append(gc.ReadAttributeRecord(attr, gc.STATUS_UNSUPPORTED_ATTRIBUTE))
                else:
                    dtype, value = known
                    records.append(gc.ReadAttributeRecord(attr, gc.STATUS_SUCCESS, dtype, value))
            payload = gc.build_global_command(
                frame.seq, gc.CMD_READ_ATTRIBUTES_RSP,
                gc.ReadAttributesResponse(records).encode(),
                direction=1 - frame.direction, manufacturer=frame.manufacturer)
            await self.coord.send_aps(dev.nwk, m.src_ep, m.cluster, payload, wait_confirm=False)
            answered = sum(1 for r in records if r.status == gc.STATUS_SUCCESS)
            first = (dev.ieee, m.cluster) not in self._answered
            self._answered.add((dev.ieee, m.cluster))
            (log.info if first else log.debug)(
                "%s: answered a read of cluster %#06x (%d of %d attributes known)",
                dev.friendly_name or dev.ieee_str, m.cluster, answered, len(records))
        except Exception:
            # never let answering a device raise into the task that runs it
            log.debug("answering a read from %s failed", dev.ieee_str, exc_info=True)

    # ----------------------------------------------------------- publish --

    async def _publish_state(self, dev: Device) -> None:
        payload = {**dev.state, "linkquality": dev.lqi, "last_seen": dev.last_seen}
        await self.broker.publish(self.topics.state(dev), json.dumps(payload).encode(), retain=True)
        self._emit_device_state(dev, payload)

    def _emit_device_state(self, dev: Device, payload: dict[str, Any]) -> None:
        if self.on_state_change:
            try:
                self.on_state_change(dev.ieee, payload)
            except Exception:
                log.exception("on_state_change observer failed")

    def _emit_device_event(self, action: str, dev: Device) -> None:
        if self.on_device_event:
            try:
                self.on_device_event(action, dev)
            except Exception:
                log.exception("on_device_event observer failed")

    async def _publish_availability(self, dev: Device, online: bool) -> None:
        await self.broker.publish(self.topics.availability(dev), self.topics.availability_payload(online), retain=True)

    async def _publish_permit_join(self) -> None:
        w = self.coord.guard.window
        payload = {"open": w is not None, "seconds_left": (int(w.expires_at - time.monotonic()) if w else 0),
                   "requested_by": (w.requested_by if w else None)}
        await self.broker.publish(f"{self.base}/bridge/permit_join", json.dumps(payload).encode(), retain=True)

    async def _publish_bridge_info(self) -> None:
        devs = self.registry.all()
        info = {
            "version": __import__("oneroof_zigbee").__version__, "coordinator_ieee": ieee_str(self.coord.ieee),
            "channel": self.coord.secrets.channel, "pan_id": f"{self.coord.secrets.pan_id:#06x}",
            "strict_install_codes": self.coord.strict, "device_count": len(devs),
        }
        await self.broker.publish(f"{self.base}/bridge/info", json.dumps(info).encode(), retain=True)
        from .ha.exposes import device_description
        devices = []
        for d in devs:
            entry = {"ieee": d.ieee_str, "friendly_name": d.friendly_name, "manufacturer": d.manufacturer, "model": d.model,
                     "vendor": d.vendor, "kind": d.kind, "category": d.category,
                     "interviewed": d.interviewed, "router": d.is_router,
                     "endpoints": {str(e.id): e.category for e in d.endpoints.values()}}
            try:
                entry.update(device_description(d))  # the exposes description other One Roof apps build on
            except Exception:
                log.exception("exposes for %s", d.ieee_str)
                entry.setdefault("definition", {"vendor": d.vendor or "Zigbee", "model": d.model or "unknown",
                                                "description": d.kind, "exposes": []})
            devices.append(entry)
        await self.broker.publish(f"{self.base}/bridge/devices", json.dumps(devices).encode(), retain=True)

    _LEGACY_ENTITY_SHAPES = (
        ("switch", "switch"), ("light", "light"), ("switch", "state"), ("select", "power_on_behavior"),
        ("binary_sensor", "alarm_1"), ("binary_sensor", "tamper"), ("binary_sensor", "battery_low"),
        ("sensor", "illuminance_lux"), ("button", "identify"), ("sensor", "action"), ("sensor", "voltage"),
        ("sensor", "device_temperature"), ("sensor", "power_outage_count"), ("binary_sensor", "occupancy"),
        ("binary_sensor", "contact"), ("sensor", "temperature"), ("sensor", "humidity"), ("sensor", "pressure"),
        ("sensor", "power"), ("sensor", "energy"), ("sensor", "current"), ("lock", "child_lock"), ("select", "indicator_mode"),
    )

    def _holding_for_name(self, dev: Device) -> bool:
        """Still waiting for the owner to name a freshly joined device before Home Assistant hears
        of it. The hold ends when it is named, or after HA_NAME_HOLD_S with the address as name."""
        since = dev.context.get("ha_name_hold")
        if since is None:
            return False
        if dev.friendly_name != dev.ieee_str or time.time() - float(since) >= self.HA_NAME_HOLD_S:
            dev.context.pop("ha_name_hold", None)
            return False
        return True

    async def _release_name_holds(self) -> None:
        """Devices nobody named within the hold go to Home Assistant anyway, under their address."""
        for dev in self.registry.all():
            if "ha_name_hold" in dev.context and not self._holding_for_name(dev) and dev.interviewed:
                self.audit.event("ha_announced_unnamed", ieee=dev.ieee_str,
                                 hint="name it in the panel, then rename the entity ids in Home Assistant")
                await self._announce(dev)
                await self._publish_state(dev)

    async def _announce(self, dev: Device) -> None:
        if not self.cfg.homeassistant.discovery:
            return
        if self._holding_for_name(dev):
            log.info("%s: not announced to Home Assistant yet - waiting for a name (up to %d min)",
                     dev.ieee_str, self.HA_NAME_HOLD_S // 60)
            return
        msgs = discovery_messages(dev, self.base, self.cfg.homeassistant.discovery_prefix, legacy=self.legacy)
        current = {t for t, _ in msgs}
        # Entity configs are retained; one that no longer applies (the device was described
        # differently before: wrong interview, model knowledge improved, definition changed) must be
        # blanked, or Home Assistant keeps a stale entity forever.
        known = dev.context.get("discovery_topics")
        if known is None:
            # First announce with tracking: sweep the entity shapes earlier versions may have left
            # behind for this device (a blank retained publish on an absent topic is harmless).
            pfx = self.cfg.homeassistant.discovery_prefix
            known = [f"{pfx}/{comp}/{dev.ieee_str}/{obj}/config" for comp, obj in self._LEGACY_ENTITY_SHAPES]
        for stale in set(known) - current:
            await self.broker.publish(stale, b"", retain=True)
        dev.context["discovery_topics"] = sorted(current)
        for topic, payload in msgs:
            await self.broker.publish(topic, payload, retain=True)
        await self._publish_availability(dev, dev.available)

    async def _forget(self, dev: Device) -> None:
        if self.cfg.homeassistant.discovery:
            for topic, payload in removal_messages(dev, self.cfg.homeassistant.discovery_prefix, legacy=self.legacy):
                await self.broker.publish(topic, payload, retain=True)
        for topic in (self.topics.state(dev), self.topics.availability(dev)):
            await self.broker.publish(topic, b"", retain=True)
        self.registry.remove(dev.ieee)
        self.coord.known_ieee.discard(dev.ieee)
        await self._publish_bridge_info()
        self._emit_device_event("left", dev)

    async def _on_ha_status(self, topic: str, payload: bytes, user: str | None = None) -> None:
        if payload == b"online":
            log.info("Home Assistant came online — re-announcing %d devices", len(self.registry.all()))
            for dev in self.registry.all():
                await self._announce(dev)
                await self._publish_state(dev)

    # ---------------------------------------------------------- commands --

    async def _on_set(self, topic: str, payload: bytes, user: str | None = None) -> None:
        name = topic.split("/")[-2]
        dev = self.registry.by_name(name)
        if dev is None:
            log.warning("set for unknown device %r by %s", name, user)
            return
        try:
            cmd = json.loads(payload or b"{}")
            if not isinstance(cmd, dict):
                raise ValueError("payload must be a JSON object")
        except ValueError as e:
            log.warning("bad set payload from %s: %s", user, e)
            return
        self.audit.event("command", ieee=dev.ieee_str, by=user, keys=sorted(cmd))
        try:
            await self.apply_command(dev, cmd)
        except Exception as e:
            # the audit already recorded that the command arrived; without this it would look as
            # though it had been carried out
            log.warning("command to %s failed: %s", dev.ieee_str, e)
            self.audit.event("command_failed", ieee=dev.ieee_str, by=user, keys=sorted(cmd),
                             error=str(e)[:200] or e.__class__.__name__)

    async def _on_get(self, topic: str, payload: bytes, user: str | None = None) -> None:
        """Legacy layout: `<base>/<name>/get` → re-publish current state (and refresh on_off if asked)."""
        name = topic.split("/")[-2]
        dev = self.registry.by_name(name)
        if dev is None:
            return
        try:
            body = json.loads(payload or b"{}")
        except ValueError:
            body = {}
        if isinstance(body, dict) and "state" in body:
            await self._read_on_off(dev)
        await self._publish_state(dev)

    async def _read_on_off(self, dev: Device) -> bool:
        """Ask every switching endpoint whether it is on. A two-gang switch has two answers, and
        each goes through the model's translation so the second gang's answer lands on state_l2
        and never overwrites the first's."""
        heard = False
        for ep in dev.endpoints.values():
            if 0x0006 not in ep.in_clusters:
                continue
            try:
                state = await self.read_attributes(dev, ep.id, 0x0006, [0x0000])
            except (ZnpError, asyncio.TimeoutError):
                return heard
            heard = True
            self._note_state_evidence(dev, 0x0006, state)
            if state:
                self._apply_changes(dev, quirks.translate_state(dev, ep.id, state))
        if heard:
            dev.last_seen = time.time()
        return heard

    async def apply_command(self, dev: Device, cmd: dict[str, Any]) -> None:
        """Apply a JSON command. Keys are feature keys (``state``, ``state_l2``, ``brightness``, ``child_lock`` …);
        each is routed to the endpoint its feature lives on."""
        ep_obj = dev.primary_endpoint()
        if ep_obj is None:
            raise ZnpError("device not interviewed yet")
        feats = self._features(dev)
        by_key = {f["key"]: f for f in feats}
        forced_ep = int(cmd["endpoint"]) if "endpoint" in cmd else None
        per_ep: dict[int, dict[str, Any]] = {}
        for k, v in cmd.items():
            if k in ("endpoint", "transition"):
                continue
            if k in ("heating_setpoint", "target_temperature"):  # accepted aliases of the published key
                k = "current_heating_setpoint"
            if k not in by_key and k.startswith("state_"):
                # Historical gang aliases: a consumer built on an older exposes generation may say
                # state_left where this device now exposes state_l1 (or the reverse). Route by gang
                # position instead of dropping the tap silently.
                order = {"left": 0, "l1": 0, "1": 0, "right": 1, "l2": 1, "2": 1,
                         "center": 2, "middle": 2, "l3": 2, "3": 2, "l4": 3, "4": 3}
                idx = order.get(k[6:])
                gangs = [g["key"] for g in feats if g.get("base") == "state" and g.get("access") == "rw"]
                if idx is not None and idx < len(gangs) and gangs[idx] != k:
                    log.info("command key %r mapped to gang %r on %s", k, gangs[idx], dev.friendly_name)
                    k = gangs[idx]
            f = by_key.get(k)
            if f is not None and f.get("base"):
                ep = forced_ep if forced_ep is not None else (f["endpoint"] or ep_obj.id)
                per_ep.setdefault(ep, {})[f["base"]] = v
                if f["cluster"] == vz.TUYA_CLUSTER:
                    per_ep[ep].setdefault("__dp__", {})[k] = v
            else:
                log.warning("command key %r is not a feature of %s — sent to its primary endpoint as-is and may be ignored",
                            k, dev.friendly_name)
                per_ep.setdefault(forced_ep if forced_ep is not None else ep_obj.id, {})[k] = v
        transition = int(float(cmd.get("transition", 0)) * 10)
        try:
            for ep, body in per_ep.items():
                await self._apply_command_ep(dev, ep, body, transition)
        except Exception:
            # Part of it may have gone through and part not; whatever was written to the state
            # in good faith is now a guess. The device knows - ask it.
            self._schedule_refresh(dev, delay=1.0)
            raise
        await self._publish_state(dev)

    async def _apply_command_ep(self, dev: Device, ep: int, cmd: dict[str, Any], transition: int) -> None:
        ins = set(dev.endpoints[ep].in_clusters) if ep in dev.endpoints else set()
        feats = {f["base"]: f for f in self._features(dev) if f["endpoint"] == ep}
        dps: dict[str, Any] = cmd.pop("__dp__", {})

        def key_of(base: str) -> str:
            f = feats.get(base)
            return f["key"] if f else base

        async def send(cluster: int, name: str, params: dict[str, Any]) -> None:
            cid, body = zcl.encode_command(cluster, name, params)
            await self.coord.send_aps(dev.nwk, ep, cluster, gc.build_cluster_command(self._next_seq(), cid, body))

        # Tuya datapoint devices: every writable dp feature goes through setData
        tuya_cover = vz.TUYA_CLUSTER in ins and feats.get("cover", {}).get("cluster") == vz.TUYA_CLUSTER
        state = cmd.get("state")
        if tuya_cover and isinstance(state, str) and state.upper() in ("OPEN", "CLOSE", "STOP"):
            dps["cover"] = state.upper()
            cmd.pop("state")
        for key, value in dps.items():
            payload = quirks.encode_tuya_command(dev, key, value, self._next_seq() & 0xFFFF)
            if payload is None:
                raise ValueError(f"{key} is not writable on this device")
            await self.coord.send_aps(dev.nwk, ep, vz.TUYA_CLUSTER, gc.build_cluster_command(self._next_seq(), vz.TUYA_CMD_SET_DATA, payload))
            if key != "cover":
                self._apply_changes(dev, {key: value})
        if dps:
            return

        if isinstance(state, str):
            s = state.upper()
            if 0x0102 in ins and s in ("OPEN", "CLOSE", "STOP"):
                await send(0x0102, {"OPEN": "up_open", "CLOSE": "down_close", "STOP": "stop"}[s], {})
            elif 0x0101 in ins and s in ("LOCK", "UNLOCK") and 0x0006 not in ins:
                await send(0x0101, "lock_door" if s == "LOCK" else "unlock_door", {"pin_code": b""})
                self._apply_changes(dev, {key_of("state"): s})
            elif s in ("ON", "OFF", "TOGGLE") and 0x0006 in ins:
                if s == "ON" and "brightness" in cmd and 0x0008 in ins:
                    pass  # handled by brightness below with on_off
                else:
                    await send(0x0006, s.lower(), {})
                    if s != "TOGGLE":
                        self._apply_changes(dev, {key_of("state"): s})
                    else:
                        self._schedule_refresh(dev, delay=0.5)  # only the device knows which way it went
                if s == "OFF":
                    # {"state": "OFF", "brightness": N} (Home Assistant remembers the level it will
                    # come back at): OFF is the order. A level command here would switch it on again.
                    cmd = {k: v for k, v in cmd.items() if k != "brightness"}
        if "brightness" in cmd and 0x0008 in ins:
            level = max(0, min(254, int(cmd["brightness"])))
            await send(0x0008, "move_to_level_with_on_off", {"level": level, "transition_time": transition})
            self._apply_changes(dev, {key_of("brightness"): level, key_of("state"): "ON" if level > 0 else "OFF"})
        if "color_temp" in cmd and 0x0300 in ins:
            await send(0x0300, "move_to_color_temp", {"color_temp": int(cmd["color_temp"]), "transition_time": transition})
            self._apply_changes(dev, {key_of("color_temp"): int(cmd["color_temp"])})
        if isinstance(cmd.get("color"), dict) and 0x0300 in ins:
            col = cmd["color"]
            if "x" in col and "y" in col:
                await send(0x0300, "move_to_color", {"x": float(col["x"]), "y": float(col["y"]), "transition_time": transition})
                self._apply_changes(dev, {key_of("color"): {"x": float(col["x"]), "y": float(col["y"])}})
            elif "h" in col and "s" in col:
                await send(0x0300, "move_to_hue_and_saturation", {"hue": int(col["h"] * 254 / 360), "saturation": int(col["s"] * 254 / 100), "transition_time": transition})
            elif "hue" in col and "saturation" in col:  # zigbee2mqtt-style payload, sent by HomeKit bridges
                await send(0x0300, "move_to_hue_and_saturation", {"hue": int(float(col["hue"]) * 254 / 360), "saturation": int(float(col["saturation"]) * 254 / 100), "transition_time": transition})
        if "position" in cmd and 0x0102 in ins:
            pos = max(0, min(100, int(cmd["position"])))
            await send(0x0102, "go_to_lift_percentage", {"percentage": 100 - pos})
        if "current_heating_setpoint" in cmd and 0x0201 in ins:
            value = float(cmd["current_heating_setpoint"])
            attr, other = 0x0012, None
            if feats.get("current_heating_setpoint", {}).get("single_setpoint"):
                # One set temperature (an air conditioner keeps both ZCL setpoints equal): write the
                # one that matches the mode being set or already in force — heating in heat, cooling
                # otherwise.
                mode = str(cmd.get("system_mode") or dev.state.get(key_of("system_mode")) or "")
                attr, other = (0x0012, 0x0011) if mode == "heat" else (0x0011, 0x0012)
            raw = int(round(value * 100))
            try:
                await self._write_attr(dev, ep, 0x0201, attr, zcl.DataType.int16, raw)
            except Exception:
                # An air conditioner that implements only one of the two setpoint attributes would
                # otherwise refuse every temperature change while its mode, fan and louver all work.
                if other is None:
                    raise
                log.info("%s: setpoint attribute %#06x refused, writing %#06x instead",
                         dev.friendly_name or dev.ieee_str, attr, other)
                await self._write_attr(dev, ep, 0x0201, other, zcl.DataType.int16, raw)
            self._apply_changes(dev, {key_of("current_heating_setpoint"): value})
        if "current_cooling_setpoint" in cmd and 0x0201 in ins:
            await self._write_attr(dev, ep, 0x0201, 0x0011, zcl.DataType.int16, int(round(float(cmd["current_cooling_setpoint"]) * 100)))
            self._apply_changes(dev, {key_of("current_cooling_setpoint"): float(cmd["current_cooling_setpoint"])})
        if "system_mode" in cmd and 0x0201 in ins:
            mode = str(cmd["system_mode"])
            allowed = feats.get("system_mode", {}).get("values") or list(zcl.SYSTEM_MODE_BY_NAME)
            if mode not in zcl.SYSTEM_MODE_BY_NAME or mode not in allowed:
                raise ValueError(f"system_mode must be one of {allowed}")
            await self._write_attr(dev, ep, 0x0201, 0x001C, zcl.DataType.enum8, zcl.SYSTEM_MODE_BY_NAME[mode])
            self._apply_changes(dev, {key_of("system_mode"): mode})
        if "fan_mode" in cmd and 0x0202 in ins:
            fan = str(cmd["fan_mode"])
            if fan not in zcl.FAN_MODE_BY_NAME:
                raise ValueError(f"fan_mode must be one of {zcl.FAN_MODES}")
            await self._write_attr(dev, ep, 0x0202, 0x0000, zcl.DataType.enum8, zcl.FAN_MODE_BY_NAME[fan])
            self._apply_changes(dev, {key_of("fan_mode"): fan})
        # attributes of a device-specific cluster the model table knows (standard attributes, no
        # manufacturer code; the wire type comes from the table)
        touched: dict[int, bool] = {}
        for base, value in list(cmd.items()):
            f = feats.get(base)
            if not f or f["access"] == "r" or quirks.private_attribute(dev, f["cluster"], base) is None:
                continue
            attr, dtype, wire = quirks.encode_private_attribute(dev, f["cluster"], base, value)
            await self._write_attr(dev, ep, f["cluster"], attr, dtype, wire)
            if f["access"] == "w":
                touched[f["cluster"]] = True  # a command in disguise: nothing to remember, the device answers through its feedback attributes
            else:
                shown = wire / (quirks.private_attribute(dev, f["cluster"], base).scale or 1) if isinstance(wire, int) and not isinstance(wire, bool) and f["type"] == "numeric" else value
                if f["type"] == "binary":
                    shown = f.get("value_on", "ON") if wire else f.get("value_off", "OFF")
                self._apply_changes(dev, {f["key"]: shown})
                touched.setdefault(f["cluster"], False)
        for cluster in touched:
            self._schedule_feedback_read(dev, ep, cluster)
        if "identify" in cmd and 0x0003 in ins:
            await send(0x0003, "identify", {"time": int(cmd["identify"])})
        if "power_on_behavior" in cmd and 0x0006 in ins:
            from .features import POWER_ON_BEHAVIOR
            val = str(cmd["power_on_behavior"])
            if val not in POWER_ON_BEHAVIOR:
                raise ValueError(f"power_on_behavior must be one of {list(POWER_ON_BEHAVIOR)}")
            await self._write_attr(dev, ep, 0x0006, 0x4003, zcl.DataType.enum8, POWER_ON_BEHAVIOR[val])
            self._apply_changes(dev, {key_of("power_on_behavior"): val})
        if "child_lock" in cmd and 0x0006 in ins and "child_lock" in feats:
            lock = str(cmd["child_lock"]).upper() in ("LOCK", "ON", "TRUE", "1")
            await self._write_attr(dev, ep, 0x0006, 0x8000, zcl.DataType.bool_, lock)
            self._apply_changes(dev, {"child_lock": "LOCK" if lock else "UNLOCK"})
        if "indicator_mode" in cmd and 0x0006 in ins and "indicator_mode" in feats:
            modes = {"off": 0, "off/on": 1, "on/off": 2, "on": 3}
            val = str(cmd["indicator_mode"])
            if val not in modes:
                raise ValueError(f"indicator_mode must be one of {list(modes)}")
            await self._write_attr(dev, ep, 0x0006, 0x8001, zcl.DataType.enum8, modes[val])
            self._apply_changes(dev, {"indicator_mode": val})
        if "countdown" in cmd and 0x0006 in ins:
            secs = int(cmd["countdown"])
            if not 1 <= secs <= 6553:
                raise ValueError("countdown must be 1..6553 seconds")
            # OnWithTimedOff: control u8 (0 = accept when off too), on_time u16 (1/10 s), off_wait_time u16
            body = bytes([0x00]) + (secs * 10).to_bytes(2, "little") + (0).to_bytes(2, "little")
            await self.coord.send_aps(dev.nwk, ep, 0x0006, gc.build_cluster_command(self._next_seq(), 0x42, body))
            self._apply_changes(dev, {key_of("state"): "ON"})

    async def _write_attr(self, dev: Device, ep: int, cluster: int, attr: int, dtype: zcl.DataType, value: Any,
                          manufacturer: int | None = None) -> None:
        """Write one attribute and believe the device about whether it took it.

        A Write Attributes Response carries a status per attribute. Ignoring it means a refused
        write looks exactly like a successful one: the state is published as if it had changed, and
        the device sits there doing what it did before."""
        seq = self._next_seq()
        frame = gc.build_write_attributes(seq, [gc.WriteAttributeRecord(attr, int(dtype), value)], manufacturer=manufacturer)
        rsp = await self._request(dev, ep, cluster, frame, seq, gc.CMD_WRITE_ATTRIBUTES_RSP)
        try:
            records = gc.decode_global_command(rsp).records
        except Exception:
            return   # it answered, in a shape we do not model: not evidence of refusal
        refused = [r for r in records if r.status != gc.STATUS_SUCCESS]
        if refused:
            raise ZnpError(f"device refused attribute {attr:#06x} on cluster {cluster:#06x} "
                           f"(status {refused[0].status:#04x})")

    def _schedule_feedback_read(self, dev: Device, ep: int, cluster: int) -> None:
        """After writing a device-specific cluster, read back what it says about it (last_result,
        code_count, the protocol in force). The device also reports these unsolicited; the read
        covers the case where it does not."""
        attrs = list(quirks.feedback_reads(dev, cluster))
        if not attrs:
            return

        async def run() -> None:
            await asyncio.sleep(0.5)
            try:
                state = await self.read_attributes(dev, ep, cluster, attrs)
            except (ZnpError, asyncio.TimeoutError) as e:
                log.info("%s: feedback read of %s failed: %s", dev.ieee_str, zcl.cluster_name(cluster), e)
                return
            if self._apply_changes(dev, quirks.translate_state(dev, ep, state)):
                await self._publish_state(dev)

        asyncio.get_running_loop().create_task(run())

    # ------------------------------------------------ ui-facing helpers --

    async def set_description(self, dev: Device, text: str, who: str) -> None:
        text = text.strip()
        if len(text) > 200:
            raise ValueError("description too long (max 200)")
        dev.description = text or None
        self.registry.save()
        self.audit.event("device_described", ieee=dev.ieee_str, by=who)
        self._emit_device_event("renamed", dev)

    async def read_live(self, dev: Device, ep: int, cluster: int, attrs: list[int]) -> tuple[dict[str, Any], dict[str, Any]]:
        if not attrs or len(attrs) > 16:
            raise ValueError("1..16 attributes")
        seq = self._next_seq()
        rsp = await self._request(dev, ep, cluster, gc.build_read_attributes(seq, attrs), seq, gc.CMD_READ_ATTRIBUTES_RSP)
        decoded = gc.decode_global_command(rsp)
        values = {f"0x{r.attr:04x}": (r.value.hex() if isinstance(r.value, (bytes, bytearray)) else r.value) if r.status == 0 else f"status {r.status:#04x}"
                  for r in decoded.records}
        state = self._decode_records(dev, ep, cluster, [r for r in decoded.records if r.status == gc.STATUS_SUCCESS])
        state = quirks.translate_state(dev, ep, state)
        if state:
            self._apply_changes(dev, state)
            await self._publish_state(dev)
        return values, state

    async def configure_reporting(self, dev: Device, ep: int, cluster: int, attr: int, mn: int, mx: int, change: Any, who: str) -> str:
        c = zcl.get_cluster(cluster)
        a = c.attributes.get(attr) if c else None
        if a is None:
            raise ValueError("unknown attribute for that cluster")
        if not (0 <= mn <= 65534 and 0 <= mx <= 65534):
            raise ValueError("min/max must be 0..65534 seconds")
        await self.coord.bind(dev.nwk, dev.ieee, ep, cluster)
        rec = gc.ReportingConfigRecord(attr=attr, dtype=int(a.dtype), min_interval=mn, max_interval=mx, reportable_change=change)
        seq = self._next_seq()
        rsp = await self._request(dev, ep, cluster, gc.build_configure_reporting(seq, [rec]), seq, gc.CMD_CONFIGURE_REPORTING_RSP)
        status = "ok"
        dec = gc.decode_global_command(rsp)
        bad = [r for r in getattr(dec, "records", []) if getattr(r, "status", 0) != 0]
        if bad:
            status = f"status {bad[0].status:#04x}"
        self._record_bindings(dev, ep, cluster, "coordinator", 1)
        self._record_reporting(dev, ep, cluster, attr, mn, mx, change, status)
        self.registry.save()
        self.audit.event("reporting_configured", ieee=dev.ieee_str, by=who, cluster=f"{cluster:#06x}", attribute=f"{attr:#06x}", status=status)
        return status

    async def bind(self, dev: Device, ep: int, cluster: int, target: str, target_ep: int, who: str, *, unbind: bool = False) -> None:
        if target == "coordinator":
            dst_ieee, dst_ep = self.coord.ieee, 1
        else:
            tdev = self.registry.by_name(target)
            if tdev is None:
                raise ValueError("unknown target device")
            dst_ieee, dst_ep = tdev.ieee, target_ep
        if unbind:
            status = await self.coord.unbind(dev.nwk, dev.ieee, ep, cluster, dst_ieee, dst_ep)
            dev.bindings = [b for b in dev.bindings if not (b["endpoint"] == ep and b["cluster"] == cluster and b["target"] == target)]
        else:
            status = await self.coord.bind(dev.nwk, dev.ieee, ep, cluster, dst_ieee=dst_ieee, dst_ep=dst_ep)
            if status == 0:
                self._record_bindings(dev, ep, cluster, target, dst_ep)
        if status != 0:
            raise ZnpError(f"{'unbind' if unbind else 'bind'} failed with ZDO status {status:#04x}")
        self.registry.save()
        self.audit.event("unbind" if unbind else "bind", ieee=dev.ieee_str, by=who, cluster=f"{cluster:#06x}", target=target)

    async def ota_notify(self, dev: Device) -> None:
        """Ask the device to query for an image now (ImageNotify). The device must have an OTA client (out cluster 0x0019)."""
        ep = next((e.id for e in dev.endpoints.values() if 0x0019 in e.out_clusters), None)
        if ep is None:
            raise ValueError("device has no OTA client endpoint")
        await self.coord.send_aps(dev.nwk, ep, 0x0019, gc.build_cluster_command(self._next_seq(), 0x00, self.ota.image_notify_payload(),
                                                                                 direction=zcl.DIRECTION_SERVER_TO_CLIENT))

    # ---------------------------------------------------------- requests --

    CONTROL_ACTIONS = ("permit_join", "rotate_network_key", "remove", "scan_air", "radio_tuning")
    ROTATE_AFTER_JOIN_QUIET_S = 120.0  # one rotation per pairing session, not one per device
    # At start a green badge is only kept for a device heard this recently. Mains devices talk
    # often; battery devices may sleep for hours between reports, so they get a longer grace.
    STARTUP_ONLINE_MAINS_S = 3600.0
    STARTUP_ONLINE_BATTERY_S = 86400.0
    _rotate_debounce: "asyncio.Task[None] | None" = None

    async def _on_request(self, topic: str, payload: bytes, user: str | None = None) -> None:
        action = topic.split("/")[-1]
        who = user or "unknown"
        try:
            body = json.loads(payload or b"{}")
            if not isinstance(body, dict):
                raise ValueError("payload must be a JSON object")
        except ValueError as e:
            await self._respond(action, False, error=str(e))
            return
        result = await self.handle_request(action, body, who)
        await self._respond(action, result.pop("ok"), **result)

    async def handle_request(self, action: str, body: dict[str, Any], who: str) -> dict[str, Any]:
        """Single policy/audit path for bridge requests, shared by MQTT and the UI.

        `who` is the authenticated identity ("<mqtt user>" or "ui:<user>"); for
        control actions the bare user name must be in `control_users`."""
        handler = {
            "permit_join": self._req_permit_join, "remove": self._req_remove, "rename": self._req_rename,
            "interview": self._req_interview, "rotate_network_key": self._req_rotate_key, "devices": self._req_devices, "scan_air": self._req_scan_air,
            "radio_tuning": self._req_radio_tuning, "rotation_policy": self._req_rotation_policy,
            "verify_audit": self._req_verify_audit,
        }.get(action)
        if handler is None:
            return {"ok": False, "error": "unknown request"}
        bare = who.split(":", 1)[1] if who.startswith("ui:") else who
        if action in self.CONTROL_ACTIONS and bare not in self.control_users:
            self.audit.security("request_denied", action=action, by=who, reason="user not in control_users")
            return {"ok": False, "error": "not authorized"}
        try:
            result = await handler(body, who)
            return {"ok": True, **(result or {})}
        except (JoinPolicyError, PermissionError, InstallCodeError, ValueError, ZnpError) as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            log.exception("request %s failed", action)
            return {"ok": False, "error": f"internal: {type(e).__name__}"}

    def _radio_tuning_file(self) -> Path:
        return self.cfg.data_dir / "radio.json"

    def load_radio_tuning(self) -> dict[str, int]:
        try:
            data = json.loads(self._radio_tuning_file().read_text())
        except (OSError, ValueError):
            return {}
        return {k: int(v) for k, v in data.items() if isinstance(v, (int, float))}

    async def _req_radio_tuning(self, body: dict[str, Any], who: str) -> dict[str, Any]:
        """Read or change the radio's routing and broadcast behaviour. Keys, PAN, channel and the
        devices' membership are never touched — see Coordinator.apply_radio_tuning."""
        settings = body.get("settings")
        if settings is None:
            return {"current": await self.coord.read_radio_tuning(),
                    "configured": self.load_radio_tuning(),
                    "fields": {k: {"min": lo, "max": hi, "help": h}
                               for k, (_nv, lo, hi, h) in self.coord.RADIO_TUNING.items()}}
        if not isinstance(settings, dict):
            raise ValueError("settings must be an object")
        wanted = {str(k): int(v) for k, v in settings.items()}
        result = await self.coord.apply_radio_tuning(wanted)
        self.coord.radio_tuning = wanted
        try:
            self._radio_tuning_file().write_text(json.dumps(wanted, indent=1))
        except OSError as e:
            log.warning("radio settings applied but not saved: %s", e)
        self.audit.security("radio_tuning_requested", by=who, settings=wanted)
        return result

    async def _req_scan_air(self, body: dict[str, Any], who: str) -> dict[str, Any]:
        self.audit.event("air_scan_requested", by=who)
        duration = int(body.get("duration", 3))
        if not 1 <= duration <= 5:
            raise ValueError("duration is the scan exponent, 1..5")
        return await self.coord.scan_air(duration=duration)

    async def _respond(self, action: str, ok: bool, **data: Any) -> None:
        await self.broker.publish(f"{self.base}/bridge/response/{action}", json.dumps({"ok": ok, **data}).encode())

    async def _req_permit_join(self, body: dict[str, Any], who: str) -> dict[str, Any]:
        seconds = int(body.get("seconds", 60))
        if seconds == 0:
            await self.coord._force_close_join()
            return {"open": False}
        ieee = ieee_int(body["ieee"]) if body.get("ieee") else None
        code = parse_install_code(str(body["install_code"])) if body.get("install_code") else None
        eff = await self.coord.permit_join(seconds, who, ieee=ieee, install_code=code)
        return {"open": True, "seconds": eff}

    async def _req_remove(self, body: dict[str, Any], who: str) -> dict[str, Any]:
        dev = self.registry.by_name(str(body.get("ieee") or body.get("friendly_name", "")))
        if dev is None:
            raise ValueError("unknown device")
        try:
            await self.coord.remove_device(dev.nwk, dev.ieee)
        except ZnpError as e:
            log.info("leave request failed (%s); forgetting locally", e)
        await self._forget(dev)
        self.audit.event("device_removed_by_request", ieee=dev.ieee_str, by=who)
        return {"ieee": dev.ieee_str}

    async def _req_rename(self, body: dict[str, Any], who: str) -> dict[str, Any]:
        dev = self.registry.by_name(str(body.get("ieee") or body.get("from", "")))
        name = str(body.get("friendly_name") or body.get("to", "")).strip()
        if dev is None or not name or any(ch in name for ch in "/+#"):
            raise ValueError("need ieee and a friendly_name without / + #")
        old_state, old_avail = self.topics.state(dev), self.topics.availability(dev)
        self.registry.rename(dev.ieee, name)
        if self.legacy and old_state != self.topics.state(dev):
            for topic in (old_state, old_avail):
                await self.broker.publish(topic, b"", retain=True)
            await self._publish_state(dev)
            await self._publish_availability(dev, dev.available)
        await self._announce(dev)
        self._emit_device_event("renamed", dev)
        return {"ieee": dev.ieee_str, "friendly_name": name}

    async def _req_interview(self, body: dict[str, Any], who: str) -> dict[str, Any]:
        dev = self.registry.by_name(str(body.get("ieee", "")))
        if dev is None:
            raise ValueError("unknown device")
        dev.interviewed = False
        self._start_interview(dev)
        return {"ieee": dev.ieee_str}

    async def _req_devices(self, body: dict[str, Any], who: str) -> dict[str, Any]:
        return {"devices": [d.to_json() for d in self.registry.all()]}

    async def _req_verify_audit(self, body: dict[str, Any], who: str) -> dict[str, Any]:
        if not self.audit.path:
            return {"verified": None}
        ok, line = Audit.verify(Path(self.audit.path))
        return {"verified": ok, "first_bad_line": line}

    async def _req_rotate_key(self, body: dict[str, Any], who: str) -> dict[str, Any]:
        """Two ways to rotate the network key.

        mode "over_the_air" (default): the new key is handed to every device under its own link key,
        then switched (see rotation.py). Nothing is re-paired; whoever holds only the old network key
        is locked out. Whoever also holds the trust-centre seed is not — for that, use "repair".

        mode "repair": a fresh key AND a fresh trust-centre seed on next start; every device must be
        paired again. Confirmation sentence required.
        """
        from .security import Keystore, NetworkSecrets
        mode = str(body.get("mode", "over_the_air"))
        ks = Keystore(self.cfg.data_dir / "network.keystore")
        if mode == "repair":
            if body.get("confirm") != "I understand all devices must be re-paired":
                raise ValueError('send {"confirm": "I understand all devices must be re-paired"}')
            fresh = NetworkSecrets.generate(self.coord.secrets.channel)
            ks.save(fresh)
            self.audit.security("network_key_rotation_scheduled", by=who, mode="repair")
            return {"restart_required": True}
        if mode == "finish":
            # the coordinator's half of a rotation that did not complete on the radio
            ok = await self.coord.finish_key_switch()
            self.audit.security("network_key_switch_finish_requested", by=who, ok=ok)
            return {"verified": ok}
        if mode == "rollback":
            # the coordinator returns to the key the devices use — from the keystore, the radio's
            # alternate slot, or (handed in by the UI) a backup taken before the rotation
            if self._rotation is not None and self._rotation.running:
                self._rotation.cancel()
            previous = None
            if body.get("previous_key_hex"):
                key = bytes.fromhex(str(body["previous_key_hex"]))
                if len(key) != 16:
                    raise ValueError("previous key must be 16 bytes")
                previous = (key, int(body.get("previous_seq", 0)))
            ok = await self.coord.rollback_key_switch(previous)
            self.audit.security("network_key_switch_rollback_requested", by=who, ok=ok, source="backup" if previous else "auto")
            return {"rolled_back": ok}
        if mode == "relabel":
            seq = int(body.get("seq", -1))
            if not 0 <= seq <= 255:
                raise ValueError("seq must be 0..255")
            ok = await self.coord.relabel_key_sequence(seq)
            self.audit.security("network_key_relabel_requested", by=who, seq=seq, ok=ok)
            return {"relabelled": ok}
        if mode == "cancel":
            if self._rotation is None or not self._rotation.cancel():
                raise ValueError("no key rotation is waiting")
            return {"cancelled": True}
        if mode not in ("over_the_air", "check"):
            raise ValueError("mode must be over_the_air, check, finish, rollback, cancel or repair")
        from .rotation import DEFAULT_WINDOW_S, KeyRotation
        if self._rotation is None:
            self._rotation = KeyRotation(self.coord, self.registry, ks, self.audit,
                                         require_all=self.cfg.zigbee.rotation_require_all, max_window_s=self.cfg.zigbee.rotation_max_window_seconds)
        if mode == "check":
            # the rotation's own evidence, gathered up front: who would take the key, who would hold it up
            self.audit.event("key_rotation_check_requested", by=who)
            return {"check": await self._rotation.check()}
        st = self._rotation.start(window_s=int(body.get("window_s", DEFAULT_WINDOW_S)), by=who)
        return {"rotation": st.to_json()}

    def rotation_status(self) -> dict[str, Any]:
        return self._rotation.state.to_json() if self._rotation else {"phase": "idle"}

    def _resume_rotation(self) -> None:
        """A key rotation the previous run left unfinished is picked up where it stopped."""
        from .rotation import KeyRotation
        from .security import Keystore
        ks = Keystore(self.cfg.data_dir / "network.keystore")
        try:
            pending = ks.load().pending_rotation if ks.exists() else None
        except (OSError, ValueError) as e:
            log.warning("keystore unreadable for rotation resume: %s", e)
            return
        if not pending:
            return
        if self._rotation is None:
            self._rotation = KeyRotation(self.coord, self.registry, ks, self.audit,
                                         require_all=self.cfg.zigbee.rotation_require_all, max_window_s=self.cfg.zigbee.rotation_max_window_seconds)
        log.warning("resuming the key rotation left unfinished by the previous run (sequence %s)", pending.get("seq"))
        self._rotation.resume(pending)
