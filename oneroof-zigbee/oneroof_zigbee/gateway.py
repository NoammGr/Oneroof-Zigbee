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
from .zcl import vendor as vz
from .znp import Coordinator, IncomingAps, JoinedDevice, ZnpError
from .znp.wire import ieee_int, ieee_str

log = logging.getLogger("oneroof_zigbee.gateway")

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
    0x0201: [(0x0000, zcl.DataType.int16, 30, 3600, 20), (0x0012, zcl.DataType.int16, 1, 3600, 10), (0x001C, zcl.DataType.enum8, 1, 3600, None)],
}
_READ_ON_JOIN: dict[int, list[int]] = {
    0x0006: [0x0000, 0x4003], 0x0008: [0x0000], 0x0300: [0x0003, 0x0004, 0x0007, 0x0008], 0x0001: [0x0020, 0x0021],
    0x0402: [0x0000], 0x0405: [0x0000], 0x0403: [0x0000], 0x0400: [0x0000], 0x0406: [0x0000],
    0x0500: [0x0001, 0x0002], 0x0B04: [0x0600, 0x0601, 0x0602, 0x0603, 0x0604, 0x0605, 0x0505, 0x0508, 0x050B],
    0x0702: [0x0301, 0x0302, 0x0000], 0x0102: [0x0008], 0x0201: [0x0000, 0x0012, 0x001C],
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
        self._interview_tasks: dict[int, asyncio.Task[None]] = {}
        self._lookup_times: dict[int, float] = {}
        self._locate_task: asyncio.Task[None] | None = None
        self._settled: set[int] = set()  # Tuya devices given their settle read this run
        self._rotation: Any = None  # KeyRotation, created on first use
        from .monitor import Monitor
        self.monitor = Monitor(lambda t, **f: self.audit.security(t, **f))
        self._monitor_task: asyncio.Task[None] | None = None
        self._timers: dict[tuple[int, str], asyncio.Task[None]] = {}
        self._started = False
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
        if self.legacy:
            self.broker.subscribe(f"{b}/+/get", self._on_get)  # legacy-layout clients may ask for a state refresh
        self.broker.subscribe(f"{b}/bridge/request/+", self._on_request)
        self.broker.subscribe("homeassistant/status", self._on_ha_status)

        self._load_activity()
        self._load_profiles()
        self._monitor_task = asyncio.create_task(self._monitor_loop(), name="monitor")
        await self.broker.publish(f"{b}/bridge/state", self.topics.bridge_state_payload(True), retain=True)
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
            if dev.nwk:
                # Address known from the previous setup's backup: talk to the device directly. A
                # sleepy device simply does not answer (interview_failed) and is retried on contact.
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

    ROUTER_POLL_AFTER_S = 900  # a mains device silent this long is asked for one attribute

    async def _monitor_loop(self) -> None:
        tick = 0
        while True:
            await asyncio.sleep(60)
            tick += 1
            try:
                self.monitor.sweep([(d.ieee, bool(d.is_router or d.rx_on_when_idle)) for d in self.registry.all()])
                self._save_profiles()
                if tick % 5 == 0:
                    await self._poll_silent_routers()
            except Exception:
                log.debug("monitor sweep failed", exc_info=True)

    async def _poll_silent_routers(self) -> None:
        """Mains devices that do not report by themselves (not yet bound, or models that only answer)
        are asked for one attribute now and then: keeps last-seen and link quality fresh, feeds the
        liveness monitor, and their pending binding/reporting setup runs on that contact."""
        now = time.time()
        for dev in self.registry.all():
            if not (dev.is_router or dev.rx_on_when_idle) or not dev.nwk or not dev.endpoints:
                continue
            if dev.last_seen and now - dev.last_seen < self.ROUTER_POLL_AFTER_S:
                continue
            if dev.ieee in self._interview_tasks:
                continue
            ep = next((e for e in dev.endpoints.values() if 0x0006 in e.in_clusters), None) or dev.primary_endpoint()
            if ep is None:
                continue
            cluster, attr = (0x0006, 0x0000) if 0x0006 in ep.in_clusters else (0x0000, 0x0004)
            try:
                state = await self.read_attributes(dev, ep.id, cluster, [attr])
                if state:
                    self._apply_changes(dev, state)
                    await self._publish_state(dev)
            except (ZnpError, asyncio.TimeoutError) as e:
                log.debug("%s: poll failed (%s)", dev.ieee_str, e)
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
        await self.broker.publish(f"{self.base}/bridge/state", self.topics.bridge_state_payload(False), retain=True)

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
        await self._publish_availability(dev, True)
        self._emit_device_event("joined", dev)
        if j.plain_join and self.cfg.zigbee.rotate_key_after_plain_join:
            dev.context["rotate_after_join"] = True
        if not dev.interviewed:
            self._start_interview(dev)
        else:
            await self._publish_bridge_info()
            await self._maybe_rotate_after_join(dev)

    async def _maybe_rotate_after_join(self, dev: Device) -> None:
        """A device paired without an install code received the network key under the public key,
        so a sniffer present at that moment may hold it. Now that the device has its own link key
        (trust-centre key exchange is mandatory here), rotate the network key over the air: the new
        key reaches every device under per-device keys and the exposed one dies within minutes."""
        if not dev.context.pop("rotate_after_join", False):
            return
        from .rotation import KeyRotation
        from .security import Keystore
        if self._rotation is None:
            self._rotation = KeyRotation(self.coord, self.registry, Keystore(self.cfg.data_dir / "network.keystore"), self.audit)
        if self._rotation.running:
            return
        try:
            self._rotation.start(window_s=300, by="policy:rotate_after_plain_join")
            self.audit.security("key_rotation_after_plain_join", ieee=dev.ieee_str)
        except ValueError as e:
            log.info("rotation after join not started: %s", e)

    async def _on_left(self, ieee: int, nwk: int) -> None:
        dev = self.registry.get(ieee)
        if dev:
            await self._forget(dev)

    def _start_interview(self, dev: Device) -> None:
        old = self._interview_tasks.pop(dev.ieee, None)
        if old:
            old.cancel()
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
            for ep in dev.endpoints.values():
                for cluster in ep.in_clusters:
                    if cluster == 0x0500:
                        await self._enroll_ias(dev, ep.id)
                    if cluster in _READ_ON_JOIN:
                        try:
                            state = await self.read_attributes(dev, ep.id, cluster, _READ_ON_JOIN[cluster])
                            self._apply_changes(dev, quirks.translate_state(dev, ep.id, state))
                        except (ZnpError, asyncio.TimeoutError):
                            log.info("%s: read %s failed (sleepy device?)", dev.ieee_str, zcl.cluster_name(cluster))
                    if cluster in _REPORTING and self._may_bind(policy, cluster):
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
            log.warning("interview of %s failed: %s", dev.ieee_str, e)
            dev.interview_error = str(e)
            dev.context.pop("reporting_done", None)  # try again when the device next talks
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
            for ep in dev.endpoints.values():
                for cluster in ep.in_clusters:
                    if cluster in _REPORTING and self._may_bind(policy, cluster):
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

    async def _tuya_query(self, dev: Device, ep: int) -> None:
        """Ask a Tuya datapoint device to report every datapoint (dataQuery)."""
        try:
            await self.coord.send_aps(dev.nwk, ep, vz.TUYA_CLUSTER, gc.build_cluster_command(self._next_seq(), vz.TUYA_CMD_QUERY, b"", disable_default_response=True), wait_confirm=False)
        except (ZnpError, asyncio.TimeoutError) as e:
            log.info("%s: datapoint query failed: %s", dev.ieee_str, e)

    _TUYA_SETTLE_ATTRS = [0x0004, 0x0000, 0x0001, 0x0005, 0x0007, 0xFFFE]

    async def _vendor_settle(self, dev: Device) -> None:
        """Vendor-specific one-off after configuration. Tuya mains devices keep reporting a Basic
        cluster attribute every 200 ms until the coordinator has read this attribute set once."""
        if not str(dev.manufacturer or "").startswith("_TZ"):
            return
        prim = dev.primary_endpoint()
        ep = next((e.id for e in dev.endpoints.values() if 0x0000 in e.in_clusters), prim.id if prim else 1)
        try:
            await self.read_attributes(dev, ep, 0x0000, self._TUYA_SETTLE_ATTRS)
            self._settled.add(dev.ieee)
        except (ZnpError, asyncio.TimeoutError) as e:
            log.info("%s: Tuya settle read failed (%s)", dev.ieee_str, e)

    async def _setup_reporting(self, dev: Device, ep: int, cluster: int) -> None:
        try:
            await self.coord.bind(dev.nwk, dev.ieee, ep, cluster)
            records = [gc.ReportingConfigRecord(attr=a, dtype=int(dt), min_interval=mn, max_interval=mx, reportable_change=ch)
                       for a, dt, mn, mx, ch in _REPORTING[cluster]]
            seq = self._next_seq()
            rsp = await self._request(dev, ep, cluster, gc.build_configure_reporting(seq, records), seq, gc.CMD_CONFIGURE_REPORTING_RSP)
            status = "ok"
            try:
                dec = gc.decode_global_command(rsp)
                bad = [r for r in getattr(dec, "records", []) if getattr(r, "status", 0) != 0]
                if bad:
                    status = f"status {bad[0].status:#04x}"
            except Exception:
                pass
            self._record_bindings(dev, ep, cluster, "coordinator", 1)
            for a, _dt, mn, mx, ch in _REPORTING[cluster]:
                self._record_reporting(dev, ep, cluster, a, mn, mx, ch, status)
        except (ZnpError, asyncio.TimeoutError) as e:
            log.info("%s: reporting setup for %s failed: %s", dev.ieee_str, zcl.cluster_name(cluster), e)
            for a, _dt, mn, mx, ch in _REPORTING[cluster]:
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
            # Traffic from a short address we do not know: the firmware
            # authenticated it (it is on our network), but we have no record.
            self.audit.security("traffic_from_unknown_device", nwk=f"{m.src_addr:#06x}", cluster=f"{m.cluster:#06x}")
            return
        dev.last_seen = time.time()
        dev.lqi = m.lqi
        if not dev.available:
            # Heard from it: it is online, whatever its import/registry state said.
            dev.available = True
            await self._publish_availability(dev, True)
            self._emit_device_event("online", dev)
        if (str(dev.manufacturer or "").startswith("_TZ") and dev.ieee not in self._settled
                and dev.ieee not in self._interview_tasks and dev.context.get("reporting_done")):
            self._settled.add(dev.ieee)  # once per device per start (the device forgets it on its own power cycle)
            asyncio.create_task(self._vendor_settle(dev), name=f"settle-{dev.ieee_str}")
        if dev.context.get("imported_from") and not dev.context.get("reporting_done") and dev.ieee not in self._interview_tasks:
            dev.context["reporting_done"] = True  # set first so a burst of frames schedules it once
            if dev.endpoints and dev.interviewed:
                self._interview_tasks[dev.ieee] = asyncio.create_task(self._post_import_setup(dev), name=f"post-import-{dev.ieee_str}")
            else:
                self._start_interview(dev)  # no endpoints, or never marked interviewed: learn/confirm now
        # m.secure is the *APS-layer* flag; ordinary ZCL traffic is NWK-encrypted only,
        # so it is informational, not an alert. NWK security is enforced by the firmware.
        try:
            frame = zcl.decode_frame(m.payload)
        except zcl.ZclFrameError as e:
            log.debug("%s: undecodable ZCL on %#06x: %s", dev.ieee_str, m.cluster, e)
            return

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
                changed = quirks.translate_state(dev, m.src_ep, changed)
        elif m.cluster == 0x0019 and frame.direction == zcl.DIRECTION_CLIENT_TO_SERVER:
            rsp = self.ota.handle(dev.ieee, dev.nwk, m.src_ep, frame.command, frame.payload)
            if rsp is not None:
                cmd_id, body = rsp
                out = gc.build_cluster_command(frame.seq, cmd_id, body, direction=zcl.DIRECTION_SERVER_TO_CLIENT,
                                               disable_default_response=True)
                asyncio.create_task(self.coord.send_aps(dev.nwk, m.src_ep, 0x0019, out, wait_confirm=False))
            return
        elif m.cluster == vz.TUYA_CLUSTER and frame.direction == zcl.DIRECTION_SERVER_TO_CLIENT:
            changed = await self._tuya_report(dev, frame)
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

    def _apply_changes(self, dev: Device, changed: dict[str, Any]) -> list[dict[str, Any]]:
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
            return None
        self.registry.add_or_update(ieee, nwk)
        self.audit.event("short_address_learned", ieee=dev.ieee_str, nwk=f"{nwk:#06x}")
        return dev

    async def _default_response(self, dev: Device, m: IncomingAps, frame: zcl.ZclFrame) -> None:
        try:
            payload = gc.build_default_response(frame.seq, frame.command, gc.STATUS_SUCCESS, zcl.DIRECTION_CLIENT_TO_SERVER, frame.manufacturer)
            await self.coord.send_aps(dev.nwk, m.src_ep, m.cluster, payload, wait_confirm=False)
        except Exception:
            log.debug("default response to %s failed", dev.ieee_str, exc_info=True)

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
        devices = [{"ieee": d.ieee_str, "friendly_name": d.friendly_name, "manufacturer": d.manufacturer, "model": d.model,
                    "vendor": d.vendor, "kind": d.kind, "category": d.category,
                    "interviewed": d.interviewed, "router": d.is_router,
                    "endpoints": {str(e.id): e.category for e in d.endpoints.values()}} for d in devs]
        await self.broker.publish(f"{self.base}/bridge/devices", json.dumps(devices).encode(), retain=True)

    async def _announce(self, dev: Device) -> None:
        if not self.cfg.homeassistant.discovery:
            return
        for topic, payload in discovery_messages(dev, self.base, self.cfg.homeassistant.discovery_prefix, legacy=self.legacy):
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
            log.warning("command to %s failed: %s", dev.ieee_str, e)

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
        if isinstance(body, dict) and "state" in body and dev.primary_endpoint() and 0x0006 in dev.primary_endpoint().in_clusters:
            try:
                ep = dev.primary_endpoint().id
                state = await self.read_attributes(dev, ep, 0x0006, [0x0000])
                self._apply_changes(dev, quirks.translate_state(dev, ep, state))
            except (ZnpError, asyncio.TimeoutError):
                pass
        await self._publish_state(dev)

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
            if k == "heating_setpoint":  # accepted alias of the published key
                k = "current_heating_setpoint"
            f = by_key.get(k)
            if f is not None and f.get("base"):
                ep = forced_ep if forced_ep is not None else (f["endpoint"] or ep_obj.id)
                per_ep.setdefault(ep, {})[f["base"]] = v
                if f["cluster"] == vz.TUYA_CLUSTER:
                    per_ep[ep].setdefault("__dp__", {})[k] = v
            else:
                per_ep.setdefault(forced_ep if forced_ep is not None else ep_obj.id, {})[k] = v
        transition = int(float(cmd.get("transition", 0)) * 10)
        for ep, body in per_ep.items():
            await self._apply_command_ep(dev, ep, body, transition)
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
        if "position" in cmd and 0x0102 in ins:
            pos = max(0, min(100, int(cmd["position"])))
            await send(0x0102, "go_to_lift_percentage", {"percentage": 100 - pos})
        if "current_heating_setpoint" in cmd and 0x0201 in ins:
            await self._write_attr(dev, ep, 0x0201, 0x0012, zcl.DataType.int16, int(round(float(cmd["current_heating_setpoint"]) * 100)))
            self._apply_changes(dev, {key_of("current_heating_setpoint"): float(cmd["current_heating_setpoint"])})
        if "system_mode" in cmd and 0x0201 in ins:
            modes = {"off": 0, "auto": 1, "cool": 3, "heat": 4}
            await self._write_attr(dev, ep, 0x0201, 0x001C, zcl.DataType.enum8, modes[str(cmd["system_mode"])])
            self._apply_changes(dev, {key_of("system_mode"): str(cmd["system_mode"])})
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

    async def _write_attr(self, dev: Device, ep: int, cluster: int, attr: int, dtype: zcl.DataType, value: Any) -> None:
        seq = self._next_seq()
        frame = gc.build_write_attributes(seq, [gc.WriteAttributeRecord(attr, int(dtype), value)])
        await self._request(dev, ep, cluster, frame, seq, gc.CMD_WRITE_ATTRIBUTES_RSP)

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

    CONTROL_ACTIONS = ("permit_join", "rotate_network_key", "remove")

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
            "interview": self._req_interview, "rotate_network_key": self._req_rotate_key, "devices": self._req_devices,
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
        if mode != "over_the_air":
            raise ValueError("mode must be over_the_air or repair")
        from .rotation import DEFAULT_WINDOW_S, KeyRotation
        if self._rotation is None:
            self._rotation = KeyRotation(self.coord, self.registry, ks, self.audit)
        st = self._rotation.start(window_s=int(body.get("window_s", DEFAULT_WINDOW_S)), by=who)
        return {"rotation": st.to_json()}

    def rotation_status(self) -> dict[str, Any]:
        return self._rotation.state.to_json() if self._rotation else {"phase": "idle"}
