"""UI routes. Every control action re-uses the gateway's request handlers so
the MQTT path and the UI path enforce identical policy and audit identically."""

from __future__ import annotations

import asyncio
import collections
import json
import logging
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from .. import __version__
from ..admin import ROLE_TEMPLATES, Admin
from ..gateway import Gateway
from ..config import ConfigError
from ..security import Audit
from ..znp.wire import ieee_int, ieee_str
from .server import HttpError, Request, Response, Server

log = logging.getLogger("oneroof_zigbee.ui.api")
STATIC = Path(__file__).parent / "static"


class RingLogHandler(logging.Handler):
    """Keeps the last N application log records in memory for the Logs page."""

    def __init__(self, bus: EventBus, n: int = 2000) -> None:
        super().__init__()
        self.records: collections.deque[dict[str, Any]] = collections.deque(maxlen=n)
        self.bus = bus

    def emit(self, record: logging.LogRecord) -> None:
        try:
            item = {"ts": record.created, "level": record.levelname, "logger": record.name, "msg": self.format(record)}
        except Exception:
            return
        self.records.append(item)
        self.bus.publish("log", item)


class EventBus:
    """Fan-out of UI events to every open SSE connection."""

    def __init__(self) -> None:
        self._queues: set[asyncio.Queue[tuple[str, Any]]] = set()

    def publish(self, event: str, data: Any) -> None:
        for q in list(self._queues):
            if q.qsize() > 500:  # slow consumer: drop it rather than grow without bound
                self._queues.discard(q)
                continue
            q.put_nowait((event, data))

    async def stream(self) -> AsyncIterator[tuple[str, Any]]:
        q: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
        self._queues.add(q)
        try:
            while True:
                try:
                    yield await asyncio.wait_for(q.get(), 20)
                except asyncio.TimeoutError:
                    yield ("ping", {"t": time.time()})
        finally:
            self._queues.discard(q)


class UiApi:
    def __init__(self, gw: Gateway, server: Server, bus: EventBus, log_handler: RingLogHandler, *, acts_as: str,
                 admin: "Admin | None" = None) -> None:
        self.gw = gw
        self.admin = admin
        self.bus = bus
        self.logs = log_handler
        self.acts_as = acts_as
        self.started = time.time()
        self._map_cache: dict[str, Any] = {"nodes": [], "links": [], "updated": None}
        self._map_lock = asyncio.Lock()
        self._index = (STATIC / "index.html").read_bytes() if (STATIC / "index.html").exists() else b"<h1>UI not built</h1>"

        r = server.route
        r("GET", "/", self.index)
        r("GET", "/index.html", self.index)
        r("GET", "/favicon.ico", self.favicon)
        r("GET", "/favicon.svg", self.favicon)
        r("GET", "/api/bridge", self.bridge)
        r("GET", "/api/devices", self.devices)
        r("GET", "/api/devices/<ieee>", self.device)
        r("GET", "/api/audit", self.audit)
        r("GET", "/api/audit/verify", self.audit_verify)
        r("GET", "/api/logs", self.app_logs)
        r("GET", "/api/map", self.map)
        r("POST", "/api/permit_join", self.permit_join)
        r("POST", "/api/devices/<ieee>/set", self.dev_set)
        r("POST", "/api/devices/<ieee>/rename", self.dev_rename)
        r("POST", "/api/devices/<ieee>/remove", self.dev_remove)
        r("POST", "/api/devices/<ieee>/interview", self.dev_interview)
        r("POST", "/api/devices/<ieee>/identify", self.dev_identify)
        r("POST", "/api/devices/<ieee>/describe", self.dev_describe)
        r("POST", "/api/devices/<ieee>/read", self.dev_read)
        r("POST", "/api/devices/<ieee>/reporting", self.dev_reporting)
        r("POST", "/api/devices/<ieee>/bind", self.dev_bind)
        r("POST", "/api/devices/<ieee>/unbind", self.dev_unbind)
        r("POST", "/api/map/refresh", self.map_refresh)
        r("POST", "/api/rotate_network_key", self.rotate)
        r("POST", "/api/settings", self.settings)
        r("GET", "/api/config", self.config_get)
        r("POST", "/api/config", self.config_save)
        r("GET", "/api/users", self.users_get)
        r("POST", "/api/users", self.users_upsert)
        r("POST", "/api/users/<name>/remove", self.users_remove)
        r("GET", "/api/tls/ca", self.tls_ca)
        r("POST", "/api/backup", self.backup)
        r("POST", "/api/restore", self.restore)
        r("POST", "/api/restart", self.restart)
        r("GET", "/api/activity", self.activity)
        r("GET", "/api/firmware", self.fw_list)
        r("POST", "/api/firmware/upload", self.fw_upload)
        r("POST", "/api/firmware/<file>/remove", self.fw_remove)
        r("GET", "/api/devices/<ieee>/update", self.fw_status)
        r("POST", "/api/devices/<ieee>/update/check", self.fw_check)
        r("POST", "/api/devices/<ieee>/update/start", self.fw_start)
        r("POST", "/api/devices/<ieee>/update/cancel", self.fw_cancel)
        r("POST", "/api/import/preview", self.import_preview)
        r("POST", "/api/import/apply", self.import_apply)
        server.sse("/api/events", lambda req: self.bus.stream())

        # hook gateway → bus
        gw.audit.subscribe(self._on_audit)
        gw.on_state_change = self._on_state
        gw.on_device_event = self._on_device_event
        gw.on_activity = lambda ieee, ev: self.bus.publish("activity", {"ieee": ieee_str(ieee), **ev})

    # -- event hooks -------------------------------------------------------

    def _on_audit(self, rec: dict[str, Any]) -> None:
        data = {k: v for k, v in rec.items() if k != "prev"}
        self.bus.publish("security" if rec["level"] == "security" else "audit", data)
        if rec["type"] in ("permit_join_opened", "permit_join_closed"):
            self.bus.publish("permit_join", self._permit_state())

    def _on_state(self, ieee: int, state: dict[str, Any]) -> None:
        self.bus.publish("state", {"ieee": ieee_str(ieee), "state": state})

    def _on_device_event(self, action: str, dev: Any) -> None:
        self.bus.publish("device", {"action": action, "device": self._dev_json(dev)})

    # -- helpers -----------------------------------------------------------

    @property
    def can_control(self) -> bool:
        return self.acts_as in self.gw.control_users

    @property
    def who(self) -> str:
        return f"ui:{self.acts_as}"

    def _permit_state(self) -> dict[str, Any]:
        w = self.gw.coord.guard.window
        return {"open": w is not None, "seconds_left": int(w.expires_at - time.monotonic()) if w else 0,
                "requested_by": w.requested_by if w else None}

    def _dev_json(self, d: Any, *, detail: bool = False) -> dict[str, Any]:
        out = {
            "ieee": d.ieee_str, "friendly_name": d.friendly_name, "description": d.description,
            "manufacturer": d.manufacturer, "model": d.model,
            "sw_build": d.sw_build, "power_source": d.power_source, "is_router": d.is_router, "interviewed": d.interviewed,
            "interview_error": d.interview_error, "available": d.available, "lqi": d.lqi, "last_seen": d.last_seen,
            "joined_at": d.joined_at, "nwk": f"{d.nwk:#06x}", "nwk_decimal": d.nwk,
            "endpoints": {str(e.id): {"category": e.category, "in_clusters": e.in_clusters, "out_clusters": e.out_clusters}
                          for e in d.endpoints.values()},
            "state": d.state,
        }
        if not detail:
            return out
        from ..features import features_for
        from ..oui import vendor_of
        from ..zcl import cluster_name, describe_endpoint
        out.update({
            "oui_vendor": vendor_of(d.ieee), "manufacturer_code": d.context.get("manufacturer_code"),
            "hw_version": d.hw_version, "date_code": d.date_code, "zcl_version": d.zcl_version,
            "app_version": d.app_version, "stack_version": d.stack_version,
            "mqtt": {"state_topic": self.gw.topics.state(d), "set_topic": self.gw.topics.set(d),
                     "availability_topic": self.gw.topics.availability(d), "legacy_layout": self.gw.legacy},
            "endpoints": {str(e.id): {
                "category": e.category, "profile": e.profile, "device_id": e.device_id,
                "device_type": describe_endpoint(e.in_clusters, e.out_clusters, e.device_id, e.profile)["device_type"],
                "in_clusters": [{"id": c, "name": cluster_name(c)} for c in e.in_clusters],
                "out_clusters": [{"id": c, "name": cluster_name(c)} for c in e.out_clusters],
            } for e in d.endpoints.values()},
            "exposes": features_for(d), "activity": d.activity[-50:], "reporting": d.reporting, "bindings": d.bindings, "raw": d.raw,
        })
        return out

    def _find(self, req: Request) -> Any:
        try:
            ieee = ieee_int(req.params["ieee"])
        except ValueError as e:
            raise HttpError(400, "bad ieee") from e
        dev = self.gw.registry.get(ieee)
        if dev is None:
            raise HttpError(404, "unknown device")
        return dev

    def _require_control(self) -> None:
        if not self.can_control:
            self.gw.audit.security("request_denied", action="ui", by=self.who, reason="ui user not in control_users")
            raise HttpError(403, f"not authorized: add '{self.acts_as}' to mqtt.control_users")

    # -- GET ---------------------------------------------------------------

    async def index(self, req: Request) -> Response:
        return Response(200, self._index, "text/html; charset=utf-8")

    _FAVICON = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#e2603c"/>'
                b'<path d="M10 10h12l-12 12h12" fill="none" stroke="#fff" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/>'
                b'<path d="M23.5 8.5a4 4 0 0 1 0 0M21.5 9.2a3.2 3.2 0 0 1 3.2-3.2M21.5 11.4a5.4 5.4 0 0 1 5.4-5.4" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round"/></svg>')

    async def favicon(self, req: Request) -> Response:
        return Response(200, self._FAVICON, "image/svg+xml", {"Cache-Control": "public, max-age=86400"})

    async def bridge(self, req: Request) -> Response:
        c = self.gw.coord
        return Response.json({
            "version": __version__, "coordinator_ieee": ieee_str(c.ieee), "channel": c.secrets.channel,
            "pan_id": f"{c.secrets.pan_id:#06x}", "strict_install_codes": c.strict,
            "require_install_code": c.guard.policy.require_install_code, "max_join_seconds": c.guard.policy.max_seconds,
            "device_count": len(self.gw.registry.all()), "permit_join": self._permit_state(),
            "uptime_s": int(time.time() - self.started), "ui_user": self.acts_as, "ui_can_control": self.can_control,
            "log_level": logging.getLevelName(logging.getLogger().level),
            "restart_required": (self.admin.restart_required if self.admin else []), "managed": (self.admin.managed if self.admin else False),
        })

    async def devices(self, req: Request) -> Response:
        return Response.json([self._dev_json(d) for d in self.gw.registry.all()])

    async def device(self, req: Request) -> Response:
        return Response.json(self._dev_json(self._find(req), detail=True))

    async def audit(self, req: Request) -> Response:
        n = max(1, min(2000, int(req.query.get("n", "200") or 200)))
        level = req.query.get("level", "all")
        path = self.gw.audit.path
        rows: list[dict[str, Any]] = []
        if path and Path(path).exists():
            with open(path, "rb") as f:
                lines = collections.deque(f, maxlen=n if level == "all" else 20000)
            for line in lines:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if level == "security" and rec.get("level") != "security":
                    continue
                rec.pop("prev", None)
                rows.append(rec)
        return Response.json(rows[-n:])

    async def audit_verify(self, req: Request) -> Response:
        if not self.gw.audit.path:
            return Response.json({"ok": None, "first_bad_line": 0})
        ok, line = Audit.verify(Path(self.gw.audit.path))
        self.gw.audit.event("audit_verified", by=self.who, ok=ok)
        return Response.json({"ok": ok, "first_bad_line": line})

    async def app_logs(self, req: Request) -> Response:
        n = max(1, min(2000, int(req.query.get("n", "500") or 500)))
        return Response.json(list(self.logs.records)[-n:])

    async def map(self, req: Request) -> Response:
        return Response.json(self._map_cache)

    # -- POST --------------------------------------------------------------

    async def permit_join(self, req: Request) -> Response:
        self._require_control()
        result = await self.gw.handle_request("permit_join", req.json, self.who)
        return Response.json(result, 200 if result.get("ok") else 400)

    async def dev_set(self, req: Request) -> Response:
        dev = self._find(req)
        self.gw.audit.event("command", ieee=dev.ieee_str, by=self.who, keys=sorted(req.json))
        try:
            await self.gw.apply_command(dev, req.json)
        except Exception as e:
            raise HttpError(400, str(e)) from e
        return Response.json({"ok": True, "state": dev.state})

    async def dev_rename(self, req: Request) -> Response:
        dev = self._find(req)
        result = await self.gw.handle_request("rename", {"ieee": dev.ieee_str, "friendly_name": req.json.get("friendly_name", "")}, self.who)
        return Response.json(result, 200 if result.get("ok") else 400)

    async def dev_remove(self, req: Request) -> Response:
        self._require_control()
        dev = self._find(req)
        result = await self.gw.handle_request("remove", {"ieee": dev.ieee_str}, self.who)
        return Response.json(result, 200 if result.get("ok") else 400)

    async def dev_interview(self, req: Request) -> Response:
        dev = self._find(req)
        result = await self.gw.handle_request("interview", {"ieee": dev.ieee_str}, self.who)
        return Response.json(result, 200 if result.get("ok") else 400)

    async def dev_identify(self, req: Request) -> Response:
        dev = self._find(req)
        try:
            await self.gw.apply_command(dev, {"identify": 10})
        except Exception as e:
            raise HttpError(400, str(e)) from e
        return Response.json({"ok": True})

    async def dev_describe(self, req: Request) -> Response:
        dev = self._find(req)
        try:
            await self.gw.set_description(dev, str(req.json.get("description", "")), self.who)
        except ValueError as e:
            raise HttpError(400, str(e)) from e
        return Response.json({"ok": True, "description": dev.description})

    @staticmethod
    def _int(v: Any, name: str) -> int:
        try:
            return int(str(v), 0)
        except (TypeError, ValueError) as e:
            raise HttpError(400, f"{name} must be an integer") from e

    async def dev_read(self, req: Request) -> Response:
        dev = self._find(req)
        ep = self._int(req.json.get("endpoint", dev.primary_endpoint().id if dev.primary_endpoint() else 1), "endpoint")
        cluster = self._int(req.json.get("cluster"), "cluster")
        attrs = req.json.get("attributes") or []
        if not isinstance(attrs, list):
            raise HttpError(400, "attributes must be a list")
        attrs = [self._int(a, "attribute") for a in attrs]
        try:
            values, state = await self.gw.read_live(dev, ep, cluster, attrs)
        except ValueError as e:
            raise HttpError(400, str(e)) from e
        except Exception as e:
            raise HttpError(502, f"device did not answer: {e}") from e
        self.gw.audit.event("attributes_read", ieee=dev.ieee_str, by=self.who, cluster=f"{cluster:#06x}")
        return Response.json({"ok": True, "values": values, "decoded": state})

    async def dev_reporting(self, req: Request) -> Response:
        dev = self._find(req)
        b = req.json
        ep = self._int(b.get("endpoint", 1), "endpoint")
        cluster, attr = self._int(b.get("cluster"), "cluster"), self._int(b.get("attribute"), "attribute")
        mn, mx = self._int(b.get("min", 0), "min"), self._int(b.get("max", 3600), "max")
        change = b.get("change")
        if change is not None and not isinstance(change, (int, float)):
            change = self._int(change, "change")
        try:
            status = await self.gw.configure_reporting(dev, ep, cluster, attr, mn, mx, change, self.who)
        except ValueError as e:
            raise HttpError(400, str(e)) from e
        except Exception as e:
            raise HttpError(502, f"device did not answer: {e}") from e
        return Response.json({"ok": status == "ok", "status": status, "reporting": dev.reporting})

    async def dev_bind(self, req: Request) -> Response:
        return await self._bind(req, unbind=False)

    async def dev_unbind(self, req: Request) -> Response:
        return await self._bind(req, unbind=True)

    async def _bind(self, req: Request, *, unbind: bool) -> Response:
        dev = self._find(req)
        b = req.json
        ep = self._int(b.get("endpoint", 1), "endpoint")
        cluster = self._int(b.get("cluster"), "cluster")
        target = str(b.get("target", "coordinator"))
        tep = self._int(b.get("target_endpoint", 1), "target_endpoint")
        try:
            await self.gw.bind(dev, ep, cluster, target, tep, self.who, unbind=unbind)
        except ValueError as e:
            raise HttpError(400, str(e)) from e
        except Exception as e:
            raise HttpError(502, str(e)) from e
        return Response.json({"ok": True, "bindings": dev.bindings})

    async def map_refresh(self, req: Request) -> Response:
        if self._map_lock.locked():
            return Response.json({"ok": False, "error": "refresh already running"}, 409)
        async with self._map_lock:
            self._map_cache = await self._build_map()
        return Response.json({"ok": True, **self._map_cache})

    async def rotate(self, req: Request) -> Response:
        self._require_control()
        result = await self.gw.handle_request("rotate_network_key", req.json, self.who)
        return Response.json(result, 200 if result.get("ok") else 400)

    async def settings(self, req: Request) -> Response:
        lvl = str(req.json.get("log_level", "")).upper()
        if lvl:
            if lvl not in ("DEBUG", "INFO", "WARNING", "ERROR"):
                raise HttpError(400, "bad log_level")
            logging.getLogger().setLevel(lvl)
            self.gw.audit.event("log_level_changed", by=self.who, level=lvl)
        return Response.json({"ok": True, "log_level": logging.getLevelName(logging.getLogger().level)})

    # -- settings ----------------------------------------------------------

    def _admin(self) -> Admin:
        if self.admin is None:
            raise HttpError(404, "administration not available")
        return self.admin

    def _tls_info(self) -> dict[str, Any]:
        cfg = self.gw.cfg
        info: dict[str, Any] = {"mode": cfg.mqtt.tls.mode, "enabled": cfg.mqtt.tls.enabled}
        ca = cfg.data_dir / "tls" / "ca.crt"
        if cfg.mqtt.tls.mode == "auto" and ca.exists():
            from ..security.tls import fingerprint
            info.update({"ca_path": str(ca), "ca_fingerprint_sha256": fingerprint(ca)})
        return info

    async def config_get(self, req: Request) -> Response:
        a = self._admin()
        cfg = self.gw.cfg
        return Response.json({
            "managed": a.managed, "config_path": str(a.config_path) if a.config_path else None,
            "restart_required": a.restart_required, "config": a.editable_config(),
            "serial_ports": a.serial_ports(), "tls": self._tls_info(), "defaults": a.DEFAULTS,
            "coordinator": {"ieee": ieee_str(self.gw.coord.ieee), "version": (self.gw.coord.version.__dict__ if self.gw.coord.version else None),
                            "channel": self.gw.coord.secrets.channel, "pan_id": f"{self.gw.coord.secrets.pan_id:#06x}"},
            "roles": {k: {"description": v["description"], "control": v["control"]} for k, v in ROLE_TEMPLATES.items()},
            "ha_setup": {"host": "<this host>", "port": cfg.mqtt.port, "tls": cfg.mqtt.tls.enabled, "user": "homeassistant",
                         "base_topic": cfg.mqtt.base_topic, "discovery_prefix": cfg.homeassistant.discovery_prefix},
            "data_dir": str(cfg.data_dir),
        })

    async def config_save(self, req: Request) -> Response:
        a = self._admin()
        self._require_control()
        try:
            changed = a.save_config(req.json)
        except (ValueError, ConfigError) as e:
            raise HttpError(400, str(e)) from e
        except PermissionError as e:
            raise HttpError(403, str(e)) from e
        self.gw.audit.event("config_changed", by=self.who, keys=changed)
        return Response.json({"ok": True, "changed": changed, "restart_required": a.restart_required})

    async def users_get(self, req: Request) -> Response:
        return Response.json({"users": self._admin().list_users(), "gateway_user": self.gw.cfg.mqtt.gateway_user})

    async def users_upsert(self, req: Request) -> Response:
        a = self._admin()
        self._require_control()
        b = req.json
        try:
            a.upsert_user(str(b.get("name", "")).strip(), role=str(b.get("role", "custom")),
                          password=(str(b["password"]) if b.get("password") else None),
                          control=(bool(b["control"]) if "control" in b else None),
                          subscribe=(list(b["subscribe"]) if isinstance(b.get("subscribe"), list) else None),
                          publish=(list(b["publish"]) if isinstance(b.get("publish"), list) else None))
        except ValueError as e:
            raise HttpError(400, str(e)) from e
        self.gw.audit.event("user_upserted", by=self.who, user=str(b.get("name")), role=str(b.get("role")),
                            password_changed=bool(b.get("password")))
        return Response.json({"ok": True, "users": a.list_users()})

    async def users_remove(self, req: Request) -> Response:
        a = self._admin()
        self._require_control()
        name = req.params["name"]
        try:
            a.remove_user(name)
        except ValueError as e:
            raise HttpError(400, str(e)) from e
        self.gw.audit.event("user_removed", by=self.who, user=name)
        return Response.json({"ok": True, "users": a.list_users()})

    async def tls_ca(self, req: Request) -> Response:
        ca = self.gw.cfg.data_dir / "tls" / "ca.crt"
        if not ca.exists():
            raise HttpError(404, "no local CA (tls mode is not auto)")
        return Response(200, ca.read_bytes(), "application/x-pem-file", {"Content-Disposition": 'attachment; filename="oneroof-zigbee-ca.crt"'})

    async def backup(self, req: Request) -> Response:
        a = self._admin()
        self._require_control()
        try:
            blob = a.make_backup(str(req.json.get("password", "")))
        except ValueError as e:
            raise HttpError(400, str(e)) from e
        self.gw.audit.security("backup_created", by=self.who, size=len(blob))
        import base64
        return Response.json({"ok": True, "filename": f"oneroof-zigbee-{time.strftime('%Y%m%d-%H%M%S')}.ozbk", "data_b64": base64.b64encode(blob).decode()})

    async def restore(self, req: Request) -> Response:
        a = self._admin()
        self._require_control()
        import base64
        try:
            blob = base64.b64decode(str(req.json.get("data_b64", "")), validate=True)
            restored = a.restore_backup(blob, str(req.json.get("password", "")))
        except ValueError as e:
            raise HttpError(400, str(e)) from e
        self.gw.audit.security("backup_restored", by=self.who, files=restored)
        return Response.json({"ok": True, "restored": restored, "restart_required": a.restart_required})

    async def restart(self, req: Request) -> Response:
        a = self._admin()
        self._require_control()
        self.gw.audit.event("restart_requested", by=self.who)
        try:
            a.request_restart()
        except PermissionError as e:
            raise HttpError(403, str(e)) from e
        return Response.json({"ok": True})

    # -- activity / firmware / import -------------------------------------

    async def activity(self, req: Request) -> Response:
        n = max(1, min(2000, int(req.query.get("n", "200") or 200)))
        rows = self.gw.query_activity(device=req.query.get("device") or None, key=req.query.get("key") or None, n=n)
        keys = sorted({r.get("key") for r in self.gw.activity if r.get("key")})
        return Response.json({"rows": rows, "keys": keys})

    async def fw_list(self, req: Request) -> Response:
        return Response.json({"images": [i.to_json() for i in self.gw.ota.images.values()], "allow_downgrade": self.gw.ota.allow_downgrade,
                              "policy": "Firmware is only ever taken from files you upload here; the gateway never downloads firmware."})

    async def fw_upload(self, req: Request) -> Response:
        self._require_control()
        import base64
        from ..ota import OtaError
        try:
            data = base64.b64decode(str(req.json.get("data_b64", "")), validate=True)
            img = self.gw.ota.add_image(str(req.json.get("filename", "firmware.ota")), data)
        except (ValueError, OtaError) as e:
            raise HttpError(400, str(e)) from e
        return Response.json({"ok": True, "image": img.to_json()})

    async def fw_remove(self, req: Request) -> Response:
        self._require_control()
        self.gw.ota.remove_image(req.params["file"])
        self.gw.audit.event("firmware_removed", by=self.who, file=req.params["file"])
        return Response.json({"ok": True})

    async def fw_status(self, req: Request) -> Response:
        dev = self._find(req)
        st = self.gw.ota.status(dev.ieee)
        st["has_ota_client"] = any(0x0019 in e.out_clusters for e in dev.endpoints.values())
        return Response.json(st)

    async def fw_check(self, req: Request) -> Response:
        """Ask the device what firmware it runs (it answers with a QueryNextImage)."""
        dev = self._find(req)
        try:
            await self.gw.ota_notify(dev)
        except Exception as e:
            raise HttpError(400, str(e)) from e
        self.gw.audit.event("firmware_check_requested", ieee=dev.ieee_str, by=self.who)
        return Response.json({"ok": True})

    async def fw_start(self, req: Request) -> Response:
        self._require_control()
        dev = self._find(req)
        from ..ota import OtaError
        try:
            img = self.gw.ota.arm(dev.ieee, str(req.json.get("file", "")), self.who)
            await self.gw.ota_notify(dev)
        except (OtaError, ValueError) as e:
            self.gw.ota.disarm(dev.ieee)
            raise HttpError(400, str(e)) from e
        except Exception as e:
            raise HttpError(502, str(e)) from e
        return Response.json({"ok": True, "image": img.to_json()})

    async def fw_cancel(self, req: Request) -> Response:
        self._require_control()
        dev = self._find(req)
        self.gw.ota.disarm(dev.ieee)
        self.gw.audit.event("firmware_update_cancelled", ieee=dev.ieee_str, by=self.who)
        return Response.json({"ok": True})

    def _import_files(self, body: dict[str, Any]) -> dict[str, str]:
        files: dict[str, str] = {}
        for name in ("configuration.yaml", "database.db", "coordinator_backup.json", "state.json"):
            v = body.get(name)
            if isinstance(v, str) and v.strip():
                if len(v) > 1_500_000:
                    raise HttpError(413, f"{name} too large")
                files[name] = v
        if not files:
            raise HttpError(400, "upload at least one of configuration.yaml, database.db, coordinator_backup.json")
        return files

    async def import_preview(self, req: Request) -> Response:
        self._require_control()
        try:
            return Response.json({"ok": True, **self._admin().import_preview(self._import_files(req.json))})
        except ValueError as e:
            raise HttpError(400, str(e)) from e

    async def import_apply(self, req: Request) -> Response:
        self._require_control()
        a = self._admin()
        try:
            b = req.json
            result = a.import_apply(self._import_files(b), self.gw.registry, self.gw.coord.secrets, self.gw.coord.known_ieee,
                                    keep_broker=bool(b.get("keep_broker", True)), keep_entities=bool(b.get("keep_entities", True)),
                                    broker_user=(str(b["broker_user"]) if b.get("broker_user") else None),
                                    broker_password=(str(b["broker_password"]) if b.get("broker_password") else None))
        except ValueError as e:
            raise HttpError(400, str(e)) from e
        self.gw.audit.security("previous_setup_import", by=self.who, devices=result["devices"], network_adopted=result["network_adopted"])
        for dev in self.gw.registry.all():
            await self.gw._announce(dev)
            self._on_device_event("renamed", dev)
        await self.gw._publish_bridge_info()
        return Response.json({"ok": True, **result, "restart_required": a.restart_required})

    # -- map ---------------------------------------------------------------

    async def _build_map(self) -> dict[str, Any]:
        coord = self.gw.coord
        reg = self.gw.registry
        nodes: dict[int, dict[str, Any]] = {coord.ieee: {"ieee": ieee_str(coord.ieee), "friendly_name": "Coordinator", "type": "coordinator", "lqi": None}}
        for d in reg.all():
            nodes[d.ieee] = {"ieee": d.ieee_str, "friendly_name": d.friendly_name,
                             "type": "router" if d.is_router else "end_device", "lqi": d.lqi}
        links: list[dict[str, Any]] = []
        targets = [(coord.ieee, 0x0000)] + [(d.ieee, d.nwk) for d in reg.all() if d.is_router and d.available]
        for ieee, nwk in targets:
            try:
                for n in await coord.neighbors(nwk, timeout=6.0):
                    if n.ieee not in nodes:
                        nodes[n.ieee] = {"ieee": ieee_str(n.ieee), "friendly_name": ieee_str(n.ieee), "type": "unknown", "lqi": n.lqi}
                    links.append({"source": ieee_str(ieee), "target": ieee_str(n.ieee), "lqi": n.lqi, "depth": n.depth,
                                  "relationship": ["parent", "child", "sibling", "none", "former"][n.relationship] if n.relationship < 5 else "unknown"})
            except Exception as e:
                log.info("map: neighbour table of %s failed: %s", ieee_str(ieee), e)
        return {"nodes": list(nodes.values()), "links": links, "updated": time.time()}
