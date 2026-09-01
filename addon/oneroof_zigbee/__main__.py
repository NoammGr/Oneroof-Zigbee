"""`python -m oneroof_zigbee run -c config.yaml`  /  `python -m oneroof_zigbee passwd ...`"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import json
import logging
import signal
import ssl
import sys
from pathlib import Path

from .config import Config, ConfigError, TlsConfig
from .devices import Registry
from .gateway import Gateway
from .mqtt import Acl, Broker, PasswordFile
from .security import Audit, JoinGuard, JoinPolicy, Keystore
from .znp import AbsentTransport, Coordinator, Transport, ZnpError, open_serial

log = logging.getLogger("oneroof_zigbee")
_last_broker: Broker | None = None  # exposed for the smoke test
_last_ui = None


def _tls_context(cfg: Config, tls: "TlsConfig") -> ssl.SSLContext | None:
    """Build a server TLS context; mode auto generates a local CA + cert in data_dir/tls."""
    from .security.tls import ensure_server_cert, fingerprint, server_context
    if not tls.enabled:
        return None
    if tls.mode == "auto":
        cert, key, ca = ensure_server_cert(cfg.data_dir, tls.hostnames)
        log.info("TLS: local CA %s  (SHA-256 %s) — install it on clients, or pin the broker cert", ca, fingerprint(ca))
    else:
        cert, key = tls.cert, tls.key  # type: ignore[assignment]
    return server_context(cert, key, tls.client_ca)


async def run(cfg: Config, config_path: Path | None = None, *, managed: bool = False, on_broker_ready=None) -> int:
    from . import __version__
    log.info("One Roof Zigbee %s starting (%s)", __version__, "add-on" if managed else "standalone")
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    audit = Audit(cfg.data_dir / "audit.log")
    secrets = Keystore(cfg.data_dir / "network.keystore").load_or_create(cfg.zigbee.channel)
    if secrets.channel != cfg.zigbee.channel:
        log.warning("config channel %d differs from formed network channel %d; keeping the network's channel "
                    "(rotate the key to re-form)", cfg.zigbee.channel, secrets.channel)

    passwords = PasswordFile(cfg.mqtt.password_file)
    if not passwords.has_user(cfg.mqtt.gateway_user):
        import secrets as pysecrets
        passwords.set_password(cfg.mqtt.gateway_user, pysecrets.token_urlsafe(32))
    acl = Acl()
    acl.allow(cfg.mqtt.gateway_user, publish=["#"], subscribe=["#"])
    for name, u in cfg.mqtt.users.items():
        acl.allow(name, publish=u.publish, subscribe=u.subscribe)
    control_users = {cfg.mqtt.gateway_user, *cfg.mqtt.control_users}
    # UI-managed users and their permissions must be in the ACL BEFORE the broker accepts clients:
    # Home Assistant reconnects within a second and subscribes once; a denial then sticks.
    from .admin import Admin
    admin = Admin(cfg, config_path, passwords, acl, control_users, managed=managed)  # loads users.yaml into the ACL
    admin.audit = audit

    global _last_broker
    if cfg.mqtt.external is not None:
        from .mqtt.external import ExternalBroker
        e = cfg.mqtt.external
        broker = ExternalBroker(e.server, user=e.user, password=e.password, ca=str(e.ca) if e.ca else None, client_id=e.client_id)
        await broker.start()
        log.warning("using EXTERNAL broker %s — the built-in broker is not running; MQTT control requests are refused "
                    "(use the UI); switch to the built-in TLS broker from Settings when ready", e.server)
    else:
        broker = Broker(auth=passwords, acl=acl, host=cfg.mqtt.listen, port=cfg.mqtt.port, tls=_tls_context(cfg, cfg.mqtt.tls))
        await broker.start()
        if cfg.mqtt.tls.enabled:
            log.info("MQTT broker listening on %s:%d (TLS 1.2+)", cfg.mqtt.listen, cfg.mqtt.port)
        else:
            log.warning("MQTT broker listening on %s:%d in PLAINTEXT — credentials and device state are readable on the network", cfg.mqtt.listen, cfg.mqtt.port)
        if cfg.mqtt.plaintext_port is not None and cfg.mqtt.tls.enabled:
            await broker.add_listener(cfg.mqtt.listen, cfg.mqtt.plaintext_port, tls=None)
            log.warning("additional PLAINTEXT MQTT listener on %s:%d (mqtt.plaintext_port) — for legacy devices only", cfg.mqtt.listen, cfg.mqtt.plaintext_port)
    _last_broker = broker
    if on_broker_ready is not None:
        try:
            on_broker_ready()
        except Exception:
            log.exception("on_broker_ready hook failed")
    if cfg.compat.legacy_layout:
        log.info("legacy layout: topics %s/<friendly name> and legacy discovery identities", cfg.mqtt.base_topic)

    coordinator_present = True
    try:
        reader, writer = await open_serial(cfg.serial.port, cfg.serial.baudrate, rtscts=cfg.serial.rtscts)
        transport = Transport(reader, writer)
        transport.start()
    except (FileNotFoundError, PermissionError, OSError, ValueError) as e:
        # The dongle is not there at boot (unplugged, USB passthrough not attached yet). Exiting
        # would take the broker — the house's MQTT backbone — and the UI down with it, and the
        # add-on would crash-loop. Come up in the same degraded mode as losing the link at
        # runtime: everything but the radio runs, and the connection supervisor below keeps
        # trying to open the port with backoff.
        log.error("coordinator not present at start (%s) — broker and UI come up without it; retrying in the background", e)
        transport = AbsentTransport()
        coordinator_present = False
    guard = JoinGuard(JoinPolicy(max_seconds=cfg.zigbee.permit_join_max_seconds,
                                 cooldown_seconds=cfg.zigbee.permit_join_cooldown_seconds,
                                 require_install_code=cfg.zigbee.permit_join_require_install_code,
                                 close_after_first_join=cfg.zigbee.permit_join_close_after_first_join), audit)
    coord = Coordinator(transport, secrets, guard, audit, strict_install_codes=cfg.zigbee.strict_install_codes)
    coord.keystore = Keystore(cfg.data_dir / "network.keystore")  # key-sequence fixes found at start are persisted
    try:  # routing/broadcast settings chosen in the panel; the coordinator re-applies them if the radio drifted
        coord.radio_tuning = {str(k): int(v) for k, v in
                              json.loads((cfg.data_dir / "radio.json").read_text()).items()}
    except (OSError, ValueError, TypeError):
        coord.radio_tuning = {}
    if coordinator_present:
        try:
            await coord.start()
        except ZnpError as e:
            # The port opened but the radio does not answer (dead stick, wrong device). Same
            # degraded mode: everything else runs, the supervisor loop below keeps retrying.
            log.error("coordinator not answering at start (%s) — broker and UI come up without it; retrying in the background", e)
            with contextlib.suppress(Exception):
                await transport.close()
            coordinator_present = False

    if isinstance(broker, Broker):
        broker.audit = audit  # login failures / lockouts as security records (notifications, Activity)
    if managed and isinstance(broker, Broker):
        broker.adopt_login = admin.adopt_login  # adopt Home Assistant's existing broker login (time-boxed)
    if control_users == {cfg.mqtt.gateway_user}:
        log.warning("no control users yet — add one under Settings → Users & access before pairing")

    registry = Registry(cfg.data_dir / "devices.json")
    gw = Gateway(cfg, coord, broker, audit, registry, control_users=control_users)
    if not coordinator_present:
        gw.coordinator_online = False
    await gw.start()

    # Telegram notifications: the only outbound connection, behind the egress allow-list (off until enabled in the UI).
    from .notify import EgressClient, NotifySecrets, NotifySettings, TelegramNotifier

    def _friendly(ieee: str) -> str | None:
        try:
            from .znp.wire import ieee_int
            d = registry.get(ieee_int(ieee))
        except ValueError:
            return None
        return d.friendly_name if d else None

    notifier = TelegramNotifier(audit, EgressClient(audit), NotifySettings(cfg.data_dir / "notify.yaml"),
                                NotifySecrets(cfg.data_dir / "notify.secrets"), resolve_name=_friendly)
    notifier.start()

    ui_server = None
    if cfg.ui.enabled:
        from .ui.api import EventBus, RingLogHandler, UiApi
        from .ui.server import Server
        bus = EventBus()
        ring = RingLogHandler(bus)
        ring.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger().addHandler(ring)
        ui_server = Server(cfg.ui.listen, cfg.ui.port, tls=_tls_context(cfg, cfg.ui.tls))
        UiApi(gw, ui_server, bus, ring, acts_as=cfg.ui.acts_as, admin=admin, notifier=notifier)
        await ui_server.start()
        global _last_ui
        _last_ui = ui_server
        if cfg.ui.acts_as not in control_users:
            log.warning("UI acts as %r which is not in control_users — pairing/removing from the UI will be refused", cfg.ui.acts_as)

    stop = asyncio.Event()
    restart = asyncio.Event()
    admin.set_restart_hook(lambda: asyncio.get_running_loop().call_later(0.5, restart.set))  # let the HTTP reply flush first
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    async def _fired(ev: asyncio.Event, timeout: float | None = None) -> bool:
        try:
            await asyncio.wait_for(ev.wait(), timeout)
        except asyncio.TimeoutError:
            return False
        return True

    # Coordinator connection supervisor. When the serial link to the dongle
    # drops (unplugged, USB glitch, adapter reset) we do NOT exit: the broker,
    # UI and notifier stay up, we alert (coordinator_offline → Telegram + UI),
    # and reconnect in place with backoff. The gateway keeps the same
    # Coordinator object across the reconnect (see Coordinator.rebind), and its
    # device commands already fail gracefully while the link is down.
    rc = 0
    stop_t = asyncio.create_task(stop.wait())
    restart_t = asyncio.create_task(restart.wait())
    while True:
        closed = asyncio.create_task(transport.closed.wait())
        await asyncio.wait({stop_t, restart_t, closed}, return_when=asyncio.FIRST_COMPLETED)
        if not closed.done():
            closed.cancel()
        if restart.is_set():
            audit.event("restart_requested")
            rc = 4  # RESTART_EXIT_CODE: main() re-execs, the add-on supervisor restarts the container
            break
        if stop.is_set():
            break
        # Transport closed on its own: the coordinator link is gone.
        log.error("coordinator serial link closed — reconnecting")
        gw.coordinator_online = False
        audit.security("coordinator_offline", reason="serial link closed")
        await transport.close()
        delay = 2.0
        while not (stop.is_set() or restart.is_set()):
            if await _fired(stop, delay) or restart.is_set():
                break
            try:
                reader, writer = await open_serial(cfg.serial.port, cfg.serial.baudrate, rtscts=cfg.serial.rtscts)
                transport = Transport(reader, writer)
                transport.start()
                coord.rebind(transport)
                await coord.start()
            except (OSError, ValueError, ZnpError, asyncio.TimeoutError) as e:
                delay = min(delay * 2, 30.0)
                log.warning("coordinator reconnect failed (%s); retrying in %.0fs", e, delay)
                with contextlib.suppress(Exception):
                    await transport.close()
                continue
            gw.coordinator_online = True
            audit.event("coordinator_online")
            log.info("coordinator reconnected")
            break
        if restart.is_set():
            audit.event("restart_requested")
            rc = 4
            break
        if stop.is_set():
            break
        # reconnected — fall through to wait on the new transport again
    for _t in (stop_t, restart_t):
        if not _t.done():
            _t.cancel()
    await notifier.stop()
    await gw.stop()
    if ui_server:
        await ui_server.stop()
    await transport.close()
    await broker.stop()
    return rc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="oneroof-zigbee")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the gateway")
    r.add_argument("-c", "--config", type=Path, default=Path("config.yaml"))
    pw = sub.add_parser("passwd", help="set an MQTT user's password")
    pw.add_argument("-c", "--config", type=Path, default=Path("config.yaml"))
    pw.add_argument("user")
    pw.add_argument("--password", help="omit to be prompted")
    va = sub.add_parser("verify-audit", help="check the audit log hash chain")
    va.add_argument("-c", "--config", type=Path, default=Path("config.yaml"))
    pr = sub.add_parser("pair", help="open the join window (optionally with an install code) via MQTT")
    pr.add_argument("-c", "--config", type=Path, default=Path("config.yaml"))
    pr.add_argument("--host", default="127.0.0.1")
    pr.add_argument("--user", default="admin")
    pr.add_argument("--password", help="omit to be prompted")
    pr.add_argument("--seconds", type=int, default=60)
    pr.add_argument("--ieee", help="device IEEE, e.g. 0x00124b00deadbeef (required with --install-code)")
    pr.add_argument("--install-code", help="install code from the device label, hex, spaces allowed")
    pr.add_argument("--close", action="store_true", help="close the window instead")
    im = sub.add_parser("import", help="import a previous setup (no re-pairing when keeping the same dongle)")
    im.add_argument("-c", "--config", type=Path, default=Path("config.yaml"))
    im.add_argument("source_dir", type=Path, help="data folder of the previous setup (configuration.yaml, database.db, coordinator_backup.json)")
    im.add_argument("--apply", action="store_true", help="write the result (default: preview only)")
    args = p.parse_args(argv)

    try:
        cfg = Config.load(args.config)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    logging.basicConfig(level=getattr(logging, cfg.log_level, logging.INFO),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    if args.cmd == "passwd":
        password = args.password or getpass.getpass(f"password for {args.user}: ")
        if len(password) < 12:
            print("password must be at least 12 characters", file=sys.stderr)
            return 2
        PasswordFile(cfg.mqtt.password_file).set_password(args.user, password)
        print(f"updated {args.user} in {cfg.mqtt.password_file}")
        return 0
    if args.cmd == "verify-audit":
        ok, line = Audit.verify(cfg.data_dir / "audit.log")
        print("audit log OK" if ok else f"audit log TAMPERED at line {line}")
        return 0 if ok else 1
    if args.cmd == "pair":
        return asyncio.run(pair(cfg, args))
    if args.cmd == "import":
        return import_previous(cfg, args)
    try:
        rc = asyncio.run(run(cfg, args.config))
    except KeyboardInterrupt:
        return 0
    if rc == 4:
        from .admin import Admin
        log.info("restarting")
        Admin.exec_self()
    return rc


def import_previous(cfg: Config, args: argparse.Namespace) -> int:
    import json

    from .devices import Registry
    from .importer import apply_plan, build_plan
    from .security import Keystore

    files = {}
    for name in ("configuration.yaml", "database.db", "coordinator_backup.json", "state.json"):
        f = args.source_dir / name
        if f.exists():
            files[name] = f.read_text(errors="replace")
    if not files:
        print(f"no importable files found in {args.source_dir}", file=sys.stderr)
        return 2
    try:
        plan = build_plan(configuration_yaml=files.get("configuration.yaml"), database_db=files.get("database.db"),
                          coordinator_backup=files.get("coordinator_backup.json"), state_json=files.get("state.json"))
    except ValueError as e:
        print(f"import error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(plan.summary(), indent=2))
    if not args.apply:
        print("\npreview only — add --apply to import")
        return 0
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    ks = Keystore(cfg.data_dir / "network.keystore")
    current = ks.load_or_create(cfg.zigbee.channel)
    secrets = apply_plan(plan, Registry(cfg.data_dir / "devices.json"), current)
    if secrets is not current:
        ks.save(secrets)
        print("network parameters adopted; start the gateway with the SAME dongle and devices will keep working")
    print(f"imported {len(plan.devices)} devices")
    return 0


async def pair(cfg: Config, args: argparse.Namespace) -> int:
    """Talk to the running gateway over MQTT with our own client and watch the result."""
    import json

    from .mqtt import Client

    password = args.password or getpass.getpass(f"MQTT password for {args.user}: ")
    tls = None
    if cfg.mqtt.tls.enabled:
        from .security.tls import client_context
        ca = cfg.data_dir / "tls" / "ca.crt" if cfg.mqtt.tls.mode == "auto" else None
        tls = client_context(ca if ca and ca.exists() else None, server_hostname_check=args.host not in ("127.0.0.1", "localhost", "::1"))
    base = cfg.mqtt.base_topic
    done = asyncio.Event()
    joined: list[str] = []

    async def on_msg(topic: str, payload: bytes) -> None:
        try:
            body = json.loads(payload or b"{}")
        except ValueError:
            return
        if topic.endswith("/response/permit_join"):
            print("gateway:", body)
            if not body.get("ok") or args.close:
                done.set()
        elif topic.endswith("/bridge/event"):
            t = body.get("type")
            if t in ("device_joined", "interview_started", "interview_done", "interview_failed", "permit_join_closed"):
                print(f"event: {t} {body.get('ieee', '')} {body.get('model') or ''} {body.get('error') or ''}".rstrip())
            if t == "interview_done":
                joined.append(body.get("ieee", "?"))
                done.set()
            if t == "permit_join_closed":
                done.set()
        elif topic.endswith("/bridge/security"):
            print("SECURITY:", body)

    client = Client(args.host, cfg.mqtt.port, username=args.user, password=password, client_id="oneroof-zigbee-pair", tls=tls)
    try:
        await client.connect()
    except Exception as e:
        print(f"cannot connect to broker at {args.host}:{cfg.mqtt.port}: {e}", file=sys.stderr)
        return 1
    await client.subscribe(f"{base}/bridge/response/permit_join", on_msg)
    await client.subscribe(f"{base}/bridge/event", on_msg)
    await client.subscribe(f"{base}/bridge/security", on_msg)
    req: dict[str, object] = {"seconds": 0 if args.close else args.seconds}
    if args.install_code:
        if not args.ieee:
            print("--install-code requires --ieee", file=sys.stderr)
            return 2
        req["ieee"] = args.ieee
        req["install_code"] = args.install_code
    elif args.ieee:
        req["ieee"] = args.ieee
    await client.publish(f"{base}/bridge/request/permit_join", json.dumps(req).encode(), qos=1)
    if not args.close:
        print(f"waiting up to {args.seconds}s for a device… (Ctrl-C to stop)")
    try:
        await asyncio.wait_for(done.wait(), args.seconds + 15)
    except asyncio.TimeoutError:
        print("no device joined")
    finally:
        await client.disconnect()
    return 0 if (args.close or joined) else 1


if __name__ == "__main__":
    sys.exit(main())
