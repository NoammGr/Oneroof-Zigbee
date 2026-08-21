"""A small, strict MQTT 3.1.1 broker.

Design notes / deliberate deviations from the spec (all documented in
docs/ARCHITECTURE.md):

* Anonymous connections are rejected with CONNACK 0x05. No opt-out.
* Every session is treated as *clean session = 1*; persistent sessions are
  not implemented, so CONNACK always has ``session_present = 0``.
* QoS 2 is downgraded to QoS 1 (PUBREC/PUBREL/PUBCOMP are not implemented
  and a PUBLISH with QoS 2 is treated as QoS 1 — we PUBACK it).
* Outbound QoS 1 messages are sent once and their PUBACK is tracked; there
  is no redelivery on reconnect because sessions are not persistent.
* Max packet size is 256 KiB; clients are dropped at 1.5x keepalive.
* Topics beginning with ``$`` are writable only by ``sys_user`` (the
  gateway's own user); everything else goes through the :class:`Acl`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from oneroof_zigbee.mqtt import packets as pk
from oneroof_zigbee.mqtt.auth import Acl, Authenticator

log = logging.getLogger("oneroof_zigbee.mqtt.broker")

MAX_CONNECTIONS = 256
MAX_CONCURRENT_VERIFY = 2
MAX_RETAINED_TOPICS = 5000          # in-process (gateway) publishes are exempt
MAX_RETAINED_BYTES = 16 * 1024 * 1024

LocalCallback = Callable[[str, bytes, "str | None"], Awaitable[None]]
"""(topic, payload, publisher_username) — username is None for in-process publishes
and retained replays, the authenticated broker user otherwise."""

MAX_SUBSCRIPTIONS = 64
MAX_INFLIGHT = 1000
MAX_OUTBOUND_QUEUE = 1000
CONNECT_TIMEOUT = 10.0
WRITE_TIMEOUT = 10.0
AUTH_FAILURES_BEFORE_LOCKOUT = 5
AUTH_LOCKOUT_SECONDS = 30.0
AUTH_FAILURE_WINDOW = 60.0
SYS_CLIENTS_CONNECTED = "$SYS/broker/clients/connected"


@dataclass(slots=True)
class _Retained:
    payload: bytes
    qos: int


@dataclass(slots=True)
class _LocalSubscription:
    topic_filter: str
    callback: LocalCallback


class _Session:
    """State for one connected TCP client."""

    def __init__(self, broker: Broker, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.broker = broker
        self.reader = reader
        self.writer = writer
        peer = writer.get_extra_info("peername")
        self.ip: str = peer[0] if peer else "?"
        self.client_id = ""
        self.username = ""
        self.keepalive = 0
        self.will: pk.Publish | None = None
        self.subscriptions: dict[str, int] = {}  # filter -> granted qos
        self.inflight: dict[int, float] = {}  # outbound packet id -> send time
        self._next_pid = 1
        self._outq: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=MAX_OUTBOUND_QUEUE)
        self._writer_task: asyncio.Task[None] | None = None
        self.connected = False
        self.clean_disconnect = False
        self._closing = False

    # -- outbound ---------------------------------------------------------

    def send(self, packet: pk.Packet) -> None:
        if self._closing:
            return
        try:
            self._outq.put_nowait(pk.encode(packet))
        except asyncio.QueueFull:
            log.warning("client %r (%s): outbound queue full, dropping connection", self.client_id, self.ip)
            self.close()

    async def _write_loop(self) -> None:
        try:
            while True:
                data = await self._outq.get()
                if data is None:
                    return
                self.writer.write(data)
                await asyncio.wait_for(self.writer.drain(), WRITE_TIMEOUT)
        except (asyncio.TimeoutError, ConnectionError, OSError) as exc:
            log.info("client %r (%s): write failed: %s", self.client_id, self.ip, exc)
        finally:
            self.close()
            with contextlib.suppress(Exception):
                self.writer.close()

    def close(self) -> None:
        """Flush queued packets (e.g. the CONNACK) and then close the socket."""
        if self._closing:
            return
        self._closing = True
        try:
            self._outq.put_nowait(None)  # writer loop closes the transport after the sentinel
        except asyncio.QueueFull:
            with contextlib.suppress(Exception):
                self.writer.close()

    def next_packet_id(self) -> int:
        for _ in range(pk.MAX_PACKET_ID):
            pid = self._next_pid
            self._next_pid = pid % pk.MAX_PACKET_ID + 1
            if pid not in self.inflight:
                return pid
        raise RuntimeError("no free packet identifiers")

    def deliver(self, topic: str, payload: bytes, qos: int, retain: bool) -> None:
        """Queue a PUBLISH for this client at ``min(qos, granted)``."""
        if qos > 0:
            if len(self.inflight) >= MAX_INFLIGHT:
                log.warning("client %r: %d unacked messages, delivering QoS 0", self.client_id, MAX_INFLIGHT)
                qos = 0
        pid = None
        if qos > 0:
            pid = self.next_packet_id()
            self.inflight[pid] = time.monotonic()
        self.send(pk.Publish(topic=topic, payload=payload, qos=qos, retain=retain, packet_id=pid))

    # -- inbound ----------------------------------------------------------

    async def run(self) -> None:
        self._writer_task = asyncio.create_task(self._write_loop())
        try:
            await self._handshake()
            if self.connected:
                await self._loop()
        except pk.MalformedPacket as exc:
            log.warning("client %r (%s): protocol error: %s", self.client_id, self.ip, exc)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError) as exc:
            log.info("client %r (%s): connection lost: %s", self.client_id, self.ip, exc)
        finally:
            self.close()
            if self._writer_task:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(self._writer_task, WRITE_TIMEOUT)
            with contextlib.suppress(Exception):
                await self.writer.wait_closed()
            if self.connected:
                await self.broker._on_session_closed(self)

    async def _read_packet(self, timeout: float | None) -> pk.Packet:
        buf = bytearray()
        while True:
            try:
                packet, _ = pk.decode_one(bytes(buf))
                return packet
            except pk.NeedMoreData:
                pass
            # Read exactly what is missing once the header is known, else 1 byte.
            try:
                _, _, length, hsize = pk.decode_fixed_header(bytes(buf))
                need = hsize + length - len(buf)
            except pk.NeedMoreData:
                need = 1
            chunk = await asyncio.wait_for(self.reader.readexactly(need), timeout)
            buf += chunk

    async def _handshake(self) -> None:
        first = await self._read_packet(CONNECT_TIMEOUT)
        if not isinstance(first, pk.Connect):
            raise pk.MalformedPacket("first packet was not CONNECT")
        broker = self.broker
        if broker._is_locked_out(self.ip):
            log.warning("auth: %s is locked out, rejecting", self.ip)
            await self._reject(pk.CONNACK_NOT_AUTHORIZED)
            return
        if not first.username:
            log.warning("auth: anonymous connect from %s rejected", self.ip)
            broker._record_auth_failure(self.ip)
            await self._reject(pk.CONNACK_NOT_AUTHORIZED)
            return
        ok = await broker._verify_credentials(self.ip, first.username, first.password or b"")
        if not ok:
            log.warning("auth: bad credentials for user %r from %s", first.username, self.ip)
            await self._reject(pk.CONNACK_BAD_CREDENTIALS)
            return
        broker._clear_auth_failures(self.ip)
        self.username = first.username
        self.client_id = first.client_id or f"auto-{id(self):x}"
        self.keepalive = first.keepalive
        if first.will_topic is not None:
            self.will = pk.Publish(
                topic=first.will_topic,
                payload=first.will_payload,
                qos=min(first.will_qos, 1),
                retain=first.will_retain,
            )
        if not first.clean_session:
            log.info("client %r requested persistent session; treating as clean session", self.client_id)
        self.connected = True
        await broker._on_session_opened(self)
        self.send(pk.Connack(session_present=False, return_code=pk.CONNACK_ACCEPTED))
        log.info("client %r user %r connected from %s", self.client_id, self.username, self.ip)

    async def _reject(self, code: int) -> None:
        self.send(pk.Connack(session_present=False, return_code=code))
        self.close()

    async def _loop(self) -> None:
        timeout = self.keepalive * 1.5 if self.keepalive else None
        while not self._closing:
            packet = await self._read_packet(timeout)
            match packet:
                case pk.Publish():
                    await self._on_publish(packet)
                case pk.Puback(packet_id=pid):
                    if self.inflight.pop(pid, None) is None:
                        log.debug("client %r: PUBACK for unknown id %d", self.client_id, pid)
                case pk.Subscribe():
                    self._on_subscribe(packet)
                case pk.Unsubscribe(packet_id=pid, topics=topics):
                    for tf in topics:
                        if self.subscriptions.pop(tf, None) is not None:
                            self.broker._unsubscribe_session(self, tf)
                    self.send(pk.Unsuback(pid))
                case pk.Pingreq():
                    self.send(pk.Pingresp())
                case pk.Disconnect():
                    self.clean_disconnect = True
                    self.will = None
                    self.close()
                    return
                case pk.Connect():
                    raise pk.MalformedPacket("second CONNECT")
                case _:
                    raise pk.MalformedPacket(f"unexpected {type(packet).__name__} from client")

    async def _on_publish(self, p: pk.Publish) -> None:
        qos = min(p.qos, 1)  # QoS 2 downgraded
        if self.broker._may_publish(self.username, p.topic):
            await self.broker._route(p.topic, p.payload, qos, p.retain, publisher=self.username)
        else:
            log.warning("acl: user %r denied publish to %r", self.username, p.topic)
        if qos == 1 and p.packet_id is not None:
            self.send(pk.Puback(p.packet_id))

    def _on_subscribe(self, s: pk.Subscribe) -> None:
        codes: list[int] = []
        for tf, req_qos in s.topics:
            if not self.broker.acl.can_subscribe(self.username, tf):
                log.warning("acl: user %r denied subscribe to %r", self.username, tf)
                codes.append(pk.SUBACK_FAILURE)
                continue
            if tf not in self.subscriptions and len(self.subscriptions) >= MAX_SUBSCRIPTIONS:
                log.warning("client %r: subscription limit reached", self.client_id)
                codes.append(pk.SUBACK_FAILURE)
                continue
            granted = min(req_qos, 1)
            self.subscriptions[tf] = granted
            self.broker._subscribe_session(self, tf)
            codes.append(granted)
        self.send(pk.Suback(s.packet_id, codes))
        # Retained messages are sent after SUBACK (3.8.4 allows either order).
        for (tf, _), code in zip(s.topics, codes):
            if code != pk.SUBACK_FAILURE:
                self.broker._send_retained(self, tf, code)


class Broker:
    """MQTT 3.1.1 broker with an in-process publish/subscribe fast path."""

    def __init__(
        self,
        *,
        auth: Authenticator,
        acl: Acl,
        host: str = "127.0.0.1",
        port: int = 1883,
        tls: ssl.SSLContext | None = None,
        sys_user: str | None = None,
    ) -> None:
        self.auth = auth
        self.acl = acl
        self.host = host
        self.port = port
        self.tls = tls
        self.sys_user = sys_user
        self._server: asyncio.base_events.Server | None = None
        self._extra_servers: list[asyncio.base_events.Server] = []
        self._sessions: set[_Session] = set()
        self._tasks: set[asyncio.Task[None]] = set()
        self._subs: dict[str, set[_Session]] = {}  # filter -> sessions
        self._local_subs: list[_LocalSubscription] = []
        self._retained: dict[str, _Retained] = {}
        self._auth_failures: dict[str, list[float]] = {}
        self._lockouts: dict[str, float] = {}
        # DoS limits: total connections, concurrent scrypt verifications, retained store size.
        self._conn_sem = asyncio.Semaphore(MAX_CONNECTIONS)
        self._verify_sem = asyncio.Semaphore(MAX_CONCURRENT_VERIFY)
        self._retained_bytes = 0

    # -- lifecycle --------------------------------------------------------

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._on_connection, self.host, self.port, ssl=self.tls)
        self.port = self._server.sockets[0].getsockname()[1]
        await self._publish_client_count()
        log.info("listening on %s:%d%s", self.host, self.port, " (TLS)" if self.tls else "")

    async def add_listener(self, host: str, port: int, *, tls: ssl.SSLContext | None) -> int:
        """Open an additional listener sharing sessions, auth, ACL and retained store."""
        srv = await asyncio.start_server(self._on_connection, host, port, ssl=tls)
        self._extra_servers.append(srv)
        bound = srv.sockets[0].getsockname()[1]
        log.info("additional listener on %s:%d%s", host, bound, " (TLS)" if tls else " (plaintext)")
        return bound

    async def stop(self) -> None:
        for srv in self._extra_servers:
            srv.close()
        if self._server is not None:
            self._server.close()  # stop accepting; existing connections keep running
        for s in list(self._sessions):
            s.close()
        if self._tasks:
            done, pending = await asyncio.wait(self._tasks, timeout=WRITE_TIMEOUT)
            for t in pending:
                t.cancel()
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None
        for srv in self._extra_servers:
            await srv.wait_closed()
        self._extra_servers.clear()
        log.info("stopped")

    @property
    def client_count(self) -> int:
        return len(self._sessions)

    async def _on_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._conn_sem.locked():
            log.warning("connection limit (%d) reached; refusing %s", MAX_CONNECTIONS, writer.get_extra_info("peername"))
            writer.close()
            return
        async with self._conn_sem:
            session = _Session(self, reader, writer)
            task = asyncio.current_task()
            if task is not None:
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            await session.run()

    async def _verify_credentials(self, ip: str, username: str, password: bytes) -> bool:
        """scrypt is deliberately expensive; bound concurrency and count the attempt
        toward the lockout *before* doing the work so parallel guesses cannot bypass it."""
        self._record_auth_attempt(ip)
        if self._is_locked_out(ip):
            return False
        async with self._verify_sem:
            return await asyncio.get_running_loop().run_in_executor(None, self.auth.verify, username, password)

    async def _on_session_opened(self, session: _Session) -> None:
        # Client ID takeover: a new connection with the same id disconnects the old one (3.1.4).
        for other in list(self._sessions):
            if other.client_id == session.client_id:
                log.info("client %r: taken over by new connection from %s", session.client_id, session.ip)
                other.close()
        self._sessions.add(session)
        await self._publish_client_count()

    async def _on_session_closed(self, session: _Session) -> None:
        self._sessions.discard(session)
        for tf in list(session.subscriptions):
            self._unsubscribe_session(session, tf)
        if session.inflight:
            log.warning("client %r: disconnected with %d unacked QoS1 messages", session.client_id, len(session.inflight))
        log.info("client %r disconnected%s", session.client_id, "" if session.clean_disconnect else " (abrupt)")
        if session.will is not None and not session.clean_disconnect:
            w = session.will
            if self._may_publish(session.username, w.topic):
                await self._route(w.topic, w.payload, w.qos, w.retain, publisher=session.username)
            else:
                log.warning("acl: user %r will to %r dropped", session.username, w.topic)
        await self._publish_client_count()

    async def _publish_client_count(self) -> None:
        await self._route(SYS_CLIENTS_CONNECTED, str(len(self._sessions)).encode(), 0, True)

    # -- auth rate limiting -----------------------------------------------

    def _is_locked_out(self, ip: str) -> bool:
        until = self._lockouts.get(ip)
        if until is None:
            return False
        if time.monotonic() >= until:
            del self._lockouts[ip]
            return False
        return True

    def _record_auth_attempt(self, ip: str) -> None:
        """Count an attempt; successes clear the history afterwards (see _clear_auth_failures)."""
        self._record_auth_failure(ip)

    def _record_auth_failure(self, ip: str) -> None:
        now = time.monotonic()
        hist = [t for t in self._auth_failures.get(ip, []) if now - t < AUTH_FAILURE_WINDOW]
        hist.append(now)
        if len(hist) >= AUTH_FAILURES_BEFORE_LOCKOUT:
            self._lockouts[ip] = now + AUTH_LOCKOUT_SECONDS
            self._auth_failures.pop(ip, None)
            log.warning("auth: %s locked out for %.0f s after %d failures", ip, AUTH_LOCKOUT_SECONDS, len(hist))
        else:
            self._auth_failures[ip] = hist

    def _clear_auth_failures(self, ip: str) -> None:
        self._auth_failures.pop(ip, None)

    # -- authorisation ----------------------------------------------------

    def _may_publish(self, username: str, topic: str) -> bool:
        if topic.startswith("$"):
            return self.sys_user is not None and username == self.sys_user
        return self.acl.can_publish(username, topic)

    # -- subscriptions ----------------------------------------------------

    def _subscribe_session(self, session: _Session, tf: str) -> None:
        self._subs.setdefault(tf, set()).add(session)

    def _unsubscribe_session(self, session: _Session, tf: str) -> None:
        sessions = self._subs.get(tf)
        if sessions is not None:
            sessions.discard(session)
            if not sessions:
                del self._subs[tf]

    def _send_retained(self, session: _Session, tf: str, granted_qos: int) -> None:
        for topic, r in list(self._retained.items()):
            if pk.topic_matches(tf, topic):
                session.deliver(topic, r.payload, min(r.qos, granted_qos), True)

    # -- routing ----------------------------------------------------------

    async def _route(self, topic: str, payload: bytes, qos: int, retain: bool, publisher: str | None = None) -> None:
        if retain:
            old = self._retained.pop(topic, None)
            if old is not None:
                self._retained_bytes -= len(old.payload)
            if payload:
                if (publisher is not None and (len(self._retained) >= MAX_RETAINED_TOPICS
                                               or self._retained_bytes + len(payload) > MAX_RETAINED_BYTES)):
                    log.warning("retained store full; dropping retain flag for %r from %r", topic, publisher)
                else:
                    self._retained[topic] = _Retained(payload, qos)
                    self._retained_bytes += len(payload)
        # TCP subscribers: one delivery per session at the highest matching granted QoS.
        targets: dict[_Session, int] = {}
        for tf, sessions in self._subs.items():
            if pk.topic_matches(tf, topic):
                for s in sessions:
                    granted = s.subscriptions.get(tf, 0)
                    targets[s] = max(targets.get(s, 0), granted)
        for s, granted in targets.items():
            s.deliver(topic, payload, min(qos, granted), False)
        # In-process subscribers.
        for ls in list(self._local_subs):
            if pk.topic_matches(ls.topic_filter, topic):
                try:
                    await ls.callback(topic, payload, publisher)
                except Exception:
                    log.exception("local subscriber for %r raised", ls.topic_filter)

    # -- in-process API ---------------------------------------------------

    async def publish(self, topic: str, payload: bytes, retain: bool = False, qos: int = 0) -> None:
        """Publish from inside the process (the gateway). Not subject to the ACL."""
        pk.validate_topic(topic)
        if qos not in (0, 1, 2):
            raise ValueError("qos must be 0, 1 or 2")
        await self._route(topic, bytes(payload), min(qos, 1), retain)

    def subscribe(self, topic_filter: str, cb: LocalCallback) -> Callable[[], None]:
        """Subscribe from inside the process. Returns an unsubscribe function.

        Retained messages matching the filter are delivered asynchronously.
        """
        pk.validate_filter(topic_filter)
        sub = _LocalSubscription(topic_filter, cb)
        self._local_subs.append(sub)
        matching = [(t, r.payload) for t, r in self._retained.items() if pk.topic_matches(topic_filter, t)]
        if matching:

            async def _deliver_retained() -> None:
                for t, p in matching:
                    if sub in self._local_subs:
                        try:
                            await cb(t, p, None)
                        except Exception:
                            log.exception("local subscriber for %r raised", topic_filter)

            asyncio.get_running_loop().create_task(_deliver_retained())

        def unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._local_subs.remove(sub)

        return unsubscribe

    def retained(self, topic: str) -> bytes | None:
        r = self._retained.get(topic)
        return r.payload if r else None
