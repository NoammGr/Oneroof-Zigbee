"""A small asyncio MQTT 3.1.1 client (for tests, the CLI and external brokers).

Supports username/password, optional TLS, Last Will, QoS 0/1 publish,
subscribe with per-filter callbacks, keepalive pings and automatic
reconnect with exponential backoff. QoS 2 is never requested.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import ssl
from collections.abc import Awaitable, Callable

from oneroof_zigbee.mqtt import packets as pk

log = logging.getLogger("oneroof_zigbee.mqtt.client")

MessageCallback = Callable[[str, bytes], Awaitable[None]]


class MqttError(Exception):
    pass


class ConnectRefused(MqttError):
    def __init__(self, code: int) -> None:
        super().__init__(f"CONNACK return code {code}")
        self.code = code


class Client:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        username: str,
        password: str | bytes,
        client_id: str = "",
        tls: ssl.SSLContext | None = None,
        keepalive: int = 30,
        will: pk.Publish | None = None,
        reconnect: bool = True,
        max_backoff: float = 60.0,
    ) -> None:
        self.host, self.port = host, port
        self.username = username
        self.password = password.encode() if isinstance(password, str) else password
        self.client_id = client_id or f"oz-{random.getrandbits(32):08x}"
        self.tls = tls
        self.keepalive = keepalive
        self.will = will
        self.reconnect = reconnect
        self.max_backoff = max_backoff
        self.connected = asyncio.Event()
        self.disconnected = asyncio.Event()
        self.disconnected.set()
        self.on_connect: Callable[[], Awaitable[None]] | None = None
        self._subs: dict[str, tuple[int, MessageCallback]] = {}
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._task: asyncio.Task[None] | None = None
        self._ping_task: asyncio.Task[None] | None = None
        self._pending: dict[int, asyncio.Future[object]] = {}
        self._next_pid = 1
        self._stopping = False
        self._last_error: BaseException | None = None

    # -- lifecycle --------------------------------------------------------

    async def connect(self, timeout: float = 10.0) -> None:
        """Start the connection task and wait for the first CONNACK."""
        self._stopping = False
        self._task = asyncio.create_task(self._run(), name=f"mqtt-client-{self.client_id}")
        waiter = asyncio.ensure_future(self.connected.wait())
        done, _ = await asyncio.wait({self._task, waiter}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        waiter.cancel()
        if self.connected.is_set():
            return
        if self._task in done and self._last_error is not None:
            raise self._last_error
        if not done:
            await self.disconnect()
            raise MqttError("connect timeout")

    async def disconnect(self) -> None:
        self._stopping = True
        if self._writer is not None and self.connected.is_set():
            with contextlib.suppress(Exception):
                await self._send(pk.Disconnect())
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None

    async def _run(self) -> None:
        backoff = 0.5
        while not self._stopping:
            try:
                await self._session()
                backoff = 0.5
            except ConnectRefused as exc:
                self._last_error = exc
                log.error("broker refused connection: %s", exc)
                if exc.code in (pk.CONNACK_BAD_CREDENTIALS, pk.CONNACK_NOT_AUTHORIZED) or not self.reconnect:
                    return
            except asyncio.CancelledError:
                raise
            except ssl.SSLError as exc:
                # a certificate problem will not fix itself; surface it immediately
                self._last_error = exc
                log.error("TLS error: %s", exc)
                return
            except Exception as exc:
                self._last_error = exc
                log.warning("connection error: %s", exc)
            finally:
                await self._teardown()
            if self._stopping or not self.reconnect:
                return
            await asyncio.sleep(backoff + random.uniform(0, backoff / 2))
            backoff = min(backoff * 2, self.max_backoff)

    async def _teardown(self) -> None:
        self.connected.clear()
        self.disconnected.set()
        if self._ping_task:
            self._ping_task.cancel()
            self._ping_task = None
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(MqttError("disconnected"))
        self._pending.clear()
        if self._writer is not None:
            with contextlib.suppress(Exception):
                self._writer.close()
                await self._writer.wait_closed()
        self._reader = self._writer = None

    async def _session(self) -> None:
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port, ssl=self.tls), 10.0
        )
        connect = pk.Connect(client_id=self.client_id, clean_session=True, keepalive=self.keepalive,
                             username=self.username, password=self.password)
        if self.will is not None:
            connect.will_topic, connect.will_payload = self.will.topic, self.will.payload
            connect.will_qos, connect.will_retain = self.will.qos, self.will.retain
        await self._send(connect)
        ack = await asyncio.wait_for(self._read_packet(), 10.0)
        if not isinstance(ack, pk.Connack):
            raise MqttError("expected CONNACK")
        if ack.return_code != pk.CONNACK_ACCEPTED:
            raise ConnectRefused(ack.return_code)
        if self._subs:  # restore subscriptions before reporting "connected"
            pid = self._packet_id()
            await self._send(pk.Subscribe(pid, [(tf, q) for tf, (q, _) in self._subs.items()]))
            while True:
                packet = await asyncio.wait_for(self._read_packet(), 10.0)
                if isinstance(packet, pk.Suback) and packet.packet_id == pid:
                    break
                await self._dispatch(packet)
        self.disconnected.clear()
        self.connected.set()
        log.info("connected to %s:%d as %r", self.host, self.port, self.client_id)
        if self.keepalive:
            self._ping_task = asyncio.create_task(self._ping_loop())
        if self.on_connect:
            await self.on_connect()
        while True:
            await self._dispatch(await self._read_packet())

    async def _ping_loop(self) -> None:
        while True:
            await asyncio.sleep(self.keepalive * 0.8)
            await self._send(pk.Pingreq())

    # -- I/O --------------------------------------------------------------

    async def _send(self, packet: pk.Packet) -> None:
        if self._writer is None:
            raise MqttError("not connected")
        self._writer.write(pk.encode(packet))
        await self._writer.drain()

    async def _read_packet(self) -> pk.Packet:
        assert self._reader is not None
        buf = bytearray()
        while True:
            try:
                packet, _ = pk.decode_one(bytes(buf))
                return packet
            except pk.NeedMoreData:
                pass
            try:
                _, _, length, hsize = pk.decode_fixed_header(bytes(buf))
                need = hsize + length - len(buf)
            except pk.NeedMoreData:
                need = 1
            buf += await self._reader.readexactly(need)

    def _packet_id(self) -> int:
        pid = self._next_pid
        self._next_pid = pid % pk.MAX_PACKET_ID + 1
        return pid

    async def _await_ack(self, pid: int, timeout: float = 10.0) -> object:
        fut: asyncio.Future[object] = asyncio.get_running_loop().create_future()
        self._pending[pid] = fut
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(pid, None)

    async def _dispatch(self, packet: pk.Packet) -> None:
        match packet:
            case pk.Publish(topic=topic, payload=payload, qos=qos, packet_id=pid):
                if qos > 0 and pid is not None:
                    await self._send(pk.Puback(pid))
                for tf, (_, cb) in list(self._subs.items()):
                    if pk.topic_matches(tf, topic):
                        try:
                            await cb(topic, payload)
                        except Exception:
                            log.exception("callback for %r raised", tf)
            case pk.Puback(packet_id=pid) | pk.Unsuback(packet_id=pid):
                fut = self._pending.get(pid)
                if fut and not fut.done():
                    fut.set_result(None)
            case pk.Suback(packet_id=pid, return_codes=codes):
                fut = self._pending.get(pid)
                if fut and not fut.done():
                    fut.set_result(codes)
            case pk.Pingresp():
                pass
            case _:
                raise MqttError(f"unexpected {type(packet).__name__} from broker")

    # -- API --------------------------------------------------------------

    async def publish(self, topic: str, payload: bytes | str, qos: int = 0, retain: bool = False) -> None:
        data = payload.encode() if isinstance(payload, str) else payload
        if qos == 0:
            await self._send(pk.Publish(topic=topic, payload=data, qos=0, retain=retain))
            return
        pid = self._packet_id()
        await self._send(pk.Publish(topic=topic, payload=data, qos=1, retain=retain, packet_id=pid))
        await self._await_ack(pid)

    async def subscribe(self, topic_filter: str, cb: MessageCallback, qos: int = 1) -> int:
        """Subscribe and return the granted QoS (0x80 on failure). Resubscribed on reconnect."""
        pk.validate_filter(topic_filter)
        self._subs[topic_filter] = (qos, cb)
        if not self.connected.is_set():
            return qos
        codes = await self._send_subscribe([(topic_filter, qos)])
        if codes[0] == pk.SUBACK_FAILURE:
            del self._subs[topic_filter]
        return codes[0]

    async def _send_subscribe(self, topics: list[tuple[str, int]]) -> list[int]:
        pid = self._packet_id()
        await self._send(pk.Subscribe(pid, topics))
        codes = await self._await_ack(pid)
        assert isinstance(codes, list)
        return codes

    async def unsubscribe(self, topic_filter: str) -> None:
        self._subs.pop(topic_filter, None)
        if self.connected.is_set():
            pid = self._packet_id()
            await self._send(pk.Unsubscribe(pid, [topic_filter]))
            await self._await_ack(pid)
