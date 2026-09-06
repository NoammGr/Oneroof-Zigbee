"""Adapter that gives the gateway the same publish/subscribe surface as the
built-in Broker, but backed by a connection to an *existing* broker (kept
during a migration from a previous setup).

Security note: an external broker cannot tell us which user published a
request, so every MQTT control request (permit_join, remove, rotate) arrives
with user=None and is refused by the gateway's control_users check. Control
stays in the UI (which acts as a named user). Device `set` commands are
accepted, as they are from any HA user on the built-in broker.
"""

from __future__ import annotations

import logging
import ssl
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

from .client import Client
from .packets import Publish, topic_matches

log = logging.getLogger("oneroof_zigbee.mqtt.external")

LocalCallback = Callable[[str, bytes, "str | None"], Awaitable[None]]


class ExternalBroker:
    def __init__(self, server: str, *, user: str | None, password: str | None, ca: str | None, client_id: str,
                 will_topic: str | None = None, will_payload: bytes = b"offline") -> None:
        u = urlparse(server)
        self.host = u.hostname or "localhost"
        self.port = u.port or (8883 if u.scheme == "mqtts" else 1883)
        self.tls: ssl.SSLContext | None = None
        if u.scheme == "mqtts":
            self.tls = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        self._subs: list[tuple[str, LocalCallback]] = []
        # The last will: if the gateway dies or loses the broker, the broker itself says so on
        # bridge/state, and Home Assistant marks every device unavailable instead of showing the
        # last thing each one said, for as long as it takes someone to notice.
        will = Publish(will_topic, will_payload, qos=1, retain=True) if will_topic else None
        self._client = Client(self.host, self.port, username=user or "", password=password or "", client_id=client_id,
                              tls=self.tls, will=will)
        self._will_topic = will_topic
        self.external = True

    async def start(self) -> None:
        await self._client.connect()
        await self._client.subscribe("#", self._on_message)  # the gateway filters; keeps one subscription on the wire
        log.info("connected to external broker %s:%d%s", self.host, self.port, " (TLS)" if self.tls else "")

    async def stop(self) -> None:
        await self._client.disconnect()

    async def _on_message(self, topic: str, payload: bytes) -> None:
        for f, cb in list(self._subs):
            if topic_matches(f, topic):
                try:
                    await cb(topic, payload, None)
                except Exception:
                    log.exception("subscriber for %r failed", f)

    async def publish(self, topic: str, payload: bytes, retain: bool = False, qos: int = 0) -> None:
        await self._client.publish(topic, payload, qos=min(qos, 1), retain=retain)

    def subscribe(self, topic_filter: str, cb: LocalCallback) -> Callable[[], None]:
        entry = (topic_filter, cb)
        self._subs.append(entry)

        def unsub() -> None:
            if entry in self._subs:
                self._subs.remove(entry)
        return unsub
