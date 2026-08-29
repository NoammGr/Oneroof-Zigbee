"""The only outbound HTTP client in the gateway.

Policy, enforced before any socket is opened:

* an explicit host allow-list (default: the Telegram Bot API host only);
* HTTPS only — TLS 1.2+ with certificate verification against the system trust
  store and hostname checking (`ssl.create_default_context`);
* a global on/off switch: with notifications disabled nothing leaves at all;
* every attempt, allowed or refused, is written to an in-memory ledger that the
  UI shows under "Outbound connections"; refused attempts raise `EgressRefused`
  and are recorded in the audit log as a security event.

The request path is never logged or audited: the Telegram path carries the bot
token. Only the host name is ever recorded.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("oneroof_zigbee.notify.egress")

DEFAULT_ALLOWED_HOSTS = frozenset({"api.telegram.org"})
TIMEOUT_S = 10.0
_MAX_RESPONSE = 1_000_000


class EgressRefused(Exception):
    """The egress policy refused the request (nothing was sent)."""


def default_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()  # system trust store, CERT_REQUIRED, check_hostname
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class EgressClient:
    def __init__(self, audit: Any = None, *, allowed_hosts: set[str] | frozenset[str] | None = None, enabled: bool = False,
                 ssl_context: ssl.SSLContext | None = None, timeout: float = TIMEOUT_S,
                 connect_to: dict[str, tuple[str, int]] | None = None) -> None:
        """`ssl_context` and `connect_to` exist for the test-suite's local HTTPS endpoint only; the
        defaults are the system trust store and a direct connection to the allow-listed host."""
        self.audit = audit
        self.allowed_hosts = frozenset(h.lower() for h in (allowed_hosts if allowed_hosts is not None else DEFAULT_ALLOWED_HOSTS))
        self.enabled = enabled
        self.timeout = timeout
        self._ssl = ssl_context or default_ssl_context()
        self._connect_to = connect_to or {}
        self.ledger: dict[str, dict[str, Any]] = {}

    # -- ledger ------------------------------------------------------------

    def _entry(self, host: str) -> dict[str, Any]:
        return self.ledger.setdefault(host, {"count": 0, "last": None, "refused": 0, "last_error": None})

    def _refuse(self, host: str, reason: str) -> None:
        e = self._entry(host)
        e["count"] += 1
        e["refused"] += 1
        e["last"] = time.time()
        e["last_error"] = f"refused: {reason}"
        log.warning("outbound connection to %s refused: %s", host, reason)
        if self.audit is not None:
            self.audit.security("egress_refused", host=host, reason=reason)
        raise EgressRefused(f"{host}: {reason}")

    def snapshot(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "allowed_hosts": sorted(self.allowed_hosts),
                "hosts": {h: dict(e) for h, e in sorted(self.ledger.items())}}

    # -- policy ------------------------------------------------------------

    def check(self, url: str) -> tuple[str, int]:
        """Apply the policy to `url`; returns (host, port) or raises EgressRefused."""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not host:
            self._refuse("?", "no host in URL")
        if parts.scheme != "https":
            self._refuse(host, f"scheme {parts.scheme or 'none'} is not https")
        if not self.enabled:
            self._refuse(host, "notifications are disabled")
        if host not in self.allowed_hosts:
            self._refuse(host, "host is not on the allow-list")
        port = parts.port or 443
        return host, port

    # -- HTTP --------------------------------------------------------------

    async def post_json(self, url: str, body: dict[str, Any]) -> tuple[int, Any]:
        """HTTPS POST with a JSON body; returns (status, parsed JSON or None)."""
        host, port = self.check(url)
        e = self._entry(host)
        e["count"] += 1
        e["last"] = time.time()
        path = urlsplit(url).path or "/"
        payload = json.dumps(body, separators=(",", ":")).encode()
        req = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: OneRoof-Zigbee\r\nAccept: application/json\r\n"
               f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n").encode() + payload
        chost, cport = self._connect_to.get(host, (host, port))
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(chost, cport, ssl=self._ssl, server_hostname=host), self.timeout)
            writer.write(req)
            await asyncio.wait_for(writer.drain(), self.timeout)
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.timeout)
            status_line, _, hdr_blob = head.partition(b"\r\n")
            status = int(status_line.split(b" ", 2)[1])
            headers: dict[str, str] = {}
            for line in hdr_blob.decode("latin-1").split("\r\n"):
                k, _, v = line.partition(":")
                if k:
                    headers[k.strip().lower()] = v.strip()
            raw = await asyncio.wait_for(self._read_body(reader, headers), self.timeout)
        except EgressRefused:
            raise
        except Exception as ex:
            e["last_error"] = f"{type(ex).__name__}: {ex}"[:200]
            raise
        finally:
            if writer is not None:
                writer.close()
        e["last_error"] = None if status < 400 else f"HTTP {status}"
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, None

    @staticmethod
    async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str]) -> bytes:
        if headers.get("transfer-encoding", "").lower() == "chunked":
            out = b""
            while True:
                size = int((await reader.readline()).split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    return out
                out += await reader.readexactly(size)
                await reader.readline()
                if len(out) > _MAX_RESPONSE:
                    raise ValueError("response too large")
        n = int(headers.get("content-length", "0") or 0)
        if n > _MAX_RESPONSE:
            raise ValueError("response too large")
        return await reader.readexactly(n) if n else await reader.read(_MAX_RESPONSE)
