"""A deliberately small asyncio HTTP/1.1 server for the UI.

Why our own: the UI needs GET/POST JSON, one static page and Server-Sent
Events. A framework would add thousands of lines of third-party code to the
most exposed part of the system. This is ~250 lines and does only what the
UI needs:

* request line + headers parsed with strict limits (8 KiB headers, 64 KiB body)
* one request per connection (`Connection: close`) — simple and safe
* source-address allow-list (loopback, and the HA Ingress proxy)
* mutating requests require `X-OneRoof: 1` + JSON content type
* security headers on every response
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("oneroof_zigbee.ui.server")

MAX_HEADER_BYTES = 8 * 1024
MAX_BODY_BYTES = 2 * 1024 * 1024  # restore uploads carry an encrypted backup
HEADER_TIMEOUT = 10.0
HA_INGRESS_PROXY = "172.30.32.2"
LOOPBACK = ("127.0.0.1", "::1", "::ffff:127.0.0.1")

_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                               "img-src 'self' data:; connect-src 'self'; frame-ancestors 'self' *",
}
_REASONS = {200: "OK", 204: "No Content", 400: "Bad Request", 403: "Forbidden", 404: "Not Found",
            405: "Method Not Allowed", 413: "Payload Too Large", 415: "Unsupported Media Type",
            500: "Internal Server Error", 502: "Bad Gateway", 409: "Conflict"}
_TOKEN = re.compile(r"^[A-Za-z0-9_.~:-]+$")


class HttpError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class Request:
    method: str
    path: str            # path without query, already stripped of the Ingress prefix
    query: dict[str, str]
    headers: dict[str, str]
    body: bytes
    peer: str
    json: Any = None
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "application/json; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def json(data: Any, status: int = 200) -> Response:
        return Response(status, json.dumps(data, separators=(",", ":")).encode())

    @staticmethod
    def error(status: int, message: str) -> Response:
        return Response.json({"ok": False, "error": message}, status)


Handler = Callable[[Request], Awaitable[Response]]
SseSource = Callable[[Request], AsyncIterator[tuple[str, Any]]]


class Server:
    def __init__(self, host: str, port: int, *, allow_peers: tuple[str, ...] = LOOPBACK + (HA_INGRESS_PROXY,),
                 tls: "ssl.SSLContext | None" = None) -> None:
        self.host, self.port = host, port
        self.tls = tls
        self.allow_peers = allow_peers
        self._routes: list[tuple[str, re.Pattern[str], Handler]] = []
        self._sse: dict[str, SseSource] = {}
        self._server: asyncio.base_events.Server | None = None
        self._conns: set[asyncio.Task[None]] = set()

    # -- routing ---------------------------------------------------------

    def route(self, method: str, pattern: str, handler: Handler) -> None:
        regex = "^" + re.sub(r"<(\w+)>", r"(?P<\1>[^/]+)", pattern) + "$"
        self._routes.append((method, re.compile(regex), handler))

    def sse(self, path: str, source: SseSource) -> None:
        self._sse[path] = source

    # -- lifecycle -------------------------------------------------------

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._on_conn, self.host, self.port, limit=MAX_HEADER_BYTES, ssl=self.tls)
        self.port = self._server.sockets[0].getsockname()[1]
        log.info("UI listening on %s://%s:%d", "https" if self.tls else "http", self.host, self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
        for t in list(self._conns):
            t.cancel()
        if self._conns:
            await asyncio.gather(*self._conns, return_exceptions=True)
        if self._server:
            await self._server.wait_closed()

    # -- connection ------------------------------------------------------

    async def _on_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = (writer.get_extra_info("peername") or ("?",))[0]
        task = asyncio.current_task()
        if task:
            self._conns.add(task)
            task.add_done_callback(self._conns.discard)
        try:
            if peer not in self.allow_peers:
                log.warning("UI: refused connection from %s", peer)
                await self._send(writer, Response.error(403, "forbidden"))
                return
            try:
                req = await asyncio.wait_for(self._read_request(reader, peer), HEADER_TIMEOUT)
            except HttpError as e:
                await self._send(writer, Response.error(e.status, str(e)))
                return
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                return
            if req.method == "GET" and req.path in self._sse:
                await self._stream(writer, req, self._sse[req.path])
                return
            resp = await self._dispatch(req)
            await self._send(writer, resp)
        except Exception:
            log.exception("UI: connection handler failed")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_request(self, reader: asyncio.StreamReader, peer: str) -> Request:
        try:
            line = await reader.readuntil(b"\r\n")
        except asyncio.LimitOverrunError as e:
            raise HttpError(413, "request line too long") from e
        parts = line.decode("latin-1").rstrip().split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
            raise HttpError(400, "bad request line")
        method, target = parts[0].upper(), parts[1]
        headers: dict[str, str] = {}
        total = len(line)
        while True:
            try:
                line = await reader.readuntil(b"\r\n")
            except asyncio.LimitOverrunError as e:
                raise HttpError(413, "headers too large") from e
            total += len(line)
            if total > MAX_HEADER_BYTES:
                raise HttpError(413, "headers too large")
            if line == b"\r\n":
                break
            name, _, value = line.decode("latin-1").partition(":")
            headers[name.strip().lower()] = value.strip()
        body = b""
        if "content-length" in headers:
            try:
                n = int(headers["content-length"])
            except ValueError as e:
                raise HttpError(400, "bad content-length") from e
            if n > MAX_BODY_BYTES:
                # drain (bounded) so the peer receives the 413 instead of a reset
                remaining = min(n, 4 * MAX_BODY_BYTES)
                while remaining > 0:
                    chunk = await reader.read(min(remaining, 65536))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                raise HttpError(413, "body too large")
            body = await reader.readexactly(n)
        elif headers.get("transfer-encoding"):
            raise HttpError(400, "chunked bodies not supported")
        path, _, qs = target.partition("?")
        if not path.startswith("/") or ".." in path:
            raise HttpError(400, "bad path")
        # Home Assistant Ingress forwards the full path; honour X-Ingress-Path to strip the prefix.
        prefix = headers.get("x-ingress-path", "")
        if prefix and path.startswith(prefix):
            path = path[len(prefix):] or "/"
        query: dict[str, str] = {}
        for kv in qs.split("&"):
            if kv:
                k, _, v = kv.partition("=")
                query[_unquote(k)] = _unquote(v)
        req = Request(method, path, query, headers, body, peer)
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            # every state-changing request needs the custom header (CSRF) and a JSON object body
            # (DELETE may come without a body; it then gets an empty object)
            if headers.get("x-oneroof") != "1":
                raise HttpError(403, "missing X-OneRoof header")
            if (body or method != "DELETE") and not headers.get("content-type", "").startswith("application/json"):
                raise HttpError(415, "JSON body required")
            try:
                req.json = json.loads(body or b"{}")
            except ValueError as e:
                raise HttpError(400, "invalid JSON") from e
            if not isinstance(req.json, dict):
                raise HttpError(400, "JSON object required")
        return req

    async def _dispatch(self, req: Request) -> Response:
        allowed: list[str] = []
        for method, regex, handler in self._routes:
            m = regex.match(req.path)
            if not m:
                continue
            if method != req.method:
                allowed.append(method)
                continue
            req.params = m.groupdict()
            try:
                return await handler(req)
            except HttpError as e:
                return Response.error(e.status, str(e))
            except Exception:
                log.exception("UI: handler %s %s failed", req.method, req.path)
                return Response.error(500, "internal error")
        if allowed:
            return Response.error(405, "method not allowed")
        return Response.error(404, "not found")

    # -- output ----------------------------------------------------------

    @staticmethod
    def _head(status: int, content_type: str, extra: dict[str, str], length: int | None) -> bytes:
        lines = [f"HTTP/1.1 {status} {_REASONS.get(status, 'Unknown')}", f"Content-Type: {content_type}", "Connection: close"]
        if length is not None:
            lines.append(f"Content-Length: {length}")
        for k, v in {**_SECURITY_HEADERS, **extra}.items():
            lines.append(f"{k}: {v}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")

    async def _send(self, writer: asyncio.StreamWriter, resp: Response) -> None:
        writer.write(self._head(resp.status, resp.content_type, resp.headers, len(resp.body)) + resp.body)
        await writer.drain()

    async def _stream(self, writer: asyncio.StreamWriter, req: Request, source: SseSource) -> None:
        writer.write(self._head(200, "text/event-stream; charset=utf-8", {"X-Accel-Buffering": "no"}, None))
        writer.write(b": connected\n\n")
        await writer.drain()
        try:
            async for event, data in source(req):
                payload = json.dumps(data, separators=(",", ":"))
                writer.write(f"event: {event}\ndata: {payload}\n\n".encode())
                await writer.drain()
        except ConnectionError:
            pass
        except asyncio.CancelledError:
            return


def _unquote(s: str) -> str:
    from urllib.parse import unquote_plus
    return unquote_plus(s)
