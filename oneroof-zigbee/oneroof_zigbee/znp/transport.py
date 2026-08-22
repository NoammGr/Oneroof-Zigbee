"""Async ZNP transport: serial port ⇄ UNPI frames with SREQ/SRSP matching.

Design:
* One outstanding SREQ at a time (ZNP is strictly half-duplex for SREQs);
  a lock serialises callers.
* AREQ indications are dispatched to listeners keyed by (subsystem, command).
* `Transport` is hardware-agnostic: it only needs an asyncio
  (StreamReader, StreamWriter) pair, so tests inject a fake pair.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable

from .unpi import Frame, FrameType, Parser, Subsystem

# Frames whose payload carries key material never reach the log, even at DEBUG.
_SYS_NV_CMDS = (0x07, 0x08, 0x09)          # OSAL_NV_ITEM_INIT / READ / WRITE (the ExNV sec-material table holds counters only)
_SECRET_NV_ITEMS = {0x003A, 0x003B, 0x0062, 0x0082, 0x0101}  # active/alternate key info, PRECFGKEY, NWKKEY, TCLK table
_SECRET_APP_CNF = {0x04, 0x07}              # BDB_ADD_INSTALLCODE, BDB_SET_ACTIVE_DEFAULT_CENTRALIZED_KEY

log = logging.getLogger("oneroof_zigbee.znp.transport")

Listener = Callable[[Frame], Awaitable[None] | None]


class ZnpError(RuntimeError):
    pass


class ZnpTimeout(ZnpError):
    pass


class ZnpStatusError(ZnpError):
    def __init__(self, frame: Frame, status: int) -> None:
        super().__init__(f"{frame.subsystem.name}:{frame.command:#04x} failed with status {status:#04x}")
        self.status = status


class Transport:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, timeout: float = 6.0) -> None:
        self._reader = reader
        self._writer = writer
        self._redact_srsp = False
        self._timeout = timeout
        self._parser = Parser()
        self._lock = asyncio.Lock()
        self._pending: tuple[Frame, asyncio.Future[Frame]] | None = None
        self._listeners: dict[tuple[Subsystem, int], list[Listener]] = defaultdict(list)
        self._any_listeners: list[Listener] = []
        self._rx_task: asyncio.Task[None] | None = None
        self._closed = asyncio.Event()

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._rx_task = asyncio.create_task(self._rx_loop(), name="znp-rx")

    async def close(self) -> None:
        if self._rx_task:
            self._rx_task.cancel()
            try:
                await self._rx_task
            except (asyncio.CancelledError, Exception):
                pass
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except Exception:
            pass
        self._closed.set()

    @property
    def closed(self) -> asyncio.Event:
        return self._closed

    # -- listeners ---------------------------------------------------------

    def on(self, subsystem: Subsystem, command: int, cb: Listener) -> None:
        self._listeners[(subsystem, command)].append(cb)

    def on_any(self, cb: Listener) -> None:
        self._any_listeners.append(cb)

    async def wait_for(self, subsystem: Subsystem, command: int, *, timeout: float,
                       predicate: Callable[[Frame], bool] | None = None) -> Frame:
        """Await the next AREQ matching (subsystem, command[, predicate])."""
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Frame] = loop.create_future()

        def _cb(frame: Frame) -> None:
            if not fut.done() and (predicate is None or predicate(frame)):
                fut.set_result(frame)

        self.on(subsystem, command, _cb)
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError as e:
            raise ZnpTimeout(f"no {subsystem.name}:{command:#04x} within {timeout}s") from e
        finally:
            self._listeners[(subsystem, command)].remove(_cb)

    # -- requests ----------------------------------------------------------

    async def request(self, frame: Frame, *, timeout: float | None = None, check_status: bool = True) -> Frame:
        """Send an SREQ and return the matching SRSP.

        If `check_status` and the response's first byte is non-zero, raise
        ZnpStatusError.  Commands whose responses do not start with a status
        must pass check_status=False.
        """
        if frame.type is not FrameType.SREQ:
            raise ValueError("request() is for SREQ frames; use send() for AREQ")
        async with self._lock:
            loop = asyncio.get_running_loop()
            fut: asyncio.Future[Frame] = loop.create_future()
            self._pending = (frame, fut)
            try:
                self._write(frame)
                rsp = await asyncio.wait_for(fut, timeout or self._timeout)
            except asyncio.TimeoutError as e:
                raise ZnpTimeout(f"{frame.subsystem.name}:{frame.command:#04x} timed out") from e
            finally:
                self._pending = None
        if check_status and rsp.data and rsp.data[0] != 0:
            raise ZnpStatusError(frame, rsp.data[0])
        return rsp

    def send(self, frame: Frame) -> None:
        """Fire-and-forget AREQ (e.g. SYS_RESET_REQ)."""
        if frame.type is not FrameType.AREQ:
            raise ValueError("send() is for AREQ frames")
        self._write(frame)

    def _secret(self, frame: Frame) -> bool:
        """True when the frame (or the reply it will get) carries key material."""
        if frame.subsystem is Subsystem.SYS and frame.command in _SYS_NV_CMDS and len(frame.data) >= 2:
            item = int.from_bytes(frame.data[0:2], "little")
            if frame.type is FrameType.SREQ:
                self._redact_srsp = item in _SECRET_NV_ITEMS and frame.command == 0x08
            return item in _SECRET_NV_ITEMS
        if frame.subsystem is Subsystem.APP_CNF and frame.command in _SECRET_APP_CNF:
            return True
        if frame.subsystem is Subsystem.ZDO and frame.command == 0x4E:  # EXT_UPDATE_NWK_KEY carries the key
            return True
        return False

    def _write(self, frame: Frame) -> None:
        raw = frame.encode()
        log.debug("TX %s:%#04x %s", frame.subsystem.name, frame.command,
                  "<redacted>" if self._secret(frame) else frame.data.hex())
        self._writer.write(raw)

    # -- receive -----------------------------------------------------------

    async def _rx_loop(self) -> None:
        try:
            while True:
                chunk = await self._reader.read(512)
                if not chunk:
                    log.error("serial port closed by peer")
                    break
                for frame in self._parser.feed(chunk):
                    self._dispatch(frame)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("rx loop crashed")
        finally:
            self._closed.set()
            if self._pending and not self._pending[1].done():
                self._pending[1].set_exception(ZnpError("transport closed"))

    def _dispatch(self, frame: Frame) -> None:
        redact = False
        if frame.type is FrameType.SRSP and frame.subsystem is Subsystem.SYS and frame.command == 0x08:
            redact, self._redact_srsp = self._redact_srsp, False
        log.debug("RX %s %s:%#04x %s", frame.type.name, frame.subsystem.name, frame.command,
                  "<redacted>" if redact else frame.data.hex())
        if frame.type is FrameType.SRSP and frame.subsystem is Subsystem.RPC_ERR:
            pending = self._pending
            if pending and not pending[1].done():
                pending[1].set_exception(ZnpError(f"RPC error {frame.data.hex()} for {pending[0].subsystem.name}:{pending[0].command:#04x}"))
            return
        if frame.type is FrameType.SRSP:
            pending = self._pending
            if pending and pending[0].subsystem is frame.subsystem and pending[0].command == frame.command:
                if not pending[1].done():
                    pending[1].set_result(frame)
            else:
                log.warning("unsolicited SRSP %s:%#04x", frame.subsystem.name, frame.command)
            return
        for cb in list(self._listeners.get((frame.subsystem, frame.command), ())) + list(self._any_listeners):
            try:
                res = cb(frame)
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
            except Exception:
                log.exception("listener failed for %s:%#04x", frame.subsystem.name, frame.command)


async def open_serial(port: str, baudrate: int = 115200, *, rtscts: bool = False) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a local serial device, or a network coordinator via `tcp://host:port`
    (SMLIGHT SLZB-06, ZigStar LAN, ser2net). Network link: plain TCP on your LAN —
    the ZNP stream carries the network key during formation, so keep such
    coordinators on a trusted VLAN."""
    if port.startswith("tcp://"):
        host, _, p = port[len("tcp://"):].rpartition(":")
        if not host or not p.isdigit():
            raise ValueError("tcp:// port must look like tcp://host:6638")
        log.warning("coordinator over plain TCP %s:%s — make sure this link is on a trusted network", host, p)
        return await asyncio.open_connection(host, int(p))
    import serial_asyncio  # local import: keeps the codec importable without hardware deps

    return await serial_asyncio.open_serial_connection(url=port, baudrate=baudrate, rtscts=rtscts)
