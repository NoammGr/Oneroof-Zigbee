"""Zigbee OTA Upgrade cluster (0x0019) server — deliberately conservative.

Policy
* The gateway NEVER fetches firmware from the internet. Images are uploaded
  by the user into `<data_dir>/firmware/`, parsed, and listed with SHA-256.
* A device only ever receives an image whose manufacturer code AND image type
  match what the device itself reports in its QueryNextImage request, and
  whose file version is higher (downgrade requires `allow_downgrade`).
* Nothing is offered automatically: every update is started by a person
  from the UI for one specific device, and is audit-logged.
* Devices that query on their own are told "no image available" unless an
  update for them was explicitly armed.

Wire format (ZCL spec 11.4): OTA file header magic 0x0BEEF11E, then
header_version u16, header_length u16, field_control u16, manufacturer u16,
image_type u16, file_version u32, stack_version u16, header_string[32],
total_image_size u32, optional fields; sub-elements follow the header.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("oneroof_zigbee.ota")

OTA_MAGIC = 0x0BEEF11E
CLUSTER = 0x0019
# server→client commands
IMAGE_NOTIFY = 0x00
QUERY_NEXT_IMAGE_RSP = 0x02
IMAGE_BLOCK_RSP = 0x05
UPGRADE_END_RSP = 0x07
# client→server
QUERY_NEXT_IMAGE_REQ = 0x01
IMAGE_BLOCK_REQ = 0x03
IMAGE_PAGE_REQ = 0x04
UPGRADE_END_REQ = 0x06
# statuses
SUCCESS, ABORT, NO_IMAGE_AVAILABLE, WAIT_FOR_DATA = 0x00, 0x95, 0x98, 0x97

MAX_BLOCK = 64  # bytes per block; conservative for all radios
MAX_IMAGE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class OtaImage:
    path: Path
    manufacturer: int
    image_type: int
    file_version: int
    stack_version: int
    header_string: str
    total_size: int
    sha256: str
    size_on_disk: int

    def to_json(self) -> dict[str, Any]:
        return {"file": self.path.name, "manufacturer": f"{self.manufacturer:#06x}", "image_type": f"{self.image_type:#06x}",
                "file_version": f"{self.file_version:#010x}", "file_version_decimal": self.file_version, "stack_version": self.stack_version,
                "header_string": self.header_string, "size": self.size_on_disk, "sha256": self.sha256}


class OtaError(ValueError):
    pass


def parse_image(path: Path) -> OtaImage:
    data = path.read_bytes()
    if len(data) > MAX_IMAGE_BYTES:
        raise OtaError("image larger than 2 MiB")
    off = data.find(OTA_MAGIC.to_bytes(4, "little"))
    if off < 0:
        raise OtaError("not a Zigbee OTA file (magic 0x0BEEF11E not found)")
    if off:
        log.info("%s: OTA header at offset %d (vendor wrapper skipped)", path.name, off)
    h = data[off:]
    if len(h) < 56:
        raise OtaError("truncated OTA header")
    (_magic, _hver, hlen, _fc, manuf, itype, fver, sver) = struct.unpack_from("<IHHHHHIH", h, 0)
    hstr = h[20:52].split(b"\x00", 1)[0].decode("ascii", "replace")
    (total,) = struct.unpack_from("<I", h, 52)
    if hlen < 56 or hlen > len(h):
        raise OtaError("invalid header length")
    if total != len(h):
        raise OtaError(f"total image size {total} does not match file ({len(h)} bytes) — corrupt or wrapped download")
    return OtaImage(path, manuf, itype, fver, sver, hstr, total, hashlib.sha256(h).hexdigest(), len(h))


@dataclass
class Session:
    ieee: int
    nwk: int
    endpoint: int
    image: OtaImage
    data: bytes
    started: float = field(default_factory=time.time)
    offset: int = 0
    last_activity: float = field(default_factory=time.time)
    finished: bool = False
    result: str | None = None

    def progress(self) -> float:
        return round(100 * self.offset / max(1, len(self.data)), 1)


class OtaServer:
    def __init__(self, firmware_dir: Path, audit: Any, *, allow_downgrade: bool = False) -> None:
        self.dir = firmware_dir
        self.audit = audit
        self.allow_downgrade = allow_downgrade
        self.images: dict[str, OtaImage] = {}
        self.armed: dict[int, str] = {}        # ieee → image file armed by the user
        self.sessions: dict[int, Session] = {}  # ieee → running transfer
        self.last_query: dict[int, dict[str, Any]] = {}
        self.reload()

    # ---------------------------------------------------------------- library --

    def reload(self) -> None:
        self.images.clear()
        if not self.dir.exists():
            return
        for p in sorted(self.dir.iterdir()):
            if p.is_file() and not p.name.startswith("."):
                try:
                    self.images[p.name] = parse_image(p)
                except OtaError as e:
                    log.warning("firmware %s ignored: %s", p.name, e)

    def add_image(self, filename: str, data: bytes) -> OtaImage:
        safe = "".join(ch for ch in os.path.basename(filename) if ch.isalnum() or ch in "._-")[:120] or "firmware.ota"
        if len(data) > MAX_IMAGE_BYTES:
            raise OtaError("image larger than 2 MiB")
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.dir / (safe + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        try:
            img = parse_image(tmp)
        except OtaError:
            tmp.unlink(missing_ok=True)
            raise
        final = self.dir / safe
        os.replace(tmp, final)
        img = dataclasses.replace(img, path=final)
        self.images[safe] = img
        self.audit.security("firmware_uploaded", file=safe, sha256=img.sha256, manufacturer=f"{img.manufacturer:#06x}",
                            image_type=f"{img.image_type:#06x}", version=f"{img.file_version:#010x}")
        return img

    def remove_image(self, filename: str) -> None:
        img = self.images.pop(filename, None)
        if img:
            img.path.unlink(missing_ok=True)
        for ieee, f in list(self.armed.items()):
            if f == filename:
                del self.armed[ieee]

    def candidates_for(self, manufacturer: int, image_type: int, current_version: int | None) -> list[OtaImage]:
        out = [i for i in self.images.values() if i.manufacturer == manufacturer and i.image_type == image_type]
        if current_version is not None and not self.allow_downgrade:
            out = [i for i in out if i.file_version > current_version]
        return sorted(out, key=lambda i: i.file_version, reverse=True)

    # ------------------------------------------------------------------ arming --

    def arm(self, ieee: int, filename: str, who: str) -> OtaImage:
        img = self.images.get(filename)
        if img is None:
            raise OtaError("unknown firmware file")
        q = self.last_query.get(ieee)
        if q and (q["manufacturer"] != img.manufacturer or q["image_type"] != img.image_type):
            raise OtaError(f"image is for manufacturer {img.manufacturer:#06x}/type {img.image_type:#06x}, "
                           f"but the device reports {q['manufacturer']:#06x}/{q['image_type']:#06x}")
        if q and q.get("file_version") is not None and img.file_version <= q["file_version"] and not self.allow_downgrade:
            raise OtaError("image version is not newer than the device's (downgrade disabled)")
        self.armed[ieee] = filename
        self.audit.security("firmware_update_armed", ieee=f"0x{ieee:016x}", file=filename, sha256=img.sha256, by=who)
        return img

    def disarm(self, ieee: int) -> None:
        self.armed.pop(ieee, None)
        s = self.sessions.pop(ieee, None)
        if s:
            s.finished, s.result = True, "cancelled"

    # --------------------------------------------------------------- protocol --

    def handle(self, ieee: int, nwk: int, endpoint: int, cmd: int, payload: bytes) -> tuple[int, bytes] | None:
        """Return (response_cmd, response_payload) or None. Pure function of state; the gateway sends it."""
        try:
            if cmd == QUERY_NEXT_IMAGE_REQ:
                return self._query(ieee, nwk, endpoint, payload)
            if cmd in (IMAGE_BLOCK_REQ, IMAGE_PAGE_REQ):
                return self._block(ieee, payload)
            if cmd == UPGRADE_END_REQ:
                return self._end(ieee, payload)
        except struct.error:
            log.debug("malformed OTA request %#04x from 0x%016x", cmd, ieee)
        return None

    def _query(self, ieee: int, nwk: int, endpoint: int, p: bytes) -> tuple[int, bytes]:
        fc, manuf, itype, fver = struct.unpack_from("<BHHI", p, 0)
        self.last_query[ieee] = {"ts": time.time(), "manufacturer": manuf, "image_type": itype, "file_version": fver,
                                 "hw_version": struct.unpack_from("<H", p, 9)[0] if fc & 1 and len(p) >= 11 else None}
        armed = self.armed.get(ieee)
        img = self.images.get(armed) if armed else None
        if img is None or img.manufacturer != manuf or img.image_type != itype or (img.file_version <= fver and not self.allow_downgrade):
            return QUERY_NEXT_IMAGE_RSP, bytes([NO_IMAGE_AVAILABLE])
        self.sessions[ieee] = Session(ieee, nwk, endpoint, img, img.path.read_bytes()[-img.total_size:])
        self.audit.event("firmware_update_started", ieee=f"0x{ieee:016x}", file=img.path.name, version=f"{img.file_version:#010x}")
        return QUERY_NEXT_IMAGE_RSP, struct.pack("<BHHII", SUCCESS, img.manufacturer, img.image_type, img.file_version, img.total_size)

    def _block(self, ieee: int, p: bytes) -> tuple[int, bytes]:
        s = self.sessions.get(ieee)
        fc, manuf, itype, fver, offset, maxsize = struct.unpack_from("<BHHIIB", p, 0)
        if s is None or s.finished or manuf != s.image.manufacturer or itype != s.image.image_type or fver != s.image.file_version:
            return IMAGE_BLOCK_RSP, bytes([ABORT])
        if offset > len(s.data):
            return IMAGE_BLOCK_RSP, bytes([ABORT])
        n = min(maxsize, MAX_BLOCK, len(s.data) - offset)
        chunk = s.data[offset:offset + n]
        s.offset = offset + n
        s.last_activity = time.time()
        return IMAGE_BLOCK_RSP, struct.pack("<BHHIIB", SUCCESS, manuf, itype, fver, offset, n) + chunk

    def _end(self, ieee: int, p: bytes) -> tuple[int, bytes]:
        status, manuf, itype, fver = struct.unpack_from("<BHHI", p, 0)
        s = self.sessions.get(ieee)
        if s:
            s.finished = True
            s.result = "success" if status == SUCCESS else f"device reported {status:#04x}"
        self.armed.pop(ieee, None)
        self.audit.security("firmware_update_finished", ieee=f"0x{ieee:016x}", status=f"{status:#04x}",
                            version=f"{fver:#010x}", ok=status == SUCCESS)
        if status != SUCCESS:
            return UPGRADE_END_RSP, struct.pack("<HHIII", manuf, itype, fver, 0, 0)
        # current_time = 0, upgrade_time = 0 → apply immediately
        return UPGRADE_END_RSP, struct.pack("<HHIII", manuf, itype, fver, 0, 0)

    def image_notify_payload(self) -> bytes:
        """ImageNotify with payload type 0 (query jitter only): asks the device to send QueryNextImage."""
        return bytes([0x00, 100])

    def status(self, ieee: int) -> dict[str, Any]:
        s = self.sessions.get(ieee)
        q = self.last_query.get(ieee)
        return {
            "armed": self.armed.get(ieee),
            "last_query": ({**q, "manufacturer": f"{q['manufacturer']:#06x}", "image_type": f"{q['image_type']:#06x}",
                            "file_version": f"{q['file_version']:#010x}"} if q else None),
            "session": ({"file": s.image.path.name, "progress": s.progress(), "offset": s.offset, "total": len(s.data),
                         "finished": s.finished, "result": s.result, "started": s.started, "last_activity": s.last_activity} if s else None),
            "candidates": [i.to_json() for i in (self.candidates_for(q["manufacturer"], q["image_type"], q["file_version"]) if q else [])],
        }
