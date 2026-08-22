"""Network secrets at rest.

The network key, PAN id, extended PAN id and channel are generated from
`secrets` on first start and persisted in one file, encrypted with
AES-256-GCM under a key derived (scrypt) from a passphrase.  The passphrase
comes from the ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE environment variable or a
0600 file next to the store; if neither exists, one is generated and written
to that file.  This gives:

* secrets never appear in the YAML config (unlike a plain `network_key:` line),
* a config backup on its own does not leak the network key,
* an attacker needs both the store *and* the passphrase file.

Honest limitation: on a single host without a TPM, the passphrase file lives on
the same disk.  The encryption raises the bar for accidental leakage (backups,
support bundles, log uploads) — it is not a defence against root on the box.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("oneroof_zigbee.security.keystore")

_MAGIC = b"OZKS1"
_SCRYPT = dict(n=2**15, r=8, p=1, dklen=32, maxmem=128 * 1024 * 1024)
_ENV = "ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE"


@dataclass
class NetworkSecrets:
    network_key: bytes
    pan_id: int
    ext_pan_id: int
    channel: int
    tc_install_code: bytes  # 16 random bytes + CRC16: strict-mode replacement for the public TC link key
    frame_counter: int = 0

    @property
    def tc_link_key(self) -> bytes:
        from .installcode import derive_link_key
        return derive_link_key(self.tc_install_code)

    @staticmethod
    def generate(channel: int) -> NetworkSecrets:
        return NetworkSecrets(
            network_key=secrets.token_bytes(16),
            pan_id=secrets.randbelow(0xFFFE - 1) + 1,  # avoid 0x0000 and 0xFFFF
            ext_pan_id=int.from_bytes(secrets.token_bytes(8), "little") or 1,
            channel=channel,
            tc_install_code=_with_crc(secrets.token_bytes(16)),
        )

    def to_json(self) -> bytes:
        d = asdict(self)
        d["network_key"] = self.network_key.hex()
        d["tc_install_code"] = self.tc_install_code.hex()
        return json.dumps(d).encode()

    @staticmethod
    def from_json(raw: bytes) -> NetworkSecrets:
        d = json.loads(raw)
        d["network_key"] = bytes.fromhex(d["network_key"])
        d["tc_install_code"] = bytes.fromhex(d["tc_install_code"])
        return NetworkSecrets(**d)

    def __repr__(self) -> str:  # never leak keys through logging/repr
        return f"NetworkSecrets(pan_id={self.pan_id:#06x}, channel={self.channel}, keys=<redacted>)"


def _with_crc(code: bytes) -> bytes:
    from .installcode import crc16
    return code + crc16(code).to_bytes(2, "little")


class Keystore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._pass_path = path.with_name(path.name + ".pass")

    # -- passphrase --------------------------------------------------------

    def _passphrase(self) -> bytes:
        env = os.environ.get(_ENV)
        if env:
            return env.encode()
        if self._pass_path.exists():
            return self._pass_path.read_bytes().strip()
        pw = secrets.token_urlsafe(32).encode()
        _write_private(self._pass_path, pw + b"\n")
        log.warning("generated keystore passphrase at %s — back it up; without it the network must be re-formed", self._pass_path)
        return pw

    def _kek(self, salt: bytes) -> bytes:
        return hashlib.scrypt(self._passphrase(), salt=salt, **_SCRYPT)

    # -- load / save -------------------------------------------------------

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> NetworkSecrets:
        blob = self.path.read_bytes()
        if not blob.startswith(_MAGIC):
            raise ValueError("keystore: bad magic")
        salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
        raw = AESGCM(self._kek(salt)).decrypt(nonce, ct, _MAGIC)
        return NetworkSecrets.from_json(raw)

    def save(self, s: NetworkSecrets) -> None:
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        ct = AESGCM(self._kek(salt)).encrypt(nonce, s.to_json(), _MAGIC)
        _write_private(self.path, _MAGIC + salt + nonce + ct)

    def load_or_create(self, channel: int) -> NetworkSecrets:
        if self.exists():
            s = self.load()
            log.info("loaded network secrets: %r", s)
            return s
        s = NetworkSecrets.generate(channel)
        self.save(s)
        log.warning("generated NEW network secrets (%r) — all devices will need to be paired", s)
        return s


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
