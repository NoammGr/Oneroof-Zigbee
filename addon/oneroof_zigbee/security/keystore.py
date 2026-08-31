"""Network secrets at rest.

The network key, PAN id, extended PAN id and channel are generated from
`secrets` on first start and persisted in one file, encrypted with
AES-256-GCM under a key derived (scrypt) from a passphrase.  The passphrase
comes from the ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE environment variable, else
from the 0600 file named by ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE_FILE, else from
a 0600 file next to the store; if none exists, one is generated.  As a Home
Assistant add-on the file is kept in the add-on's *private* /data — the
Supervisor's own volume, not the config folder the File editor and Samba can
browse — and a passphrase file found next to the store is moved there.  This
gives:

* secrets never appear in the YAML config (unlike a plain `network_key:` line),
* a config backup, the config folder or a Samba share on its own does not leak
  the network key: the store is there, the passphrase is not,
* an attacker needs both the store *and* the passphrase file.

Honest limitation: on a single host without a TPM, the passphrase file still
lives on the same disk, and a full Home Assistant backup contains both (protect
it with a backup password).  The encryption raises the bar for accidental
leakage (backups, support bundles, log uploads) — it is not a defence against
root on the box.
"""

from __future__ import annotations

from typing import Any

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
_ENV_FILE = "ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE_FILE"


@dataclass
class NetworkSecrets:
    network_key: bytes
    pan_id: int
    ext_pan_id: int
    channel: int
    tc_install_code: bytes  # 16 random bytes + CRC16: strict-mode replacement for the public TC link key
    frame_counter: int = 0
    tclk_seed: bytes | None = None  # trust-centre link-key seed of an imported network (devices' link keys derive from it)
    key_seq: int = 0                # network key sequence number the devices know this key by (rotations count it up)
    previous_network_key: bytes | None = None  # the key before the last rotation: kept as the radio's alternate key so
                                               # stragglers that missed the switch are still heard until they rejoin
    previous_key_seq: int | None = None        # the sequence the devices know the previous key by
    pending_rotation: dict[str, Any] | None = None  # a rotation in progress (new key, sequence, who has it): resumed after a restart
    last_rotation_ts: float | None = None  # when the network key last changed — the scheduled-rotation clock
    formed_ts: float | None = None  # when this network was formed — devices silent since then cannot be online

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
        d["tclk_seed"] = self.tclk_seed.hex() if self.tclk_seed else None
        d["previous_network_key"] = self.previous_network_key.hex() if self.previous_network_key else None
        return json.dumps(d).encode()

    @staticmethod
    def from_json(raw: bytes) -> NetworkSecrets:
        d = json.loads(raw)
        d["network_key"] = bytes.fromhex(d["network_key"])
        d["tc_install_code"] = bytes.fromhex(d["tc_install_code"])
        if d.get("tclk_seed"):
            d["tclk_seed"] = bytes.fromhex(d["tclk_seed"])
        if d.get("previous_network_key"):
            d["previous_network_key"] = bytes.fromhex(d["previous_network_key"])
        return NetworkSecrets(**d)

    def __repr__(self) -> str:  # never leak keys through logging/repr
        return f"NetworkSecrets(pan_id={self.pan_id:#06x}, channel={self.channel}, keys=<redacted>)"


def _with_crc(code: bytes) -> bytes:
    from .installcode import crc16
    return code + crc16(code).to_bytes(2, "little")


class Keystore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._legacy_pass_path = path.with_name(path.name + ".pass")
        env_file = os.environ.get(_ENV_FILE)
        self._pass_path = Path(env_file) if env_file else self._legacy_pass_path

    @property
    def pass_path(self) -> Path:
        """Where the passphrase file lives (the private folder as an add-on)."""
        return self._pass_path

    # -- passphrase --------------------------------------------------------

    def _passphrase(self) -> bytes:
        env = os.environ.get(_ENV)
        if env:
            return env.encode()
        if self._pass_path.exists():
            return self._pass_path.read_bytes().strip()
        if self._pass_path != self._legacy_pass_path and self._legacy_pass_path.exists():
            # older versions kept the passphrase next to the store, in the browsable config folder:
            # move it into the private location and leave nothing readable behind
            pw = self._legacy_pass_path.read_bytes().strip()
            _write_private(self._pass_path, pw + b"\n")
            try:
                with open(self._legacy_pass_path, "r+b") as f:
                    f.write(b"\x00" * max(64, len(pw) + 1))
                    f.flush()
                    os.fsync(f.fileno())
                self._legacy_pass_path.unlink()
            except OSError as e:
                log.warning("old passphrase file %s could not be removed (%s) — delete it by hand", self._legacy_pass_path, e)
            log.warning("keystore passphrase moved from %s to the private folder %s", self._legacy_pass_path, self._pass_path)
            return pw
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
        return self.decrypt(self.path.read_bytes(), self._passphrase())

    @staticmethod
    def decrypt(blob: bytes, passphrase: bytes) -> NetworkSecrets:
        """Decrypt a keystore file's bytes with a given passphrase (a backup's copy, for instance)."""
        if not blob.startswith(_MAGIC):
            raise ValueError("keystore: bad magic")
        salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
        raw = AESGCM(hashlib.scrypt(passphrase, salt=salt, **_SCRYPT)).decrypt(nonce, ct, _MAGIC)
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
