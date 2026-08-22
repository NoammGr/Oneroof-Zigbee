"""Notification secrets at rest (bot token, chat id).

Same scheme as the network keystore: one file encrypted with AES-256-GCM under
a key derived (scrypt) from a random passphrase kept in a 0600 file next to it.
The token is never written to the YAML settings, never returned by the API
(`has_token` only), never logged and never put in the audit log.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets as pysecrets
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..security.keystore import _SCRYPT, _write_private

log = logging.getLogger("oneroof_zigbee.notify.secrets")

_MAGIC = b"OZNS1"


class NotifySecrets:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._pass_path = path.with_name(path.name + ".pass")
        self._cache: dict[str, Any] | None = None

    def __repr__(self) -> str:  # never leak through logging
        return f"NotifySecrets(path={str(self.path)!r}, has_token={self.has_token()})"

    def _passphrase(self) -> bytes:
        if self._pass_path.exists():
            return self._pass_path.read_bytes().strip()
        pw = pysecrets.token_urlsafe(32).encode()
        _write_private(self._pass_path, pw + b"\n")
        return pw

    def _kek(self, salt: bytes) -> bytes:
        return hashlib.scrypt(self._passphrase(), salt=salt, **_SCRYPT)

    def load(self) -> dict[str, Any]:
        if self._cache is not None:
            return dict(self._cache)
        if not self.path.exists():
            self._cache = {}
            return {}
        try:
            blob = self.path.read_bytes()
            if not blob.startswith(_MAGIC):
                raise ValueError("bad magic")
            salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
            self._cache = json.loads(AESGCM(self._kek(salt)).decrypt(nonce, ct, _MAGIC))
        except Exception as e:  # a corrupt or foreign file: behave as "no secrets", say so without detail
            log.error("notification secrets unreadable (%s); enter the bot token again", type(e).__name__)
            self._cache = {}
        return dict(self._cache)

    def save(self, data: dict[str, Any]) -> None:
        salt, nonce = pysecrets.token_bytes(16), pysecrets.token_bytes(12)
        ct = AESGCM(self._kek(salt)).encrypt(nonce, json.dumps(data).encode(), _MAGIC)
        _write_private(self.path, _MAGIC + salt + nonce + ct)
        self._cache = dict(data)

    def update(self, **fields: Any) -> None:
        d = self.load()
        for k, v in fields.items():
            if v is None:
                d.pop(k, None)
            else:
                d[k] = v
        self.save(d)

    def clear_token(self) -> None:
        self.update(bot_token=None)

    def has_token(self) -> bool:
        return bool(self.load().get("bot_token"))

    def chat_id(self) -> str | None:
        v = self.load().get("chat_id")
        return str(v) if v not in (None, "") else None

    def token(self) -> str | None:
        v = self.load().get("bot_token")
        return str(v) if v else None

    def mode(self) -> int | None:
        try:
            return os.stat(self.path).st_mode & 0o777
        except OSError:
            return None
