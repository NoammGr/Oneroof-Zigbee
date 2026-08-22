"""Authentication and authorisation for the broker.

* :class:`PasswordFile` — plain-text file, one ``user:scrypt$n$r$p$salt$hash``
  per line. Hashes use :func:`hashlib.scrypt`; verification uses
  :func:`hmac.compare_digest`. The file is created/rewritten with mode 0o600.
* :class:`Authenticator` — protocol the broker calls on CONNECT.
* :class:`Acl` — per-user publish/subscribe filter lists, default deny.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
from pathlib import Path
from typing import Protocol, runtime_checkable

from oneroof_zigbee.mqtt.packets import MalformedPacket, topic_matches, validate_filter

log = logging.getLogger("oneroof_zigbee.mqtt.auth")

# scrypt parameters: N=2**15, r=8, p=1 is ~32 MiB and tens of ms on a small box.
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 256 * 1024 * 1024
_MAX_N = 1 << 20  # refuse absurd cost parameters in the file (DoS guard)

# A fake record used so that verification of unknown users costs the same
# time as verification of known users (no user-enumeration via timing).
_DUMMY_SALT = bytes(16)


@runtime_checkable
class Authenticator(Protocol):
    """Anything with ``verify(username, password) -> bool``.

    ``password`` is the raw bytes from the CONNECT packet; the broker never
    decodes or logs it.
    """

    def verify(self, username: str, password: bytes) -> bool: ...


class PasswordFile:
    """scrypt-hashed password store backed by a simple text file."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._users: dict[str, tuple[int, int, int, bytes, bytes]] = {}
        if self.path.exists():
            self._load()

    # -- file I/O ---------------------------------------------------------

    def _load(self) -> None:
        users: dict[str, tuple[int, int, int, bytes, bytes]] = {}
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    user, rec = line.split(":", 1)
                    algo, n, r, p, salt_hex, hash_hex = rec.split("$")
                    if algo != "scrypt":
                        raise ValueError(algo)
                    n_i, r_i, p_i = int(n), int(r), int(p)
                    if not (1 < n_i <= _MAX_N and n_i & (n_i - 1) == 0 and 0 < r_i <= 32 and 0 < p_i <= 16):
                        raise ValueError("bad scrypt params")
                    users[user] = (n_i, r_i, p_i, bytes.fromhex(salt_hex), bytes.fromhex(hash_hex))
                except ValueError:
                    log.warning("%s:%d: unparseable password record ignored", self.path, lineno)
        self._users = users

    def _save(self) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        lines = [
            f"{u}:scrypt${n}${r}${p}${salt.hex()}${h.hex()}\n" for u, (n, r, p, salt, h) in self._users.items()
        ]
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.writelines(lines)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    # -- API --------------------------------------------------------------

    @staticmethod
    def _hash(pw: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
        return hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, dklen=SCRYPT_DKLEN, maxmem=SCRYPT_MAXMEM)

    def set_password(self, user: str, password: str | bytes) -> None:
        if not user or ":" in user or any(c.isspace() for c in user):
            raise ValueError("invalid username")
        pw = password.encode("utf-8") if isinstance(password, str) else password
        salt = secrets.token_bytes(16)
        h = self._hash(pw, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
        with self._lock:
            self._users[user] = (SCRYPT_N, SCRYPT_R, SCRYPT_P, salt, h)
            self._save()

    def remove(self, user: str) -> bool:
        with self._lock:
            if self._users.pop(user, None) is None:
                return False
            self._save()
            return True

    def has_user(self, user: str) -> bool:
        if self.path.exists():
            self._load()
        return user in self._users

    def users(self) -> list[str]:
        return sorted(self._users)

    def verify(self, username: str, password: str | bytes) -> bool:
        pw = password.encode("utf-8") if isinstance(password, str) else password
        rec = self._users.get(username)
        if rec is None:
            # Burn the same amount of work so timing does not reveal user existence.
            self._hash(pw, _DUMMY_SALT, SCRYPT_N, SCRYPT_R, SCRYPT_P)
            return False
        n, r, p, salt, expected = rec
        actual = self._hash(pw, salt, n, r, p)
        return hmac.compare_digest(actual, expected)


class Acl:
    """Per-user allow-lists of topic filters. Anything not listed is denied.

    ``can_publish``: the topic must match at least one allowed publish filter.

    ``can_subscribe``: we must guarantee that *every* topic the requested
    filter could match is covered by an allowed subscribe filter. Computing
    exact filter containment is possible but fiddly, so this implementation
    is deliberately conservative (sound, not complete). A requested filter
    ``req`` is allowed by an allowed filter ``al`` iff one of:

    * ``al == req`` (identical filters);
    * ``al == "#"`` (everything, but note the ``$`` rule below);
    * ``al`` ends with ``/#`` and ``req`` equals the prefix before ``/#`` or
      starts with that prefix followed by ``/``;
    * ``req`` has no wildcards at all and ``topic_matches(al, req)``.

    This rejects some subscriptions that a complete check would allow
    (e.g. allowed ``a/+/c`` vs requested ``a/b/c`` is allowed via the last
    rule, but allowed ``a/+/#`` vs requested ``a/b/#`` is rejected). Clients
    can always subscribe to the exact filter they were granted. Because
    ``#`` / ``+`` filters never match ``$``-prefixed topics, granting ``#``
    does not grant ``$SYS/#``; ``$SYS`` access must be listed explicitly.
    """

    def __init__(self) -> None:
        self._pub: dict[str, list[str]] = {}
        self._sub: dict[str, list[str]] = {}
        self._deny_pub: dict[str, list[str]] = {}  # publish filters refused unless a *specific* allow matches

    def allow(self, user: str, *, publish: list[str] | None = None, subscribe: list[str] | None = None,
              deny_publish: list[str] | None = None) -> None:
        for f in (publish or []) + (subscribe or []) + (deny_publish or []):
            validate_filter(f)
        if publish:
            self._pub.setdefault(user, []).extend(publish)
        if subscribe:
            self._sub.setdefault(user, []).extend(subscribe)
        if deny_publish:
            self._deny_pub.setdefault(user, []).extend(deny_publish)

    def clear(self, user: str) -> None:
        self._pub.pop(user, None)
        self._sub.pop(user, None)
        self._deny_pub.pop(user, None)

    @classmethod
    def from_dict(cls, data: dict[str, dict[str, list[str]]]) -> Acl:
        """``{"user": {"publish": [...], "subscribe": [...]}}``."""
        acl = cls()
        for user, rules in data.items():
            acl.allow(user, publish=list(rules.get("publish", [])), subscribe=list(rules.get("subscribe", [])))
        return acl

    def can_publish(self, user: str, topic: str) -> bool:
        """Allow filters grant. A deny filter refuses a topic that is covered only by the bare
        catch-all "#"; any narrower allow (e.g. "<base>/+/set", "<base>/bridge/request/#") wins over
        the deny, so "publish anywhere except the gateway's device topics, commands excepted" is
        expressible."""
        allows = self._pub.get(user, ())
        if not any(topic_matches(f, topic) for f in allows):
            return False
        if any(topic_matches(d, topic) for d in self._deny_pub.get(user, ())):
            return any(topic_matches(f, topic) for f in allows if f != "#")
        return True

    def can_subscribe(self, user: str, topic_filter: str) -> bool:
        try:
            validate_filter(topic_filter)
        except MalformedPacket:
            return False
        has_wild = "+" in topic_filter or "#" in topic_filter
        for allowed in self._sub.get(user, ()):
            if allowed == topic_filter:
                return True
            if allowed == "#" and not topic_filter.startswith("$"):
                return True
            if allowed.endswith("/#"):
                prefix = allowed[:-2]
                if topic_filter == prefix or topic_filter.startswith(prefix + "/"):
                    return True
            if not has_wild and topic_matches(allowed, topic_filter):
                return True
        return False
