"""Runtime administration used by the UI Settings page: editable config,
user/ACL management (live), TLS info, encrypted backup/restore, restart.

Security notes
* Passwords are never returned; the UI only sees `has_password`.
* Users live in `<data_dir>/users.yaml` (0600) so they can be managed from
  the UI in both standalone and add-on mode; `config.yaml` users are merged
  in as read-only.
* Backups are AES-256-GCM under a scrypt key from a user-chosen password;
  they contain the network key, so the password matters — we enforce ≥ 12.
"""

from __future__ import annotations

import glob
import hashlib
import io
import json
import contextlib
import logging
import os
import secrets as pysecrets
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import Config
from .security import NetworkSecrets
from .mqtt import Acl, PasswordFile

log = logging.getLogger("oneroof_zigbee.admin")

ROLE_TEMPLATES: dict[str, dict[str, Any]] = {
    "homeassistant": {"subscribe": ["#"], "publish": ["#", "{base}/+/set", "{base}/+/get", "{base}/bridge/request/#"],
                      "deny_publish": ["{base}/#"], "control": False,
                      "description": "Home Assistant and the apps that share its login (One Roof Bridge …): read everything, publish "
                                     "anywhere except the gateway's own device topics (commands via /set allowed), cannot open the network"},
    "admin": {"subscribe": ["{base}/#"], "publish": ["{base}/#"], "control": True,
              "description": "Admin: everything incl. pairing, removing, key rotation"},
    "readonly": {"subscribe": ["{base}/+/state", "{base}/bridge/state", "{base}/bridge/info", "{base}/bridge/devices"], "publish": [], "control": False,
                 "description": "Read-only: dashboards, loggers"},
    "client": {"subscribe": ["#"], "publish": ["#"], "control": False,
               "description": "Client: full publish/subscribe (other apps, bridges), cannot open the network"},
    "custom": {"subscribe": [], "publish": [], "control": False, "description": "Custom ACL"},
}
_BACKUP_MAGIC = b"OZBK1"
_SCRYPT = dict(n=2**15, r=8, p=1, dklen=32, maxmem=128 * 1024 * 1024)
RESTART_EXIT_CODE = 4


class Admin:
    def __init__(self, cfg: Config, config_path: Path | None, passwords: PasswordFile, acl: Acl, control_users: set[str],
                 *, managed: bool = False) -> None:
        self.cfg = cfg
        self.config_path = config_path
        self.passwords = passwords
        self.acl = acl
        self.control_users = control_users
        self.managed = managed  # True in the HA add-on: config.yaml is generated from add-on options
        self.audit: Any = None  # set by the runtime so adoption is recorded
        self.restart_required: list[str] = []
        self.users_path = cfg.data_dir / "users.yaml"
        self._on_restart: Any = None
        self.load_users()

    # ---------------------------------------------------------------- users --

    def _read_users_file(self) -> dict[str, dict[str, Any]]:
        if not self.users_path.exists():
            return {}
        try:
            data = yaml.safe_load(self.users_path.read_text()) or {}
        except (OSError, yaml.YAMLError):
            log.exception("users.yaml unreadable")
            return {}
        return {str(k): dict(v or {}) for k, v in (data.get("users") or {}).items()}

    def _write_users_file(self, users: dict[str, dict[str, Any]]) -> None:
        tmp = self.users_path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump({"users": users}, f, sort_keys=True)
        os.replace(tmp, self.users_path)

    def load_users(self) -> None:
        """Apply users.yaml on top of the live ACL / control set."""
        base = self.cfg.mqtt.base_topic
        for name, u in self._read_users_file().items():
            role = u.get("role", "custom")
            sub, pub, control = self._expand(role, u, base)
            self.acl.clear(name)
            self.acl.allow(name, publish=pub, subscribe=sub, deny_publish=self._deny(role, base))
            if control:
                self.control_users.add(name)
            else:
                self.control_users.discard(name)

    @staticmethod
    def _expand(role: str, u: dict[str, Any], base: str) -> tuple[list[str], list[str], bool]:
        t = ROLE_TEMPLATES.get(role, ROLE_TEMPLATES["custom"])
        if role == "custom":
            return list(u.get("subscribe", [])), list(u.get("publish", [])), bool(u.get("control", False))
        return ([s.format(base=base) for s in t["subscribe"]], [p.format(base=base) for p in t["publish"]], bool(u.get("control", t["control"])))

    @staticmethod
    def _deny(role: str, base: str) -> list[str]:
        t = ROLE_TEMPLATES.get(role, ROLE_TEMPLATES["custom"])
        return [d.format(base=base) for d in t.get("deny_publish", [])]

    def list_users(self) -> list[dict[str, Any]]:
        file_users = self._read_users_file()
        out: list[dict[str, Any]] = []
        names = set(file_users) | set(self.cfg.mqtt.users) | {self.cfg.mqtt.gateway_user} | set(self.passwords.users())
        for name in sorted(names):
            src = "gateway" if name == self.cfg.mqtt.gateway_user else "ui" if name in file_users else "config" if name in self.cfg.mqtt.users else "password-only"
            u = file_users.get(name, {})
            role = u.get("role", "custom" if src != "gateway" else "gateway")
            if src == "config":
                cu = self.cfg.mqtt.users[name]
                sub, pub = cu.subscribe, cu.publish
            else:
                sub, pub, _ = self._expand(role, u, self.cfg.mqtt.base_topic) if src == "ui" else ([], [], False)
            out.append({"name": name, "role": role, "source": src, "has_password": self.passwords.has_user(name),
                        "control": name in self.control_users, "subscribe": sub, "publish": pub,
                        "editable": src in ("ui", "password-only")})
        return out

    def upsert_user(self, name: str, *, role: str, password: str | None, control: bool | None,
                    subscribe: list[str] | None, publish: list[str] | None) -> None:
        if not name or len(name) > 64 or any(c in name for c in " /+#:\n\t"):
            raise ValueError("invalid user name")
        if name == self.cfg.mqtt.gateway_user or name in self.cfg.mqtt.users:
            raise ValueError("that user is defined in config.yaml; edit it there")
        if role not in ROLE_TEMPLATES:
            raise ValueError(f"role must be one of {list(ROLE_TEMPLATES)}")
        users = self._read_users_file()
        existing = users.get(name, {})
        if password is None and not self.passwords.has_user(name):
            raise ValueError("a password is required for a new user")
        if password is not None:
            if len(password) < 12:
                raise ValueError("password must be at least 12 characters")
            self.passwords.set_password(name, password)
            if self.managed and role == "homeassistant":
                self._sync_service_login(password)
        entry: dict[str, Any] = {"role": role}
        if role == "custom":
            entry["subscribe"] = [str(s) for s in (subscribe if subscribe is not None else existing.get("subscribe", []))]
            entry["publish"] = [str(p) for p in (publish if publish is not None else existing.get("publish", []))]
        ctl = control if control is not None else existing.get("control", ROLE_TEMPLATES[role]["control"])
        entry["control"] = bool(ctl)
        users[name] = entry
        self._write_users_file(users)
        self.load_users()

    def _sync_service_login(self, password: str) -> None:
        """Add-on only: the password handed to Home Assistant as the MQTT service lives in
        <data>/.service-login so it can be re-announced on every start; keep it current when the
        user changes it in the UI."""
        import os
        path = self.cfg.data_dir / ".service-login"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(password)
        except OSError as e:
            log.warning("could not update the service login file (%s); the next start announces the old password", e)

    def remove_user(self, name: str) -> None:
        if name == self.cfg.mqtt.gateway_user:
            raise ValueError("cannot remove the gateway's own user")
        if name in self.cfg.mqtt.users:
            raise ValueError("that user is defined in config.yaml; remove it there")
        users = self._read_users_file()
        users.pop(name, None)
        self._write_users_file(users)
        self.passwords.remove(name)
        self.acl.allow(name, publish=[], subscribe=[])
        self.control_users.discard(name)

    # --------------------------------------------------------------- config --

    DEFAULTS: dict[str, dict[str, Any]] = {
        "serial": {"baudrate": 115200, "rtscts": False},
        "zigbee": {"channel": 15, "strict_install_codes": False, "permit_join_max_seconds": 120,
                   "permit_join_require_install_code": False, "permit_join_cooldown_seconds": 5,
                   "permit_join_close_after_first_join": True, "rotate_key_after_plain_join": True,
                   "rotation_require_all": True, "rotation_max_window_seconds": 21600, "rotation_interval_days": 30},
        "mqtt": {"listen": "0.0.0.0", "port": 8883, "plaintext_port": None, "base_topic": "oneroof/zigbee", "tls": {"mode": "auto"}},
        "homeassistant": {"discovery": True, "discovery_prefix": "homeassistant"},
        "ui": {"enabled": True, "port": 8099},
    }

    def serial_ports(self) -> list[str]:
        pats = ["/dev/ttyUSB*", "/dev/ttyACM*", "/dev/serial/by-id/*", "/dev/tty.usb*", "/dev/cu.usb*", "/dev/tty.SLAB*", "/dev/cu.SLAB*"]
        found: list[str] = []
        for p in pats:
            found.extend(sorted(glob.glob(p)))
        return found

    def editable_config(self) -> dict[str, Any]:
        c = self.cfg
        return {
            "serial": {"port": c.serial.port, "baudrate": c.serial.baudrate, "rtscts": c.serial.rtscts, "adapter": c.serial.adapter,
                       "is_network": c.serial.is_network},
            "zigbee": {"channel": c.zigbee.channel, "strict_install_codes": c.zigbee.strict_install_codes,
                       "permit_join_max_seconds": c.zigbee.permit_join_max_seconds,
                       "permit_join_require_install_code": c.zigbee.permit_join_require_install_code,
                       "permit_join_cooldown_seconds": c.zigbee.permit_join_cooldown_seconds,
                       "permit_join_close_after_first_join": c.zigbee.permit_join_close_after_first_join,
                       "rotate_key_after_plain_join": c.zigbee.rotate_key_after_plain_join,
                       "rotation_require_all": c.zigbee.rotation_require_all, "rotation_max_window_seconds": c.zigbee.rotation_max_window_seconds,
                       "rotation_interval_days": c.zigbee.rotation_interval_days},
            "mqtt": {"listen": c.mqtt.listen, "port": c.mqtt.port, "plaintext_port": c.mqtt.plaintext_port, "base_topic": c.mqtt.base_topic,
                     "tls": {"mode": c.mqtt.tls.mode, "cert": str(c.mqtt.tls.cert) if c.mqtt.tls.cert else None,
                             "key": str(c.mqtt.tls.key) if c.mqtt.tls.key else None,
                             "client_ca": str(c.mqtt.tls.client_ca) if c.mqtt.tls.client_ca else None,
                             "hostnames": c.mqtt.tls.hostnames}},
            "homeassistant": {"discovery": c.homeassistant.discovery, "discovery_prefix": c.homeassistant.discovery_prefix},
            "compat": {"legacy_layout": c.compat.legacy_layout},
            "external": ({"server": c.mqtt.external.server, "user": c.mqtt.external.user, "has_password": bool(c.mqtt.external.password),
                          "ca": str(c.mqtt.external.ca) if c.mqtt.external.ca else None} if c.mqtt.external else None),
            "ui": {"enabled": c.ui.enabled, "listen": c.ui.listen, "port": c.ui.port, "acts_as": c.ui.acts_as},
            "log_level": c.log_level,
        }

    def save_config(self, patch: dict[str, Any]) -> list[str]:
        """Merge `patch` into config.yaml after validating; returns the list of changed keys."""
        if self.managed:
            raise PermissionError("configuration is managed by the Home Assistant add-on options")
        if not self.config_path:
            raise PermissionError("no config file path known")
        raw = yaml.safe_load(self.config_path.read_text()) or {}
        allowed = {"serial": {"port", "baudrate", "rtscts"},
                   "zigbee": {"channel", "strict_install_codes", "permit_join_max_seconds", "permit_join_require_install_code", "permit_join_cooldown_seconds",
                              "permit_join_close_after_first_join", "rotate_key_after_plain_join", "rotation_require_all", "rotation_max_window_seconds"},
                   "mqtt": {"listen", "port", "plaintext_port", "base_topic", "tls", "external"},
                   "compat": {"legacy_layout"},
                   "homeassistant": {"discovery", "discovery_prefix"},
                   "ui": {"enabled", "listen", "port", "acts_as"}}
        changed: list[str] = []
        for section, keys in allowed.items():
            if section not in patch:
                continue
            if not isinstance(patch[section], dict):
                raise ValueError(f"{section} must be an object")
            raw.setdefault(section, {})
            for k, v in patch[section].items():
                if k not in keys:
                    raise ValueError(f"{section}.{k} is not editable here")
                if raw[section].get(k) != v:
                    raw[section][k] = v
                    changed.append(f"{section}.{k}")
        if "log_level" in patch and raw.get("log_level") != patch["log_level"]:
            raw["log_level"] = str(patch["log_level"]).upper()
            changed.append("log_level")
        Config.from_dict(raw, base=self.config_path.parent)  # validate before writing
        if changed:
            backup = self.config_path.with_suffix(".yaml.bak")
            backup.write_text(self.config_path.read_text())
            tmp = self.config_path.with_suffix(".yaml.tmp")
            tmp.write_text(yaml.safe_dump(raw, sort_keys=False))
            os.replace(tmp, self.config_path)
            self.restart_required.extend(c for c in changed if c not in self.restart_required)
        return changed

    # ---------------------------------------------------------------- backup --

    BACKUP_FILES = ("network.keystore", "network.keystore.pass", "devices.json", "users.yaml", "definitions.yaml", "mqtt.passwd",
                    "tls/ca.key", "tls/ca.crt", "tls/server.key", "tls/server.crt")

    def _backup_path(self, rel: str) -> Path:
        """Where a backed-up file lives: the keystore passphrase sits in the private folder as an
        add-on (see security.keystore), everything else in the data folder."""
        if rel == "network.keystore.pass":
            from .security import Keystore
            return Keystore(self.cfg.data_dir / "network.keystore").pass_path
        return self.cfg.data_dir / rel

    def make_backup(self, password: str) -> bytes:
        if len(password) < 12:
            raise ValueError("backup password must be at least 12 characters")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for rel in self.BACKUP_FILES:
                p = self._backup_path(rel)
                if p.exists():
                    tar.add(p, arcname=rel)
            if self.config_path and self.config_path.exists():
                tar.add(self.config_path, arcname="config.yaml")
            meta = json.dumps({"created": time.time(), "version": __import__("oneroof_zigbee").__version__}).encode()
            info = tarfile.TarInfo("meta.json")
            info.size = len(meta)
            tar.addfile(info, io.BytesIO(meta))
        salt, nonce = pysecrets.token_bytes(16), pysecrets.token_bytes(12)
        key = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
        return _BACKUP_MAGIC + salt + nonce + AESGCM(key).encrypt(nonce, buf.getvalue(), _BACKUP_MAGIC)

    def secrets_from_backup(self, blob: bytes, password: str) -> "NetworkSecrets":
        """The network secrets inside a backup, decrypted in memory — nothing is written. Used to
        roll the coordinator back to the key a backup was taken with."""
        from .security import Keystore
        if not blob.startswith(_BACKUP_MAGIC):
            raise ValueError("not an OneRoof Zigbee backup")
        salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
        key = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
        try:
            raw = AESGCM(key).decrypt(nonce, ct, _BACKUP_MAGIC)
        except Exception as e:
            raise ValueError("wrong password or corrupt backup") from e
        store = passphrase = None
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            for m in tar.getmembers():
                if m.name == "network.keystore" and m.isfile():
                    store = tar.extractfile(m).read()  # type: ignore[union-attr]
                elif m.name == "network.keystore.pass" and m.isfile():
                    passphrase = tar.extractfile(m).read().strip()  # type: ignore[union-attr]
        if store is None or passphrase is None:
            raise ValueError("the backup holds no keystore and passphrase")
        return Keystore.decrypt(store, passphrase)

    def previous_setup_key(self, files: dict[str, str]) -> tuple[bytes, int, int | None, int | None]:
        """The network key a previous setup (Zigbee2MQTT folder) ran with, read in place: ``(key,
        sequence, pan_id, ext_pan_id)``. Only the key is taken — names, layout and broker settings
        are left alone. The sequence comes from coordinator_backup.json when it has one, else 0."""
        from .importer import build_plan
        plan = build_plan(configuration_yaml=files.get("configuration.yaml"), database_db=None,
                          coordinator_backup=files.get("coordinator_backup.json"))
        n = plan.network
        if not n.network_key:
            raise ValueError("the previous setup's files hold no readable network key")
        seq = 0
        if files.get("coordinator_backup.json"):
            try:
                nk = (json.loads(files["coordinator_backup.json"]) or {}).get("network_key") or {}
                if isinstance(nk.get("sequence_number"), int):
                    seq = int(nk["sequence_number"]) & 0xFF
            except ValueError:
                pass
        return n.network_key, seq, n.pan_id, n.ext_pan_id

    def restore_backup(self, blob: bytes, password: str) -> list[str]:
        if not blob.startswith(_BACKUP_MAGIC):
            raise ValueError("not an OneRoof Zigbee backup")
        salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
        key = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
        try:
            raw = AESGCM(key).decrypt(nonce, ct, _BACKUP_MAGIC)
        except Exception as e:
            raise ValueError("wrong password or corrupt backup") from e
        restored: list[str] = []
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            for m in tar.getmembers():
                if m.name == "meta.json" or not m.isfile():
                    continue
                if m.name not in self.BACKUP_FILES and m.name != "config.yaml":
                    continue  # never write arbitrary paths
                if m.name == "config.yaml":
                    if self.managed or not self.config_path:
                        continue
                    dest = self.config_path
                else:
                    dest = self._backup_path(m.name)
                dest.parent.mkdir(parents=True, exist_ok=True)
                data = tar.extractfile(m).read()  # type: ignore[union-attr]
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                restored.append(m.name)
        self.restart_required.append("restore")
        return restored

    # ---------------------------------------------------------------- import --

    IMPORT_FILES = ("configuration.yaml", "database.db", "coordinator_backup.json", "state.json")

    def import_scan(self) -> list[dict[str, Any]]:
        """Find previous-setup folders under the allowed roots (no upload needed). A folder qualifies
        when it holds a configuration.yaml with a `serial:` or `devices:` section, or a database.db."""
        out: list[dict[str, Any]] = []
        for root in self.cfg.import_roots:
            if not root.is_dir():
                continue
            candidates = [root] + [p for p in root.iterdir() if p.is_dir()] if root.is_dir() else []
            for folder in candidates:
                cfgf = folder / "configuration.yaml"
                if not cfgf.is_file() and not (folder / "database.db").is_file():
                    continue
                try:
                    head = cfgf.read_text(errors="replace")[:20000] if cfgf.is_file() else ""
                except OSError:
                    continue
                if cfgf.is_file() and not any(k in head for k in ("serial:", "devices:", "advanced:", "mqtt:")):
                    continue
                files = {n: (folder / n).is_file() for n in self.IMPORT_FILES}
                out.append({"path": str(folder), "files": files})
        return out

    def import_read_folder(self, folder: str) -> dict[str, str]:
        p = Path(folder).resolve()
        if not any(str(p).startswith(str(r.resolve()) + "/") or p == r.resolve() for r in self.cfg.import_roots if r.exists()):
            raise PermissionError("folder is outside the allowed import locations")
        files: dict[str, str] = {}
        for name in self.IMPORT_FILES:
            f = p / name
            if f.is_file():
                if f.stat().st_size > 1_500_000:
                    raise ValueError(f"{name} is too large")
                files[name] = f.read_text(errors="replace")
        if not files:
            raise ValueError("no importable files in that folder")
        return files

    def import_preview(self, files: dict[str, str]) -> dict[str, Any]:
        from .importer import build_plan
        plan = build_plan(configuration_yaml=files.get("configuration.yaml"), database_db=files.get("database.db"),
                          coordinator_backup=files.get("coordinator_backup.json"), state_json=files.get("state.json"))
        return plan.summary()

    def import_apply(self, files: dict[str, str], registry: Any, current_secrets: NetworkSecrets, known_ieee: set[int],
                     *, keep_broker: bool = True, broker_user: str | None = None, broker_password: str | None = None,
                     keep_entities: bool = True) -> dict[str, Any]:
        """Import devices + network from a previous setup and (optionally) keep its broker, base
        topic and Home Assistant identities, so nothing that consumes it today has to change."""
        from .importer import apply_plan, build_plan
        from .security import Keystore
        plan = build_plan(configuration_yaml=files.get("configuration.yaml"), database_db=files.get("database.db"),
                          coordinator_backup=files.get("coordinator_backup.json"), state_json=files.get("state.json"))
        secrets = apply_plan(plan, registry, current_secrets)
        if secrets is not current_secrets:
            Keystore(self.cfg.data_dir / "network.keystore").save(secrets)
            self.restart_required.append("import: network parameters")
        known_ieee.update(d.ieee for d in plan.devices)
        compat_changes: list[str] = []
        if (keep_broker or keep_entities) and self.config_path and not self.managed:
            raw = yaml.safe_load(self.config_path.read_text()) or {}
            raw.setdefault("mqtt", {})
            if keep_entities:
                raw.setdefault("compat", {})["legacy_layout"] = True
                raw["mqtt"]["base_topic"] = plan.mqtt.base_topic
                raw.setdefault("homeassistant", {})["discovery_prefix"] = plan.mqtt.homeassistant_prefix
                compat_changes += ["compat.legacy_layout", "mqtt.base_topic"]
            if keep_broker and plan.mqtt.server:
                ext = {"server": plan.mqtt.server, "client_id": "oneroof-zigbee"}
                user = broker_user or plan.mqtt.user
                pw = broker_password or plan.mqtt.password
                if user:
                    ext["user"] = user
                if pw:
                    ext["password"] = pw
                if plan.mqtt.ca:
                    ext["ca"] = plan.mqtt.ca
                raw["mqtt"]["external"] = ext
                compat_changes.append("mqtt.external")
            Config.from_dict(raw, base=self.config_path.parent)
            self.config_path.with_suffix(".yaml.bak").write_text(self.config_path.read_text())
            tmp = self.config_path.with_suffix(".yaml.tmp")
            tmp.write_text(yaml.safe_dump(raw, sort_keys=False))
            os.replace(tmp, self.config_path)
            self.restart_required.extend(c for c in compat_changes if c not in self.restart_required)
        elif keep_entities and self.managed:
            # Add-on: options.json is the Supervisor's; the add-on merges overrides.yaml over it at start.
            ov = {"legacy_layout": True, "base_topic": plan.mqtt.base_topic, "discovery_prefix": plan.mqtt.homeassistant_prefix}
            tmp = self.cfg.data_dir / "overrides.yaml.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                yaml.safe_dump(ov, f)
            os.replace(tmp, self.cfg.data_dir / "overrides.yaml")
            compat_changes += ["legacy_layout", "mqtt.base_topic"]
            self.restart_required.extend(c for c in compat_changes if c not in self.restart_required)
        # Recreate the previous broker login so clients outside Home Assistant keep connecting unchanged.
        if plan.mqtt.user and plan.mqtt.password and plan.mqtt.user not in (self.cfg.mqtt.gateway_user, *self.cfg.mqtt.users):
            try:
                self.upsert_user(plan.mqtt.user, role="client", password=plan.mqtt.password, control=False, subscribe=None, publish=None)
                compat_changes.append(f"user:{plan.mqtt.user}")
            except ValueError as e:
                log.warning("could not recreate previous broker login %r: %s", plan.mqtt.user, e)
        if self.managed:
            self.open_login_adoption_window()
        return {"devices": len(plan.devices), "network_adopted": secrets is not current_secrets, "summary": plan.summary(),
                "compat": compat_changes}

    # ------------------------------------------------- login adoption (add-on) --
    # Home Assistant keeps the login its MQTT integration was set up with (the previous broker's) and
    # retries it every few seconds from its own address inside the add-on network. For one hour after
    # an import (or the first start) the add-on adopts that login instead of rejecting it: the user
    # is created with the Home Assistant role and the event is recorded. Trust-on-first-use, limited
    # to Home Assistant's own address and to that window; nothing outside can reach this listener.

    ADOPT_WINDOW_SECONDS = 3600
    ADOPT_FROM = ("172.30.32.1", "172.30.32.2")  # Supervisor gateway / Home Assistant core addresses

    def _adopt_file(self) -> Path:
        return self.cfg.data_dir / ".adopt-login-until"

    def open_login_adoption_window(self, seconds: int = ADOPT_WINDOW_SECONDS) -> None:
        try:
            self._adopt_file().write_text(str(int(time.time()) + seconds))
        except OSError as e:
            log.warning("could not open the login adoption window (%s)", e)

    def login_adoption_open(self) -> bool:
        try:
            return time.time() < float(self._adopt_file().read_text().strip())
        except (OSError, ValueError):
            return False

    def adopt_login(self, ip: str, username: str, password: bytes) -> bool:
        """Called by the broker on a failed login. True = user created, let the connection in."""
        if not self.managed or ip not in self.ADOPT_FROM or not self.login_adoption_open():
            return False
        if self.passwords.has_user(username) or username in (self.cfg.mqtt.gateway_user, *self.cfg.mqtt.users):
            return False  # a real user with a wrong password is never "adopted"
        try:
            pw = password.decode("utf-8")
            self.upsert_user(username, role="homeassistant", password=pw, control=False, subscribe=None, publish=None)
        except (UnicodeDecodeError, ValueError) as e:
            log.warning("login %r from %s not adopted: %s", username, ip, e)
            return False
        with contextlib.suppress(OSError):
            self._adopt_file().unlink()  # one adoption per window
        log.warning("Adopted Home Assistant's existing broker login %r (from %s): the MQTT integration is connected "
                    "without any change on the Home Assistant side. Review it under Settings → Users & access.", username, ip)
        if self.audit:
            self.audit.security("broker_login_adopted", user=username, ip=ip)
        return True

    # --------------------------------------------------------------- restart --

    def set_restart_hook(self, fn: Any) -> None:
        self._on_restart = fn

    def request_restart(self) -> None:
        if self._on_restart is None:
            raise PermissionError("restart not available")
        self._on_restart()

    @staticmethod
    def exec_self() -> None:
        """Replace the process with a fresh copy of itself (standalone restart)."""
        os.execv(sys.executable, [sys.executable, *sys.argv])
