"""The add-on entrypoint (addon/run.py), exercised without a Supervisor: option mapping,
overrides written by the import, and registration as Home Assistant's MQTT service against a fake
Supervisor endpoint."""

from __future__ import annotations

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

RUN_PY = Path(__file__).resolve().parent.parent / "addon" / "run.py"


def load_run(tmp_path, monkeypatch):
    monkeypatch.setenv("ONEROOF_DATA", str(tmp_path / "cfg"))
    monkeypatch.setenv("ONEROOF_OPTIONS", str(tmp_path / "options.json"))
    (tmp_path / "cfg").mkdir(exist_ok=True)
    spec = importlib.util.spec_from_file_location("addon_run", RUN_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeSupervisor(BaseHTTPRequestHandler):
    calls: list[tuple[str, str, dict | None]] = []
    provided_by_other = False

    def _reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        FakeSupervisor.calls.append(("POST", self.path, body))
        if self.headers.get("Authorization") != "Bearer test-token":
            return self._reply(401, {"result": "error", "message": "unauthorized"})
        if FakeSupervisor.provided_by_other:
            return self._reply(400, {"result": "error", "message": "Service is already provided by addon core_mosquitto"})
        self._reply(200, {"result": "ok", "data": {}})

    def do_DELETE(self):
        FakeSupervisor.calls.append(("DELETE", self.path, None))
        self._reply(200, {"result": "ok", "data": {}})

    def log_message(self, *a):
        pass


@pytest.fixture
def supervisor(monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), FakeSupervisor)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    FakeSupervisor.calls = []
    FakeSupervisor.provided_by_other = False
    monkeypatch.setenv("SUPERVISOR_URL", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.setenv("SUPERVISOR_TOKEN", "test-token")
    monkeypatch.setenv("HOSTNAME", "1f2e3d4c-oneroof-zigbee")
    yield srv
    srv.shutdown()


def test_build_config_defaults_and_coordinator(tmp_path, monkeypatch):
    run = load_run(tmp_path, monkeypatch)
    cfg = run.build_config({"serial_port": "/dev/serial/by-id/usb-x", "channel": 15, "mqtt_port": 8883, "mqtt_plaintext_port": 1883})
    assert cfg["serial"]["port"] == "/dev/serial/by-id/usb-x" and cfg["mqtt"]["plaintext_port"] == 1883
    assert cfg["mqtt"]["tls"]["mode"] == "auto" and "external" not in cfg["mqtt"] and "compat" not in cfg
    assert run.coordinator_port({"network_coordinator": "10.0.0.5:6638"}) == "tcp://10.0.0.5:6638"
    assert run.coordinator_port({"network_coordinator": "/dev/ttyUSB0"}) == "/dev/ttyUSB0"
    assert run.coordinator_port({"network_coordinator": "nonsense"}) == ""


def test_overrides_from_import_turn_legacy_layout_on(tmp_path, monkeypatch):
    run = load_run(tmp_path, monkeypatch)
    (tmp_path / "cfg" / "overrides.yaml").write_text(yaml.safe_dump({"legacy_layout": True, "base_topic": "zigbee2mqtt", "discovery_prefix": "homeassistant"}))
    cfg = run.build_config({"serial_port": "/dev/x", "channel": 15, "mqtt_port": 8883})
    assert cfg["compat"] == {"legacy_layout": True} and cfg["mqtt"]["base_topic"] == "zigbee2mqtt"
    assert cfg["homeassistant"]["discovery_prefix"] == "homeassistant"
    from oneroof_zigbee.config import Config
    c = Config.from_dict(cfg)  # the generated config is valid
    assert c.compat.legacy_layout and c.mqtt.base_topic == "zigbee2mqtt"


def test_registers_as_home_assistant_mqtt_service(tmp_path, monkeypatch, supervisor, capsys):
    run = load_run(tmp_path, monkeypatch)
    run.register_mqtt_service("homeassistant", "pw-123", 1883)
    method, path, body = FakeSupervisor.calls[-1]
    assert (method, path) == ("POST", "/services/mqtt")
    assert body == {"host": "1f2e3d4c-oneroof-zigbee", "port": 1883, "ssl": False, "username": "homeassistant", "password": "pw-123", "protocol": "3.1.1"}
    assert "Registered as Home Assistant's MQTT service" in capsys.readouterr().out
    run.unregister_mqtt_service()
    assert FakeSupervisor.calls[-1][:2] == ("DELETE", "/services/mqtt")


def test_old_broker_still_registered_gives_clear_instruction(tmp_path, monkeypatch, supervisor, capsys):
    run = load_run(tmp_path, monkeypatch)
    FakeSupervisor.provided_by_other = True
    run.register_mqtt_service("homeassistant", "pw-123", 1883)
    out = capsys.readouterr().out
    assert "Stop the Mosquitto add-on" in out or "old broker" in out


def test_no_plaintext_port_skips_registration(tmp_path, monkeypatch, supervisor, capsys):
    run = load_run(tmp_path, monkeypatch)
    run.register_mqtt_service("homeassistant", "pw-123", None)
    assert FakeSupervisor.calls == [] and "skipped" in capsys.readouterr().out


def test_package_ships_the_ui():
    """The add-on copies the package into the image; the UI must be package data, not a repo-only file."""
    import importlib.resources
    from oneroof_zigbee import ui
    assert (importlib.resources.files(ui) / "static" / "index.html").is_file()
    import tomllib
    pyproject = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text())
    assert "ui/static/*" in pyproject["tool"]["setuptools"]["package-data"]["oneroof_zigbee"]


def test_changing_the_ha_users_password_updates_the_service_login(tmp_path):
    """Add-on: the password announced to Home Assistant as the MQTT service must follow UI changes."""
    from oneroof_zigbee.admin import Admin
    from oneroof_zigbee.config import Config
    from oneroof_zigbee.mqtt import Acl, PasswordFile
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(f"serial:\n  port: /dev/null\ndata_dir: {tmp_path}\nmqtt:\n  password_file: {tmp_path}/passwd\n")
    cfg = Config.load(cfg_path)
    admin = Admin(cfg, cfg_path, PasswordFile(cfg.mqtt.password_file), Acl(), set(), managed=True)
    admin.upsert_user("homeassistant", role="homeassistant", password="first-password-123", control=False, subscribe=None, publish=None)
    assert (tmp_path / ".service-login").read_text() == "first-password-123"
    admin.upsert_user("homeassistant", role="homeassistant", password="second-password-456", control=False, subscribe=None, publish=None)
    assert (tmp_path / ".service-login").read_text() == "second-password-456"
    admin.upsert_user("other", role="client", password="client-password-789", control=False, subscribe=None, publish=None)
    assert (tmp_path / ".service-login").read_text() == "second-password-456", "only the Home Assistant user is announced"


def test_addon_places_the_keystore_passphrase_in_the_private_folder(tmp_path, monkeypatch):
    """run.py keeps the keystore passphrase in the add-on's private volume (next to options.json),
    creates it before privileges drop, and moves one left in the config folder by an older version."""
    import importlib.util
    monkeypatch.setenv("ONEROOF_OPTIONS", str(tmp_path / "data" / "options.json"))
    monkeypatch.setenv("ONEROOF_DATA", str(tmp_path / "config"))
    monkeypatch.setenv("ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE_FILE", str(tmp_path / "data" / "network.keystore.pass"))  # restored at teardown
    (tmp_path / "data").mkdir()
    (tmp_path / "config").mkdir()
    legacy = tmp_path / "config" / "network.keystore.pass"
    legacy.write_bytes(b"old-secret\n")
    spec = importlib.util.spec_from_file_location("run_addon", RUN_PY)
    run = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(run)
    target = run.place_keystore_passphrase()
    assert target == tmp_path / "data" / "network.keystore.pass"
    assert target.read_bytes().strip() == b"old-secret" and oct(target.stat().st_mode & 0o777) == "0o600"
    assert not legacy.exists()
    assert __import__("os").environ["ONEROOF_ZIGBEE_KEYSTORE_PASSPHRASE_FILE"] == str(target)
    # second start: nothing changes, nothing regenerated
    assert run.place_keystore_passphrase().read_bytes().strip() == b"old-secret"


def test_version_agrees_everywhere():
    """The Dockerfile build fails when the package and the add-on disagree; catch it before Docker does."""
    import re
    from pathlib import Path
    from oneroof_zigbee import __version__
    root = Path(__file__).resolve().parent.parent
    pyproject = re.search(r'^version = "([^"]+)"', (root / "pyproject.toml").read_text(), re.M).group(1)
    config = re.search(r'^version: "([^"]+)"', (root / "addon" / "config.yaml").read_text(), re.M).group(1)
    assert __version__ == pyproject == config


def test_the_mqtt_service_registration_survives_our_own_restart():
    """The Supervisor restarts every add-on that consumes a service when its provider disappears.
    Withdrawing the MQTT registration on our way out therefore bounces the HomeKit bridge (and with
    it every accessory in Apple Home) each time this add-on restarts. The registration is left in
    place and refreshed on the next start; it is withdrawn only when an external broker takes over."""
    src = RUN_PY.read_text()
    tail = src[src.index("    finally:\n        hb.cancel()"):]
    assert "unregister_mqtt_service()" not in tail, "the service must not be withdrawn on exit"
    announce = src[src.index("def announce_service"):src.index("def announce_service") + 500]
    assert "unregister_mqtt_service()" in announce, "an external broker does withdraw it"
