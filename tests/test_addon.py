"""The add-on entrypoint (oneroof-zigbee/run.py), exercised without a Supervisor: option mapping,
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

RUN_PY = Path(__file__).resolve().parent.parent / "oneroof-zigbee" / "run.py"


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
    monkeypatch.setenv("HOSTNAME", "5a3a8b95-oneroof-zigbee")
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
    assert body == {"host": "5a3a8b95-oneroof-zigbee", "port": 1883, "ssl": False, "username": "homeassistant", "password": "pw-123", "protocol": "3.1.1"}
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
    """The add-on installs the package from a tarball; the UI must be package data, not a repo-only file."""
    import importlib.resources
    from oneroof_zigbee import ui
    assert (importlib.resources.files(ui) / "static" / "index.html").is_file()
    import tomllib
    pyproject = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text())
    assert "ui/static/*" in pyproject["tool"]["setuptools"]["package-data"]["oneroof_zigbee"]
