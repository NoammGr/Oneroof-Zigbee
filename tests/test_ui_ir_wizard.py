"""The IR blaster's "set up from the remote" card reads its stage from the device's own words."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

HTML = Path(__file__).resolve().parents[1] / "addon" / "oneroof_zigbee" / "ui" / "static" / "index.html"


def _chunk(src: str, start: str, end: str) -> str:
    i = src.index(start)
    return src[i:src.index(end, i)]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_ir_setup_stage_follows_last_result():
    src = HTML.read_text().split("<script>")[1].split("</script>")[0]
    code = _chunk(src, "const IR_PROTOCOLS=", "function irIsBlaster(")
    prog = code + """
const out = {
  idle: irSetupStage({last_result: 'idle', protocol: 'learn'}, false),
  listening: irSetupStage({last_result: 'press on/off on the AC remote now'}, true),
  detected: irSetupStage({last_result: 'detected: electra enabled (cool 24C fan auto swing off)'}, true),
  none: irSetupStage({last_result: 'no known protocol in that frame - learn codes one by one'}, true),
  failed: irSetupStage({last_result: 'learn ? failed: nothing received'}, true),
  switched: irSetupStage({last_result: 'protocol gree (defaults, learn one frame to calibrate)', protocol: 'gree'}, true),
  manual: irSetupStage({last_result: 'protocol learn', protocol: 'learn'}, true),
  trials: IR_TRIALS.map(t => t.id), protocols: IR_PROTOCOLS,
};
console.log(JSON.stringify(out));
"""
    r = subprocess.run(["node", "-e", prog], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    got = json.loads(r.stdout)
    assert got["idle"]["stage"] == "idle"
    assert got["listening"]["stage"] == "listening"
    assert got["detected"] == {"stage": "trial", "proto": "electra", "detail": "cool 24C fan auto swing off"}
    assert got["none"]["stage"] == "manual"
    assert got["failed"]["stage"] == "failed"
    assert got["switched"] == {"stage": "trial", "proto": "gree", "detail": ""}, "a protocol picked by hand is tried the same way"
    assert got["manual"]["stage"] == "manual"
    assert got["trials"] == ["on", "off", "fan", "swing", "heat"] and len(got["protocols"]) == 4


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_page_script_parses(tmp_path):
    # the script goes through a file: as one argv element it is longer than Linux allows
    src = HTML.read_text().split("<script>")[1].split("</script>")[0]
    js = tmp_path / "page.js"
    js.write_text(src)
    r = subprocess.run(["node", "--check", str(js)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-500:]
