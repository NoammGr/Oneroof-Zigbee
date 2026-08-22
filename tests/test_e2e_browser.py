"""Browser end-to-end: real Chrome (headless, via DevTools protocol) against the
real stack from test_e2e's fixture. Skipped when Chrome or `websockets` is not
available (CI without a browser); run locally with `pytest tests/test_e2e_browser.py`.

Checks, per page: renders, zero console errors / uncaught exceptions. Then the
interactions that matter: a dashboard toggle reaches the radio; a state report
updates the dashboard card and the activity feed live; pairing from the Pair
page opens the join window on the coordinator; settings save marks a restart;
an install-code form validates; a help popover opens; phone width has no
horizontal overflow.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import urllib.request

import pytest
import pytest_asyncio

from tests.sim import plug
from tests.test_e2e import BASE, PLUG_IEEE, PLUG_NWK, Stack, api, stack, wait_for  # noqa: F401

CHROME = next((p for p in ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", shutil.which("google-chrome") or "",
                           shutil.which("chromium") or "", shutil.which("chromium-browser") or ""] if p and os.path.exists(p)), None)
websockets = pytest.importorskip("websockets")
pytestmark = [pytest.mark.asyncio(loop_scope="module"),
              pytest.mark.skipif(CHROME is None, reason="no Chrome available for browser e2e")]


class Browser:
    def __init__(self, port: int) -> None:
        self.port = port
        self.errors: list[str] = []
        self._id = 0

    async def __aenter__(self):
        import tempfile
        self.profile = tempfile.mkdtemp(prefix="oneroof-chrome-")
        self.log = open(os.path.join(self.profile, "chrome.log"), "w")
        self.proc = subprocess.Popen(
            [CHROME, "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage", "--no-first-run",
             "--no-default-browser-check", "--disable-extensions", "--hide-scrollbars", f"--user-data-dir={self.profile}",
             f"--remote-debugging-port={self.port}", "--remote-allow-origins=*", "--window-size=1280,900", "about:blank"],
            stdout=self.log, stderr=subprocess.STDOUT)
        targets = None
        for _ in range(300):  # up to 30 s: CI runners can be slow to bring Chrome up
            if self.proc.poll() is not None:
                break
            try:
                targets = json.load(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json", timeout=1))
                if any(t.get("type") == "page" for t in targets):
                    break
            except Exception:
                await asyncio.sleep(0.1)
        if not targets or not any(t.get("type") == "page" for t in targets):
            self.log.flush()
            tail = open(self.log.name).read()[-800:]
            self.proc.terminate()
            pytest.skip(f"Chrome did not start a DevTools page (exit={self.proc.poll()}): {tail!r}")
        url = [t for t in targets if t["type"] == "page"][0]["webSocketDebuggerUrl"]
        self.ws = await websockets.connect(url, max_size=50_000_000)
        await self.cmd("Page.enable")
        await self.cmd("Runtime.enable")
        await self.cmd("Log.enable")
        return self

    async def __aexit__(self, *a):
        try:
            await self.ws.close()
        finally:
            self.proc.terminate()
            self.log.close()

    async def cmd(self, method, **params):
        self._id += 1
        await self.ws.send(json.dumps({"id": self._id, "method": method, "params": params}))
        while True:
            m = json.loads(await self.ws.recv())
            if m.get("method") == "Runtime.exceptionThrown":
                self.errors.append(m["params"]["exceptionDetails"].get("text", "exception"))
            if m.get("method") == "Log.entryAdded" and m["params"]["entry"]["level"] == "error":
                self.errors.append(m["params"]["entry"]["text"])
            if m.get("id") == self._id:
                if "error" in m:
                    raise RuntimeError(m["error"])
                return m.get("result", {})

    async def js(self, expr):
        r = await self.cmd("Runtime.evaluate", expression=expr, awaitPromise=True, returnByValue=True)
        if r.get("exceptionDetails"):
            raise RuntimeError(r["exceptionDetails"].get("text"))
        return r.get("result", {}).get("value")

    async def go(self, base: str, hash_: str, settle: float = 1.5):
        await self.cmd("Page.navigate", url=f"{base}#{hash_}")
        await asyncio.sleep(settle)

    async def size(self, w: int, h: int):
        await self.cmd("Emulation.setDeviceMetricsOverride", width=w, height=h, deviceScaleFactor=1, mobile=w < 700)
        await asyncio.sleep(0.4)

    async def click_text(self, text: str, tag: str = "button"):
        ok = await self.js(f"(()=>{{const b=[...document.querySelectorAll('{tag}')].find(b=>b.textContent.trim()==={json.dumps(text)});if(!b)return false;b.click();return true;}})()")
        assert ok, f"no <{tag}> with text {text!r}"


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def browser(stack):  # noqa: F811
    async with Browser(9400) as b:
        yield b


async def test_b01_every_page_renders_without_console_errors(stack, browser):  # noqa: F811
    s, b = stack, browser
    base = f"http://127.0.0.1:{s.ui.port}/"
    # make sure there is something to show
    if _gw(s).registry.get(PLUG_IEEE) is None:
        await api(s, "POST", "/api/permit_join", {"seconds": 30})
        d = s.world.add(plug(PLUG_IEEE, PLUG_NWK))
        s.world.announce(d)
        await wait_for(lambda: (lambda x: x and x.interviewed)(_gw(s).registry.get(PLUG_IEEE)), 8)
    for page in ["dashboard", "devices", "pair", "map", "logs", "activity", "settings", f"device/0x{PLUG_IEEE:016x}"]:
        await b.go(base, page)
        title = await b.js("document.querySelector('h1') && document.querySelector('h1').textContent")
        assert title, f"{page}: no heading rendered"
        assert await b.js("document.documentElement.scrollWidth <= window.innerWidth"), f"{page}: horizontal overflow"
    from oneroof_zigbee import __version__
    assert await b.js("document.querySelector('#h-ver').textContent") == f"v{__version__}", "running version shown in the header"
    # every device tab
    for tab in ["About", "Controls", "State", "Clusters", "Reporting", "Bind", "Firmware"]:
        await b.click_text(tab)
        await asyncio.sleep(0.3)
    assert b.errors == [], f"console errors: {b.errors}"


async def test_b02_dashboard_toggle_reaches_radio_and_report_updates_card(stack, browser):  # noqa: F811
    s, b = stack, browser
    base = f"http://127.0.0.1:{s.ui.port}/"
    d = s.world.devices[PLUG_NWK]
    await b.go(base, "dashboard", 2.0)
    cards = await b.js("document.querySelectorAll('.dash-card, .card').length")
    assert cards >= 1
    d.received_commands.clear()
    clicked = await b.js("(()=>{const t=document.querySelector('.sw input');if(!t)return 'none';t.click();return 'ok';})()")
    assert clicked == "ok", "dashboard has a toggle for the plug"
    await wait_for(lambda: any(c == 0x0006 and cmd in (0x00, 0x01, 0x02) for c, cmd, _ in d.received_commands), 5)
    # a power report from the device shows up on the card without reload
    s.world.report(d, 0x0B04, 0x050B, 0x29, (333).to_bytes(2, "little"))
    await wait_for(lambda: json.loads(s.got[f"{BASE}/0x{PLUG_IEEE:016x}/state"])["power"] == 333.0)
    await asyncio.sleep(0.8)
    assert await b.js("document.body.textContent.includes('333')"), "live value rendered on dashboard"
    assert b.errors == []


async def test_b03_pair_page_opens_window_and_validates_install_code(stack, browser):  # noqa: F811
    s, b = stack, browser
    base = f"http://127.0.0.1:{s.ui.port}/"
    await _gw(s).coord._force_close_join()
    await b.go(base, "pair", 1.5)
    await b.click_text("Open join window")
    await wait_for(lambda: s.fake.permit_durations and s.fake.permit_durations[-1] == 60, 5)
    await asyncio.sleep(0.8)
    assert await b.js("document.body.textContent.includes('seconds left')")
    # install-code form rejects a bad code client-side (no request leaves the page)
    before = len([f for f in s.fake.requests if f.subsystem.name == "APP_CNF" and f.command == 0x04])
    await b.js("document.querySelector('summary').click()")
    await asyncio.sleep(0.3)
    await b.js("""(()=>{const ins=document.querySelectorAll('details input');ins[0].value='0x00124b00deadbeef';ins[0].dispatchEvent(new Event('input',{bubbles:true}));
                 ins[1].value='not-hex';ins[1].dispatchEvent(new Event('input',{bubbles:true}));})()""")
    await b.click_text("Open window for this device")
    await asyncio.sleep(0.5)
    assert await b.js("/Check the IEEE address and install code/.test(document.body.textContent)"), "client-side validation toast"
    assert len([f for f in s.fake.requests if f.subsystem.name == "APP_CNF" and f.command == 0x04]) == before, "no install code sent to the radio"
    assert s.fake.permit_durations[-1] == 60, "window unchanged" 
    await b.click_text("Close window now")
    await wait_for(lambda: s.fake.permit_durations[-1] == 0, 5)
    assert b.errors == []


async def test_b04_activity_live_and_logs_verify(stack, browser):  # noqa: F811
    s, b = stack, browser
    base = f"http://127.0.0.1:{s.ui.port}/"
    d = s.world.devices[PLUG_NWK]
    await b.go(base, "activity", 1.5)
    s.world.report(d, 0x0B04, 0x0505, 0x21, (2390).to_bytes(2, "little"))
    await asyncio.sleep(1.0)
    assert await b.js("document.body.textContent.includes('voltage')"), "live activity row appended"
    await b.go(base, "logs", 1.5)
    await b.click_text("Verify chain")
    await asyncio.sleep(0.8)
    assert await b.js("/intact|OK|valid/i.test(document.body.textContent)")
    assert b.errors == []


async def test_b05_settings_save_marks_restart_and_help_popover(stack, browser):  # noqa: F811
    s, b = stack, browser
    base = f"http://127.0.0.1:{s.ui.port}/"
    await b.go(base, "settings", 2.0)
    n = await b.js("document.querySelectorAll('.help').length")
    assert n >= 30, f"help icons present ({n})"
    await b.js("document.querySelector('.help').click()")
    await asyncio.sleep(0.3)
    assert await b.js("(()=>{const p=document.getElementById('helppop');return !!p && getComputedStyle(p).display!=='none' && p.textContent.length>20;})()")
    # change the join cooldown and save → restart banner
    changed = await b.js("""(()=>{const i=[...document.querySelectorAll('input[type=number]')].find(x=>x.value==='0'||x.value==='5');if(!i)return false;i.value='7';i.dispatchEvent(new Event('input',{bubbles:true}));i.dispatchEvent(new Event('change',{bubbles:true}));return true;})()""")
    assert changed
    await b.js("(()=>{const btn=[...document.querySelectorAll('button')].find(x=>x.textContent.trim()==='Save'&&!x.disabled);btn&&btn.click();})()")
    await asyncio.sleep(1.0)
    assert await b.js("/Restart required/i.test(document.body.textContent)")
    import yaml
    assert yaml.safe_load(s.cfg_path.read_text())["zigbee"]["permit_join_cooldown_seconds"] == 7
    assert b.errors == []


async def test_b06_phone_layout(stack, browser):  # noqa: F811
    s, b = stack, browser
    base = f"http://127.0.0.1:{s.ui.port}/"
    await b.size(390, 844)
    for page in ["dashboard", "pair", "settings", f"device/0x{PLUG_IEEE:016x}"]:
        await b.go(base, page, 1.2)
        assert await b.js("document.documentElement.scrollWidth <= window.innerWidth + 1"), f"{page}: overflow on phone"
    assert await b.js("getComputedStyle(document.querySelector('#tabs, nav.tabs, .tabs')).display !== 'none'")
    await b.size(1280, 900)
    assert b.errors == []


def _gw(s: Stack):
    from tests.test_e2e import _find_gateway
    return _find_gateway(s.ui)
