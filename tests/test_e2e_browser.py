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
        # Wait for the SPA to boot and render a heading before settling, instead
        # of trusting a fixed sleep: a cold first load (parse the ~170 KB script,
        # connect the SSE stream) can exceed `settle` under CI load, which made
        # this flaky on the first page. Every view renders an <h1>, so it is a
        # reliable readiness marker.
        for _ in range(100):  # up to ~10 s
            try:
                if await self.js("!!(document.querySelector('h1') && document.querySelector('h1').textContent)"):
                    break
            except RuntimeError:
                pass  # a navigation is still in flight; retry
            await asyncio.sleep(0.1)
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


async def test_b07_datapoints_tab_teaches_a_tuya_model(stack, browser):  # noqa: F811
    """A TS0601 nobody knows: raw datapoints show up in the Datapoints tab, mapping one through the row editor
    writes a definition, the state key changes and the Settings card lists the definition."""
    from tests.sim import SimDevice
    s, b = stack, browser
    base = f"http://127.0.0.1:{s.ui.port}/"
    ieee, nwk = 0x00158D00000000B7, 0x7B07
    if _gw(s).registry.get(ieee) is None:
        await api(s, "POST", "/api/permit_join", {"seconds": 30})
        d = s.world.add(SimDevice(ieee, nwk, "_TZE200_browserz", "TS0601", [0x0000, 0x0004, 0x0005, 0xEF00], [0x0019], 0x0051, router=False, power_source=3))
        s.world.announce(d)
        await wait_for(lambda: (lambda x: x and x.interviewed)(_gw(s).registry.get(ieee)), 8)
        await api(s, "POST", f"/api/devices/0x{ieee:016x}/rename", {"friendly_name": "Leak sensor"})
    # one report with an ambiguous layout (1 bool only) → raw dp_1, nothing inferred
    s.world.fake.emit_incoming(nwk, 0xEF00, bytes([0x09, 0x31, 0x02, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01]))
    await wait_for(lambda: json.loads(s.got.get(f"{BASE}/0x{ieee:016x}/state", b"{}")).get("dp_1") is True, 5)
    await b.go(base, f"device/0x{ieee:016x}", 2.0)
    await b.click_text("Datapoints")
    await asyncio.sleep(1.0)
    assert await b.js("[...document.querySelectorAll('.dptab tbody tr')].some(tr=>tr.textContent.includes('dp_1'))"), "raw datapoint listed"
    await b.click_text("Map…")
    await asyncio.sleep(0.3)
    await b.js("""(()=>{const ed=document.querySelector('.dpedit');const inp=ed.querySelector('input[type=text]');inp.value='water_leak';inp.dispatchEvent(new Event('input',{bubbles:true}));
      const sel=[...ed.querySelectorAll('select')][0];sel.value='binary';sel.dispatchEvent(new Event('change',{bubbles:true}));const dc=[...ed.querySelectorAll('input[type=text]')].find(i=>/^door/.test(i.placeholder));dc.value='moisture';})()""")
    await b.click_text("Save for this model")
    await wait_for(lambda: _gw(s).definitions.get("_TZE200_browserz", "TS0601") is not None, 5)
    defn = _gw(s).definitions.get("_TZE200_browserz", "TS0601")
    assert defn["datapoints"][0] == {"dp": 1, "key": "water_leak", "name": "Water leak", "type": "binary", "access": "r", "category": "sensor", "dtype": "bool", "device_class": "moisture"}
    await wait_for(lambda: json.loads(s.got.get(f"{BASE}/0x{ieee:016x}/state", b"{}")).get("water_leak") is True, 5)
    assert json.loads(s.got[f"homeassistant/binary_sensor/0x{ieee:016x}/water_leak/config"])["device_class"] == "moisture"
    await asyncio.sleep(1.0)
    assert await b.js("[...document.querySelectorAll('.dptab tbody tr')].some(tr=>tr.textContent.includes('water_leak')&&tr.textContent.includes('defined'))"), "mapping shown in the table"
    # the About tab shows the type override card; Settings lists the definition
    await b.click_text("About")
    await asyncio.sleep(0.8)
    assert await b.js("/Type & category/.test(document.body.textContent)")
    await b.go(base, "settings", 2.0)
    assert await b.js("[...document.querySelectorAll('table tbody tr')].some(tr=>tr.textContent.includes('_TZE200_browserz')&&tr.textContent.includes('TS0601'))"), "definition listed under Settings"
    assert b.errors == [], f"console errors: {b.errors}"


def _gw(s: Stack):
    from tests.test_e2e import _find_gateway
    return _find_gateway(s.ui)


async def test_b08_dashboard_cards_are_one_size_and_nothing_overlaps(stack, browser):  # noqa: F811
    """The dashboard is a grid of equal cards: same height whatever the device, every card's
    content inside its own box, and no label running under the control beside it."""
    from tests.sim import SimDevice
    s, b = stack, browser
    base = f"http://127.0.0.1:{s.ui.port}/"
    # two devices of different shape: a plug with power metering and a battery sensor
    for dev in (plug(PLUG_IEEE, PLUG_NWK),
                SimDevice(0x00158D00000000C8, 0x7C08, "LUMI", "lumi.weather",
                          [0x0000, 0x0001, 0x0402, 0x0405, 0x0403], [], 0x0302, router=False, power_source=3)):
        if _gw(s).registry.get(dev.ieee) is None:
            await api(s, "POST", "/api/permit_join", {"seconds": 30})
            s.world.announce(s.world.add(dev))
            await wait_for(lambda i=dev.ieee: (lambda x: x and x.interviewed)(_gw(s).registry.get(i)), 8)
    await b.go(base, "dashboard", 2.5)
    await asyncio.sleep(1.5)  # cards fill themselves from the exposes endpoint
    n = await b.js("document.querySelectorAll('.dcard').length")
    assert n >= 2, f"need a few devices to compare, saw {n}"
    sizes = await b.js("(()=>{const h=[...document.querySelectorAll('.dcard')].map(c=>c.offsetHeight);"
                       "return h.length+':'+[...new Set(h)].join(',');})()")
    assert len(sizes.split(":")[1].split(",")) == 1, f"cards differ in height: {sizes}"
    assert await b.js("[...document.querySelectorAll('.dbody')].every(x=>x.scrollHeight<=x.clientHeight+1)"), \
        "a card's content spills out of its box"
    overlap = await b.js("""(()=>{for(const r of document.querySelectorAll('.dcard .frow')){
        const fn=r.querySelector('.fn'),ctl=r.lastElementChild;
        if(!fn||!ctl||ctl===fn)continue;
        const a=fn.getBoundingClientRect(),c=ctl.getBoundingClientRect();
        if(a.right>c.left+1)return 'overlap: '+fn.textContent.trim();}
      return 'ok';})()""")
    assert overlap == "ok", overlap
    assert await b.js("document.documentElement.scrollWidth <= window.innerWidth"), "dashboard overflows sideways"
    assert b.errors == [], f"console errors: {b.errors}"


async def test_b09_dashboard_can_be_sorted(stack, browser):  # noqa: F811
    """The dashboard offers useful orders — by name, category, what is offline, weakest signal,
    lowest battery, highest power, most recently heard — and every one of them renders."""
    from tests.sim import SimDevice
    s, b = stack, browser
    base = f"http://127.0.0.1:{s.ui.port}/"
    for dev in (plug(PLUG_IEEE, PLUG_NWK),
                SimDevice(0x00158D00000000C9, 0x7C09, "LUMI", "lumi.weather",
                          [0x0000, 0x0001, 0x0402, 0x0405], [], 0x0302, router=False, power_source=3)):
        if _gw(s).registry.get(dev.ieee) is None:
            await api(s, "POST", "/api/permit_join", {"seconds": 30})
            s.world.announce(s.world.add(dev))
            await wait_for(lambda i=dev.ieee: (lambda x: x and x.interviewed)(_gw(s).registry.get(i)), 8)
    await b.go(base, "dashboard", 2.5)
    await asyncio.sleep(1.2)
    opts = await b.js("[...document.querySelectorAll('.bar select option')].map(o=>o.value).join(',')")
    for want in ("name", "category", "status", "lqi", "battery", "power", "seen"):
        assert want in opts, f"{want} missing from the sort options: {opts}"
    titles = await b.js("[...document.querySelectorAll('.dcard .dh a')].map(a=>a.textContent)")
    assert titles == sorted(titles, key=str.lower), f"default order is by name: {titles}"
    n = len(titles)
    for order in ("category", "status", "lqi", "battery", "power", "seen", "name"):
        await b.js(f"(()=>{{const s=document.querySelector('.bar select');s.value='{order}';"
                   "s.dispatchEvent(new Event('change',{bubbles:true}));return 1;})()")
        await asyncio.sleep(0.6)
        got = await b.js("document.querySelectorAll('.dcard').length")
        assert got == n, f"{order}: {got} cards instead of {n}"
    assert b.errors == [], f"console errors: {b.errors}"


async def test_b10_logs_can_be_narrowed_to_one_device(stack, browser):  # noqa: F811
    """The log page can answer 'what happened to THIS device' — a device picker that filters both
    tabs, with a tally of what its events were."""
    s, b = stack, browser
    base = f"http://127.0.0.1:{s.ui.port}/"
    if _gw(s).registry.get(PLUG_IEEE) is None:
        await api(s, "POST", "/api/permit_join", {"seconds": 30})
        s.world.announce(s.world.add(plug(PLUG_IEEE, PLUG_NWK)))
        await wait_for(lambda: (lambda x: x and x.interviewed)(_gw(s).registry.get(PLUG_IEEE)), 8)
    await b.go(base, "logs", 2.0)
    await asyncio.sleep(0.8)
    opts = await b.js("(()=>{const s=[...document.querySelectorAll('.bar select')]"
                      ".find(x=>x.title&&x.title.indexOf('one device')>=0);"
                      "return s?[...s.options].map(o=>o.textContent).join('|'):'none';})()")
    assert opts != "none", "no device picker on the log page"
    assert "All devices" in opts, opts
    ieee = f"0x{PLUG_IEEE:016x}"
    picked = await b.js("(()=>{const s=[...document.querySelectorAll('.bar select')]"
                        ".find(x=>x.title&&x.title.indexOf('one device')>=0);"
                        f"s.value='{ieee}';s.dispatchEvent(new Event('change',{{bubbles:true}}));"
                        "return s.value;})()")
    assert picked == ieee, picked
    await asyncio.sleep(0.6)
    # every visible audit row now concerns that device, and the tally names it
    ok = await b.js(f"[...document.querySelectorAll('.log .row')].every(r=>r.textContent.toLowerCase().includes('{ieee}')"
                    " || r.textContent.includes('Nothing to show') || r.querySelector('.devname')!==null)")
    assert ok, "rows for other devices survived the filter"
    assert await b.js("!!document.body.textContent.match(/device_joined|interview|nothing in the log/i)")
    assert b.errors == [], f"console errors: {b.errors}"


async def test_b11_dashboard_default_view_checkbox(stack, browser):  # noqa: F811
    """The Default checkbox makes the current sort (and category) the view the dashboard opens
    with — remembered in the browser, surviving a reload, and cleared by unchecking."""
    s, b = stack, browser
    base = f"http://127.0.0.1:{s.ui.port}/"
    await b.go(base, "dashboard", 2.0)

    # pick a non-default sort, tick the box
    await b.js("(()=>{const s=[...document.querySelectorAll('.bar select')]"
               ".find(x=>x.title==='Order the cards');s.value='lqi';"
               "s.dispatchEvent(new Event('change',{bubbles:true}));return s.value;})()")
    checked = await b.js("(()=>{const c=document.getElementById('dashdef');"
                         "c.checked=true;c.dispatchEvent(new Event('change',{bubbles:true}));"
                         "return c.checked;})()")
    assert checked is True
    stored = await b.js("localStorage.getItem('oneroof.dashboard.default')")
    assert '"sort":"lqi"' in (stored or ""), stored

    # a fresh visit opens with that sort, box already ticked
    await b.go(base, "logs", 1.0)
    await b.go(base, "dashboard", 1.5)
    assert await b.js("[...document.querySelectorAll('.bar select')]"
                      ".find(x=>x.title==='Order the cards').value") == "lqi"
    assert await b.js("document.getElementById('dashdef').checked") is True

    # changing the sort unticks the box (it no longer matches the saved default)…
    await b.js("(()=>{const s=[...document.querySelectorAll('.bar select')]"
               ".find(x=>x.title==='Order the cards');s.value='name';"
               "s.dispatchEvent(new Event('change',{bubbles:true}));})()")
    assert await b.js("document.getElementById('dashdef').checked") is False

    # …and unchecking clears the memory entirely
    await b.js("(()=>{const c=document.getElementById('dashdef');c.checked=true;"
               "c.dispatchEvent(new Event('change',{bubbles:true}));"
               "c.checked=false;c.dispatchEvent(new Event('change',{bubbles:true}));})()")
    assert await b.js("localStorage.getItem('oneroof.dashboard.default')") is None
    assert b.errors == [], f"console errors: {b.errors}"


async def test_b12_automatic_rotation_is_the_owners_switch_and_the_check_names_devices(stack, browser):  # noqa: F811
    """Settings carries a live 'Automatic key rotation' card (off by default, saved without a
    restart), Maintenance can 'Check first' and names who would hold a rotation up, and the
    log page shows device names where the gateway wrote addresses."""
    s, b = stack, browser
    base = f"http://127.0.0.1:{s.ui.port}/"
    if _gw(s).registry.get(PLUG_IEEE) is None:
        await api(s, "POST", "/api/permit_join", {"seconds": 30})
        s.world.announce(s.world.add(plug(PLUG_IEEE, PLUG_NWK)))
        await wait_for(lambda: (lambda x: x and x.interviewed)(_gw(s).registry.get(PLUG_IEEE)), 8)
    ieee = f"0x{PLUG_IEEE:016x}"
    await api(s, "POST", f"/api/devices/{ieee}/rename", {"friendly_name": "Kitchen kettle plug"})

    # the switch: off by default, saved live
    await b.go(base, "settings", 2.0)
    assert await b.js("/Automatic rotation is off/.test(document.body.textContent)")
    saved = await b.js("""(async()=>{const h=[...document.querySelectorAll('h2')].find(h=>h.textContent.startsWith('Automatic key rotation'));
      const card=h.nextElementSibling;const c=card.querySelector('input[type=checkbox]');c.checked=true;c.dispatchEvent(new Event('change',{bubbles:true}));
      const n=card.querySelector('input[type=number]');n.value='14';n.dispatchEvent(new Event('input',{bubbles:true}));
      [...card.querySelectorAll('button')].find(x=>x.textContent.trim()==='Save').click();await new Promise(r=>setTimeout(r,800));return card.textContent;})()""")
    assert "Automatic rotation is on" in saved and "every 14 days" in saved, saved
    st, body = await api(s, "GET", "/api/rotation_policy")
    assert st == 200 and body["policy"] == {"after_plain_join": True, "every_days": 14}
    # the policy is live: whatever b05 left in the restart banner, nothing about rotation joined it
    banner = await b.js("(()=>{const n=document.querySelector('.notice.restart');return n&&!n.classList.contains('hidden')?n.textContent:'';})()")
    assert "rotat" not in banner.lower(), banner
    st, body = await api(s, "POST", "/api/rotation_policy", {"after_plain_join": False, "every_days": 0})
    assert st == 200 and body["policy"] == {"after_plain_join": False, "every_days": 0}

    # a second router that has gone quiet: paired, named, then it stops answering address queries
    gone_ieee, gone_nwk = 0xA4C1380000000077, 0x7777
    if _gw(s).registry.get(gone_ieee) is None:
        await api(s, "POST", "/api/permit_join", {"seconds": 30})
        s.world.announce(s.world.add(plug(gone_ieee, gone_nwk)))
        await wait_for(lambda: (lambda x: x and x.interviewed)(_gw(s).registry.get(gone_ieee)), 8)
    gone = f"0x{gone_ieee:016x}"
    await api(s, "POST", f"/api/devices/{gone}/rename", {"friendly_name": "Hall lamp"})
    s.fake.nwk_to_ieee.pop(gone_nwk, None)

    # the check: names, not addresses; the quiet router is called out first
    await b.click_text("Check first")
    for _ in range(40):  # a router that never answers costs two address-query timeouts
        await asyncio.sleep(0.5)
        text = await b.js("document.getElementById('main').textContent")
        if "would hold a rotation up" in text:
            break
    # earlier tests may have left other devices in this stack; the quiet router is the only one not ready
    assert "would hold a rotation up" in text and "1 router does not answer" in text, text[-900:]
    rows = await b.js("[...document.querySelectorAll('.rc-list a.devname')].map(a=>a.title+'='+a.textContent)")
    assert rows[0] == f"{gone}=Hall lamp" and f"{ieee}=Kitchen kettle plug" in rows, rows
    assert gone not in text and ieee not in text

    # the log: an address inside a detail line reads as the device's name (the address stays on hover)
    await b.go(base, "logs", 2.0)
    # b10 may have left the page narrowed to one device — widen it again
    await b.js("(()=>{const s=[...document.querySelectorAll('.bar select')].find(x=>x.title&&x.title.indexOf('one device')>=0);"
               "if(s&&s.value){s.value='';s.dispatchEvent(new Event('change',{bubbles:true}));}})()")
    await asyncio.sleep(0.8)
    row = await b.js("(()=>{const r=[...document.querySelectorAll('.log .row')].find(r=>r.textContent.includes('key_rotation_checked'));"
                     "return r?{text:r.textContent,links:[...r.querySelectorAll('a.devname')].map(a=>a.title)}:null;})()")
    assert row and row["links"] == [gone] and "Hall lamp" in row["text"] and gone not in row["text"], row
    assert b.errors == [], f"console errors: {b.errors}"
