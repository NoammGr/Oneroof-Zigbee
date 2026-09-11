# Changelog

## [2.19.0] — 2026-09-11

### Added — battery forecast
Every battery reading is remembered (`battery_log` on the device). The device page says
"40 % · about 2 weeks left · replace by Sep 25" from a line through the last four months of
readings — honest about thin data (an early guess under two weeks of history, nothing under
five days), and "holding steady" when it is not falling. The Network health card lists
batteries at 15 % or under and any about two weeks from empty; the health line for Home
Assistant counts them ("2 batteries to replace"); Telegram says so once
(`battery_replace_soon`), and again after a fresh battery.

### Added — nightly backups
Settings → Backup & restore → **Nightly backups**: switch it on and set a password once
(kept in the add-on's private storage, never inside the backup). An encrypted backup lands in
the add-on config folder (`backups/nightly-….ozbk`) every night at about 3 am, and only the
newest ones are kept (default 14). **Back up now** makes one on the spot; each one in the list
downloads or restores in two clicks with the stored password. Audited as
`backup_schedule_changed`, `backup_made`, `backup_failed`, `backup_restored`.

### Added — scan the QR code
Pair → install-code form → **Scan the QR code**: photograph the sticker on the device or its
box and the address and install code fill in by themselves — in the Zigbee Alliance form
(`Z:…$I:…`), as labelled pairs, or as the two bare hex strings. The reader (jsQR 1.4.0,
Apache-2.0) is bundled and served by the gateway; nothing is loaded from anyone else's host.

### Added — the family on one Home Assistant card
`docs/homeassistant-family-card.yaml`: the four Health sensors and their reasons on one
Lovelace card.

## [2.18.0] — 2026-09-11

### Added — "Is my network healthy?"
A **Network health** card at the top of the Dashboard, from what the gateway already knows:
devices it cannot reach, devices that went offline and back four times or more in a day
(flapping), devices quiet for far longer than their kind should be (mains 6 h, battery 26 h),
and — after **Check now** walks the routers' neighbour tables — every device whose best hop
to a relay is weak (LQI under 80, "a router in between would give it a parent next door") and
any router carrying more than ten children. Every finding names the device and says why, in
one line, and links to its page.

### Added — who a device talks through, on its page
Under Last seen: **Talks through** — the relay it reaches best and the link's strength
(strong / fair / weak, with the LQI), judged from the last walk of the neighbour tables; a
weak hop says so and what would fix it; a device that flapped today says how many times.

### Added — one line of health for Home Assistant
The gateway publishes `oneroof/zigbee/health` every minute (ok / degraded, the reasons, version,
uptime, coordinator state, the counts) with MQTT discovery, so a **Health** sensor appears on
the OneRoof Zigbee bridge device by itself; every One Roof add-on publishes the same shape, so
one card shows the family. The sensor goes unavailable three minutes after the gateway stops.

### Added — release hygiene, tested
A test now fails when the two changelog copies differ, the three version strings disagree, or
the changelog does not lead with the version being shipped.

API: `GET api/health`, `POST api/health` (walks the tables first; audited as
`network_health_checked`); device JSON gains `parent` and `flaps_24h`.

## [2.17.1] — 2026-09-10

### Changed — the house map is withdrawn
Versions 2.15.0 to 2.17.0 turned the Map page into a 3D house (rooms from device names, Home
Assistant areas, a Location field on the device page). On a real network it did not describe
the house, so it is gone: the Map page is the network graph again, exactly as in 2.14.1, and
the device page has no Location. Nothing else from those versions remains. A `house.json`
left in the add-on config folder is unused and can be deleted.

### Fixed — a device file written by a newer version no longer stops the gateway
Coming back from 2.17.0, `devices.json` carries a field this version does not know. The
registry now keeps only the fields it knows instead of refusing the file, so the gateway
starts with all its devices.

## [2.14.1] — 2026-09-08

### Fixed — the air conditioner's temperature jumped back a degree a second after you set it
Pick 25 °C in Apple Home (or Home Assistant) and a second later it read 24; set it again and it
stayed. ZCL forbids an air conditioner's two setpoints being equal — they sit at least one
dead band (1 °C) apart — so the One Roof IR blaster carries the set temperature on the setpoint
of the mode in force and keeps the other one a degree behind: cooling 25, heating 24 while
cooling at 25. It reports the two in separate frames, and the gateway took whichever arrived
for "the" set temperature: the trailing 24 overwrote the 25. The second attempt only stuck
because it changed nothing on the device, so nothing was reported back. The gateway now takes
only the setpoint that belongs to the mode in force (heating in heat, cooling otherwise; when
the unit is off, the mode it was last in) and drops the partner.

### Changed
- Settings → Automatic key rotation: the hint under the switch says when a rotation is
  actually triggered — only after a pairing session you opened without an install code; a
  device that drops off and comes back on its own never counts.

## [2.14.0] — 2026-09-07

### Changed — automatic key rotation is your decision, and off by default
On a real network the automatic rotation after a plain pairing ran for four days without ever
finishing: three routers never answered on the current key, three battery sensors refused the
key every time they woke up, and each retry offered a security frame to the most fragile devices
again. Under Home Assistant there was no way to stop it short of editing the add-on options.

- **Settings → Automatic key rotation**: a live switch for *after a pairing without an install
  code* and a number for *also every N days* (0 = never). Applied at once, no restart, persisted
  in `rotation_policy.json`; switching a policy off cancels the rotation it started (the current
  key stays in force). Both are **off by default** now. The add-on option
  `rotate_key_after_plain_join` only seeds the first value; the two fields left the read-only
  Zigbee card. Reading the policy is open to every UI user, changing it needs a control user
  (`key_rotation_policy_changed` in the audit).
- **Check first** (Settings → Maintenance, next to *Rotate key over the air*): sends no key —
  asks every router to answer on the current key and judges each battery device by when it last
  spoke — and lists, by name, who would hold a rotation up and what to do about it
  (`api/rotate_network_key` with `mode: "check"`; audit `key_rotation_checked`).
- What the gateway can and cannot prove, said plainly in the help: "delivered" means the radio
  accepted the send; after the switch every router is verified on the new key; a battery device
  is handed the key the moment it next speaks and cannot be verified until it does.

### Fixed — a sleeping sensor whose key offer was refused was retried like a dead router
A battery device is reachable only in the seconds after it speaks. When the transport refused
the offer at that moment (`NWK_NO_ROUTE`), the device landed in the *failed* list as well as
the *pending* one and was knocked on every half hour for hours. It now stays *asleep* — offered
again the moment it next speaks, nothing in between.

### Changed — the log shows device names
Every device address in a log line (audit and application log) is shown as the device's name;
the address stays on hover, and the name opens the device page. A list of who is missing from
a rotation now reads as rooms, not hex.

## [2.13.1] — 2026-09-07

### Fixed — a plug that reports but never answers flapped offline/online all night
Seen on a real network the first night on 2.13.0: a smart plug in the garage whose power reports
kept arriving while every read the gateway sent it timed out (its route to us worked, ours to it
did not). The 2.13.0 poll called it offline after two unanswered reads, its next power report a
few seconds later cleared the miss count *and* the five-minute backoff and marked it online, the
next poll a minute later failed again — offline, online, offline, every one to three minutes,
all night. Every consumer (One Roof Bridge, Home Assistant) asked for its state on each
"back online", so each flip cost the whole network another timed-out read as well.

- A device that fails its polls but **has been heard since the first miss** is alive, just not
  answering: it stays online with the state it last reported and is asked again after 5, then
  10, 15, 30 minutes — not every minute. It is written up once in the log ("reports but does not
  answer reads — check its link quality and route") and in the audit
  (`device_not_answering_reads`).
- A device that fails its polls **and has not been heard since the first miss** is gone, as
  before: offline after two misses, then tried on the same growing backoff.
- A report no longer clears the backoff. Only an answered read, or the device coming back after
  being offline, resets the bookkeeping.
- A device that comes back online after being offline is now asked what it *is* straight away
  (`_schedule_refresh`), not on the next poll — a bulb cut from power comes back in whatever
  state its firmware chose.

## [2.13.0] — 2026-09-06

### Fixed — a light that shows ON while it is dark: every way a stale state could survive
An end-to-end check of the path from a device to Apple Home / Home Assistant found several ways
the gateway could keep saying what a device *was* rather than what it *is*. All closed:

- **A refused bind was recorded as reporting "ok".** The bind is what makes a device report a
  physical press; a device that refused it (a full binding table, an endpoint that does not bind)
  was written up as reporting fine, never reported anything, and showed the state of its last
  command for ever. The ZDO status is now checked: a refusal is recorded as `bind failed (0x..)`,
  the device is polled every minute like any device that cannot report, and the setup is retried.
- **A reporting setup that failed was never retried.** A device that fell asleep or dropped a frame
  during its interview kept its old state until somebody restarted the gateway. It is now tried
  again the next time the device talks (the one moment a battery device listens), backing off ten
  minutes between attempts. A firmware refusal (unreportable attribute) is final and not retried.
- **The silent-device poll went by "heard from", not by "said what it is".** A plug reporting its
  power every ten seconds was never asked about its button; a two-gang switch was asked about one
  gang; the answer skipped the model's translation, so a second gang could overwrite the first.
  The poll now goes by the last on/off, level, cover, thermostat, colour or Tuya evidence, asks
  every endpoint, and translates the answers. A mains device that fails two polls in a row is now
  marked **offline** (Apple Home shows "No Response", Home Assistant "unavailable") instead of
  showing the last thing it said — a bulb switched off at the wall used to look ON for up to four
  hours. It is tried every five minutes and is back the moment it is heard.
- **A rejoin was not followed by a question.** A device coming back from a power cut is not
  re-interviewed (that storm is over) — but a bulb comes back ON at the wall while the gateway
  remembered it OFF. It is now asked what it is a few seconds after it rejoins.
- **Losing the coordinator said nothing.** While the serial link was gone every device kept its
  last state. `bridge/state` now goes offline for the outage (everything downstream marks its
  devices unavailable) and every device is asked again when the link is back. On an **external
  broker** the gateway now leaves a last will, so a crash is announced by the broker itself.
- **`{"state": "OFF", "brightness": N}` switched the light back on.** Home Assistant sends the
  level it will come back at with the off order; the level command followed the off command and
  the light was on again at that level — with the panel, HA and Apple Home all agreeing it was on.
  OFF is now the order. `TOGGLE` (only the device knows which way it went) and any command that
  failed part-way are followed by a read instead of a guess.
- **A report from an endpoint the descriptors did not list** (Aqara's shared 0xF2) was written to
  the plain `state` key. On a single switch that is fine and now maps to its one switch; on a
  multi-gang device nobody knows which gang spoke and the value was shown as the whole device's —
  it is dropped.
- **The registry file lagged behind.** State and online/offline changes only reached
  `devices.json` when something else happened to save it, so a restart published a state from
  hours earlier before it could ask anyone. Changes now mark the registry dirty; the monitor tick
  and a clean stop write it.

### Fixed — Home Assistant discovery
- A **second dimmer channel** (`state_l2` / `brightness_l2`) was announced as a JSON-schema light,
  which only knows `state` and `brightness`: it showed the first channel's state and switched the
  first channel. It is now a template light that names its own keys.
- A **cover** was given the shared state payload as its state topic; the payload is not
  `open`/`closed`, so the cover sat on "unknown". It now goes by its position (or assumes state
  where only the commands are known).
- `<name>/get` with `{"state": ""}` now reads every switching endpoint, not just the first.

## [2.12.0] — 2026-09-05

### Changed — a new device reaches Home Assistant with its real name, not its address
- Home Assistant builds an entity id from the **first** name it hears for a device and keeps it for
  good — so a contact sensor paired before it was named lived on as
  `binary_sensor.0x00158d00000000d3_contact` even after it became "Back door" everywhere else. A
  device that pairs while still called by its address is now kept out of Home Assistant until you
  name it in the panel; the moment you do, it appears there as `binary_sensor.back_door_contact`.
  Its state, link quality and the panel itself are not held back — only the Home Assistant
  announcement. Its device page shows **name it to add to Home Assistant** while it waits.
- Nothing is hidden for good: a device nobody names goes to Home Assistant under its address after
  10 minutes, with an audit note, exactly as before. Devices Home Assistant already knows — a
  re-pair, a rejoin after a power cut, an imported network — are not held; their entities stay put.
- The tests now pin the whole path: the entity id proposed to Home Assistant follows the panel name,
  a rename re-announces under the new name with the same unique id and topics, and a fresh join
  waits for its name.

## [2.11.1] — 2026-09-05

### Added — the One Roof router is recognised as ours
- A stick running the **One Roof router firmware** (the range extender built from the coordinator
  repo) now shows up as **One Roof Router** by One Roof, with a description of what it does, instead
  of "Unknown device" with a blank identity. Its About panel fills in the model, build, date code and
  ZCL / app / stack versions the firmware reports.
- **Transmit power** control on the router (−20 … 20 dBm, 9 by default, up to 20 with the stick's
  amplifier) — the same Basic-cluster attribute the firmware persists across power cycles. It is read
  once at interview so the panel shows the real value, and appears in Home Assistant as a number
  entity. Identify blinks the router's green LED for the time you ask.
- No on/off, brightness or colour controls are offered for it — a relay has nothing to switch.

### Fixed — a relay's link quality no longer reads "—" for a quarter hour after a restart
- The restart refresh asks devices about their switch, light, cover and thermostat state — a pure
  relay has none of those, so it was asked nothing yet marked "seen", which also pushed the
  silent-router poll out 15 minutes. It is now asked for what the model table knows about it
  (the router's transmit power) or, failing that, its name, so link quality and last-seen are real
  from the first minute; a device that answers nothing is no longer stamped as seen.

## [2.11.0] — 2026-09-04

### Changed — the same worry reaches your phone once, not hourly
- Recurring per-device notifications (a device going silent, an anomaly repeating) are now sent
  **at most once per 6 hours per device and kind**. A wall-switched bulb that "goes silent" every
  evening, or a marginal plug that drops hourly, told you nothing new after the first message —
  and trained you to ignore the channel that also carries real alerts. The audit still records
  every single event; only the phone is spared the repeats. A different device, or a different
  kind of problem on the same device, is always its own message.

## [2.10.2] — 2026-09-04

### Fixed
- **A bystander rejoin during someone else's pairing window no longer schedules a rotation.**
  Re-pairing one device opens a window; a wall-switched bulb that happens to power up in those
  seconds rejoins securely with the key it already holds — the trust centre delivers it nothing,
  so there is nothing to retire. Only a rejoin the trust centre actually re-keyed during a window
  is treated as a through-the-window pairing. Genuinely new or factory-reset devices joining
  through a window rotate exactly as before.

## [2.10.1] — 2026-09-04

### Fixed — rotations stop being scheduled after every Aqara reboot
- A TC-rekeyed rejoin is no longer flagged as key exposure. This coordinator **mandates
  trust-centre key exchange**, so every device holds a unique verified link key and a rejoin's
  key re-delivery travels under it — never under the public key. Flagging it scheduled a full
  rotation after every reboot of an Aqara device (they habitually TC-rejoin at boot), each one
  then waiting for days on wall-switched bulbs, for no security gain. Real exposure — a pairing
  window without an install code — still rotates exactly as before. And either way: a pending
  rotation never needs lights turned on for it; a bulb takes the key within a second of being
  used naturally, and the network runs safely on the current key until then.

## [2.10.0] — 2026-09-04

### Fixed — a restart pauses a key rotation instead of cancelling it
- An add-on restart tears every task down with the same signal a user cancel uses, and the
  rotation treated them identically: every update quietly **cancelled** a running rotation and
  wiped its saved progress — observed live, twice in one evening, at exactly the update times.
  A restart now pauses instead: progress is persisted, the audit says
  ``network_key_rotation_paused (restart — resumes on next start)``, and the next start resumes
  where it left off, exactly as the pending record was always meant to work. A user's cancel
  still cancels, keeps the current key, and clears the record.

## [2.9.1] — 2026-09-03

### Changed
- **A running key rotation shows itself on the Coordinator page** — the top-bar badge points
  there, so that is where the answer now is: the phase, who is holding it up (**by device name**,
  with the reason — "not reachable", "gets the key when it wakes"), and a reminder that nothing
  switches until everyone has the key. Cancel and rollback stay under Settings → Maintenance.

## [2.9.0] — 2026-09-03

### Fixed — a rejoining device is left in peace
- Every rejoin used to restart the full interview. An interview is a burst of dozens of reads,
  binds and reporting writes; on a marginal no-neutral device that burst is real load — it reboots
  under it, a reboot rejoins, announces arrive in pairs, and every announce cancelled the running
  interview and started the next: a self-sustaining rejoin-and-interview storm, observed live at
  one cycle every eight seconds, with the device's indicator LED blinking through all of it.
- Now: a **rejoin outside a pairing window** (a device merely coming back — power cut, parent
  change, a wobble) is not interviewed at all; a **join through a window** (a factory-reset
  re-pair — the window is what marks it) is interviewed exactly as before; a rejoining device that
  was never interviewed is still completed; and **only one interview runs per device** — a second
  announce no longer cancels and restarts the first.

## [2.8.1] — 2026-09-03

### Fixed
- The Aqara ``mode = 1`` write (2.7.0) was gated on the device *declaring* the private cluster in
  its endpoint list — but Xiaomi devices answer on it without declaring it (the real
  lumi.switch.b2lc04 interviews as plain on/off endpoints), so the write was silently skipped for
  exactly the devices that need it. It now goes to endpoint 1 unconditionally for lumi devices,
  as zigbee2mqtt does. Whether it happened is visible: ``lumi_zigbee_mode_set`` in the audit.

## [2.8.0] — 2026-09-03

### Fixed — "hub, are you there?" is finally answered
- Devices with the Poll Control cluster send a **check-in** on a timer, and the spec's answer is a
  Check-in Response — zigbee2mqtt's stack sends it automatically. Ours answered with a generic
  default response instead of the real one. A device whose check-ins go unanswered concludes the
  hub is gone; some (Aqara) say so on their indicator LED while still obeying every command. The
  proper response (no fast polling) is now sent; the first one per device is logged.

### Added — the wire log shows both directions
- With ``log_level: debug``, outgoing frames are logged too (`-> <address> ep<n> cluster … len=…`),
  so a device's whole conversation — its questions and our answers — is visible in one filtered
  view when debugging.

## [2.7.0] — 2026-09-02

### Fixed — Aqara devices are told they live on a Zigbee hub
- zigbee2mqtt writes ``mode = 1`` to Aqara's private cluster (0xFCC0, manufacturer 0x115F) every
  time it configures a lumi device. Without that write, some models keep waiting for the
  proprietary Mi Home presence protocol, decide no hub is there, and **blink their indicator
  red/blue** — while still obeying every command. The gateway now performs the same write at every
  interview (so a factory-reset or re-paired device gets it again), audited as
  ``lumi_zigbee_mode_set``. A model that refuses the write is left in peace — the refusal is
  logged, nothing fails.

## [2.6.1] — 2026-09-02

- Re-release of 2.6.0. Several builds were published under the 2.6.0 number while it was being
  finished; anyone who installed one of them would never be offered the final build, because the
  Supervisor compares version strings. No changes beyond the version.

## [2.6.0] — 2026-09-02

### Changed
- **The dashboard can remember your view.** A *Default* checkbox next to the sort makes the
  current sort and category filter the view the dashboard opens with, remembered in this browser.
  Change the sort and the tick clears (it no longer matches the saved default); untick to forget.
- **Network map lines are easier to see.** Every link now earns a clearly visible line — quality
  still shows as thickness and depth of colour, but a weak link no longer fades to nothing.
  Hovering a device pulls its own links forward in ink while the rest step back.
- The Danger zone's helper button now fills in **stock routing** (the values the standard
  zigbee2mqtt firmware uses) instead of recommending a quieter mesh. The route-request flood every
  60 s turned out to be stock behaviour, not a One Roof quirk — and it is what keeps far devices
  reachable, so recommending against it was wrong.

### Fixed — a device that misses a key change can come home again
- A device that comes back without a valid network key — powered off at the wall across a key
  rotation, or an Aqara that decided the hub was lost and left — recovers through an unsecured
  trust-centre rejoin. The gateway explicitly **refused** those (the Z-Stack default, applied at
  every boot as part of runtime hardening), which orphaned the device for good: it could only
  return while a pairing window happened to be open, which is why "re-pairing" seemed to be the
  only cure. The stock zigbee2mqtt firmware allows these rejoins; ours now does too.
- The security cost is handled the way it already is at pairing time: a rejoin the trust centre
  took part in means the key was re-delivered, possibly under the public key — so it is flagged
  with the same plain-join exposure, and the existing debounced rotation retires that key minutes
  later. A secure rejoin (no trust-centre involvement) is recognised and triggers nothing. The
  audit's `device_rejoined` event now says `rekeyed_by_tc` so the log shows which kind happened.

## [2.5.0] — 2026-09-02

### Fixed — a device that refuses a setting no longer looks like one that accepted it
- Writing an attribute ignored the device's answer. A Write Attributes Response carries a status
  per attribute, and a refusal was treated exactly like a success: the new value was published as
  though it had taken, so the app showed the temperature you asked for while the device carried on
  as before. The answer is now read, and a refused write fails instead of lying.
- **An air conditioner's temperature now falls back to the other setpoint attribute.** One set
  temperature is two attributes in the ZCL (occupied heating 0x0012 and occupied cooling 0x0011),
  and a device may implement only one. When the one that matches the mode is refused, the other is
  written with the same value — which is why mode, fan and louver could all work while the
  temperature alone did nothing.
- **A device's report gets the receipt it asked for.** Xiaomi and Aqara devices send their state
  reports and heartbeats with the ZCL default response *requested*, and judge the hub by whether it
  arrives: a hub that stays silent is marked lost on the device's indicator LED (the red/blue
  blink) even while every command still works. Reports that request a response now get one; a
  report that asks for silence still gets silence.
- **A state refresh is answered in both topic layouts.** Consumers ask for fresh values on
  `<base>/<ieee>/get` at startup and when a device returns from an outage; the gateway only
  listened for it in the legacy layout, so every such refresh went silently unanswered.
- **A command that failed says so in the log.** The audit recorded that a command arrived; if
  carrying it out then failed, nothing said so and the log read as though the device had done it.
  There is now a `command_failed` entry with the reason, findable with the device filter.

## [2.4.1] — 2026-09-01

### Fixed
- Answering a device's question logged the device by an attribute that does not exist, so every
  answer ended with `AttributeError: 'Device' object has no attribute 'name'` in the log. The
  answer itself was already on the air by then — devices were being answered correctly — but the
  gateway logged a traceback each time. The whole answer now runs inside its own guard, and the
  test follows it to the last line instead of stopping at the frame.

## [2.4.0] — 2026-09-01

### Changed — an air conditioner's louver belongs to the air conditioner
- The louver is a separate on/off endpoint on the wire, and it was published to Home Assistant as
  its own switch entity. Home Assistant models it as the climate entity's **swing mode**, and
  everything downstream looks for it there — the Apple Home bridge included, which is why an AC
  bridged through Home Assistant had no oscillation control at all.
- The louver is now the climate entity's swing mode (`swing_modes: ON/OFF`), and no longer appears
  a second time as a stray toggle. A switch endpoint on a device without a setpoint is untouched:
  a two-gang switch still has both its toggles.

## [2.3.0] — 2026-09-01

### Fixed — the gateway now answers when a device asks it something
- A device can ask the coordinator questions of its own, and until now a whole class of them fell
  on the floor. **Xiaomi and Aqara devices read the time off the gateway** after every rejoin and
  keep asking until they get it; ours never replied. A device that gets no answer retries, and
  some of them treat the silence as "the network is not there" — the indicator light says so.
- The gateway now answers a **Read Attributes** from a device: the real value where it has one
  (Time, TimeStatus, TimeZone, LocalTime; and its own Basic cluster — name, model, ZCL version,
  power source), and an explicit *unsupported attribute* where it has none. An explicit "no" ends
  the retries; silence does not.
- Any other global command it does not implement now gets the spec's **Default Response
  (unsupported general command)** instead of nothing at all — unless the device asked for silence
  with disable-default-response, which is still honoured exactly.
- The first answer to each device and cluster is logged, so the Logs page (filtered to one device)
  shows what a device has been asking for.

## [2.2.1] — 2026-09-01

### Added — the log can answer "what happened to this device?"
- A **device picker** on the Logs page filters both tabs to one device: audit events that name it,
  and application lines that mention its address or its name. It works together with the search
  box, the level filter and the security filter, and the export button exports what you can see.
- With a device chosen, a line above the log tallies its events — `device_rejoined ×7 ·
  interview_done ×1` — so a question like "is this device really losing the network, and how
  often?" is answered by looking, instead of by scrolling.
- The number of matching lines is shown next to the export button.

## [2.2.0] — 2026-09-01

### Added — Coordinator → Danger zone: how the radio routes, without re-flashing
- The firmware reads its routing and broadcast behaviour from NV at every boot, so those settings
  can be changed on a running installation. The Coordinator page now exposes them: whether the
  coordinator acts as a concentrator and **how often it floods the network with route requests**
  (the firmware default is never; a flood every minute fills the air and can starve battery and
  no-neutral devices), the route-discovery and expiry times, and the broadcast parameters. Each
  shows what the radio is set to right now.
- Applying them restarts the radio for a few seconds and **touches nothing else**: no key item, no
  PAN, no channel, no startup option — the network and every paired device are exactly as they
  were, and the result is verified against the keystore before it is reported as applied. A test
  asserts that no key, PAN, channel or startup NV item is written by a routing change.
- The chosen settings are re-applied at every start, because a re-formation resets the radio to
  the firmware's compiled-in defaults.
- Table sizes (neighbours, routes, device list) are deliberately **not** offered: those are
  compiled into the firmware and genuinely need a new image.

## [2.1.2] — 2026-09-01

### Security — a client app can no longer invent a device's state
- The `client` role could publish anywhere, including a device's own state topic. A compromised or
  careless client could therefore announce "smoke: false" or "contact: closed" and every consumer —
  Home Assistant, Apple Home, automations — would believe it. `client` now carries the same
  boundary the Home Assistant role always had: read everything, send commands through `/set`,
  never publish device state, never open the network.

## [2.1.1] — 2026-09-01

### Fixed — restarting this add-on no longer restarts the rest of the house
- The add-on withdrew its MQTT service registration from the Supervisor on **every** exit. The
  Supervisor restarts every add-on that consumes a service when its provider disappears, so each
  restart of this gateway also restarted the HomeKit bridge — and while the bridge flaps, Apple
  Home shows *every* accessory as "No Response". If this gateway restarts in a loop, the whole
  house appears broken.
- The registration now stays in place and is simply refreshed on the next start. It is withdrawn
  only when this add-on genuinely stops being the broker (an external broker is configured).

## [2.1.0] — 2026-09-01

### Added — the dashboard can be ordered
- A **Sort** control next to the category filter: by name, by category, **offline first** (what is
  wrong rises to the top), **weakest signal first**, **lowest battery first**, **highest power
  first** and **heard most recently**. It works together with the search box and the category
  chips, and a browser test renders every order.

## [2.0.0] — 2026-08-31

A network that survives its own repair. Everything below came out of one long weekend of running
this gateway on a real home: a key rotation that lost the house, a coordinator that had to be
carried to a bench, and every failure it exposed on the way back.

### Added
- **Network health & recovery tools** in Maintenance: scan the air (beacons answer whatever key
  anyone holds; the network state is parked for the seconds of the scan so the firmware actually
  reports them) and every roll-back — to the previous key on the radio or in the keystore, to the
  key inside an encrypted backup, or to the key of a previous setup's files, read in place.
- **State is fetched, not remembered.** A few seconds after every start the gateway asks each
  device that can answer what it actually is — on or off, how bright, which setpoint and mode,
  where a cover sits — and publishes that. Devices that answer are marked online at once.
- Starting **without the dongle** no longer crash-loops the add-on: the broker, the panel and the
  registry come up, the banner says the coordinator is offline, and the port is retried for ever.

### Fixed — the network
- A device that announces a **leave with rejoin** — routine Zigbee life — was deleted and then
  evicted as an intruder when it came back, leaving it searching for a network for ever. A leave
  now marks a device offline and keeps everything; forgetting one is the user's decision.
- A **stalled rotation** re-offered the key to unreachable devices every thirty seconds for hours;
  the gap now grows per device, so a fragile device is never flooded with security frames.
- A key restored onto the stick **from outside** is no longer wiped by a start-up re-formation,
  and a fresh formation is never claimed on an identity the radio refused.
- Two different keys sharing one **sequence number** are detected and repaired by re-labelling.
- Firmware that refuses attribute reporting is retried with a one-second minimum and, if it still
  refuses, polled often enough that a switch pressed by hand still reaches the app. A thermostat
  is polled on its thermostat cluster, not on on/off, which says nothing about temperature.
- Every **join re-runs the interview**: a device that rejoins was factory-reset, and its
  reporting, bindings and alarm enrolment died with its old life.

### Fixed — what you see
- **Availability is evidence, not memory**: a green badge survives a restart only for a device
  heard within the hour (mains) or the day (battery); everything else starts offline and turns
  green the moment it is heard.
- The **dashboard** is a grid of equal cards showing what a device is for, at most five rows, with
  the settings on the device page where they belong — measured by a browser test: one height for
  every card, nothing spilling out, no label under the control beside it.
- The offline banner keeps to a slim strip instead of claiming the page; the map's link table
  drops duplicates and explains what a row means.

### Fixed — what other apps see
- An air conditioner's single setpoint is published under the **standard property name** every
  consumer understands, with its whole-degree step and range, instead of a name we invented that
  left Apple Home with no temperature control at all. The old name is still accepted on `/set`.
- Multi-gang commands from an older description (`state_left` where the device now says
  `state_l1`) are routed by gang position instead of dropped without a trace, and colour commands
  in the usual dialect are understood.
- A device whose description cannot be built keeps an empty definition instead of vanishing from
  downstream apps, and device names may no longer contain the characters that break MQTT topics.

### Security
- The radio's **network information base** never reaches a log: it carries key-descriptor fields
  on some stack generations, and the air scan moves it through NV.

## [1.10.16] — 2026-08-31

### Fixed — the offline banner and the network map
- The "coordinator offline" banner claimed the page's stretchy grid row and filled the whole
  screen with colour; it is now a slim strip and the content keeps its place.
- The network map breathes: a taller canvas, spacing that adapts to how many devices there are,
  labels that keep out of each other's way (the coordinator and routers win; hover always shows
  the full card), a halo behind every label so lines never make text unreadable, and nothing is
  clipped at the edges any more.

## [1.10.15] — 2026-08-31

### Fixed — a fresh formation is never claimed on an identity the radio refused
- Some firmware ignores the configured PAN and channel when forming and picks its own; the gateway
  then announced the keystore's identity while the radio ran another, and every start raised
  `network_parameters_mismatch`. A fresh network's identity is arbitrary — the keys are ours and
  verified either way — so the gateway now reads back what actually formed and adopts it
  (audit: `network_identity_adopted`). Found on the bench while validating the One Roof
  coordinator firmware with a joining ESP32-C6 router.

## [1.10.14] — 2026-08-31

### Added — the key rotates on a schedule, not only after joins
- New Settings → Zigbee option **"Rotate the key every (days)"** (default 30; 0 = only after
  joins or by hand). An old key is a standing target; now it expires by itself. The scheduled
  rotation runs through the same evidence engine as every other one — delivered to each device
  under its own link key, switched only on proof, auto-rollback — and waits politely: never while
  a pairing session is open, never while another rotation runs. The clock starts when a network is
  formed or first seen and resets whenever a rotation completes.

## [1.10.13] — 2026-08-31

### Fixed — re-pairing a whole home is safe around the automatic rotation
- The rotation that follows plain joins now fires **once per pairing session**: every plain join
  re-arms a quiet-period timer (2 minutes) and the rotation starts only after the last join —
  never one rotation per device.
- A device that joins (or is adopted) **while a rotation is running** is folded into it — it
  receives the new key, and during the switching phase the switch order too, before anyone moves.
  A freshly paired device can never be left behind on the old key. Audit:
  `rotation_adopted_new_device`.

## [1.10.12] — 2026-08-31

### Fixed — Scan the air reported an empty sky
- The firmware performs a scan but reports no beacons while its stored network state (NIB) is
  present, so the paused scan always came back empty. The scan now takes the NIB out for the few
  seconds of the scan and puts it back — the same dance zigpy-znp's proven scan tool does.

### Added — re-label the key after an interrupted rotation
- An interrupted rotation plus rollbacks can leave two *different* keys both labelled sequence 0
  on the radio, while the devices that switched know the current key as sequence 1 — the sequence
  byte decides which key a receiver tries, so every frame is dropped: right key, wrong label,
  silent network. When the recovery panel sees that collision it now offers **Re-label the key as
  sequence N**: the same key is written again under the next number, the old key stays as the
  alternate, the counter never moves backwards, nothing is re-paired.

## [1.10.11] — 2026-08-31

### Fixed — a key restored onto the stick from outside is never wiped by a re-formation
- Tools like zigpy-znp write the live network onto the radio but not the legacy config NV items
  the start-up check compared. The start then judged "wrong network" and re-formed — cutting every
  device off a perfectly restored network. Now, when the radio reports it is on a network, the
  start brings it up and judges by the *live* network: matching PAN and channel mean the config
  items are repaired in place (audit: `network_config_repaired`) and the key question goes to the
  normal evidence rules; re-forming happens only when the live network truly disagrees or the
  radio is not on a network at all.

## [1.10.10] — 2026-08-30

### Changed — one tidy panel for the recovery tools
- Scan the air and every roll-back option now live in a single collapsed
  "Network health & recovery tools" panel under Maintenance, each with one short caption — no more
  loose buttons and run-on text. The panel opens itself when the coordinator is on the wrong key.

### Removed — the "Advance frame counter" button
- Every code path keeps the counter safe by itself since 1.10.7 (live value read before each stack
  stop, refreshed every few minutes), so the manual override earned no place in the panel.

### Fixed — a rolled-back or externally restored key survives the next start
- When the radio sits on the keystore's *previous* network key and no rotation is pending, the
  start now adopts the radio's key (audit: `keystore_followed_radio`) instead of "finishing" the
  switch by pushing the newer keystore key back — a key that never reached a single device. A
  rollback done twice, or a key restored onto the stick from a backup outside the add-on, stays
  restored. Finishing forward still happens when a rotation really is in flight
  (`pending_rotation` is set, as every rotation since 1.10.3 records).

## [1.10.9] — 2026-08-30

### Fixed — Scan the air on firmware that refuses to scan while the network is up
- The firmware in the field answers an active scan with "invalid request" (status 194 / 0xC2)
  while the network runs. The scan now falls back to a short automatic stack pause: pause, scan,
  restart — by itself, with the outgoing frame counter read before the pause and re-verified
  after, so the counter can never go backwards. The log shows `air_scan mode=paused`.

## [1.10.8] — 2026-08-30

### Added — Scan the air
- Maintenance gains **Scan the air**: a beacon survey listing every Zigbee network in radio range
  — channel, PAN, whether it is this network, how many devices answered and the strongest signal.
  Beacons are unencrypted, so the network's routers answer whatever key anyone is on: one press
  tells apart "the routers are alive but we disagree on the key or the frame counter" from "the
  routers are not transmitting at all" (powered off, factory-reset back to pairing mode, or out of
  range) — without touching any key.

## [1.10.7] — 2026-08-30

### Fixed — a key repair could set the coordinator's frame counter back
- Every stack restart that rewrites the key items (finish, roll back, the start-up repair) also
  wrote the outgoing NWK frame counter from the keystore's *saved* value plus a margin — a value
  from the import or the last backup. A radio that had since sent more frames than that went
  **backwards**, and devices drop every frame at or below the last counter they saw as a replay:
  the right key, and still nothing works. The live counter is now read before the stop and the
  higher value is written; the keystore's copy is refreshed every five minutes.
- After such a restart the neighbour check runs again 45 s later, so the log shows a truthful
  "hears N routers" line instead of one taken seconds after the radio came up.
- Maintenance gains **Advance frame counter** (pushes the counter one million ahead; harmless) for a
  network that already went through such a repair, and the "roll back to a key from a backup or the
  previous setup" options are always reachable — handing in the key the radio is already on is a no-op,
  never a flip to something else.

## [1.10.6] — 2026-08-30

### Added — roll back to the key the previous setup ran with
- A network adopted from Zigbee2MQTT that has had exactly one (failed) rotation is still on the
  key in the old `configuration.yaml` / `coordinator_backup.json`. Maintenance now offers, next
  to the backup form, **Roll back to the key of** *&lt;folder&gt;* for every previous setup found
  on this Home Assistant: the key (and its sequence number, from `coordinator_backup.json`) is
  read in place and the coordinator returns to it — nothing else is imported, no names, layout or
  broker settings change, nothing is re-paired. The setup must be the same network (PAN id).

## [1.10.5] — 2026-08-30

### Added — roll back with a backup, and say where a previous key would come from
- Maintenance now states the key situation plainly: whether the coordinator's key matches the
  keystore, and where a previous key is available — in the keystore, in the radio's alternate
  slot, or none known.
- **Roll back from a backup.** When neither the keystore nor the radio knows the previous key (a
  rotation made by a version before 1.10.1 on firmware that does not keep the old key in its
  alternate slot), the `.ozbk` backup taken before the rotation can be handed in with its
  password: the keystore inside it is decrypted in memory, checked to be the same network, and
  the coordinator returns to that key under the backup's sequence. Nothing is restored or written
  from the backup; nothing is re-paired.
- The rollback audit record says which source was used (`auto` / `backup`).

## [1.10.4] — 2026-08-30

### Fixed
- Maintenance did not show **Roll back to the previous key** when no rotation was in progress —
  the very moment it is needed (the radio switched, the devices did not, the rotation record is
  long gone). The status renderer returned early in the idle state before reaching the notice.

## [1.10.3] — 2026-08-30

### Fixed — the switch itself: devices did not follow a broadcast switch order
- **Diagnosis corrected.** The 1.10.1 log on the real network read "active network key on the
  coordinator matches the keystore: yes … coordinator hears 0 neighbours — nothing decrypts": the
  radio *had* switched at the broadcast (its NV item merely lagged when the rotation checked it);
  it was the **devices** that never switched. A broadcast switch order never reaches a sleeping
  device and was ignored by the rest.
- **Switching is now per device, leaves first.** Every device that received the key is told to
  switch by **unicast** — sleeping devices the moment each is heard (so a broadcast is no longer
  relied on), then the routers, then the coordinator itself. Firmware that switches the
  coordinator on the first unicast order is noticed (active sequence jumped) and the current key
  is restored until every device has been told.
- **Automatic rollback.** After the switch every router that was given the key must answer an
  address query on it. If none does, the devices did not switch: the coordinator returns to the
  previous key by itself, nothing is lost, and the rotation ends `rolled_back`
  (`network_key_rotation_rolled_back`) instead of pretending.
- **Roll back** on Maintenance now means the same thing: the coordinator goes back to the key the
  devices use — from the keystore's previous key, or from the radio's own alternate key slot when
  the keystore predates 1.10.1 (no backup needed). If the keystore had moved ahead of a radio that
  never switched, it simply follows the radio. Nothing is broadcast.
- **The start never guesses a sequence.** A keystore key that is not the radio's is installed
  only with evidence: it is the radio's alternate key (a restored backup or a rollback → that
  slot's sequence), the keystore names it as the next key (→ active + 1), or the radio is a fresh
  formation that has sent next to nothing. Otherwise the radio is left alone and
  `network_key_mismatch_unresolved` says to use Finish or Roll back. Previously a live network
  could have been re-keyed under a guessed sequence and cut off entirely.
- The keystore records the previous key's sequence; a runtime stack restart re-registers the ZDO
  callbacks it dropped.

## [1.10.2] — 2026-08-30

### Changed — a key rotation switches only with evidence that everyone has the key
- **The switch now waits for evidence that everyone has the key.** Routers must answer an
  address query on the current key before they are handed the new one (a stale short address is
  re-resolved through the network first); battery devices get the key the moment they are heard,
  since they poll their parent right after sending — a transport queued while they sleep is
  dropped by the parent after seconds and nobody notices. The window extends itself, up to
  `zigbee.rotation_max_window_seconds` (default 6 h), while any device is missing. With
  `zigbee.rotation_require_all` (default on) the rotation **never switches without everyone**: the
  key keeps being offered for as long as it takes, a `network_key_rotation_stalled` security alert
  past the maximum wait names the devices holding it up, the old key stays in force meanwhile, a
  device that is gone for good is unblocked by removing it, and Maintenance has a *Cancel* button.
  Off: switch anyway after the maximum wait. After the switch every router is checked on the new
  key and reported if it does not answer (`unreachable`). Both settings are on Settings → Zigbee.
- **Two ways out of an unfinished switch**, both without pairing anything again. *Finish key
  switch* moves the coordinator to the new key; the key the radio was on is remembered as the
  previous one and stays the alternate, so the devices that missed the switch are still heard
  until they rejoin. *Roll back* (new) does the opposite with one broadcast under the current
  key: the devices that switched return to the coordinator's key (they keep the old key as their
  alternate, as the standard prescribes), the keystore follows, nothing restarts — rotate again
  afterwards. Both are offered on Maintenance whenever the radio and the devices disagree.
- **The keystore passphrase moved out of the browsable folder.** It now lives in the add-on's
  private `/data` (Supervisor-owned; not reachable from the File editor, Samba or the config
  share) instead of next to the keystore in `/addon_configs/…`; an existing file is moved there
  on the first start and wiped from the old place. The config folder alone therefore never yields
  the network key — current, previous or in-flight. The `.ozbk` backup still carries both files,
  encrypted under your backup password.
- **A rotation survives a restart.** Its new key, sequence and the devices that already hold it
  are kept in the encrypted keystore; the next start resumes it (`network_key_rotation_resumed`)
  without asking those devices again. Cancelling or finishing forgets the record.

## [1.10.1] — 2026-08-30

### Fixed — a key rotation could leave the coordinator on the old key, and a restart then re-formed the network
- **The coordinator now finishes its own half of an over-the-air rotation.** On Z-Stack 3.x.0 the
  per-device key transports do not leave the radio with the new key as its alternate, so the
  broadcast switch moved every device that had received the key while the coordinator stayed on
  the old one (`network_key_rotated … verified: false`). From then on every switched device
  answered `AF … status 0xcd` (no route) — it could not decrypt anything the coordinator sent.
  After the switch the rotation now checks the radio's active key and, if it did not follow,
  rewrites the key items at the sequence the devices know and restarts the stack (a few seconds;
  devices stay paired). Recorded in the audit as `finished_on_coordinator`.
- **A restart after a rotation no longer wipes the network.** The rotation never updated the
  dongle's precommissioned key, so the next start saw "NV ≠ keystore" and re-formed with
  `CLEAR_ALL`. The rotation records the new key as precommissioned; and when only the key differs
  while PAN, extended PAN and channel agree, the start finishes the switch instead of re-forming
  (`network_key_switch_unfinished` → `network_key_switch_finished`), installing the keystore key
  under sequence *active + 1* when the keystore predates this version.
- The keystore remembers the key sequence and the previous key; the previous key is written as
  the radio's alternate key, so a device that missed the switch is still heard (its reports
  arrive) until it rejoins and picks up the current key.
- Transports that failed are retried every 30 s during the window (a router with a stale address,
  a sleepy device whose parent had not held the frame yet); `retried` is reported.
- Maintenance shows a **Finish key switch** button whenever the radio is not on the keystore key,
  and the rotation status carries `verified`, `retried` and `coordinator_key_ok`.

## [1.10.0] — 2026-08-30

### Added — air conditioners, and the One Roof IRBlaster
- **Thermostats are no longer assumed to be radiator valves.** The gateway reads
  ControlSequenceOfOperation and the Min/Max setpoint limits at interview: a
  cooling-capable device gets `current_cooling_setpoint` with its own limits, the
  mode list follows what the device can do (off/cool/auto/dry/fan_only,
  off/heat/auto, or all six), and Fan Control on the same endpoint becomes
  `fan_mode` (low/medium/high/auto; a device's "on"/"smart" reads back as such).
  Home Assistant's climate entity gets the full mode list, `fan_modes`, and —
  for two independent setpoints — a low/high target range. Existing TRVs keep
  exactly the features they had.
- **One Roof IRBlaster** (`NoammGr` / `IRBlaster`), the Zigbee infrared blaster for
  air conditioners, is a known model: a single `target_temperature` 16–30 °C (the
  device keeps both ZCL setpoints equal; the write goes to the setpoint that
  matches the mode), mode, fan, and the endpoint-2 output as **Swing**. Its own
  cluster 0xFC00 is described by the model table (`PrivateAttr`: standard
  attributes, no manufacturer code, exact wire types — char strings, bool, int16
  ×100 …) and resolved by model, so Philips' use of the same cluster id is
  untouched. Features: `learn_key` / `send_key` (text commands), `protocol`,
  `hold`, `last_result`, `code_count` in a new **IR remote** section of the
  Controls tab, plus `temperature_offset`, `led_brightness`, `led_quiet` under
  Configuration. Writes to the cluster are followed by a read of
  last_result / code_count / protocol; `last_result` is also configured for
  reporting. Home Assistant gets `text`, `select`, `switch`, `number` and
  `sensor` entities for them.
- Model table: quirks can now relabel a generic feature per endpoint, declare a
  single target temperature, add reporting and interview reads for their own
  clusters, and assert converter context (capabilities) before the first read.

### Fixed
- The root `CHANGELOG.md` had stopped at 1.7.3 while the add-on copy went on to
  1.9.0; the two are one file again (CI compares them).

## [1.9.0] — 2026-08-29

### Added — survive the coordinator going offline
- The gateway no longer exits when the dongle's serial link drops (unplug, USB
  glitch, adapter reset). Instead the broker, UI and Telegram notifier stay up,
  it records a `coordinator_offline` alert, and it **reconnects the coordinator
  in place** with backoff — the same Coordinator object is kept across the
  reconnect (`Coordinator.rebind`), and device commands already fail gracefully
  while the link is down. This ends the crash-restart loop that happened when
  the dongle was absent.
- **Telegram**: `coordinator_offline` / `coordinator_online` are sent
  immediately (the "anomalies" category, on by default) so you know the moment
  the radio drops and when it returns.
- **UI**: a full-width banner appears while the coordinator is offline, driven
  by a new `coordinator_online` flag on `/api/bridge` and updated live over the
  event stream. The Coordinator page already showed "not answering" on offline.

## [1.8.1] — 2026-08-28

### Fixed
- Coordinator page layout: the cards used the dashboard's multi-column (masonry)
  grid, which split the different-height cards across columns and made them
  overlap. Switched to a responsive auto-fit grid so each card stays whole.

## [1.8.0] — 2026-08-28

### Added — Coordinator page
- New Coordinator tab in the UI: firmware identity (One Roof build vs stock, Z-Stack version,
  build revision), live radio state (IEEE, PAN, extended PAN, channel, NWK frame counter) and a
  keystore sync verdict — PAN, extended PAN, channel, active network key and frame counter each
  checked live against the keystore, with a Re-check button.  This is the same agreement the
  gateway enforces at every startup (a blank or mismatched coordinator is re-formed from the
  keystore), now visible instead of a log line.
- `GET /api/coordinator` serves it: reads the radio on demand (device info, extended network
  info, security material table, active key compare) and answers 503 when the coordinator does
  not respond.
- The fake coordinator's extended-network-info now reports the extended PAN id it was formed
  with instead of zeros, so the sync verdict is honest in tests.


## [1.7.3] — 2026-08-28

### Fixed — empty device list, alert storms
- A single non-serializable value in one device's state (e.g. a raw vendor datapoint delivered as
  bytes) emptied the whole device list with "internal error". State values are now always made
  JSON-safe on ingest (bytes become hex), existing records are healed at start, and one broken
  record can no longer take down the list.
- The sequence-number check understands that devices run several independent counters (Tuya plugs
  interleave time requests and reports): a value near any recent counter is normal, counters only
  move forward, and only a value matching none of them twice in a row is an anomaly. The
  plug "sequence jump" storm was this.
- "Went silent" alerts once per outage and again only after the device has been heard in between —
  a bulb cut from power by a wall switch no longer alerts every 15 minutes for days.

## [1.7.2] — 2026-08-22

### Changed
- Unknown-device alerts and the Pair page list show the vendor derived from the address block
  (e.g. Tuya devices) and point to Pair → Unknown devices to adopt or evict.

## [1.7.1] — 2026-08-22

### Changed
- Activity/Logs rows show the device's name (linked to its page) next to every record that carries
  an address.
- A battery device with known model knowledge that answers one descriptor request and then sleeps is
  considered described ("described by model knowledge") instead of failing its interview forever —
  its features come from the model table anyway. Mains devices and unknown models still report a
  real failure.

## [1.7.0] — 2026-08-22

### Added — Telegram notifications, with a strict outbound policy
- Settings → **Telegram notifications**: bot token and chat id (token stored encrypted, never shown
  or logged again), categories to send — join window, devices, security, anomalies, health,
  liveness — digest interval, quiet hours, optional addresses, a test button and the last sends.
  Security and anomaly events go immediately; routine events are batched; a hard rate limit applies.
- One outbound path only: a guarded HTTPS client with a host allow-list (`api.telegram.org`),
  TLS 1.2+ verified against the system trust store, off until notifications are enabled; every
  attempt — allowed or refused — is listed under Settings → **Outbound connections**, and refusals are
  security alerts. Nothing else leaves the network; SECURITY.md documents exactly what is sent.
- Broker login failures and lockouts are now security records (`auth_failed`, `auth_lockout`), so
  they show in Activity and can be notified.

## [1.6.7] — 2026-08-22

### Added
- Settings → MQTT broker: **Copy CA certificate** puts the broker's CA text on the clipboard, so a
  client outside Home Assistant (One Roof NVR and others) can be given TLS by pasting it into its
  settings — no file transfer; the SHA-256 fingerprint shown next to it lets you compare.

## [1.6.6] — 2026-08-22

### Added — unknown devices on the network can be adopted or evicted
- A device that holds the network key but is not in the device list (typically paired by the
  previous setup without being in its configuration) is now identified by its IEEE address, shown on
  the Pair page under "Unknown devices on the network" with its address, traffic and link quality,
  and can be **adopted** (registered and interviewed) or **evicted** (told to leave). Alerts
  `traffic_from_unknown_device` carry the IEEE and are raised once, then at the 10th/100th/1000th
  frame instead of on every frame; `unknown_device_adopted` / `unknown_device_evicted` are recorded.

## [1.6.5] — 2026-08-22

### Fixed — interviews and bindings on real hardware
- Device-level ZDO responses (node/simple descriptors, active endpoints, bind/unbind) are forwarded by
  this firmware generation only after the host registers for ZDO messages, and then in a generic
  envelope. The gateway now registers at start and converts forwarded responses into the classic
  indications, so interviews complete, bindings succeed and devices report by themselves instead of
  relying on polling. (Management responses such as the neighbour table were unaffected, which is
  why the network checks worked while every interview timed out.)

## [1.6.4] — 2026-08-22

### Changed
- A failed interview is retried on contact at most every 10 minutes (a chatty device used to trigger
  a descriptor request on every frame).
- A device whose model is known and whose values are flowing no longer shows "not interviewed" in
  the State column; the About badge says "descriptors not read yet · retried when the device is
  awake" with the reason on hover. Battery sensors sleep too fast for descriptor requests and work
  fully without them.

## [1.6.3] — 2026-08-22

### Fixed — door sensors showed the opposite state in Apple Home
- In the device descriptions on `bridge/devices`, `contact` now declares `value_on: false`: the
  value is true when the door is *closed*, so the active (open) state is false — the convention the
  previous setup used and that bridges key their polarity on. Home Assistant was already right
  (`door` class template); Apple Home via One Roof Bridge showed open for closed.

## [1.6.2] — 2026-08-22

### Fixed — phantom entities from earlier descriptions
- Entity configs are retained on the broker; when a device's description changes (corrected
  interview, better model knowledge, a definition), configs that no longer apply are now blanked so
  Home Assistant drops the entity (e.g. a door sensor once described as "MQTT Switch"). The first
  announce after this update also sweeps the shapes earlier versions could have left behind.

## [1.6.1] — 2026-08-22

### Changed — the Home Assistant role is a full broker client
- Home Assistant is the hub: its login (shared by One Roof Bridge through the Supervisor) may now
  subscribe to and publish on any topic — its other integrations' discovery topics, the NVR's events —
  with one exception kept on purpose: it cannot publish on the gateway's own device topics, so a
  leaked Home Assistant token cannot forge sensor states; commands (`/set`, `/get`, bridge requests)
  remain allowed. Opening the network stays a control-user privilege.
- ACL gained deny lists with narrower-allow override; add-on DOCS describe the Bridge and NVR setup.

## [1.6.0] — 2026-08-22

### Added — device descriptions for the other One Roof apps
- `<base>/bridge/devices` now carries, for every device, the *exposes* description the previous
  setup published (`ieee_address`, `type`, `supported`, `definition.vendor/model/description/exposes`
  with light/switch/lock/cover/climate composites and binary/numeric/enum features, access bits,
  per-gang endpoints), derived from our own feature format. One Roof Bridge builds its Apple Home
  accessories from it and One Roof NVR reads the same list — both connect through the MQTT service
  the add-on registers with the Supervisor, so no credentials are typed anywhere.

## [1.5.7] — 2026-08-22

### Changed
- The anomaly monitor ignores Basic-cluster chatter (vendor heartbeats, identity reads) for its burst
  and sequence checks; only link quality and last-seen are taken from such frames. Tuya plugs were
  raising `device_anomaly` with their own heartbeat.

## [1.5.6] — 2026-08-22

### Changed
- Sleepy (battery) devices are no longer interviewed at start — they answer only when awake and are
  interviewed on their next report; no more `interview_failed` parade after a restart.
- A ZCL sequence counter restarting near zero is treated as a device reboot, not an impersonation
  signal.

## [1.5.5] — 2026-08-22

### Fixed — values present in the state are always exposed
- Devices imported without cluster information (the previous database did not carry it) produced no
  measurement entities although their state held temperature/humidity/pressure. Three fixes: such
  devices are interviewed again on contact; the model table adds the measurements of the Aqara
  climate sensors explicitly; and, for every model, any state key with a known meaning that has no
  feature becomes a read-only entity — nothing a device reports is lost on the way to Home Assistant.

## [1.5.4] — 2026-08-22

### Added — MQTT 5 Subscription Identifiers
- The broker now supports (and advertises) subscription identifiers: the identifier a client attaches
  to a subscription is echoed in every matching PUBLISH, including retained replays and multiple
  matching subscriptions. Home Assistant's MQTT client requires this and logged a warning.

## [1.5.3] — 2026-08-22

### Fixed — Home Assistant rejected every discovery message
- Discovery payloads carried `device.sw_version: null` for devices whose firmware build is unknown
  (the normal state after an import). Home Assistant validates strictly and dropped the whole message
  (`string value is None … data['device']['sw_version']`), so no entity was ever (re)created from
  our discovery. Null fields are never emitted any more; a test scans every payload of every fixture
  model.

## [1.5.2] — 2026-08-22

### Fixed — imported devices stayed "unavailable" in Home Assistant
- A device imported from a previous setup is offline until heard from; when it then reported, its
  availability was never switched to online, so Home Assistant kept all of its entities unavailable
  while state messages were flowing. Any frame from a device now marks it online and publishes the
  (retained) availability.

## [1.5.1] — 2026-08-22

### Fixed
- Basic-cluster identity fields (application/stack/hardware version, date code, power source) and
  vendor heartbeat attributes (`basic_0xffe2` …) no longer appear as device state, in Activity or in
  Home Assistant; they go to the device record (About tab).

## [1.5.0] — 2026-08-22

### Added — unknown devices handled, and teachable
- **Datapoint inference** for Tuya datapoint devices without a built-in map: the datapoint ids and
  wire types the device actually reports are matched against the conventional layouts of product
  families (thermostats, covers, sensors, smoke/leak/gas/door, presence radars, multi-gang switches,
  lights, sirens, soil sensors). Conservative: only an unambiguous match is used; everything else stays
  a raw `dp_<n>` feature. Inferred features are tagged in the UI.
- **Device definitions you can write yourself**: a "Datapoints" tab on datapoint devices lists every
  datapoint seen with live values and lets you name each one (key, type, scale, unit, inverted,
  device class); a "Type & category" card on About lets you correct a device's kind. Definitions are
  saved per model in `definitions.yaml`, take precedence over the built-in table, apply immediately
  to every device of that model (discovery re-announced, state rebuilt), are included in backups and
  can be exported/imported as YAML. Control users only; recorded in the audit log.
- Raw datapoints are exposed for every datapoint device, so nothing reported is lost before it is
  named.

## [1.4.5] — 2026-08-22

### Fixed — entity identities for common models
- Aqara H1 wall switches (`lumi.switch.b1lc04/b2lc04`, `b1nc01/b2nc01`, `l1acn1/l2acn1`) are wall
  switches, not remotes: `switch_left`/`switch_right` entities are published again with the previous
  identities, plus device temperature, power-outage count and button actions.
- Tuya smoke detectors (`TS0601`, `_TZE200_rccxox8p` and siblings): smoke, battery, battery-low and
  self-test from datapoints.
- Aqara motion sensors no longer get spurious IAS alarm/tamper/battery-low entities; illuminance uses
  the previous layout's `illuminance` object id.

## [1.4.4] — 2026-08-22

### Added — security requirements
- **Network key rotation over the air**: the new key is handed to every device under its own link
  key, then switched; devices stay paired; whoever holds only the old key is locked out. Live progress
  in Settings → Maintenance. "Rotate and re-pair everything" remains for a leaked trust-centre seed.
- **Liveness and anomaly monitor**: per-device behavioural profiles; `device_anomaly` alerts for
  sequence jumps, link-quality swings, commands from devices that only report, bursts, silence after a
  burst, and mains devices that go silent.
- **Pairing exposure bounded**: a plain join window admits one device and closes at once; after a
  pairing without install code the key is rotated automatically within minutes.

### Changed
- Last known link quality shown for every device; silent mains devices polled every 5 minutes so
  models that never report come alive and get bound; imported devices never marked as interviewed
  are interviewed on contact; wider page layout.

## [1.3.10] — 2026-08-22

### Fixed — the imported network really lands on the coordinator
- Verified on hardware and guarded by tests against a simulated firmware that behaves the same:
  the firmware ignores the pre-configured key at formation and its key items are 17 bytes, writable
  only with the stack stopped. Formation and every start now: form → stop → write key items at exact
  length, frame counter (security material table) and trust-centre seed → start → verify key, seed,
  counter → neighbour check (`coordinator hears N neighbour(s)`). Mismatches are repaired, never
  re-formed blindly, and reported (`network_key_mismatch/repaired`, `frame_counter_verified`,
  `no_neighbours_heard`).
- The trust-centre link-key seed from the backup is restored so every device's link key stays valid.
- Secrets never reach the log: key-bearing frames are redacted at DEBUG, generated passwords are not
  printed. Tuya mains devices get the Basic-cluster read that stops their 200 ms reports.

## [1.3.0] — 2026-08-22

### Added — device knowledge: models, vendors, private protocols
- A declarative model table (206 entries, 768 model patterns) tells the gateway what a device *is*:
  Aqara/Xiaomi, Tuya (incl. the TS0601 datapoint protocol for temperature/humidity sensors, TRVs,
  wall thermostats, curtains, blinds and presence radars), IKEA, Philips Hue, Sonoff/eWeLink, Heiman,
  frient/Develco, Schneider, Legrand/Netatmo, Bosch, Danfoss, Eurotronic, Innr, OSRAM/LEDVANCE,
  SmartThings/Samjin/Centralite, Third Reality, Ubisys, Gledopto, Paulmann, Müller Licht, Linkind,
  Namron, Sunricher, Aurora, Visonic, Sercomm, Xfinity, LiXee, Moes, Lidl, Yale/Schlage/Kwikset locks.
- Each device now has a kind ("Contact sensor", "Smart plug", "Wall switch (2 gang)" …), vendor and
  category, shown in the Devices table and About tab; sensors are read-only, plug-only controls no
  longer appear on sensors, remotes and buttons publish `action`, multi-gang switches get one control
  per gang, locks/covers/thermostats have proper controls.
- Vendor reports decoded: Aqara private attributes (battery voltage and %, device temperature, power
  outage count, illuminance, power/energy), Tuya datapoints (reports and writes).
- Home Assistant discovery derives device classes and units from the features (door, motion, moisture,
  smoke, CO, gas, vibration, tamper, battery, voltage, device temperature, VOC/CO₂/PM2.5 …), adds
  select/number/lock/cover/climate entities, and keeps the legacy object ids so imported entities
  survive unchanged.
- Clusters added: scenes, analog/multistate/binary input, poll control, door lock, pump, fan, CO₂,
  PM2.5, diagnostics, Tuya and vendor-specific clusters.

## [1.2.21] — 2026-08-21

### Fixed — broker and Home Assistant integration on a real installation
- Add-on built from its own folder (no downloads at build time; version asserted at build).
- MQTT 5 clients accepted next to 3.1.1; Home Assistant's dialog can stay on its default.
- Home Assistant's existing broker login is adopted automatically for an hour after an import or
  first start; lockouts are per address *and* username so a stale login cannot block a correct one.
- Per-client subscription limit raised to 2048 (Home Assistant subscribes per entity).
- Running version shown in the UI header and the first log line.

## [1.2.9] — 2026-08-21

### Added — import straight from the Home Assistant share, complete and safe
- The import card shows "Found on this Home Assistant": the previous setup's folder is read by the add-on
  itself (read-only) — one click, no uploads. Uploads remain as a fallback (now with a `state.json` slot),
  and a file the browser cannot read is reported instead of sent half-empty.
- `coordinator_backup.json`'s device table supplies every device's short address, so imported devices are
  addressable immediately; devices without an address are looked up by a ZDO broadcast after start and
  interviewed as soon as they answer; sleepy ones are picked up on their next report.
- An interview never targets short address 0 (the coordinator itself); data recorded that way is discarded.
- `ext_pan_id` lists in `configuration.yaml` are read in the right byte order, so the coordinator's stored
  settings match the imported ones and the network is started, not re-formed.
- A restored frame counter is set well above the saved value; mismatching coordinator settings are named in
  the log (`coordinator_nv_mismatch`).

## [1.2.5] — 2026-08-21

### Added — automatic handover of Home Assistant's MQTT, first run on real hardware
- The add-on registers itself as Home Assistant's MQTT service (`services: mqtt:provide`): the MQTT
  integration and add-ons that auto-detect the broker switch to One Roof Zigbee by themselves. Importing a
  previous setup in the add-on enables the legacy layout automatically and recreates the previous broker
  login (new `client` role) so clients outside Home Assistant keep connecting.
- Plain MQTT listener (1883) inside the add-on network by default (needed by Home Assistant's discovery);
  no host ports unless enabled.

### Fixed
- Least privilege done automatically: the add-on starts as root only to read the Supervisor's options and
  own its config folder, proves the coordinator is usable by uid 1000 (opening the device exactly as
  configured) and drops root when it is; otherwise it stays root like other add-ons and says so.
- `APP_CNF_BDB_SET_ACTIVE_DEFAULT_CENTRALIZED_KEY` mode byte encoded correctly (the firmware rejected the
  old encoding with INVALID_PARAMETER, aborting network formation on a Sonoff ZBDongle-P).
- The web UI is shipped as package data ("UI not built").

## [1.1.13] — 2026-08-21

### Added — Home Assistant add-on store
- Repository laid out as a Home Assistant add-on repository (`repository.yaml`, `oneroof-zigbee/` at the
  root) under "One Roof Zigbee Add-ons", with the family icon, logo, `DOCS.md` and the changelog link.
- Release pipeline: CI (lint + tests on 3.11–3.13), Auto-tag on push to `main`, release workflow that
  verifies versions, builds add-on images (amd64, aarch64) and publishes a GitHub Release.

### Fixed — everything found bringing the add-on up on a real Home Assistant
- Store visibility: `serial_port` has no default (the Supervisor rejects a non-existent default device);
  the add-on `config.yaml` is committed (a `.gitignore` rule had excluded it).
- Build on the Supervisor's Alpine base (Python and compiled dependencies from Alpine packages).
- No host ports claimed by default (an existing broker add-on usually owns 8883/1883).
- Config folder mounted at `/config` (the Supervisor owns `/data`); root-owned `options.json` readable.
- `network_coordinator` accepts `host:port` or `tcp://host:port`; unreadable coordinators and missing
  broker logins are reported as one clear instruction.
- Test suite robust on CI (MQTT delivery waits, container-safe Chrome launch with skip).

## [1.1.0] — 2026-08-21

### Added — seamless migration from a previous setup
- **Legacy layout** (`compat.legacy_layout`): the previous setup's topics `<base>/<friendly name>`, availability
  payloads and Home Assistant discovery `unique_id`s / device identifiers, so HA
  keeps the same entities (ids, names, areas, history, automations, dashboards) and other MQTT consumers keep
  their subscriptions. Supports `<base>/<name>/get` state refresh requests.
- **Existing broker mode** (`mqtt.external`): the gateway connects to an existing broker instead of starting
  its own. MQTT control requests are refused in this mode (no authenticated
  publisher); pairing stays in the UI.
- The importer reads the previous setup's `mqtt:` section (server, login, base topic, discovery prefix); the import
  UI offers "Keep using my current MQTT broker" and "Keep Home Assistant entities and topics identical"
  (both default on). Settings → MQTT broker shows the active mode with one-click "Switch to the built-in TLS
  broker" and a compat toggle.
- Add-on: `legacy_layout`, `external_broker*`, `base_topic` options; with `services: mqtt:want` the existing
  broker login is obtained from the Supervisor automatically.

- Import also reads `state.json` (last known states) so dashboards are populated before devices report;
  devices imported without `database.db` get a full interview on first contact.
- Unknown short addresses are resolved with a ZDO IEEE lookup (rate-limited) before being treated as
  unknown devices, so imported or re-addressed devices are recognised.

### Changed
- Repository layout follows Home Assistant's add-on repository format: `repository.yaml` and the
  `oneroof-zigbee/` add-on folder at the root. The add-on builds from the folder alone (installs the gateway
  from this repository's release tarball), so it works both built locally by the Supervisor and from GHCR.

### Tests
- End-to-end scenario with a stand-in existing broker and an already-subscribed Home Assistant: identical topics,
  identical discovery identities, control via the old `/set` topic, network still not openable over MQTT.

## [1.0.0] — 2026-08-21

First release. Zigbee gateway and MQTT broker in one process, written from scratch, security first.

### Radio / coordinator
- TI Z-Stack 3.x (CC2652/CC1352) over USB or `tcp://` network coordinators; own UNPI/ZNP driver.
- Random network key, PAN and extended PAN per install; `TC_REQUIRE_KEY_EXCHANGE`, no public-key rejoin.
- Join window capped (default 120 s), auto-closing, with cooldown; install-code pairing (AES-MMO verified
  against the Zigbee test vector); optional strict mode (public ZigBeeAlliance09 key disabled).
- Unexpected joins evicted and alerted; imported/known devices recognised as rejoins.
- Interview, bind + attribute reporting, IAS zone enrolment, tolerant ZCL decoding.

### Devices (standard ZCL, no per-model database)
- Lights (on/off, level, colour xy, colour temperature), plugs (on/off, power, current, voltage, energy),
  temperature/humidity/pressure/illuminance/occupancy, IAS contact/motion/leak/smoke/CO/vibration,
  battery, window coverings, thermostats; power-on behaviour (StartUpOnOff) and countdown (OnWithTimedOff).

### Broker
- Own MQTT 3.1.1 broker: users with scrypt passwords, roles (Home Assistant / Admin / Read-only / Custom ACL),
  `control_users` gate for pairing/removal/key rotation, 5-attempt lockout, connection and retained-store caps.
- TLS 1.2+ on by default with a generated local CA (`tls/ca.crt`), optional mTLS, optional legacy plaintext port.

### Home Assistant
- MQTT discovery for all entities; bridge entities (permit join switch, last security alert, device count).
- Add-on: non-root, no privileged APIs, UI only through Ingress, read-only view of the HA config for imports.

### Web UI (single self-contained file, no external requests)
- Dashboard, Devices with detail tabs (About, Controls, State, Clusters, Reporting, Bind, Firmware), Pair,
  Network map, Logs (audit + application), Activity feed, Settings admin console with help on every setting:
  coordinator, Zigbee security, MQTT/TLS, users & access, Home Assistant, backup/restore (encrypted),
  import of a previous setup, firmware library, maintenance (log level, restart, key rotation).
- OneRoof design system (shared with OneRoof Bridge), light/dark, phone layout.

### Migration
- Import of a previous setup (`configuration.yaml`, `database.db`, `coordinator_backup.json`) without re-pairing
  when keeping the same dongle; frame-counter restore when re-forming; UI and CLI (`import`).

### Firmware (OTA)
- Local-only OTA server: uploaded images are parsed and verified (manufacturer, image type, version, size,
  SHA-256) and offered only to a matching device, only when newer, only on explicit user action.

### Security & operations
- AES-256-GCM keystore, 0600 files, SHA-256 hash-chained audit log with verification, security alerts on MQTT,
  encrypted backups, restart from the UI, `passwd` / `pair` / `verify-audit` / `import` CLI.

### Tests
- 279 tests: byte-exact codecs, coordinator bring-up against a scripted ZNP, broker, UI API, and an end-to-end
  suite that boots the production entry point with simulated devices over real TLS MQTT/HTTP plus a
  real-browser suite. CI on Python 3.11–3.13.

### Known limitations
- Not yet validated on physical hardware.
- No Tuya/Aqara private clusters, groups/scenes, Silicon Labs (EZSP) coordinators, or touchlink.

### Fixed (1.0.1)
- Join window cooldown on a freshly booted host; client-ID takeover count.
