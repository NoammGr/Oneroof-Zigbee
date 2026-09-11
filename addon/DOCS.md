# One Roof Zigbee (Home Assistant add-on)

Zigbee gateway **and** MQTT broker in one add-on, designed around security.

## Fresh start
1. Configuration → `serial_port`: pick the adapter. Start.
2. The add-on registers itself as Home Assistant's MQTT service. If no MQTT integration exists yet,
   Home Assistant offers it under Settings → Devices & services (Discovered) — confirm it and you are done.
3. Open the web UI from the sidebar → Pair.

## Coming from a previous setup
1. Stop the old Zigbee add-on and the old broker add-on.
2. Web UI → Settings → *Import a previous setup* → **Use this folder** → Import → Restart. The network is
   adopted (no re-pairing), device names, states, topics and Home Assistant entities stay identical.
3. Home Assistant's MQTT integration keeps its previous login and retries it from inside the add-on
   network. For one hour after the import (or the first start) the add-on adopts that login — the user
   appears under Settings → Users & access with the Home Assistant role and the audit log records
   `broker_login_adopted`. Nothing to type. (Manual alternative: Settings → Devices & services → MQTT →
   Configure → broker = this add-on's hostname from the log, port 1883 or 8883 with TLS, any user you
   created in Users & access.)
4. Clients outside Home Assistant keep using the previous broker login (it is recreated by the import).

## Where things are
* Add-on config folder (`/addon_configs/<slug>/`): keystore, users, `tls/ca.crt`, backups, firmware.
  The keystore's passphrase is **not** there: it lives in the add-on's private storage, where nothing in
  Home Assistant can browse it, so the folder (or a Samba copy of it) alone does not reveal the network key.
* Everything else — users, TLS, join policy, backups, firmware, log level — is in the web UI → Settings,
  with help on every setting.

## Is my network healthy?
The Dashboard opens with a Network health card: devices the gateway cannot reach, devices flapping
offline and back, devices quiet for longer than their kind should be, and — after **Check now**
walks the routers' neighbour tables — every weak hop and what would fix it. Each device page says who
it talks through. The same reaches Home Assistant as a **Health** sensor on the OneRoof Zigbee bridge
device (ok or degraded, and why).

## Network key rotation
* Manual: web UI → Settings → Maintenance → *Rotate key over the air*. Press **Check first** before it:
  the add-on asks every router to answer on the current key and judges each battery device by when it
  last spoke, and names who would hold the rotation up — power-cycle or remove those first.
* Automatic (after a pairing without an install code, or every *N* days) is **off by default** and is
  switched under web UI → Settings → *Automatic key rotation* — live, no restart. The add-on option
  `rotate_key_after_plain_join` only seeds the first value.
* What can be proven: after the switch every router is verified on the new key. A battery device is
  handed the key the moment it next speaks and cannot be verified until then.

Requires a TI CC2652/CC1352 coordinator (Sonoff ZBDongle-P, SMLIGHT, ZigStar, …).

## One Roof Bridge, One Roof Statistics and One Roof NVR
* **Bridge** (Apple Home) finds this broker through the Supervisor's MQTT service automatically and
  builds its accessories from the device descriptions on `<base>/bridge/devices`. After updating this
  add-on, restart Bridge once so it re-reads the list.
* **Statistics** (formerly Energy) finds this broker the same way and reads power, contact,
  occupancy, on/off and sensor values from the device list and `<base>/<ieee>/state` — nothing
  to set up on either side.
* **NVR** runs outside Home Assistant, so it needs a way in: in this add-on's **Network** section map
  host port **8883** (TLS; or 1883 plain if the client cannot do TLS), create a user for it under
  web UI → Settings → Users & access (role *client*), then in the NVR's MQTT settings: host, port
  8883, user, password, TLS on, and paste the CA certificate copied from web UI → Settings → MQTT
  broker → *Copy CA certificate*. Bridge then receives the NVR's events through the same broker.

