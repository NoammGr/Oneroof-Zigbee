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
* Everything else — users, TLS, join policy, backups, firmware, log level — is in the web UI → Settings,
  with help on every setting.

Requires a TI CC2652/CC1352 coordinator (Sonoff ZBDongle-P, SMLIGHT, ZigStar, …).
