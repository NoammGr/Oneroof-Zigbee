# One Roof Zigbee (Home Assistant add-on)

Zigbee gateway **and** MQTT broker in one add-on, designed around security.

* Set `serial_port` (or `network_coordinator` for a LAN coordinator) and start.
* The add-on registers itself as Home Assistant's MQTT service: the MQTT integration and
  add-ons that auto-detect the broker connect to it by themselves. No passwords to copy.
* Open the UI from the sidebar (Ingress) → Pair. Everything else (users, TLS, backups,
  import of a previous setup, firmware) is in Settings.
* **Coming from a previous setup?** Settings → *Import a previous setup* finds the old folder on
  this Home Assistant; one click keeps the network (no re-pairing), the topics and the entities.

Requires a TI CC2652/CC1352 coordinator (Sonoff ZBDongle-P, SMLIGHT, ZigStar, …).
