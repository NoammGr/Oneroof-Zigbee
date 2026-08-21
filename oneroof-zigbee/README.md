# OneRoof Zigbee (Home Assistant add-on)

Zigbee gateway **and** MQTT broker in one add-on, designed around security.

* Set `serial_port` (or `network_coordinator` for a LAN coordinator) and start.
* First start prints the `homeassistant` and `admin` MQTT passwords **once** and writes the
  CA certificate to the add-on config folder (`tls/ca.crt`).
* Add the **MQTT** integration: host = your HA host, port 8883, TLS on, user `homeassistant`,
  upload `ca.crt` as *Broker certificate*.
* Open the UI from the sidebar (Ingress) → Pair. Everything else (users, TLS, backups,
  import of a previous setup, firmware) is in Settings.

Requires a TI CC2652/CC1352 coordinator (Sonoff ZBDongle-P, SMLIGHT, ZigStar, …).
