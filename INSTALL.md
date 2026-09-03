# Installing One Roof Zigbee

A Home Assistant add-on: a Zigbee gateway with its own MQTT broker. One process, one UI.

## 1. Add the repository

[![Add repository to my Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FNoammGr%2FOneroof-Zigbee)

Or by hand: **Settings → Add-ons → Add-on Store → ⋮ → Repositories** → add
`https://github.com/NoammGr/Oneroof-Zigbee`.

## 2. Install and start

1. Install **One Roof Zigbee** from the store (the first build takes a few minutes).
2. **Configuration** tab → `serial_port` → pick your Zigbee adapter → **Save**.
3. **Start.** The add-on registers itself as Home Assistant's MQTT service — the MQTT
   integration and other add-ons find the broker by themselves. Nothing to type.

## 3. First five minutes

- Open **One Roof Zigbee** from the sidebar.
- **Pair** → *Permit join* → put your device in pairing mode. It appears, is interviewed,
  and shows up in Home Assistant on its own.
- **Dashboard** shows every device live; **Map** shows how they connect; **Logs** shows
  what happened, filterable per device.

## Coming from Zigbee2MQTT or a previous setup

Your devices, names and Home Assistant entities survive — no re-pairing:

1. Stop the old Zigbee add-on and the old broker add-on (don't uninstall yet).
2. Install and start One Roof Zigbee as above.
3. Sidebar → **Settings → Import a previous setup** → **Use this folder** → Import → Restart.
4. Done. Same network, same topics, same entities; the old broker login is adopted so
   everything reconnects without changes. When all is well, uninstall the old add-ons.

## Updating

**Settings → Add-ons → Add-on Store → ⋮ → Check for updates**, then **Update** on the
add-on's page. If a released version doesn't show up, run `ha supervisor repair` in the
Terminal add-on (rebuilds the store's copy of this repository) and check again.
Your network, devices and keys live in `/data` and survive every update.

> **Never uninstall to update** — uninstalling deletes `/data`, which holds your network keys.
> Read [SECURITY.md](SECURITY.md) before exposing anything beyond Home Assistant.
