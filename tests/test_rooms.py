"""Rooms: the owner's word on where a device is, suggested from its name or Home Assistant."""
import json
import types

import pytest

from oneroof_zigbee.rooms import RoomBook, clean_room, ha_areas, room_of_name, summarize


def test_room_names_are_cleaned_and_bounded():
    assert clean_room("  Kids'   room ") == "Kids' room" and clean_room("") == ""
    with pytest.raises(ValueError):
        clean_room("a/b")
    with pytest.raises(ValueError):
        clean_room("x" * 61)


def test_the_room_a_name_carries():
    assert room_of_name("Garage - Smart Plug") == "Garage"
    assert room_of_name("Kitchen: kettle") == "Kitchen"
    assert room_of_name("Hall – Lamp") == "Hall"
    assert room_of_name("Back door") == "" and room_of_name("A-B") == "" and room_of_name("") == ""


def test_home_assistant_areas_by_device_identifier(tmp_path):
    st = tmp_path / "ha" / ".storage"
    st.mkdir(parents=True)
    (st / "core.device_registry").write_text(json.dumps({"data": {"devices": [
        {"identifiers": [["mqtt", "oneroof_zigbee_0x00158D0000000001"]], "area_id": "k"},
        {"identifiers": [["mqtt", "zigbee2mqtt_0x00158D0000000002"]], "area_id": "g"},
        {"identifiers": [["hue", "abc"]], "area_id": "k"},
        {"identifiers": [["mqtt", "oneroof_zigbee_0x00158D0000000003"]], "area_id": None}]}}))
    (st / "core.area_registry").write_text(json.dumps({"data": {"areas": [{"id": "k", "name": "Kitchen"}, {"id": "g", "name": "Garage"}]}}))
    assert ha_areas([tmp_path / "nope", tmp_path / "ha"]) == {"0x00158d0000000001": "Kitchen", "0x00158d0000000002": "Garage"}
    assert ha_areas([tmp_path / "nope"]) == {}
    (st / "core.device_registry").write_text("{broken")
    assert ha_areas([tmp_path / "ha"]) == {}


def test_rooms_are_summarised_from_the_devices_with_their_floor(tmp_path):
    book = RoomBook(tmp_path / "rooms.json")
    book.set_floor("Kids' room", 1)
    dev = lambda room, available=True, wall=False: types.SimpleNamespace(room=room, available=available, context={"wall_off": True} if wall else {})  # noqa: E731
    rooms = summarize([dev("Kitchen"), dev("Kitchen", available=False), dev("Kids' room", wall=True), dev(None)], book)
    assert rooms == [{"name": "Kids' room", "floor": 1, "devices": 1, "offline": 0, "wall_off": 1},
                     {"name": "Kitchen", "floor": None, "devices": 2, "offline": 1, "wall_off": 0}]
    book.rename("Kids' room", "Bedroom")
    assert RoomBook(tmp_path / "rooms.json").floors == {"Bedroom": 1}
    book.set_floor("Bedroom", None)
    assert RoomBook(tmp_path / "rooms.json").floors == {}
