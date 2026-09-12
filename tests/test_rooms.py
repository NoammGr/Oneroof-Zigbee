"""Rooms: the owner's word on where a device is, suggested from its name or Home Assistant."""
import types

import pytest

from oneroof_zigbee.rooms import RoomBook, clean_room, summarize


def test_room_names_are_cleaned_and_bounded():
    assert clean_room("  Kids'   room ") == "Kids' room" and clean_room("") == ""
    with pytest.raises(ValueError):
        clean_room("a/b")
    with pytest.raises(ValueError):
        clean_room("x" * 61)


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
