"""Embedded IEEE OUI → vendor table for the chip/vendor prefixes commonly seen
on Zigbee networks. Deliberately small and offline (no lookups leave the box)."""

from __future__ import annotations

OUI: dict[int, str] = {
    0x00124B: "Texas Instruments", 0x001788: "Signify (Philips Hue)",
    0x000D6F: "Silicon Labs (Ember)", 0x90FD9F: "Silicon Labs", 0x842E14: "Silicon Labs", 0x8CF681: "Silicon Labs",
    0x04CF8C: "Xiaomi / Aqara (Lumi)", 0x54EF44: "Aqara (Lumi)", 0x00158D: "Xiaomi / Aqara (Lumi)",
    0xA4C138: "Telink Semiconductor", 0x3C6A2C: "Telink Semiconductor", 0x847127: "Telink Semiconductor",
    0x000B57: "IKEA (Silicon Labs module)", 0xCCCCCC: "IKEA", 0x5C0272: "IKEA", 0x7CB03E: "IKEA", 0xF4B3B1: "IKEA",
    0x14B457: "Legrand / Netatmo", 0x0015BC: "Develco Products", 0x0022A3: "Develco Products",
    0x00137A: "Innr / Sengled", 0xB0CE18: "Sengled", 0x0024B5: "Sengled",
    0x086BD7: "OSRAM / Ledvance", 0xF0D1B8: "Ledvance",
    0x001E5E: "Bitron / SMaBiT", 0x286D97: "SmartThings", 0x24FD5B: "SmartThings", 0xD0CF5E: "Samsung", 0x70B3D5: "Tuya (Tuya Smart)",
    0x0C4314: "Tuya", 0x60A423: "Tuya", 0xEC1BBD: "Tuya / Telink",
    0x588E81: "Tuya / Telink", 0xBC33AC: "Tuya / Silicon Labs", 0x38398F: "Tuya",
    0x001FEE: "Ubisys", 0xCCBA8F: "Sonoff (eWeLink)", 0x4C977A: "Sonoff (eWeLink)", 0x00155F: "Schneider Electric",
    0x00A0DE: "Yamaha", 0x7CC6B6: "Nordic Semiconductor", 0xF4CE36: "Nordic Semiconductor", 0xC4C1DF: "Nordic Semiconductor",
    0x000B3E: "Danfoss", 0x04B648: "Namron / Sunricher", 0x0020A4: "Yale", 0x8CF5A3: "Yale (Assa Abloy)",
    0xB4E3F9: "Heiman", 0x00B5A9: "Heiman", 0x2C1165: "Heiman", 0x5CC7C1: "Espressif", 0x3C71BF: "Espressif",
    0xA8032A: "Espressif", }


def vendor_of(ieee: int) -> str | None:
    """Best-effort: OUI is the top 24 bits (big-endian EUI-64)."""
    prefix = (ieee >> 40) & 0xFFFFFF
    return OUI.get(prefix)
