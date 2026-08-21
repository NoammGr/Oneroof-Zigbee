"""Zigbee install codes.

An install code is 6/8/12/16 random bytes + a 2-byte CRC-16/X-25 (reflected
poly 0x8408, init 0xFFFF, final XOR 0xFFFF, little-endian).  The
per-device Trust Center link key is the AES-MMO (Matyas–Meyer–Oseas) hash of
the install code *including* its CRC.

Using install codes is the single most important security upgrade over the
classic join: the network key is never transported under the well-known
"ZigBeeAlliance09" key, so a sniffer that captures the join cannot decrypt it.
"""

from __future__ import annotations

import re

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VALID_CODE_LENGTHS = (6, 8, 12, 16)


class InstallCodeError(ValueError):
    pass


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def parse(text: str) -> bytes:
    """Parse a printed install code (hex, spaces/colons/dashes allowed).

    Accepts the code with or without its CRC. Returns code+CRC (validated).
    """
    hexstr = re.sub(r"[\s:\-]", "", text).lower()
    if not re.fullmatch(r"[0-9a-f]*", hexstr) or len(hexstr) % 2:
        raise InstallCodeError("install code must be hex")
    raw = bytes.fromhex(hexstr)
    if len(raw) in VALID_CODE_LENGTHS:
        return raw + crc16(raw).to_bytes(2, "little")
    if len(raw) - 2 in VALID_CODE_LENGTHS:
        code, crc = raw[:-2], int.from_bytes(raw[-2:], "little")
        if crc16(code) != crc:
            raise InstallCodeError("install code CRC mismatch — check for a typo")
        return raw
    raise InstallCodeError(f"install code must be {VALID_CODE_LENGTHS} bytes (+2 CRC), got {len(raw)}")


def _aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 — MMO hash primitive, not data encryption
    return enc.update(block) + enc.finalize()


def aes_mmo_hash(data: bytes) -> bytes:
    """AES-128 Matyas–Meyer–Oseas hash per Zigbee spec B.6 (block size 16)."""
    block = 16
    h = bytes(block)
    # Padding: 0x80, zeros, then 16-bit big-endian bit length, total multiple of 16.
    bit_len = len(data) * 8
    padded = data + b"\x80"
    while (len(padded) + 2) % block:
        padded += b"\x00"
    padded += bit_len.to_bytes(2, "big")
    for i in range(0, len(padded), block):
        m = padded[i : i + block]
        e = _aes_ecb_encrypt(h, m)
        h = bytes(a ^ b for a, b in zip(e, m, strict=True))
    return h


def derive_link_key(install_code_with_crc: bytes) -> bytes:
    if len(install_code_with_crc) - 2 not in VALID_CODE_LENGTHS:
        raise InstallCodeError("expected install code including CRC")
    return aes_mmo_hash(install_code_with_crc)
