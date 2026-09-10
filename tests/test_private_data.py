"""Nothing private in the tree: no real Zigbee addresses, no personal e-mail, no credentials in
URLs, none of the owner's own words (names of people, rooms, cameras).

The repository is public. Sample data in tests, docs and changelogs must be invented: a Zigbee
address that is obviously a fixture (a run of zeros, aabb, dead/beef...), e-mails only at
example/noreply domains, camera or broker URLs with credentials only on test hosts. The owner's
private words live in a file OUTSIDE the repository (it must never be committed itself); when
the file is present the scan checks them too, when it is absent (CI) that part is skipped.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

IEEE = re.compile(r"0x[0-9a-fA-F]{16}")
# an address is a fixture when it reads like one: a run of zeros or a made-up word in hex
FAKE_IEEE = re.compile(r"0{5}|aaaa|aabb|dead|beef|c0ffee|d00ff1|abcdef|1234|1122|22aa|aa55|bad|ee0[0-9]|ffff|01020304", re.I)
# an e-mail, not the user:password@host of a URL, and not user@1.2.3.4
EMAIL = re.compile(r"(?<![:/@A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
OK_EMAIL = re.compile(r"@(?:[a-z0-9-]+\.)*(?:users\.noreply\.github\.com|github\.com|example|example\.com|example\.org|test|invalid|local)$", re.I)
CRED_URL = re.compile(r"\b(?:rtsps?|https?|mqtts?|wss?)://([^/@\s'\"<>]+):([^/@\s'\"<>]+)@([^/\s'\"<>:]+)")
# private ranges, loopback, example domains, and bare names without a dot (not routable from outside)
OK_HOST = re.compile(r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|[a-z0-9.-]*\.example$|[a-z0-9-]+$)", re.I)
PRIVATE_WORDS_FILE = Path(os.environ.get("ONEROOF_PRIVATE_WORDS") or Path.home() / "Downloads" / "Home" / "notes" / "private-words.txt")
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".db", ".pyc", ".zip", ".bin", ".elf",
                 ".map", ".ozbk", ".mp4", ".pdf", ".svg", ".lock"}
MAX_BYTES = 3_000_000


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    files = []
    for raw in out.split(b"\0"):
        if not raw:
            continue
        p = ROOT / raw.decode("utf-8", "surrogateescape")
        if p.suffix.lower() in SKIP_SUFFIXES or not p.is_file() or p.stat().st_size > MAX_BYTES:
            continue
        if p.name == "private-words.txt":
            raise AssertionError(f"{p} is the owner's private word list and must never be tracked")
        files.append(p)
    return files


def read(p: Path) -> str:
    return p.read_bytes().decode("utf-8", "replace")


def private_words() -> list[str]:
    if not PRIVATE_WORDS_FILE.exists():
        return []
    return [w.strip() for w in PRIVATE_WORDS_FILE.read_text().splitlines() if w.strip() and not w.startswith("#")]


def scan() -> tuple[list[str], list[str]]:
    """(findings, notes): findings are violations, notes say what was and was not checked."""
    findings: list[str] = []
    files = tracked_files()
    words = private_words()
    word_res = [re.compile(r"(?<![A-Za-z0-9])" + re.escape(w) + r"(?![A-Za-z0-9])", re.I) for w in words]
    for p in files:
        text = read(p)
        rel = p.relative_to(ROOT)
        for m in IEEE.finditer(text):
            if not FAKE_IEEE.search(m.group(0)):
                findings.append(f"{rel}: address that does not read as a fixture: {m.group(0)}")
        for m in EMAIL.finditer(text):
            if not OK_EMAIL.search(m.group(0)):
                findings.append(f"{rel}: e-mail address: {m.group(0)}")
        for m in CRED_URL.finditer(text):
            if not OK_HOST.match(m.group(3)):
                findings.append(f"{rel}: credentials in a URL to {m.group(3)}")
        for w, rx in zip(words, word_res):
            if rx.search(text):
                # the word itself is never printed: only where it is and how long
                findings.append(f"{rel}: contains a private word ({len(w)} characters, #{words.index(w) + 1} in the list)")
    notes = [f"{len(files)} tracked files scanned",
             f"{len(words)} private words checked" if words else "private word list absent: names not checked (expected on CI)"]
    return findings, notes


def test_nothing_private_in_the_tree():
    findings, notes = scan()
    assert not findings, "\n".join(["private data in the repository:"] + findings + notes)
