"""Release hygiene: the two changelog copies are one text, the three version strings agree,
and the newest changelog entry is the version being shipped. Each of these bit a release."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_changelog_copies_are_identical():
    assert (ROOT / "CHANGELOG.md").read_bytes() == (ROOT / "addon" / "CHANGELOG.md").read_bytes(), \
        "addon/CHANGELOG.md is what Home Assistant shows: copy the root CHANGELOG.md over it"


def test_versions_agree_and_the_changelog_leads_with_them():
    cfg = re.search(r'^version:\s*"([^"]+)"', (ROOT / "addon" / "config.yaml").read_text(), re.M).group(1)
    pyp = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
    ini = re.search(r'^__version__\s*=\s*"([^"]+)"', (ROOT / "addon" / "oneroof_zigbee" / "__init__.py").read_text(), re.M).group(1)
    assert cfg == pyp == ini, f"versions differ: config.yaml {cfg}, pyproject {pyp}, __init__ {ini}"
    top = re.search(r"^## \[?([0-9][^\]\s]*)", (ROOT / "CHANGELOG.md").read_text(), re.M).group(1)
    assert top == cfg, f"the changelog leads with {top} but the add-on is {cfg}"
