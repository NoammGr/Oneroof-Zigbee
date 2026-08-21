#!/bin/sh
# Full verification: unit + integration + end-to-end (stack + browser). Browser tests skip if Chrome is absent.
set -e
cd "$(dirname "$0")"
PY=${PY:-.venv/bin/python}
$PY -m ruff check oneroof_zigbee tests addon --select E,F,B --ignore E501,B905
$PY -m pytest -q --timeout=120 "$@"
