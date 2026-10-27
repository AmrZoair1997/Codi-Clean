"""Remembers the last malware scan, so the check-up can summarise it."""

from __future__ import annotations

import datetime
import json
import os
from typing import Optional

from .fsutil import CODI_HOME

STATE_FILE = os.path.join(CODI_HOME, "state.json")


def load() -> dict:
    try:
        with open(STATE_FILE) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    os.makedirs(CODI_HOME, mode=0o700, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, STATE_FILE)


def record_scan(report, removed: int, seconds: float) -> None:
    counts = {}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    zb = report.zero_breach
    data = load()
    data["last_malware_scan"] = {
        "when": datetime.datetime.now().isoformat(timespec="seconds"),
        "findings": counts,
        "quarantined": removed,
        "seconds": round(seconds),
        "zero_breach": None if zb is None else {"ran": zb.ran, "hits": len(zb.hits), "gaps": len(zb.gaps)},
    }
    try:
        _save(data)
    except OSError:
        pass


def last_scan() -> Optional[dict]:
    value = load().get("last_malware_scan")
    return value if isinstance(value, dict) else None
