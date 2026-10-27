"""Optional extra: run the audited Zero Breach Toolkit offline and read its report.

The toolkit is used unchanged from its own folder. It only reads; Codi decides
what to offer afterwards. Zero Breach looks for mercenary spyware (Pegasus,
Candiru, Predator...), not everyday adware.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

from .fsutil import HOME

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TOOLKIT = os.path.join(os.path.dirname(_HERE), "Zero-Breach-Toolkit-main")
TIMEOUT_S = 45 * 60


@dataclass
class ZbHit:
    indicator: str
    location: str
    detail: str
    evidence: str
    source: str


@dataclass
class ZbResult:
    ran: bool
    status: str = ""
    exit_code: Optional[int] = None
    hits: List[ZbHit] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    must_relay: List[str] = field(default_factory=list)
    help_links: List[str] = field(default_factory=list)
    error: str = ""


def toolkit_script(base: Optional[str] = None) -> Optional[str]:
    base = base or os.environ.get("CODI_ZERO_BREACH") or DEFAULT_TOOLKIT
    script = os.path.join(base, "scan", "zero-breach-toolkit.py")
    return script if os.path.isfile(script) else None


def parse_report(document: dict) -> ZbResult:
    result = ZbResult(ran=True)
    verdict = document.get("verdict") or {}
    result.status = str(verdict.get("status", ""))
    result.gaps = [str(g) for g in verdict.get("gaps") or []]
    result.exit_code = document.get("exit_code")
    for module in (document.get("modules") or {}).values():
        for hit in module.get("hits") or []:
            result.hits.append(ZbHit(str(hit.get("indicator", "")), str(hit.get("location", "")),
                                     str(hit.get("detail", "")), str(hit.get("evidence", "")),
                                     str(hit.get("source", ""))))
    result.must_relay = [str(m.get("text", "")) for m in document.get("must_relay") or []]
    for step in document.get("next_steps") or []:
        result.help_links.extend(str(link) for link in step.get("links") or [])
    return result


def run_scan(base: Optional[str] = None) -> ZbResult:
    script = toolkit_script(base)
    if not script:
        return ZbResult(ran=False, error="Zero Breach Toolkit not found (expected at {})".format(
            DEFAULT_TOOLKIT.replace(HOME, "~")))
    with tempfile.TemporaryDirectory(prefix="codi_zb_") as tmp:
        report = os.path.join(tmp, "report.json")
        cmd = [sys.executable, "-I", script, "--no-menu", "--no-banner", "--no-feeds",
               "--scan-type", "default", "--json", report]
        try:
            proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.PIPE, text=True, errors="replace",
                                  timeout=TIMEOUT_S, cwd=tmp)
        except subprocess.TimeoutExpired:
            return ZbResult(ran=False, error="Zero Breach did not finish within 45 minutes")
        except OSError as exc:
            return ZbResult(ran=False, error=str(exc))
        try:
            with open(report, encoding="utf-8") as fh:
                document = json.load(fh)
        except (OSError, ValueError):
            tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no report was written"]
            return ZbResult(ran=False, exit_code=proc.returncode, error=tail[0][:200])
    result = parse_report(document)
    result.exit_code = proc.returncode
    return result
