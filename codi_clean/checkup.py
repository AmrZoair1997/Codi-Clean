"""Option 3: a read-only health check of the Mac and a summary of Codi's findings."""

from __future__ import annotations

import datetime
import os
import platform
import plistlib
import shutil
from typing import List, Tuple

from . import cache, fsutil, malware, quarantine, state, ui, zerobreach
from .fsutil import HOME

OK, WARN, BAD = "ok", "warn", "bad"
_MARK = {OK: lambda t: ui.green("  ✓ " + t), WARN: lambda t: ui.yellow("  ! " + t),
         BAD: lambda t: ui.red("  ✗ " + t)}

_XPROTECT_PLISTS = (
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
    "/private/var/protected/xprotect/XProtect.bundle/Contents/Info.plist",
)


def _line(level: str, text: str, tips: List[str], tip: str = "") -> None:
    print(_MARK[level](text))
    if tip and level != OK:
        tips.append(tip)


def _protections(tips: List[str]) -> None:
    ui.section("Built-in protection")
    rc, out, _ = fsutil.run(["/usr/bin/csrutil", "status"])
    enabled = "enabled" in out.lower() and "disabled" not in out.lower()
    _line(OK if enabled else BAD, "System Integrity Protection: " + ("on" if enabled else "OFF"),
          tips, "Turn System Integrity Protection back on (needs Recovery mode); it protects macOS files.")

    rc, out, err = fsutil.run(["/usr/sbin/spctl", "--status"])
    gk = "enabled" in (out + err)
    _line(OK if gk else BAD, "Gatekeeper (blocks unverified apps): " + ("on" if gk else "OFF"), tips,
          "Turn Gatekeeper back on: System Settings > Privacy & Security > allow apps from the App Store "
          "and identified developers.")

    rc, out, _ = fsutil.run(["/usr/bin/fdesetup", "status"])
    fv = "FileVault is On" in out
    _line(OK if fv else WARN, "FileVault disk encryption: " + ("on" if fv else "off"), tips,
          "Turn on FileVault (System Settings > Privacy & Security) so a lost Mac can't be read.")

    rc, out, _ = fsutil.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    fw = "enabled" in out.lower()
    _line(OK if fw else WARN, "Firewall: " + ("on" if fw else "off"), tips,
          "Turn on the firewall: System Settings > Network > Firewall.")

    version = ""
    for path in _XPROTECT_PLISTS:
        try:
            with open(path, "rb") as fh:
                version = str(plistlib.load(fh).get("CFBundleShortVersionString", ""))
                break
        except (OSError, ValueError, plistlib.InvalidFileException):
            continue
    _line(OK if version else WARN, "XProtect (Apple's built-in malware scanner): " +
          ("version " + version if version else "version unknown"), tips)

    rc, out, _ = fsutil.run(["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
                             "CriticalUpdateInstall"])
    auto = out.strip() != "0"
    _line(OK if auto else WARN, "Automatic security updates: " + ("on" if auto else "off"), tips,
          "Turn on 'Install Security Responses and system files' in System Settings > General > "
          "Software Update > Automatic Updates.")

    try:
        os.listdir(os.path.join(HOME, "Library/Safari"))
        fda = True
    except OSError:
        fda = False
    _line(OK if fda else WARN, "Terminal has Full Disk Access: " + ("yes" if fda else
          "no (browser checks are limited)"), tips,
          "Optional: give Terminal Full Disk Access (System Settings > Privacy & Security) so Codi "
          "can check browsers. You can turn it off again afterwards.")


def _system(tips: List[str]) -> None:
    ui.section("This Mac")
    print("  macOS {}  ({})".format(platform.mac_ver()[0], platform.machine()))
    usage = shutil.disk_usage("/")
    free_pct = usage.free / usage.total * 100
    level = OK if free_pct >= 15 else WARN if free_pct >= 8 else BAD
    _line(level, "Free disk space: {} of {} ({:.0f}%)".format(
        ui.human_size(usage.free), ui.human_size(usage.total), free_pct), tips,
        "Disk space is low: run option 1 (Cache files) and empty the Trash.")


def _junk(tips: List[str]) -> int:
    ui.section("Cache & junk (nothing is removed here)")
    scan = cache.scan_caches()
    by_cat: dict = {}
    for item in scan.items:
        by_cat[item.category] = by_cat.get(item.category, 0) + item.size
    for category, size in sorted(by_cat.items(), key=lambda kv: -kv[1]):
        print("  {:>10}  {}".format(ui.human_size(size), category))
    total = sum(by_cat.values())
    print("  {:>10}  {}".format(ui.bold(ui.human_size(total)), ui.bold("could be cleaned")))
    if scan.blocked:
        print(ui.dim("  Browser junk not measured: macOS privacy protection blocked {} folder(s).".format(
            len(scan.blocked))))
    if scan.trash_bytes:
        print(ui.dim("  The Trash already holds {}; empty it in Finder to free that space.".format(
            ui.human_size(scan.trash_bytes))))
    if total > 2 * 1024 ** 3:
        tips.append("Over {} of caches can be cleaned with option 1.".format(ui.human_size(total)))
    return total


def _security(tips: List[str]) -> Tuple[int, int]:
    ui.section("Startup items & quick security look")
    report = malware.Report()
    malware.check_launch_items(report)
    malware.check_profiles(report)
    ui.clear_status()
    high = sum(1 for f in report.findings if f.severity == "high")
    other = len(report.findings) - high
    print("  {} startup items checked.".format(report.checked.get("startup items", 0)))
    if high:
        _line(BAD, "{} high-risk startup item(s)".format(high), tips,
              "Run option 2 (Malware & Spyware) to review the high-risk startup items.")
    if other:
        _line(WARN, "{} startup item(s) worth a look (often leftovers or unsigned helpers)".format(other),
              tips, "Run option 2 to see the startup items worth a look.")
    if not report.findings:
        _line(OK, "No suspicious startup items", tips)
    for f in report.findings[:5]:
        print(ui.dim("     - {}: {}".format(f.title, f.reasons[0][:90])))
    return high, other


def _codi(tips: List[str]) -> None:
    ui.section("Codi history")
    last = state.last_scan()
    if last:
        when = last.get("when", "").replace("T", " ")
        counts = last.get("findings") or {}
        found = ", ".join("{} {}".format(v, k) for k, v in counts.items()) or "nothing found"
        print("  Last malware scan: {}  ({}; {} quarantined)".format(when, found, last.get("quarantined", 0)))
        zb = last.get("zero_breach")
        if zb and zb.get("ran"):
            print("  Last Zero Breach spyware check: {} match(es)".format(zb.get("hits", 0)))
        try:
            age = datetime.datetime.now() - datetime.datetime.fromisoformat(last.get("when", ""))
            if age.days > 30:
                tips.append("Your last malware scan was {} days ago; run option 2.".format(age.days))
        except ValueError:
            pass
    else:
        print("  No malware scan yet.")
        tips.append("Run option 2 (Malware & Spyware) for a full scan.")
    items = quarantine.entries()
    print("  Quarantine: {} item(s){}".format(len(items), "" if not items else ", " + ui.human_size(
        sum(e.size for e in items))))
    print("  ClamAV antivirus: " + ("installed" if fsutil.which("clamscan") else
                                    "not installed (optional: brew install clamav)"))
    print("  Zero Breach Toolkit: " + ("found" if zerobreach.toolkit_script() else "not found"))


def run_checkup() -> None:
    ui.header("General check-up & summary")
    print("  Read-only: this option looks, it never removes anything.")
    tips: List[str] = []
    _system(tips)
    _protections(tips)
    _security(tips)
    _junk(tips)
    _codi(tips)
    ui.section("Suggestions")
    if tips:
        for tip in tips:
            print("  • " + tip)
    else:
        print(ui.green("  Everything looks good."))
