"""Option 1: find cache files and web junk, explain them, move chosen ones to the Trash."""

from __future__ import annotations

import glob
import os
import plistlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from . import fsutil, ui
from .fsutil import HOME

MIN_SIZE = 1024 * 1024          # items under 1 MB are counted, not listed
OLD_INSTALLER_DAYS = 14


@dataclass
class CacheItem:
    path: str
    category: str
    label: str
    description: str
    size: int = 0
    app_id: str = ""            # bundle id of the app that owns it, if known
    warning: str = ""
    recommended: bool = True    # included when the person picks "all"


@dataclass
class CacheScan:
    items: List[CacheItem] = field(default_factory=list)
    tiny_count: int = 0
    tiny_bytes: int = 0
    blocked: List[str] = field(default_factory=list)
    trash_bytes: Optional[int] = None


# Friendly descriptions for caches people commonly see. Anything else gets a
# generic description built from its folder name.
KNOWN_CACHES: Dict[str, str] = {
    "com.google.Chrome": "Google Chrome web cache: saved copies of pages, images and scripts",
    "Google": "Google apps cache (Chrome, Google Updater): temporary downloads and web data",
    "com.brave.Browser": "Brave browser web cache",
    "BraveSoftware": "Brave browser web cache",
    "com.microsoft.edgemac": "Microsoft Edge web cache",
    "Microsoft Edge": "Microsoft Edge web cache",
    "Firefox": "Firefox web cache: saved copies of pages, images and scripts",
    "org.mozilla.firefox": "Firefox web cache",
    "com.operasoftware.Opera": "Opera web cache",
    "com.vivaldi.Vivaldi": "Vivaldi web cache",
    "company.thebrowser.Browser": "Arc browser web cache",
    "com.spotify.client": "Spotify streaming cache: songs re-download when played",
    "com.tinyspeck.slackmacgap": "Slack cache: images and files from chats, re-downloaded on demand",
    "com.hnc.Discord": "Discord cache: images, videos and emoji from chats",
    "us.zoom.xos": "Zoom cache: temporary meeting and update files",
    "com.microsoft.teams2": "Microsoft Teams cache",
    "com.microsoft.Word": "Microsoft Word cache",
    "com.microsoft.Excel": "Microsoft Excel cache",
    "com.microsoft.Powerpoint": "Microsoft PowerPoint cache",
    "com.microsoft.Outlook": "Microsoft Outlook cache",
    "Homebrew": "Homebrew download cache: installers for packages already installed",
    "pip": "Python pip download cache: packages already installed",
    "Yarn": "Yarn JavaScript package cache",
    "node-gyp": "Node.js build headers cache",
    "JetBrains": "JetBrains IDE caches and indexes (rebuilt on next launch)",
    "com.todesktop.230313mzl4w4u92": "Cursor editor cache",
    "com.github.Electron": "Electron app cache",
    "ms-playwright": "Playwright test browsers (re-downloaded when tests need them)",
    "Adobe": "Adobe apps cache",
    "com.adobe.acc.AdobeCreativeCloud": "Adobe Creative Cloud cache",
    "com.grammarly.ProjectLlama": "Grammarly desktop cache",
    "com.anthropic.claudefordesktop": "Claude desktop app cache",
}

# Bundle ids whose caches belong to a running app. Used to warn before cleaning.
CACHE_OWNER: Dict[str, str] = {
    "Google": "com.google.Chrome", "BraveSoftware": "com.brave.Browser",
    "Microsoft Edge": "com.microsoft.edgemac", "Firefox": "org.mozilla.firefox",
}

CHROMIUM_BROWSERS = (
    ("Google Chrome", "Google/Chrome", "com.google.Chrome"),
    ("Brave", "BraveSoftware/Brave-Browser", "com.brave.Browser"),
    ("Microsoft Edge", "Microsoft Edge", "com.microsoft.edgemac"),
    ("Vivaldi", "Vivaldi", "com.vivaldi.Vivaldi"),
    ("Arc", "Arc/User Data", "company.thebrowser.Browser"),
)

# Per-profile web data that is rebuilt automatically and is mostly scripts,
# including ad and tracker scripts. Cookies and logins are never touched.
CHROMIUM_JUNK = (
    ("Service Worker/CacheStorage", "offline site storage saved by websites, much of it from ad and tracker scripts"),
    ("Code Cache", "compiled website scripts, including ad and tracker scripts"),
    ("GPUCache", "graphics cache for web pages"),
    ("DawnGraphiteCache", "graphics shader cache"),
    ("DawnWebGPUCache", "WebGPU shader cache"),
)

DEVELOPER_CACHES = (
    ("Library/Developer/Xcode/DerivedData", "Xcode build files; rebuilt next time you build"),
    ("Library/Developer/Xcode/iOS DeviceSupport", "Xcode debug symbols for iPhones; re-copied when a device connects"),
    ("Library/Developer/CoreSimulator/Caches", "iOS Simulator caches"),
    (".npm/_cacache", "npm JavaScript package download cache"),
    (".gradle/caches", "Gradle build cache"),
    (".cargo/registry/cache", "Rust crate download cache"),
    (".cache/pip", "Python pip download cache"),
)


def running_app_ids() -> Set[str]:
    """Bundle ids of open apps, read from the running .app bundles."""
    rc, out, _ = fsutil.run(["/bin/ps", "-axo", "comm="])
    ids: Set[str] = set()
    if rc != 0:
        return ids
    for line in out.splitlines():
        marker = line.find(".app/Contents/")
        if marker < 0:
            continue
        info = line[:marker + 4] + "/Contents/Info.plist"
        try:
            with open(info, "rb") as fh:
                bundle_id = plistlib.load(fh).get("CFBundleIdentifier")
            if bundle_id:
                ids.add(bundle_id)
        except (OSError, ValueError, plistlib.InvalidFileException):
            continue
    return ids


def _describe_cache(name: str) -> str:
    if name in KNOWN_CACHES:
        return KNOWN_CACHES[name]
    parts = name.split(".")
    if len(parts) >= 3 and parts[0] in ("com", "org", "net", "io", "us", "co", "app", "dev"):
        readable = "{} {}".format(parts[1].capitalize(), " ".join(parts[2:]))
    else:
        readable = name
    return "Cache for {}: temporary files the app re-creates when needed".format(readable)


def _add(scan: CacheScan, item: CacheItem) -> None:
    item.size = fsutil.path_size(item.path)
    if item.size < MIN_SIZE:
        scan.tiny_count += 1
        scan.tiny_bytes += item.size
        return
    scan.items.append(item)


def _app_caches(scan: CacheScan, running: Set[str]) -> None:
    root = os.path.join(HOME, "Library/Caches")
    try:
        names = sorted(os.listdir(root))
    except OSError:
        scan.blocked.append(root)
        return
    for name in names:
        # Apple's own caches are left alone: many are in use by the system and
        # macOS manages them itself.
        if name.startswith("com.apple.") or name.startswith("."):
            continue
        path = os.path.join(root, name)
        ui.status("Measuring " + path.replace(HOME, "~"))
        owner = CACHE_OWNER.get(name, name)
        item = CacheItem(path, "App caches", name, _describe_cache(name), app_id=owner)
        if owner in running:
            item.warning = "app is open; quit it first"
            item.recommended = False
        _add(scan, item)


def _browser_junk(scan: CacheScan, running: Set[str]) -> None:
    for browser, rel, bundle_id in CHROMIUM_BROWSERS:
        base = os.path.join(HOME, "Library/Application Support", rel)
        if not os.path.isdir(base):
            continue
        try:
            entries = os.listdir(base)
        except OSError:
            scan.blocked.append(base)
            continue
        profiles = [e for e in entries if e == "Default" or e.startswith("Profile ")]
        for profile in sorted(profiles):
            for sub, what in CHROMIUM_JUNK:
                path = os.path.join(base, profile, sub)
                if not os.path.isdir(path):
                    continue
                ui.status("Measuring " + path.replace(HOME, "~"))
                label = "{} ({}) {}".format(browser, profile, sub.split("/")[-1])
                item = CacheItem(path, "Browser ad & tracker data", label,
                                 "{}: {}. Logins and cookies are not touched".format(browser, what),
                                 app_id=bundle_id)
                if bundle_id in running:
                    item.warning = "browser is open; quit it first"
                    item.recommended = False
                _add(scan, item)


def _logs(scan: CacheScan) -> None:
    root = os.path.join(HOME, "Library/Logs")
    try:
        names = sorted(os.listdir(root))
    except OSError:
        scan.blocked.append(root)
        return
    for name in names:
        if name.startswith("."):
            continue
        path = os.path.join(root, name)
        what = ("crash reports from apps; only useful when reporting a bug"
                if name == "DiagnosticReports" else "log files written by {}".format(name))
        _add(scan, CacheItem(path, "Logs", name, "Logs: " + what))


def _developer(scan: CacheScan) -> None:
    for rel, what in DEVELOPER_CACHES:
        path = os.path.join(HOME, rel)
        if os.path.isdir(path):
            ui.status("Measuring " + path.replace(HOME, "~"))
            _add(scan, CacheItem(path, "Developer caches", rel, what))


def _old_installers(scan: CacheScan) -> None:
    root = os.path.join(HOME, "Downloads")
    cutoff = time.time() - OLD_INSTALLER_DAYS * 86400
    patterns = ("*.dmg", "*.pkg", "*.mpkg", "*.iso")
    try:
        found = sorted({p for pat in patterns for p in glob.glob(os.path.join(root, pat))})
    except OSError:
        scan.blocked.append(root)
        return
    for path in found:
        try:
            if os.lstat(path).st_mtime > cutoff:
                continue
        except OSError:
            continue
        kind = "disk image" if path.endswith((".dmg", ".iso")) else "installer package"
        _add(scan, CacheItem(path, "Old installers in Downloads", os.path.basename(path),
                             "Downloaded {} older than {} days; not needed once the app is installed"
                             .format(kind, OLD_INSTALLER_DAYS)))


def _trash_size(scan: CacheScan) -> None:
    trash = os.path.join(HOME, ".Trash")
    size, complete = fsutil.dir_size(trash)
    scan.trash_bytes = size if complete or size else None


def scan_caches() -> CacheScan:
    scan = CacheScan()
    running = running_app_ids()
    _app_caches(scan, running)
    _browser_junk(scan, running)
    _logs(scan)
    _developer(scan)
    _old_installers(scan)
    _trash_size(scan)
    ui.clear_status()
    return scan


def print_scan(scan: CacheScan) -> None:
    current = None
    for number, item in enumerate(scan.items, 1):
        if item.category != current:
            current = item.category
            ui.section(current)
        size = ui.human_size(item.size).rjust(9)
        warn = "  " + ui.yellow("! " + item.warning) if item.warning else ""
        print(" {:>3}  {}  {}{}".format(number, ui.bold(size), item.label, warn))
        print("      {}".format(ui.dim(item.description)))
        print("      {}".format(ui.dim(item.path.replace(HOME, "~"))))
    total = sum(i.size for i in scan.items)
    print("\n  Found {} items, {} in total.".format(len(scan.items), ui.bold(ui.human_size(total))))
    if scan.tiny_count:
        print(ui.dim("  {} smaller items ({}) under 1 MB were left out.".format(
            scan.tiny_count, ui.human_size(scan.tiny_bytes))))
    if scan.blocked:
        print(ui.yellow("  Blocked by macOS privacy protection (give Terminal Full Disk Access to include):"))
        for path in scan.blocked:
            print(ui.dim("    " + path.replace(HOME, "~")))


def run_cache_menu() -> None:
    ui.header("Cache files & web junk")
    print("  Scanning caches, logs, browser junk and old installers...")
    scan = scan_caches()
    if not scan.items:
        print("\n  Nothing worth cleaning was found.")
        return
    print_scan(scan)
    print("\n  Choose what to move to the Trash:")
    print("    a        all items without a warning")
    print("    1,3-5    only those numbers")
    print("    Enter    cancel, nothing is moved")
    answer = ui.ask("  Your choice: ")
    if not answer:
        print("  Cancelled. Nothing was moved.")
        return
    if answer.lower() in ("a", "all"):
        chosen = [i for i in scan.items if i.recommended]
    else:
        picks = ui.parse_selection(answer, len(scan.items))
        if picks is None:
            print(ui.red("  Not a valid choice. Nothing was moved."))
            return
        chosen = [scan.items[i] for i in picks]
    if not chosen:
        print("  Nothing selected.")
        return
    total = sum(i.size for i in chosen)
    print()
    for item in chosen:
        print("   - {}  {}".format(ui.human_size(item.size).rjust(9), item.path.replace(HOME, "~")))
    if any(i.warning for i in chosen):
        print(ui.yellow("  Some of these belong to open apps. Quit those apps first for a clean result."))
    if not ui.confirm("\n  Move these {} items ({}) to the Trash?".format(len(chosen), ui.human_size(total))):
        print("  Cancelled. Nothing was moved.")
        return
    moved, freed = 0, 0
    for item in chosen:
        try:
            fsutil.move_to_trash(item.path)
            moved += 1
            freed += item.size
        except OSError as exc:
            print(ui.red("  Could not move {}: {}".format(item.path.replace(HOME, "~"), exc)))
    print(ui.green("\n  Moved {} items ({}) to the Trash.".format(moved, ui.human_size(freed))))
    print("  The space is freed when you empty the Trash. Until then, Finder's 'Put Back' restores them.")
