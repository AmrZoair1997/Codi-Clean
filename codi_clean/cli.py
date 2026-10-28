"""`codi` opens the menu; `codi cache|malware|checkup|quarantine` runs one option directly."""

from __future__ import annotations

import os
import sys
from typing import List, Optional

from . import __version__, cache, checkup, malware, quarantine, ui

MENU = (
    ("1", "Cache files", "find caches, browser ad/tracker junk, logs and old installers", cache.run_cache_menu),
    ("2", "Malware & Spyware", "scan, explain each find, quarantine what you confirm", malware.run_malware_menu),
    ("3", "General check-up & summary", "read-only health check of this Mac", checkup.run_checkup),
    ("4", "Quarantine", "review, restore or permanently delete quarantined items", quarantine.run_quarantine_menu),
)

COMMANDS = {"cache": cache.run_cache_menu, "malware": malware.run_malware_menu,
            "checkup": checkup.run_checkup, "quarantine": quarantine.run_quarantine_menu}

USAGE = """usage: codi [cache | malware | checkup | quarantine]

  codi             open the menu
  codi cache       clean cache files and web junk
  codi malware     scan for malware, adware and spyware
  codi checkup     read-only check-up and summary
  codi quarantine  restore or purge quarantined items
"""


def _menu() -> int:
    while True:
        ui.header("Codi Clean {}  -  what would you like to do?".format(__version__))
        for key, title, hint, _ in MENU:
            print("   {}  {}  {}".format(ui.bold(key), title.ljust(28), ui.dim(hint)))
        print("   {}  Quit".format(ui.bold("q")))
        choice = ui.ask("\n  Choose 1-4: ")
        if choice is None or choice.lower() in ("q", "quit", "exit", "0"):
            return 0
        for key, _title, _hint, action in MENU:
            if choice == key:
                try:
                    action()
                except KeyboardInterrupt:
                    ui.clear_status()
                    print("\n  Stopped. Nothing further was changed.")
                ui.ask(ui.dim("\n  Press Enter to return to the menu..."))
                break
        else:
            print(ui.red("  Please type 1, 2, 3, 4 or q."))


def main(argv: Optional[List[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if sys.platform != "darwin":
        print("Codi Clean is built for macOS.", file=sys.stderr)
        return 1
    if os.geteuid() == 0:
        print("Please run codi without sudo. It never needs admin rights.", file=sys.stderr)
        return 1
    try:
        if not args:
            return _menu()
        if args[0] in ("-h", "--help", "help"):
            print(USAGE)
            return 0
        if args[0] in ("-V", "--version"):
            print("Codi Clean " + __version__)
            return 0
        action = COMMANDS.get(args[0])
        if not action or len(args) > 1:
            print(USAGE, file=sys.stderr)
            return 2
        action()
        return 0
    except KeyboardInterrupt:
        ui.clear_status()
        print("\n  Stopped. Nothing further was changed.")
        return 130
