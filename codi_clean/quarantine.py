"""Quarantine: move a flagged item into ~/.codi/quarantine so it can't run.

Each entry keeps a manifest with the original location, so it can be restored.
Purging is the only permanent step and needs the word DELETE typed out.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from typing import List

from . import fsutil, ui
from .fsutil import CODI_HOME, HOME

QUARANTINE_DIR = os.path.join(CODI_HOME, "quarantine")
_HASH_LIMIT = 512 * 1024 * 1024


@dataclass
class Entry:
    folder: str
    original: str
    title: str
    reason: str
    when: str
    size: int

    @property
    def item_path(self) -> str:
        return os.path.join(self.folder, "item", os.path.basename(self.original))


def _sha256(path: str) -> str:
    if not os.path.isfile(path) or os.path.islink(path) or os.path.getsize(path) > _HASH_LIMIT:
        return ""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _strip_exec(path: str) -> None:
    """Take away run permission from programs inside the quarantined item."""
    targets = [path]
    if os.path.isdir(path) and not os.path.islink(path):
        for folder, _dirs, files in os.walk(path):
            targets.extend(os.path.join(folder, f) for f in files)
    for target in targets:
        try:
            mode = os.lstat(target).st_mode
            if stat.S_ISREG(mode) and mode & 0o111:
                os.chmod(target, mode & ~0o111)
        except OSError:
            continue


def quarantine(path: str, title: str, reason: str, root: str = QUARANTINE_DIR) -> Entry:
    """Move path into quarantine. Raises OSError if it can't (e.g. needs admin)."""
    original = fsutil.norm(path)
    blocked = fsutil.protected_reason(original)
    if blocked:
        raise OSError("refused: {}".format(blocked))
    if not os.path.lexists(original):
        raise FileNotFoundError(original)
    os.makedirs(root, mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(original))[:60] or "item"
    folder = os.path.join(root, "{}-{}".format(stamp, safe))
    n = 2
    while os.path.exists(folder):
        folder = os.path.join(root, "{}-{}-{}".format(stamp, safe, n))
        n += 1
    os.makedirs(os.path.join(folder, "item"), mode=0o700)
    size = fsutil.path_size(original)
    manifest = {
        "original_path": original,
        "title": title,
        "reason": reason,
        "quarantined_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "size_bytes": size,
        "sha256": _sha256(original),
        "mode": stat.S_IMODE(os.lstat(original).st_mode),
    }
    dest = os.path.join(folder, "item", os.path.basename(original))
    try:
        shutil.move(original, dest)
    except OSError:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    _strip_exec(dest)
    with open(os.path.join(folder, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    return Entry(folder, original, title, reason, manifest["quarantined_at"], size)


def entries(root: str = QUARANTINE_DIR) -> List[Entry]:
    found = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return found
    for name in names:
        folder = os.path.join(root, name)
        try:
            with open(os.path.join(folder, "manifest.json")) as fh:
                m = json.load(fh)
        except (OSError, ValueError):
            continue
        found.append(Entry(folder, m.get("original_path", ""), m.get("title", ""),
                           m.get("reason", ""), m.get("quarantined_at", ""), m.get("size_bytes", 0)))
    return found


def restore(entry: Entry) -> str:
    """Put the item back where it was. Raises OSError if something is there now."""
    if os.path.lexists(entry.original):
        raise FileExistsError("something already exists at " + entry.original)
    with open(os.path.join(entry.folder, "manifest.json")) as fh:
        mode = json.load(fh).get("mode")
    os.makedirs(os.path.dirname(entry.original), exist_ok=True)
    shutil.move(entry.item_path, entry.original)
    if isinstance(mode, int) and not os.path.islink(entry.original):
        try:
            os.chmod(entry.original, mode)
        except OSError:
            pass
    shutil.rmtree(entry.folder, ignore_errors=True)
    return entry.original


def purge(entry: Entry) -> None:
    """Permanently delete a quarantined item. Cannot be undone."""
    root = os.path.dirname(entry.folder)
    if os.path.dirname(fsutil.norm(entry.folder)) != fsutil.norm(root) or \
            not os.path.exists(os.path.join(entry.folder, "manifest.json")):
        raise OSError("refused: not a Codi quarantine entry")
    for folder, dirs, files in os.walk(entry.folder):
        for name in dirs + files:
            try:
                os.chmod(os.path.join(folder, name), 0o700, follow_symlinks=False)
            except (OSError, NotImplementedError):
                pass
    shutil.rmtree(entry.folder)


def run_quarantine_menu() -> None:
    ui.header("Quarantine: review, restore or purge")
    items = entries()
    if not items:
        print("  Quarantine is empty.")
        return
    for number, e in enumerate(items, 1):
        print(" {:>3}  {}  {}".format(number, ui.bold(e.title), ui.dim(e.when.replace("T", " "))))
        print("      was at: {}".format(e.original.replace(HOME, "~")))
        print("      {}".format(ui.dim(e.reason)))
    total = sum(e.size for e in items)
    print("\n  {} items, {} in total, stored in {}".format(len(items), ui.human_size(total),
                                                          QUARANTINE_DIR.replace(HOME, "~")))
    print("\n    r 2      restore item 2 to where it was")
    print("    p 2      permanently delete item 2")
    print("    p all    permanently delete everything in quarantine")
    print("    Enter    go back")
    answer = ui.ask("  Your choice: ")
    if not answer:
        return
    action, _, which = answer.partition(" ")
    action = action.lower()
    if action not in ("r", "p"):
        print(ui.red("  Not a valid choice."))
        return
    if action == "p" and which.strip().lower() == "all":
        chosen = list(range(len(items)))
    else:
        chosen = ui.parse_selection(which, len(items))
        if not chosen:
            print(ui.red("  Not a valid item number."))
            return
    picked = [items[i] for i in chosen]
    if action == "r":
        for e in picked:
            try:
                print(ui.green("  Restored: " + restore(e).replace(HOME, "~")))
            except OSError as exc:
                print(ui.red("  Could not restore {}: {}".format(e.title, exc)))
        return
    print(ui.yellow("\n  This permanently deletes {} item(s). It cannot be undone.".format(len(picked))))
    if not ui.confirm_typed(" ", "DELETE"):
        print("  Cancelled. Nothing was deleted.")
        return
    for e in picked:
        try:
            purge(e)
            print(ui.green("  Deleted: " + e.title))
        except OSError as exc:
            print(ui.red("  Could not delete {}: {}".format(e.title, exc)))
