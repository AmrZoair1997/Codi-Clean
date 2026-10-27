"""Filesystem helpers: sizes, safe-path rules, moving to the Trash, running tools."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import List, Optional, Tuple

HOME = os.path.expanduser("~")
CODI_HOME = os.path.join(HOME, ".codi")

# Never moved, whatever a scan says. Removing these would damage macOS or the
# account itself, and SIP blocks most of them anyway.
_PROTECTED_PREFIXES = ("/System", "/usr", "/bin", "/sbin", "/private/var/db",
                       "/Library/Apple", "/Library/Extensions", "/dev", "/cores")
_PROTECTED_EXACT = {"/", "/Applications", "/Library", "/Users", "/Users/Shared",
                    "/private", "/private/tmp", "/private/var", "/tmp", "/var",
                    "/Library/LaunchAgents", "/Library/LaunchDaemons", HOME, CODI_HOME}
_PROTECTED_HOME_CHILDREN = ("Library", "Desktop", "Documents", "Downloads", "Movies",
                            "Music", "Pictures", "Public", "Applications", ".Trash",
                            "Library/Caches", "Library/Logs", "Library/LaunchAgents",
                            "Library/Application Support", "Library/Preferences",
                            "Library/Containers", "Library/Group Containers",
                            "Library/Mail", "Library/Messages", "Library/Keychains",
                            "Library/Mobile Documents", "Library/CloudStorage")


def norm(path: str) -> str:
    return os.path.normpath(os.path.abspath(os.path.expanduser(path)))


def protected_reason(path: str) -> Optional[str]:
    """Why a path must never be moved, or None if moving it is allowed."""
    p = norm(path)
    if p in _PROTECTED_EXACT or p in {os.path.join(HOME, c) for c in _PROTECTED_HOME_CHILDREN}:
        return "this is a system or account folder"
    for prefix in _PROTECTED_PREFIXES:
        if p == prefix or p.startswith(prefix + "/"):
            return "this is part of macOS"
    if p.startswith(CODI_HOME + "/"):
        return "this is Codi's own data"
    return None


def dir_size(path: str, deadline: Optional[float] = None) -> Tuple[int, bool]:
    """Total bytes under path, not following links. Returns (bytes, complete)."""
    total, complete = 0, True
    stack = [path]
    while stack:
        if deadline and time.monotonic() > deadline:
            return total, False
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        else:
                            total += entry.stat(follow_symlinks=False).st_blocks * 512
                    except OSError:
                        complete = False
        except NotADirectoryError:
            try:
                total += os.lstat(current).st_blocks * 512
            except OSError:
                complete = False
        except OSError:
            complete = False
    return total, complete


def path_size(path: str) -> int:
    if os.path.isdir(path) and not os.path.islink(path):
        return dir_size(path)[0]
    try:
        return os.lstat(path).st_blocks * 512
    except OSError:
        return 0


def run(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """Run a local command without a shell. Never raises."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=timeout, stdin=subprocess.DEVNULL)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after {}s".format(timeout)
    except OSError as exc:
        return 127, "", str(exc)


def which(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    for folder in ("/opt/homebrew/bin", "/usr/local/bin"):
        candidate = os.path.join(folder, name)
        if os.access(candidate, os.X_OK):
            return candidate
    return None


_TRASH_JXA = """
ObjC.import('Foundation');
function run(argv) {
  var url = $.NSURL.fileURLWithPath(argv[0]);
  var ok = $.NSFileManager.defaultManager.trashItemAtURLResultingItemURLError(url, null, null);
  return ok ? 'ok' : 'fail';
}
"""


def move_to_trash(path: str) -> str:
    """Move to the macOS Trash (Finder's "Put Back" still works). Raises OSError."""
    p = norm(path)
    reason = protected_reason(p)
    if reason:
        raise OSError("refused: {} ({})".format(p, reason))
    if not os.path.lexists(p):
        raise FileNotFoundError(p)
    # The system Trash API first: it handles names, volumes and Put Back.
    rc, out, _err = run(["/usr/bin/osascript", "-l", "JavaScript", "-e", _TRASH_JXA, p], timeout=60)
    if rc == 0 and out.strip() == "ok" and not os.path.lexists(p):
        return "Trash"
    trash = os.path.join(HOME, ".Trash")
    name = os.path.basename(p)
    dest = os.path.join(trash, name)
    if os.path.lexists(dest):
        stem, ext = os.path.splitext(name)
        dest = os.path.join(trash, "{} {}{}".format(stem, time.strftime("%H.%M.%S"), ext))
    shutil.move(p, dest)
    return dest
