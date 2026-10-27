"""Explain what a file is: its kind, who signed it, where it came from."""

from __future__ import annotations

import datetime
import os
import plistlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import fsutil
from .fsutil import HOME

_MACHO_MAGIC = {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}

_signing_cache: Dict[str, "Signing"] = {}


@dataclass
class Signing:
    signed: bool = False
    adhoc: bool = False
    apple: bool = False
    team: str = ""
    authority: List[str] = field(default_factory=list)
    identifier: str = ""
    error: str = ""

    def summary(self) -> str:
        if self.error:
            return "could not check ({})".format(self.error)
        if not self.signed:
            return "NOT signed: the developer is unknown"
        if self.adhoc:
            return "ad-hoc signed only: no verified developer"
        if self.apple:
            return "signed by Apple"
        who = self.authority[0] if self.authority else "unknown developer"
        return "signed: {}{}".format(who, " (team {})".format(self.team) if self.team else "")


def file_kind(path: str) -> str:
    if path.endswith(".app") and os.path.isdir(path):
        return "app"
    if path.endswith(".plist"):
        return "plist"
    if path.endswith((".dmg", ".iso")):
        return "disk image"
    if path.endswith((".pkg", ".mpkg")):
        return "installer"
    if os.path.isdir(path):
        return "folder"
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return "file"
    if head in _MACHO_MAGIC:
        return "program"
    if head[:2] == b"#!":
        return "script"
    return "file"


def signing(path: str) -> Signing:
    """codesign -dv: reads the signature without verifying every file (fast)."""
    if path in _signing_cache:
        return _signing_cache[path]
    rc, _out, err = fsutil.run(["/usr/bin/codesign", "-dv", "--verbose=2", path], timeout=20)
    info = Signing()
    if "not signed at all" in err:
        pass
    elif rc != 0:
        info.error = err.strip().splitlines()[-1][:80] if err.strip() else "codesign failed"
    else:
        info.signed = True
        for line in err.splitlines():
            key, _, value = line.partition("=")
            if key == "Authority":
                info.authority.append(value)
            elif key == "TeamIdentifier" and value != "not set":
                info.team = value
            elif key == "Identifier":
                info.identifier = value
            elif key == "Signature" and value == "adhoc":
                info.adhoc = True
        info.apple = bool(info.authority) and info.authority[-1] == "Apple Root CA" and \
            any(a.startswith(("Software Signing", "Apple Mac OS Application Signing")) for a in info.authority)
    _signing_cache[path] = info
    return info


def downloaded_from(path: str) -> str:
    rc, out, _ = fsutil.run(["/usr/bin/mdls", "-raw", "-name", "kMDItemWhereFroms", path], timeout=10)
    if rc != 0 or not out or out.strip() == "(null)":
        return ""
    urls = re.findall(r'"([^"]+)"', out)
    return urls[0] if urls else ""


def launch_plist_info(path: str) -> Optional[dict]:
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None
    if not isinstance(data, dict):
        return None
    args = data.get("ProgramArguments") or []
    if not isinstance(args, list):
        args = []
    program = data.get("Program") or (args[0] if args else "")
    return {
        "label": str(data.get("Label", "")),
        "program": str(program),
        "args": [str(a) for a in args],
        "run_at_load": bool(data.get("RunAtLoad")),
        "keep_alive": bool(data.get("KeepAlive")),
        "interval": data.get("StartInterval"),
    }


def _when(path: str) -> str:
    try:
        stamp = os.lstat(path).st_mtime
    except OSError:
        return "unknown"
    return datetime.datetime.fromtimestamp(stamp).strftime("%Y-%m-%d")


def describe(path: str) -> List[str]:
    """Plain-language facts about a path, one per line."""
    lines = []
    kind = file_kind(path)
    short = path.replace(HOME, "~")
    if kind == "plist" and "/Launch" in path:
        info = launch_plist_info(path)
        if info:
            where = "every time you log in" if "LaunchAgents" in path else "at startup, for all users"
            lines.append("What it is: a startup item that runs a program {}".format(where))
            lines.append("Name (label): {}".format(info["label"] or "none"))
            command = " ".join(info["args"]) if info["args"] else info["program"]
            lines.append("Runs: {}".format((command or "nothing")[:160]))
            behaviour = []
            if info["run_at_load"]:
                behaviour.append("starts automatically")
            if info["keep_alive"]:
                behaviour.append("restarts itself if stopped")
            if info["interval"]:
                behaviour.append("repeats every {} seconds".format(info["interval"]))
            if behaviour:
                lines.append("Behaviour: " + ", ".join(behaviour))
            target = info["program"]
            if target and os.path.exists(target):
                lines.append("Program signature: " + signing(target).summary())
            elif target:
                lines.append("Program: missing (the item is a leftover pointing at nothing)")
        else:
            lines.append("What it is: a startup item that could not be read")
    else:
        names = {"app": "an application", "program": "a compiled program",
                 "script": "a script (text commands that run when started)",
                 "disk image": "a disk image (installer download)",
                 "installer": "an installer package", "folder": "a folder", "file": "a file",
                 "plist": "a settings file"}
        lines.append("What it is: " + names.get(kind, "a file"))
        if kind in ("app", "program", "installer", "disk image"):
            lines.append("Signature: " + signing(path).summary())
        source = downloaded_from(path)
        if source:
            lines.append("Downloaded from: " + source[:160])
    lines.append("Size: {}   Last changed: {}".format(_size_text(path), _when(path)))
    lines.append("Location: " + short)
    return lines


def _size_text(path: str) -> str:
    from .ui import human_size
    return human_size(fsutil.path_size(path))
