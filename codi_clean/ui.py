"""Terminal output and the prompts that ask for confirmation."""

from __future__ import annotations

import os
import sys
from typing import List, Optional

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _style(code: str, text: str) -> str:
    return "\033[{}m{}\033[0m".format(code, text) if _COLOR else text


def bold(text: str) -> str:
    return _style("1", text)


def dim(text: str) -> str:
    return _style("2", text)


def red(text: str) -> str:
    return _style("31", text)


def green(text: str) -> str:
    return _style("32", text)


def yellow(text: str) -> str:
    return _style("33", text)


def cyan(text: str) -> str:
    return _style("36", text)


SEVERITY_COLOR = {"high": red, "medium": yellow, "low": cyan, "info": dim}


def header(title: str) -> None:
    line = "=" * 64
    print("\n" + cyan(line))
    print("  " + bold(title))
    print(cyan(line))


def section(title: str) -> None:
    print("\n" + bold(title))
    print(dim("-" * len(title)))


def status(text: str) -> None:
    """A transient progress line, overwritten by the next one."""
    if sys.stdout.isatty():
        width = 78
        sys.stdout.write("\r" + text[:width].ljust(width))
        sys.stdout.flush()


def clear_status() -> None:
    if sys.stdout.isatty():
        sys.stdout.write("\r" + " " * 78 + "\r")
        sys.stdout.flush()


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024 or unit == "GB":
            return "{:.0f} {}".format(num, unit) if unit == "B" else "{:.1f} {}".format(num, unit)
        num /= 1024.0
    return "{:.1f} TB".format(num)


def ask(prompt: str) -> Optional[str]:
    """Read one answer; None means the input ended (Ctrl+D or no terminal)."""
    try:
        return input(prompt).strip()
    except EOFError:
        print()
        return None


def confirm(prompt: str, default: bool = False) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    answer = ask("{} {} ".format(prompt, hint))
    if answer is None:
        return False
    if not answer:
        return default
    return answer.lower() in ("y", "yes")


def confirm_typed(prompt: str, word: str) -> bool:
    """For permanent actions: the person must type the exact word."""
    answer = ask("{} Type {} to confirm: ".format(prompt, bold(word)))
    return answer == word


def parse_selection(text: str, count: int) -> Optional[List[int]]:
    """'1,3-5' -> [0, 2, 3, 4]. Returns None for invalid input."""
    chosen = []
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            start, _, end = part.partition("-")
            if not (start.isdigit() and end.isdigit()):
                return None
            low, high = int(start), int(end)
            if low > high:
                low, high = high, low
            numbers = range(low, high + 1)
        elif part.isdigit():
            numbers = [int(part)]
        else:
            return None
        for n in numbers:
            if not 1 <= n <= count:
                return None
            if n - 1 not in chosen:
                chosen.append(n - 1)
    return chosen
