#!/usr/bin/env python3
"""Entry point, so Codi runs without being installed: python3 -I codi.py."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from codi_clean.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
