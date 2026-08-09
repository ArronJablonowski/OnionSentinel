#!/usr/bin/env python3
"""CLI entry point for the bounded Onion Sentinel cohort runner."""
from __future__ import annotations

import sys
from pathlib import Path


OPERATIONS_DIR = Path(__file__).resolve().parent
if str(OPERATIONS_DIR) not in sys.path:
    sys.path.insert(0, str(OPERATIONS_DIR))

from cohort_runner_service import build_parser, main  # noqa: E402


__all__ = ["build_parser", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
