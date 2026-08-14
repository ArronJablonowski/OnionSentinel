#!/usr/bin/env python3
"""Run the deterministic untrusted-telemetry release gate."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    """Execute the checked-in cross-boundary adversarial contract."""
    suite = unittest.defaultTestLoader.loadTestsFromName(
        "tests.test_untrusted_telemetry_adversarial_gate"
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 2


if __name__ == "__main__":
    raise SystemExit(main())
