"""Durability contracts for owner-only portal JSON persistence."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_atomic_json_store import write_owner_only_json  # noqa: E402


class PortalAtomicJsonStoreTests(unittest.TestCase):
    def test_write_is_owner_only_synced_and_leaves_only_final_document(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "settings.json"
            with mock.patch(
                "portal_atomic_json_store.os.fsync",
                wraps=os.fsync,
            ) as sync:
                write_owner_only_json(path, {"route": "ollama:primary"})

            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"route": "ollama:primary"},
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertGreaterEqual(sync.call_count, 2)
            self.assertEqual(list(path.parent.iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
