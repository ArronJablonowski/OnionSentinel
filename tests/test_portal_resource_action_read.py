#!/usr/bin/env python3
"""Direct contracts for Resource Library action-status reads."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_resource_action_read import read_resource_action_status  # noqa: E402


ACTION_ID = "01234567-89ab-cdef-0123-456789abcdef"


class ResourceActionReadTests(unittest.TestCase):
    def test_other_operation_is_declined_without_filesystem_access(self) -> None:
        result = read_resource_action_status(
            "health", {}, status_directory=Path("/does/not/matter"),
        )
        self.assertIsNone(result)

    def test_invalid_action_id_is_rejected(self) -> None:
        result = read_resource_action_status(
            "resource_action_status", {"id": ["../../secret"]},
            status_directory=Path("/does/not/matter"),
        )
        self.assertEqual(result.status, 400)
        self.assertIn("Invalid", result.payload["error"])

    def test_missing_status_is_pending(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = read_resource_action_status(
                "resource_action_status", {"id": [ACTION_ID]},
                status_directory=Path(raw),
            )
        self.assertEqual(result.payload, {"ok": True, "state": "pending"})
        self.assertFalse(result.encoded)

    def test_existing_status_is_delivered_byte_for_byte(self) -> None:
        expected = b'{"ok":true,"state":"complete"}'
        with tempfile.TemporaryDirectory() as raw:
            (Path(raw) / f"{ACTION_ID}.json").write_bytes(expected)
            result = read_resource_action_status(
                "resource_action_status", {"id": [ACTION_ID]},
                status_directory=Path(raw),
            )
        self.assertTrue(result.encoded)
        self.assertEqual(result.payload, expected)


if __name__ == "__main__":
    unittest.main()
