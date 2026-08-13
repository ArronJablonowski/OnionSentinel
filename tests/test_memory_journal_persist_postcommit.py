"""Characterize post-commit memory receipt orchestration."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.persistence import memory_journal  # noqa: E402


class ReceiptWriteError(RuntimeError):
    pass


def invoke(**overrides: object) -> tuple[dict[str, object], Path | None]:
    values: dict[str, object] = {
        "analysis_id": "analysis-1",
        "agent_role": "soc-analyst",
        "role_memory_file": Path("/memory/role.md"),
        "shared_memory_file": Path("/memory/shared.md"),
        "source_artifact": "/analysis/result.json",
        "primary_candidates": [{"finding": "primary"}],
        "primary_allowed": True,
        "primary_reason": "eligible",
        "reviewer_candidates": [{"finding": "reviewer"}],
        "reviewer_allowed": False,
        "reviewer_reason": "not eligible",
        "receipt_dir": Path("/receipts"),
        "normalize_candidates": lambda value: value,
        "canonical_digest": lambda value: f"digest:{value}",
        "persist_candidates": lambda **_kwargs: {"stored": 1},
        "safe_filename": str,
        "atomic_write_private_json": lambda _path, _payload: None,
        "now": lambda: "2026-08-13T00:00:00Z",
    }
    values.update(overrides)
    return memory_journal.persist_postcommit(**values)


class MemoryJournalPersistPostcommitCharacterizationTests(unittest.TestCase):
    def test_success_preserves_lane_inputs_order_and_receipt_identity(self) -> None:
        calls: list[tuple[str, object]] = []
        primary = {"lane": "primary", "status": "persisted"}
        reviewer = {"lane": "reviewer", "status": "blocked"}
        primary_candidates = object()
        reviewer_candidates = object()
        analysis_id = "a" * 140
        dependencies = {
            "normalize_candidates": object(),
            "canonical_digest": None,
            "persist_candidates": object(),
        }

        def lane(**kwargs: object) -> dict[str, object]:
            calls.append(("lane", dict(kwargs)))
            return primary if kwargs["lane"] == "primary" else reviewer

        def now() -> str:
            calls.append(("now", None))
            return "2026-08-13T01:02:03Z"

        def safe(value: object) -> str:
            calls.append(("safe", value))
            return "safe-analysis"

        def digest(value: object) -> str:
            calls.append(("digest", (value, deepcopy(value))))
            return "receipt-digest"

        def write(path: Path, payload: dict[str, object]) -> None:
            calls.append(("write", (path, payload, deepcopy(payload))))

        dependencies["canonical_digest"] = digest
        with mock.patch.object(memory_journal, "_lane", side_effect=lane):
            receipt, receipt_path = invoke(
                analysis_id=analysis_id,
                primary_candidates=primary_candidates,
                reviewer_candidates=reviewer_candidates,
                normalize_candidates=dependencies["normalize_candidates"],
                canonical_digest=digest,
                persist_candidates=dependencies["persist_candidates"],
                safe_filename=safe,
                atomic_write_private_json=write,
                now=now,
            )

        self.assertEqual([name for name, _ in calls], [
            "now", "lane", "lane", "safe", "digest", "write",
        ])
        lane_calls = [value for name, value in calls if name == "lane"]
        self.assertEqual(lane_calls[0]["lane"], "primary")
        self.assertEqual(lane_calls[0]["analysis_id"], analysis_id)
        self.assertIs(lane_calls[0]["candidates"], primary_candidates)
        self.assertTrue(lane_calls[0]["allowed"])
        self.assertEqual(lane_calls[0]["reason"], "eligible")
        self.assertEqual(lane_calls[1]["lane"], "reviewer")
        self.assertEqual(lane_calls[1]["analysis_id"], f"{analysis_id}-reviewer")
        self.assertIs(lane_calls[1]["candidates"], reviewer_candidates)
        self.assertFalse(lane_calls[1]["allowed"])
        self.assertEqual(lane_calls[1]["reason"], "not eligible")
        for lane_call in lane_calls:
            self.assertEqual(lane_call["agent_role"], "soc-analyst")
            self.assertEqual(lane_call["role_memory_file"], Path("/memory/role.md"))
            self.assertEqual(lane_call["shared_memory_file"], Path("/memory/shared.md"))
            self.assertEqual(lane_call["source_artifact"], "/analysis/result.json")
            self.assertIs(
                lane_call["normalize_candidates"], dependencies["normalize_candidates"]
            )
            self.assertIs(lane_call["canonical_digest"], digest)
            self.assertIs(
                lane_call["persist_candidates"], dependencies["persist_candidates"]
            )

        digest_value, digest_snapshot = next(
            value for name, value in calls if name == "digest"
        )
        write_path, write_value, write_snapshot = next(
            value for name, value in calls if name == "write"
        )
        self.assertIs(digest_value, receipt)
        self.assertNotIn("receipt_storage", digest_snapshot)
        self.assertIs(write_value, receipt)
        self.assertEqual(write_path, Path("/receipts/safe-analysis.json"))
        self.assertEqual(write_snapshot["receipt_storage"], {
            "status": "stored",
            "receipt_payload_digest": "receipt-digest",
        })
        self.assertEqual(receipt_path, write_path)
        self.assertEqual(receipt["analysis_id"], "a" * 128)
        self.assertEqual(receipt["committed_memory_at"], "2026-08-13T01:02:03Z")
        self.assertIs(receipt["primary"], primary)
        self.assertIs(receipt["reviewer"], reviewer)
        self.assertTrue(receipt["authoritative_analysis_committed"])
        self.assertTrue(receipt["ok"])

    def test_storage_failure_replaces_storage_result_and_returns_no_path(self) -> None:
        calls: list[tuple[str, object]] = []

        def digest(value: object) -> str:
            calls.append(("digest", deepcopy(value)))
            return "payload-digest" if isinstance(value, dict) else "error-digest"

        def write(path: Path, payload: dict[str, object]) -> None:
            calls.append(("write", (path, payload, deepcopy(payload))))
            raise ReceiptWriteError("private write failed")

        with mock.patch.object(
            memory_journal,
            "_lane",
            side_effect=({"status": "persisted"}, {"status": "blocked"}),
        ):
            receipt, receipt_path = invoke(
                canonical_digest=digest,
                atomic_write_private_json=write,
            )

        self.assertIsNone(receipt_path)
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["receipt_storage"], {
            "status": "failed",
            "error_type": "ReceiptWriteError",
            "error_digest": "error-digest",
        })
        self.assertEqual(calls[0][0], "digest")
        self.assertNotIn("receipt_storage", calls[0][1])
        self.assertEqual(calls[1][0], "write")
        write_path, write_value, write_snapshot = calls[1][1]
        self.assertEqual(write_path, Path("/receipts/analysis-1.json"))
        self.assertIs(write_value, receipt)
        self.assertEqual(write_snapshot["receipt_storage"]["status"], "stored")
        self.assertEqual(calls[2], ("digest", "private write failed"))

    def test_lane_failure_sets_initial_ok_but_does_not_skip_reviewer_or_storage(self) -> None:
        calls: list[str] = []

        def lane(**kwargs: object) -> dict[str, object]:
            calls.append(str(kwargs["lane"]))
            return {"status": "failed" if kwargs["lane"] == "primary" else "blocked"}

        def write(_path: Path, payload: dict[str, object]) -> None:
            calls.append(f"write:{payload['ok']}")

        with mock.patch.object(memory_journal, "_lane", side_effect=lane):
            receipt, receipt_path = invoke(atomic_write_private_json=write)

        self.assertEqual(calls, ["primary", "reviewer", "write:False"])
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt_path, Path("/receipts/analysis-1.json"))


if __name__ == "__main__":
    unittest.main()
