"""Direct contracts for the extracted memory writeback journal."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.persistence import memory_journal  # noqa: E402


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def normalize(value: object) -> list[dict]:
    return list(value) if isinstance(value, list) else []


def load(path: Path, _limit: int) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_private(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


class MemoryJournalPackageTests(unittest.TestCase):
    def stage(self, root: Path, analysis_id: str = "analysis-1") -> Path:
        result = memory_journal.stage(
            analysis_id=analysis_id,
            response_digest="a" * 64,
            agent_role="soc-analyst",
            role_memory_file=root / "role.md",
            shared_memory_file=root / "shared.md",
            source_artifact="/synthetic/result.json",
            primary_candidates=[{"scope": "agent", "finding": "bounded"}],
            primary_allowed=True,
            primary_reason="eligible",
            reviewer_candidates=[],
            reviewer_allowed=False,
            reviewer_reason="not reviewed",
            pending_dir=root / "pending",
            schema="memory-task-v1",
            max_bytes=64 * 1024,
            normalize_candidates=normalize,
            canonical_digest=digest,
            safe_filename=str,
            load_json=load,
            atomic_write_private_json=write_private,
        )
        self.assertIsNotNone(result)
        assert result is not None
        return result

    def test_stage_is_private_idempotent_and_digest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            staged = self.stage(root)
            self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
            task = load(staged, 64 * 1024)
            self.assertEqual(task["submitted_response_sha256"], "a" * 64)
            self.assertEqual(
                task["primary"]["candidate_manifest_digest"],
                digest(task["primary"]["candidates"]),
            )
            self.assertEqual(self.stage(root), staged)

    def test_commit_is_atomic_and_refuses_wrong_response_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            staged = self.stage(root)
            with self.assertRaisesRegex(RuntimeError, "not bound"):
                memory_journal.mark_committed(
                    "analysis-1", expected_response_digest="b" * 64,
                    pending_dir=staged.parent, committed_dir=root / "committed",
                    max_bytes=64 * 1024, safe_filename=str,
                    load_json=load, canonical_digest=digest,
                )
            committed = memory_journal.mark_committed(
                "analysis-1", expected_response_digest="a" * 64,
                pending_dir=staged.parent, committed_dir=root / "committed",
                max_bytes=64 * 1024, safe_filename=str,
                load_json=load, canonical_digest=digest,
            )
            self.assertIsNotNone(committed)
            assert committed is not None
            self.assertFalse(staged.exists())
            self.assertEqual(committed.stat().st_mode & 0o777, 0o600)

    def test_manifest_tampering_is_rejected_before_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            staged = self.stage(root)
            committed = root / "committed" / staged.name
            committed.parent.mkdir()
            staged.replace(committed)
            task = load(committed, 64 * 1024)
            task["primary"]["candidates"].append({"finding": "tampered"})
            write_private(committed, task)
            invoked: list[bool] = []
            with self.assertRaisesRegex(RuntimeError, "manifest"):
                memory_journal.process_committed(
                    committed, receipt_dir=root / "receipts",
                    schema="memory-task-v1", max_bytes=64 * 1024,
                    safe_filename=str, load_json=load,
                    canonical_digest=digest,
                    persist=lambda **_kwargs: invoked.append(True),
                )
            self.assertEqual(invoked, [])

    def test_receipt_contains_digests_not_candidate_text(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            secret_finding = "sensitive evidence text excluded from receipt"
            receipt, receipt_path = memory_journal.persist_postcommit(
                analysis_id="analysis-1", agent_role="soc-analyst",
                role_memory_file=root / "role.md",
                shared_memory_file=root / "shared.md",
                source_artifact="/synthetic/result.json",
                primary_candidates=[{"finding": secret_finding}],
                primary_allowed=True, primary_reason="eligible",
                reviewer_candidates=[], reviewer_allowed=False,
                reviewer_reason="not reviewed", receipt_dir=root / "receipts",
                normalize_candidates=normalize, canonical_digest=digest,
                persist_candidates=lambda **_kwargs: {"stored": 1},
                safe_filename=str, atomic_write_private_json=write_private,
                now=lambda: "2026-08-06T00:00:00Z",
            )
            self.assertTrue(receipt["ok"])
            self.assertIsNotNone(receipt_path)
            assert receipt_path is not None
            self.assertNotIn(secret_finding, receipt_path.read_text())
            self.assertRegex(
                receipt["primary"]["candidate_manifest_digest"],
                r"^[a-f0-9]{64}$",
            )


if __name__ == "__main__":
    unittest.main()
