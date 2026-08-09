#!/usr/bin/env python3
"""Crash-recovery contracts for commit-gated agent-memory writeback."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
RUNNER_PATH = BIN_DIR / "run-local-ai-analysis.py"
LEGACY_PIPELINE_PATH = (
    REPO_ROOT / "n8n/onion_sentinel/legacy_pipeline.py"
)


def load_runner():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    module_name = "run_local_ai_analysis_memory_journal_tests"
    spec = importlib.util.spec_from_file_location(module_name, RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class MemoryWritebackJournalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()
        cls.memory = sys.modules["agent_memory"]

    @staticmethod
    def candidate(
        *,
        scope: str = "agent",
        finding: str = (
            "Correlate TLS SNI with certificate and destination history "
            "before concluding that recurring encrypted traffic is malicious."
        ),
    ) -> dict:
        return {
            "scope": scope,
            "category": "investigation_pivot",
            "finding": finding,
            "use_when": (
                "A later TLS alert involves the same infrastructure."
            ),
            "evidence_basis": [
                "Current Zeek and alert evidence independently agreed.",
            ],
            "confidence": "high" if scope == "shared" else "medium",
            "tags": ["tls", "zeek"],
            "ttl_days": 30,
        }

    def stage_task(
        self,
        root: Path,
        *,
        analysis_id: str,
        candidates: list[dict] | None = None,
        response_digest: str = "a" * 64,
    ) -> tuple[Path, Path, Path]:
        role_memory = root / "memory" / "role.md"
        shared_memory = root / "memory" / "shared.md"
        role_memory.parent.mkdir(mode=0o700)
        role_memory.write_text("# Role Memory\n", encoding="utf-8")
        shared_memory.write_text("# Shared Memory\n", encoding="utf-8")
        role_memory.chmod(0o600)
        shared_memory.chmod(0o600)
        pending_dir = root / "journal" / "pending"
        task_path = self.runner.stage_memory_writeback_task(
            analysis_id=analysis_id,
            response_digest=response_digest,
            agent_role="soc-analyst",
            role_memory_file=role_memory,
            shared_memory_file=shared_memory,
            source_artifact="/tmp/synthetic-analysis.json",
            primary_candidates=candidates or [self.candidate()],
            primary_allowed=True,
            primary_reason="eligible after authoritative commit",
            reviewer_candidates=[],
            reviewer_allowed=False,
            reviewer_reason="reviewer did not complete",
            pending_dir=pending_dir,
        )
        self.assertIsNotNone(task_path)
        assert task_path is not None
        return task_path, role_memory, shared_memory

    def test_transient_queue_replay_commits_memory_only_after_index_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            analysis_id = "transient-memory-replay"
            queue_dir = root / "index-queue"
            quarantine_dir = root / "index-quarantine"
            committed_dir = root / "journal" / "committed"
            receipt_dir = root / "journal" / "receipts"
            response = {"summary": "bounded synthetic result"}
            pending_task, role_memory, _shared_memory = self.stage_task(
                root,
                analysis_id=analysis_id,
                response_digest=self.runner.canonical_payload_digest(
                    response
                ),
            )
            queue_path = self.runner.queue_analysis_index(
                {
                    "analysis_id": analysis_id,
                    "response": response,
                },
                queue_dir,
            )
            transient = self.runner.AnalysisIndexSubmissionError(
                "analysis index HTTP 503",
                retryable=True,
                status_code=503,
            )

            with mock.patch.object(
                self.runner,
                "post_analysis_index",
                side_effect=transient,
            ):
                first = self.runner.flush_analysis_index_queue(
                    "http://127.0.0.1:8787",
                    queue_dir=queue_dir,
                    quarantine_dir=quarantine_dir,
                    memory_pending_dir=pending_task.parent,
                    memory_committed_dir=committed_dir,
                    memory_receipt_dir=receipt_dir,
                )

            self.assertEqual(first, (0, 1, 0))
            self.assertTrue(queue_path.is_file())
            self.assertTrue(pending_task.is_file())
            self.assertNotIn(
                self.memory.MANAGED_START,
                role_memory.read_text(encoding="utf-8"),
            )
            self.assertEqual(queue_dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual(queue_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(pending_task.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(pending_task.stat().st_mode & 0o777, 0o600)

            with mock.patch.object(
                self.runner,
                "post_analysis_index",
                return_value={
                    "analysis_id": analysis_id,
                    "submission_sha256": "b" * 64,
                    "stored_response_sha256": "a" * 64,
                    "idempotent": False,
                },
            ):
                replay = self.runner.flush_analysis_index_queue(
                    "http://127.0.0.1:8787",
                    queue_dir=queue_dir,
                    quarantine_dir=quarantine_dir,
                    memory_pending_dir=pending_task.parent,
                    memory_committed_dir=committed_dir,
                    memory_receipt_dir=receipt_dir,
                )

            self.assertEqual(replay, (1, 0, 0))
            self.assertFalse(queue_path.exists())
            self.assertFalse(pending_task.exists())
            self.assertEqual(list(committed_dir.glob("*.json")), [])
            self.assertIn(
                self.memory.MANAGED_START,
                role_memory.read_text(encoding="utf-8"),
            )
            receipt_path = receipt_dir / f"{analysis_id}.json"
            self.assertTrue(receipt_path.is_file())
            self.assertEqual(committed_dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual(receipt_dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)

    def test_same_analysis_replay_after_restart_is_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            analysis_id = "restart-exactly-once"
            pending_task, role_memory, _shared_memory = self.stage_task(
                root,
                analysis_id=analysis_id,
            )
            committed_dir = root / "journal" / "committed"
            receipt_dir = root / "journal" / "receipts"
            committed_task = self.runner.mark_memory_writeback_committed(
                analysis_id,
                pending_dir=pending_task.parent,
                committed_dir=committed_dir,
            )
            self.assertIsNotNone(committed_task)
            assert committed_task is not None
            task_payload = json.loads(
                committed_task.read_text(encoding="utf-8")
            )

            first_receipt, first_path = (
                self.runner.process_committed_memory_writeback(
                    committed_task,
                    receipt_dir=receipt_dir,
                )
            )
            self.assertTrue(first_receipt["ok"])
            self.assertIsNotNone(first_path)
            self.assertFalse(committed_task.exists())

            # Simulate a process crash after memory persisted but before its
            # committed journal entry was durably retired.
            self.runner.atomic_write_private_json(
                committed_task,
                task_payload,
            )
            completed, failed = (
                self.runner.resume_committed_memory_writebacks(
                    committed_dir=committed_dir,
                    receipt_dir=receipt_dir,
                )
            )

            self.assertEqual((completed, failed), (1, 0))
            self.assertFalse(committed_task.exists())
            _manual, records = self.memory.read_memory_file(role_memory)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["reinforced_count"], 1)
            final_receipt = json.loads(
                (receipt_dir / f"{analysis_id}.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                final_receipt["primary"]["result"]["role"]["replayed"],
                1,
            )
            self.assertEqual(
                final_receipt["primary"]["result"]["role"]["reinforced"],
                0,
            )
            self.assertEqual(committed_dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual(
                (receipt_dir / f"{analysis_id}.json").stat().st_mode
                & 0o777,
                0o600,
            )

    def test_evaluation_freeze_publishes_index_but_defers_memory_replay(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            analysis_id = "frozen-evaluation-memory"
            response = {"summary": "bounded synthetic result"}
            pending_task, role_memory, _shared_memory = self.stage_task(
                root,
                analysis_id=analysis_id,
                response_digest=self.runner.canonical_payload_digest(response),
            )
            queue_dir = root / "index-queue"
            quarantine_dir = root / "index-quarantine"
            committed_dir = root / "journal" / "committed"
            receipt_dir = root / "journal" / "receipts"
            self.runner.queue_analysis_index(
                {"analysis_id": analysis_id, "response": response},
                queue_dir,
            )

            with mock.patch.object(
                self.runner,
                "post_analysis_index",
                return_value={"ok": True},
            ):
                frozen = self.runner.flush_analysis_index_queue(
                    "http://127.0.0.1:8787",
                    queue_dir=queue_dir,
                    quarantine_dir=quarantine_dir,
                    memory_pending_dir=pending_task.parent,
                    memory_committed_dir=committed_dir,
                    memory_receipt_dir=receipt_dir,
                    memory_writeback_enabled=False,
                )

            self.assertEqual(frozen, (1, 0, 0))
            self.assertFalse(pending_task.exists())
            self.assertEqual(
                [path.name for path in committed_dir.glob("*.json")],
                [f"{analysis_id}.json"],
            )
            self.assertFalse(receipt_dir.exists())
            self.assertNotIn(
                self.memory.MANAGED_START,
                role_memory.read_text(encoding="utf-8"),
            )

            resumed = self.runner.flush_analysis_index_queue(
                "http://127.0.0.1:8787",
                queue_dir=queue_dir,
                quarantine_dir=quarantine_dir,
                memory_pending_dir=pending_task.parent,
                memory_committed_dir=committed_dir,
                memory_receipt_dir=receipt_dir,
                memory_writeback_enabled=True,
            )

            self.assertEqual(resumed, (0, 0, 0))
            self.assertEqual(list(committed_dir.glob("*.json")), [])
            self.assertTrue((receipt_dir / f"{analysis_id}.json").is_file())
            self.assertIn(
                self.memory.MANAGED_START,
                role_memory.read_text(encoding="utf-8"),
            )

    def test_partial_role_shared_failure_recovers_without_reinforcement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            analysis_id = "partial-role-shared-retry"
            role_candidate = self.candidate()
            shared_candidate = self.candidate(
                scope="shared",
                finding=(
                    "Use certificate, SNI, and destination history together "
                    "when hunting recurring TLS infrastructure across roles."
                ),
            )
            pending_task, role_memory, shared_memory = self.stage_task(
                root,
                analysis_id=analysis_id,
                candidates=[role_candidate, shared_candidate],
            )
            committed_dir = root / "journal" / "committed"
            receipt_dir = root / "journal" / "receipts"
            committed_task = self.runner.mark_memory_writeback_committed(
                analysis_id,
                pending_dir=pending_task.parent,
                committed_dir=committed_dir,
            )
            self.assertIsNotNone(committed_task)
            assert committed_task is not None
            real_persist = self.runner.persist_memory_candidates
            failed_once = False

            def persist_role_then_fail(**kwargs):
                nonlocal failed_once
                if not failed_once:
                    failed_once = True
                    role_only = [
                        candidate
                        for candidate in kwargs["candidates"]
                        if candidate["scope"] == "agent"
                    ]
                    real_persist(
                        **{
                            **kwargs,
                            "candidates": role_only,
                        }
                    )
                    raise OSError("synthetic shared-memory interruption")
                return real_persist(**kwargs)

            with mock.patch.object(
                self.runner,
                "persist_memory_candidates",
                side_effect=persist_role_then_fail,
            ):
                failed_receipt, failed_path = (
                    self.runner.process_committed_memory_writeback(
                        committed_task,
                        receipt_dir=receipt_dir,
                    )
                )

            self.assertFalse(failed_receipt["ok"])
            self.assertEqual(failed_receipt["primary"]["status"], "failed")
            self.assertIsNotNone(failed_path)
            self.assertTrue(committed_task.is_file())
            _manual, role_records = self.memory.read_memory_file(role_memory)
            _manual, shared_records = self.memory.read_memory_file(
                shared_memory
            )
            self.assertEqual(len(role_records), 1)
            self.assertEqual(shared_records, [])

            completed, failed = (
                self.runner.resume_committed_memory_writebacks(
                    committed_dir=committed_dir,
                    receipt_dir=receipt_dir,
                )
            )

            self.assertEqual((completed, failed), (1, 0))
            self.assertFalse(committed_task.exists())
            _manual, role_records = self.memory.read_memory_file(role_memory)
            _manual, shared_records = self.memory.read_memory_file(
                shared_memory
            )
            self.assertEqual(len(role_records), 1)
            self.assertEqual(role_records[0]["reinforced_count"], 1)
            self.assertEqual(len(shared_records), 1)
            final_receipt = json.loads(
                (receipt_dir / f"{analysis_id}.json").read_text(
                    encoding="utf-8"
                )
            )
            result = final_receipt["primary"]["result"]
            self.assertEqual(result["role"]["replayed"], 1)
            self.assertEqual(result["role"]["reinforced"], 0)
            self.assertEqual(result["shared"]["added"], 1)

    def test_post_analysis_index_accepts_only_a_bound_commit_receipt(
        self,
    ) -> None:
        payload = {
            "analysis_id": "receipt-binding-test",
            "response": {"summary": "bounded response"},
        }
        submission_body = json.dumps(
            payload,
            separators=(",", ":"),
        ).encode("utf-8")
        submission_digest = hashlib.sha256(submission_body).hexdigest()
        valid = {
            "ok": True,
            "analysis_id": payload["analysis_id"],
            "submission_sha256": submission_digest,
            "stored_response_sha256": "c" * 64,
            "idempotent": True,
        }

        with mock.patch.object(
            self.runner.urllib.request,
            "urlopen",
            return_value=io.BytesIO(
                json.dumps(valid).encode("utf-8")
            ),
        ):
            accepted = self.runner.post_analysis_index(
                payload,
                "http://127.0.0.1:8787",
            )

        self.assertEqual(accepted["analysis_id"], payload["analysis_id"])
        self.assertEqual(
            accepted["submission_sha256"],
            submission_digest,
        )
        self.assertEqual(
            accepted["stored_response_sha256"],
            "c" * 64,
        )
        self.assertTrue(accepted["idempotent"])

        invalid_receipts = {
            "missing receipt fields": {"ok": True},
            "wrong analysis": {
                **valid,
                "analysis_id": "different-analysis",
            },
            "wrong submission digest": {
                **valid,
                "submission_sha256": "d" * 64,
            },
            "missing stored response digest": {
                key: value
                for key, value in valid.items()
                if key != "stored_response_sha256"
            },
            "malformed stored response digest": {
                **valid,
                "stored_response_sha256": "not-a-digest",
            },
        }
        for label, receipt in invalid_receipts.items():
            with self.subTest(label=label):
                with (
                    mock.patch.object(
                        self.runner.urllib.request,
                        "urlopen",
                        return_value=io.BytesIO(
                            json.dumps(receipt).encode("utf-8")
                        ),
                    ),
                    self.assertRaises(
                        self.runner.AnalysisIndexSubmissionError
                    ) as raised,
                ):
                    self.runner.post_analysis_index(
                        payload,
                        "http://127.0.0.1:8787",
                    )
                # A malformed success receipt is indeterminate: alert-store
                # may have committed. The client must retain the exact spool
                # for an idempotent replay, while still refusing promotion.
                self.assertTrue(raised.exception.retryable)
                self.assertEqual(raised.exception.status_code, 200)
                self.assertIn("commit receipt", str(raised.exception))
                self.assertRegex(
                    raised.exception.response_sha256,
                    r"^[a-f0-9]{64}$",
                )

    def test_missing_commit_receipt_cannot_promote_staged_memory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            analysis_id = "missing-receipt-no-memory"
            pending_task, role_memory, _shared_memory = self.stage_task(
                root,
                analysis_id=analysis_id,
            )
            queue_dir = root / "index-queue"
            quarantine_dir = root / "index-quarantine"
            committed_dir = root / "journal" / "committed"
            receipt_dir = root / "journal" / "receipts"
            self.runner.queue_analysis_index(
                {
                    "analysis_id": analysis_id,
                    "response": {"summary": "bounded synthetic result"},
                },
                queue_dir,
            )

            with mock.patch.object(
                self.runner.urllib.request,
                "urlopen",
                return_value=io.BytesIO(
                    b'{"ok":true,"status":"analysis_indexed"}'
                ),
            ):
                result = self.runner.flush_analysis_index_queue(
                    "http://127.0.0.1:8787",
                    queue_dir=queue_dir,
                    quarantine_dir=quarantine_dir,
                    memory_pending_dir=pending_task.parent,
                    memory_committed_dir=committed_dir,
                    memory_receipt_dir=receipt_dir,
                )

            self.assertEqual(result, (0, 1, 0))
            self.assertTrue(pending_task.exists())
            self.assertEqual(list(committed_dir.glob("*.json")), [])
            self.assertFalse(receipt_dir.exists())
            self.assertNotIn(
                self.memory.MANAGED_START,
                role_memory.read_text(encoding="utf-8"),
            )
            self.assertTrue(
                (queue_dir / f"{analysis_id}.json").is_file()
            )
            self.assertFalse(quarantine_dir.exists())

    def test_main_stages_before_submission_and_promotes_after_receipt(
        self,
    ) -> None:
        source = LEGACY_PIPELINE_PATH.read_text(encoding="utf-8")
        execute_source = source[
            source.index("def _execute("):source.index("def _finalize(")
        ]
        transaction_source = (
            REPO_ROOT
            / "n8n/onion_sentinel/analysis/persistence/transaction.py"
        ).read_text(encoding="utf-8")
        stage = execute_source.index("_stage_memory(")
        publication = execute_source.index("_publish(")
        promotion = execute_source.index("_finish_postcommit(")

        self.assertLess(stage, publication)
        self.assertLess(publication, promotion)
        self.assertLess(
            transaction_source.index("pending_path = ports.queue("),
            transaction_source.index("receipt = ports.submit("),
        )
        promote = transaction_source.index("committed_task = ports.promote_staged()")
        retire = transaction_source.index("pending_index_path.unlink", promote)
        process = transaction_source.index("ports.process_staged(committed_task)")
        self.assertLess(promote, retire)
        self.assertLess(retire, process)


if __name__ == "__main__":
    unittest.main()
