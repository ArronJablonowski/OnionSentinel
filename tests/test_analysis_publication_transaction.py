from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from n8n.onion_sentinel.analysis.persistence.transaction import (
    MemoryPromotionPorts,
    PublicationPolicy,
    PublicationPorts,
    promote_memory,
    publish,
)


class SubmissionError(Exception):
    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


class AnalysisPublicationTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.events: list[str] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def policy(self, *, controlled: bool = False) -> PublicationPolicy:
        return PublicationPolicy(
            controlled=controlled,
            controlled_identity={"job_id": "controlled-1"} if controlled else None,
            submission_error=SubmissionError,
            indeterminate_message="controlled submission indeterminate",
        )

    def ports(
        self,
        *,
        preflight_error: Exception | None = None,
        submit_error: Exception | None = None,
    ) -> PublicationPorts:
        def write_outputs() -> tuple[Path, Path, str]:
            self.events.append("write")
            json_path = self.root / "analysis.json"
            markdown_path = self.root / "analysis.md"
            json_path.write_text("{}", encoding="utf-8")
            markdown_path.write_text("report", encoding="utf-8")
            return json_path, markdown_path, "generated"

        def preflight() -> None:
            self.events.append("preflight")
            if preflight_error is not None:
                raise preflight_error

        def queue(payload: dict, controlled: bool) -> Path:
            self.events.append(f"queue:{controlled}")
            path = self.root / "pending.json"
            path.write_text(str(payload), encoding="utf-8")
            return path

        def submit(_payload: dict, controlled: bool) -> dict:
            self.events.append(f"submit:{controlled}")
            if submit_error is not None:
                raise submit_error
            return {"analysis_id": "analysis-1"}

        def quarantine(path: Path, _payload: dict, _error: Exception) -> Path:
            self.events.append("quarantine")
            rejected = self.root / "result.rejected.json"
            path.replace(rejected)
            return rejected

        return PublicationPorts(
            write_outputs=write_outputs,
            build_payload=lambda generated, path: {
                "generated_at": generated,
                "artifact_path": str(path),
            },
            preflight=preflight,
            queue=queue,
            submit=submit,
            quarantine=quarantine,
            discard_memory=lambda: self.events.append("discard_memory"),
        )

    def test_success_preserves_order_and_binds_controlled_identity(self) -> None:
        result = publish(policy=self.policy(controlled=True), ports=self.ports())
        self.assertEqual(
            self.events,
            ["write", "preflight", "queue:True", "submit:True"],
        )
        self.assertEqual(result.index_payload["controlled_job"]["job_id"], "controlled-1")
        self.assertTrue(result.pending_index_path.exists())

    def test_precommit_failure_discards_memory_and_artifacts(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "budget expired"):
            publish(
                policy=self.policy(),
                ports=self.ports(preflight_error=RuntimeError("budget expired")),
            )
        self.assertEqual(self.events[-1], "discard_memory")
        self.assertFalse((self.root / "analysis.json").exists())
        self.assertFalse((self.root / "analysis.md").exists())

    def test_deterministic_rejection_is_quarantined_and_memory_discarded(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "deterministically rejected"):
            publish(
                policy=self.policy(),
                ports=self.ports(
                    submit_error=SubmissionError("invalid", retryable=False)
                ),
            )
        self.assertEqual(self.events[-2:], ["quarantine", "discard_memory"])
        self.assertTrue((self.root / "result.rejected.json").exists())

    def test_retryable_controlled_failure_retains_exact_result(self) -> None:
        with self.assertRaisesRegex(
            RuntimeError,
            "controlled submission indeterminate; exact result retained",
        ):
            publish(
                policy=self.policy(controlled=True),
                ports=self.ports(
                    submit_error=SubmissionError("timeout", retryable=True)
                ),
            )
        self.assertTrue((self.root / "pending.json").exists())
        self.assertTrue((self.root / "analysis.json").exists())
        self.assertNotIn("discard_memory", self.events)

    def test_uncontrolled_transport_failure_is_deferred(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "analysis index deferred"):
            publish(
                policy=self.policy(),
                ports=self.ports(submit_error=OSError("offline")),
            )
        self.assertTrue((self.root / "pending.json").exists())


class MemoryPromotionTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.pending = self.root / "pending-index.json"
        self.pending.write_text("pending", encoding="utf-8")
        self.events: list[str] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def ports(
        self,
        *,
        promoted: Path | None = None,
        process_error: Exception | None = None,
        direct_error: Exception | None = None,
    ) -> MemoryPromotionPorts:
        def promote() -> Path | None:
            self.events.append("promote")
            return promoted

        def process(path: Path) -> tuple[dict, Path | None]:
            self.events.append(f"process:{path.name}")
            if process_error is not None:
                raise process_error
            return {"ok": True, "lane": "staged"}, self.root / "receipt.json"

        def direct() -> tuple[dict, Path | None]:
            self.events.append("direct")
            if direct_error is not None:
                raise direct_error
            return {"ok": True, "lane": "direct"}, None

        return MemoryPromotionPorts(
            promote_staged=promote,
            process_staged=process,
            persist_direct=direct,
            error_digest=lambda value: f"digest:{value}",
            warn=lambda value: self.events.append(f"warn:{value}"),
        )

    def test_staged_task_is_promoted_before_spool_retirement(self) -> None:
        committed = self.root / "committed.json"
        result = promote_memory(
            analysis_id="analysis-1",
            staged_task=self.root / "staged.json",
            pending_index_path=self.pending,
            ports=self.ports(promoted=committed),
        )
        self.assertEqual(self.events, ["promote", "process:committed.json"])
        self.assertFalse(self.pending.exists())
        self.assertTrue(result.receipt["ok"])

    def test_missing_staged_task_is_nonfatal_and_keeps_replay_spool(self) -> None:
        result = promote_memory(
            analysis_id="analysis-2",
            staged_task=self.root / "staged.json",
            pending_index_path=self.pending,
            ports=self.ports(promoted=None),
        )
        self.assertFalse(result.receipt["ok"])
        self.assertEqual(result.receipt["error_type"], "RuntimeError")
        self.assertTrue(self.pending.exists())
        self.assertIn("warn:post-commit memory writeback failed", self.events[-1])

    def test_committed_task_failure_does_not_restore_retired_spool(self) -> None:
        result = promote_memory(
            analysis_id="analysis-3",
            staged_task=self.root / "staged.json",
            pending_index_path=self.pending,
            ports=self.ports(
                promoted=self.root / "committed.json",
                process_error=RuntimeError("receipt unavailable"),
            ),
        )
        self.assertFalse(result.receipt["ok"])
        self.assertFalse(self.pending.exists())

    def test_direct_path_retires_spool_before_supplemental_write(self) -> None:
        result = promote_memory(
            analysis_id="analysis-4",
            staged_task=None,
            pending_index_path=self.pending,
            ports=self.ports(direct_error=OSError("memory offline")),
        )
        self.assertFalse(result.receipt["ok"])
        self.assertFalse(self.pending.exists())
        self.assertEqual(self.events[0], "direct")


if __name__ == "__main__":
    unittest.main()
