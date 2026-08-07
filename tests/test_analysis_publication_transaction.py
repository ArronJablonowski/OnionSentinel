from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from n8n.onion_sentinel.analysis.persistence.transaction import (
    PublicationPolicy,
    PublicationPorts,
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


if __name__ == "__main__":
    unittest.main()
