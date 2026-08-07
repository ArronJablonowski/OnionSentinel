from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import unittest

from n8n.onion_sentinel.analysis.persistence.postcommit import (
    HarnessCompletionInputs,
    HarnessCompletionPorts,
    finalize_harness,
)


class PostcommitHarnessFinalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        root = Path(self.temporary.name)
        self.json_path = root / "analysis.json"
        self.markdown_path = root / "analysis.md"
        self.receipt_path = root / "receipt.json"
        self.json_path.write_bytes(b'{"result":"ok"}')
        self.markdown_path.write_bytes(b"# Investigation\n")
        self.events: list[tuple[str, object]] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def inputs(self) -> HarnessCompletionInputs:
        return HarnessCompletionInputs(
            analysis_id="analysis-1",
            submitted_response_sha256="submitted",
            commit_receipt={
                "submission_sha256": "submission",
                "stored_response_sha256": "stored",
            },
            json_path=self.json_path,
            markdown_path=self.markdown_path,
            response={
                "detection_outcome": "true_positive_suspicious",
                "final_disposition_status": "open",
            },
            evaluation_memory_frozen=True,
            memory_receipt={
                "ok": True,
                "primary": {"status": "persisted"},
                "reviewer": {"status": "no_candidates"},
            },
            memory_receipt_path=self.receipt_path,
        )

    def ports(
        self,
        *,
        record_error: Exception | None = None,
        complete_error: Exception | None = None,
    ) -> HarnessCompletionPorts:
        def record(payload: dict) -> None:
            self.events.append(("record", payload))
            if record_error is not None:
                raise record_error

        def complete(payload: dict) -> None:
            self.events.append(("complete", payload))
            if complete_error is not None:
                raise complete_error

        return HarnessCompletionPorts(
            digest=lambda value: f"digest:{value!r}",
            record_memory_writeback=record,
            observe_runtime=lambda: {"disk_pressure": "normal"},
            complete=complete,
            warn=lambda message: self.events.append(("warn", message)),
        )

    def test_finalization_records_memory_then_completes_bound_payload(self) -> None:
        observed = finalize_harness(self.inputs(), self.ports())
        self.assertEqual(observed, {"disk_pressure": "normal"})
        self.assertEqual([event[0] for event in self.events], ["record", "complete"])
        memory = self.events[0][1]
        self.assertEqual(memory["primary_status"], "persisted")
        self.assertTrue(memory["receipt_stored"])
        completion = self.events[1][1]
        self.assertEqual(completion["stored_response_sha256"], "stored")
        self.assertEqual(
            completion["artifact_json_sha256"],
            hashlib.sha256(self.json_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(completion["postcommit_runtime"], observed)

    def test_audit_failure_warns_but_still_attempts_completion(self) -> None:
        observed = finalize_harness(
            self.inputs(), self.ports(record_error=RuntimeError("ledger offline"))
        )
        self.assertEqual(observed, {})
        self.assertEqual(
            [event[0] for event in self.events],
            ["record", "warn", "complete"],
        )

    def test_completion_failure_is_nonfatal_and_warned(self) -> None:
        observed = finalize_harness(
            self.inputs(), self.ports(complete_error=OSError("database full"))
        )
        self.assertEqual(observed, {"disk_pressure": "normal"})
        self.assertEqual(self.events[-1][0], "warn")
        self.assertIn("could not finalize committed analysis", self.events[-1][1])

    def test_missing_artifact_is_a_nonfatal_completion_warning(self) -> None:
        self.json_path.unlink()
        finalize_harness(self.inputs(), self.ports())
        self.assertEqual(self.events[-1][0], "warn")
        self.assertIn("FileNotFoundError", self.events[-1][1])


if __name__ == "__main__":
    unittest.main()
