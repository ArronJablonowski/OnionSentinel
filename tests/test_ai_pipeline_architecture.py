from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from n8n.onion_sentinel.analysis.persistence.postcommit import (
    HarnessCompletionInputs,
    HarnessCompletionPorts,
    finalize_harness,
)
from n8n.onion_sentinel.analysis.persistence.transaction import (
    MemoryPromotionPorts,
    PublicationPolicy,
    PublicationPorts,
    promote_memory,
    publish,
)
from n8n.onion_sentinel.pipeline import (
    AnalysisReviewPolicy,
    AnalysisReviewPorts,
    ORDER,
    RuntimeContext,
    Stage,
    run_analysis_review,
)


class SubmissionError(Exception):
    retryable = False


class AiPipelineArchitectureTests(unittest.TestCase):
    def test_soc_and_ir_complete_the_same_receipt_bound_pipeline(self) -> None:
        for role in ("soc-analyst", "incident-responder"):
            with self.subTest(role=role), TemporaryDirectory() as temporary:
                root = Path(temporary)
                events: list[str] = []
                context = RuntimeContext(f"run-{role}", arguments={"role": role})
                for stage in (Stage.LOAD, Stage.ATTEST, Stage.PREPARE):
                    context.advance(stage, f"{role} {stage.value}")

                analysis = run_analysis_review(
                    context,
                    policy=AnalysisReviewPolicy(False, True, False),
                    ports=self._analysis_ports(role, events),
                )
                response = analysis.response
                self.assertEqual(response["evidence"]["backend"], "fake-security-onion")
                context.advance(Stage.DETERMINISTIC_GUARDS, "fake guards passed")
                context.advance(Stage.VALIDATE, "fake contract validated")

                publication = publish(
                    policy=PublicationPolicy(
                        controlled=False,
                        controlled_identity=None,
                        submission_error=SubmissionError,
                        indeterminate_message="indeterminate",
                    ),
                    ports=self._publication_ports(root, role, response, events),
                )
                context.artifacts = (
                    publication.json_path,
                    publication.markdown_path,
                )
                context.advance(Stage.COMMIT, "fake store committed")

                memory = promote_memory(
                    analysis_id=context.run_id,
                    staged_task=None,
                    pending_index_path=publication.pending_index_path,
                    ports=MemoryPromotionPorts(
                        promote_staged=lambda: None,
                        process_staged=lambda _path: ({"ok": True}, None),
                        persist_direct=lambda: (
                            {"ok": True, "primary": {"status": "persisted"}},
                            root / "memory-receipt.json",
                        ),
                        error_digest=lambda value: f"digest:{value}",
                        warn=lambda value: events.append(f"warn:{value}"),
                    ),
                )
                completed: list[dict] = []
                finalize_harness(
                    HarnessCompletionInputs(
                        analysis_id=context.run_id,
                        submitted_response_sha256="response-digest",
                        commit_receipt=publication.commit_receipt,
                        json_path=publication.json_path,
                        markdown_path=publication.markdown_path,
                        response=response,
                        evaluation_memory_frozen=False,
                        memory_receipt=memory.receipt,
                        memory_receipt_path=memory.receipt_path,
                    ),
                    HarnessCompletionPorts(
                        digest=lambda value: f"digest:{value!r}",
                        record_memory_writeback=lambda _value: events.append("memory-audit"),
                        observe_runtime=lambda: {"backend": "fake-runtime"},
                        complete=completed.append,
                        warn=lambda value: events.append(f"warn:{value}"),
                    ),
                )
                context.advance(Stage.POST_COMMIT, "fake post-commit complete")
                context.advance(Stage.COMPLETE, "fake pipeline complete")

                self.assertEqual([item.current for item in context.transitions], list(ORDER[1:]))
                self.assertEqual(completed[0]["analysis_id"], context.run_id)
                self.assertEqual(completed[0]["stored_response_sha256"], f"stored-{role}")
                self.assertFalse(publication.pending_index_path.exists())
                self.assertIn(f"provider:{role}", events)
                self.assertIn("reviewer", events)
                self.assertIn("memory-audit", events)

    @staticmethod
    def _analysis_ports(role: str, events: list[str]) -> AnalysisReviewPorts:
        response = {
            "agent_role": role,
            "detection_outcome": "true_positive_suspicious",
            "final_disposition_status": "open",
            "evidence": {"backend": "fake-security-onion", "queries": 3},
        }
        return AnalysisReviewPorts(
            load_saved_response=lambda: {},
            run_primary_analysis=lambda: events.append(f"provider:{role}") or response,
            validate_primary=lambda value: value,
            observe_primary=lambda _value: events.append("primary-observed"),
            review_trigger=lambda _value: "independent review required",
            run_configured_review=lambda value, _reason: value,
            apply_saved_review_gate=lambda value: value,
            notify_saved_post_processing=lambda: None,
            controlled_reviewer_gate=lambda _value, _trigger, _frozen: {"ok": True},
            require_result_routes=lambda _value: events.append("routes-attested"),
            observe_reviewer=lambda _value: events.append("reviewer"),
        )

    @staticmethod
    def _publication_ports(
        root: Path,
        role: str,
        response: dict,
        events: list[str],
    ) -> PublicationPorts:
        def write_outputs() -> tuple[Path, Path, str]:
            json_path, markdown_path = root / "result.json", root / "result.md"
            json_path.write_text(str(response), encoding="utf-8")
            markdown_path.write_text(f"# {role}\n", encoding="utf-8")
            return json_path, markdown_path, "generated"

        def queue(payload: dict, _controlled: bool) -> Path:
            path = root / "pending-index.json"
            path.write_text(str(payload), encoding="utf-8")
            return path

        return PublicationPorts(
            write_outputs=write_outputs,
            build_payload=lambda generated, artifact: {
                "analysis_id": f"run-{role}",
                "generated_at": generated,
                "artifact_path": str(artifact),
                "response": response,
            },
            preflight=lambda: events.append("preflight"),
            queue=queue,
            submit=lambda _payload, _controlled: {
                "submission_sha256": f"submitted-{role}",
                "stored_response_sha256": f"stored-{role}",
            },
            quarantine=lambda path, _payload, _error: path,
            discard_memory=lambda: events.append("discard-memory"),
        )


if __name__ == "__main__":
    unittest.main()
