"""Direct contracts for the extracted analysis-index transaction boundary."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.persistence import analysis_index  # noqa: E402


class SubmissionError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        retryable: bool,
        status_code: int | None = None,
        response_sha256: str = "",
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code
        self.response_sha256 = response_sha256


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def private_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)


class AnalysisIndexPersistenceTests(unittest.TestCase):
    def test_payload_is_deterministic_and_preserves_correlation(self) -> None:
        prompt = {
            "agent_role": "incident-responder",
            "alert": {"alert_id": "alert-1"},
            "correlated_alert_context": {"candidates": [{"id": "related"}]},
        }
        result = analysis_index.build_payload(
            "analysis-1",
            prompt,
            {"_analysis_model": "gpt-test", "summary": "result"},
            "attempt-1",
            "2026-08-06T00:00:00Z",
            "2026-08-06T00:01:00Z",
            Path("/safe/result.json"),
        )
        self.assertEqual(result["alert_id"], "alert-1")
        self.assertEqual(result["agent_role"], "incident-responder")
        self.assertEqual(result["correlation_candidates"], [{"id": "related"}])
        self.assertEqual(result["evidence_hash"], digest(prompt))

    def test_queue_is_idempotent_and_rejects_identity_collision(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            queue_dir = Path(temp_name) / "queue"
            payload = {"analysis_id": "analysis-1", "response": {"ok": True}}
            kwargs = {
                "safe_filename": lambda value: str(value),
                "load_json": lambda path: json.loads(path.read_text()),
                "canonical_digest": digest,
                "atomic_write_private_json": private_json,
            }
            path = analysis_index.queue(payload, queue_dir, **kwargs)
            self.assertEqual(analysis_index.queue(payload, queue_dir, **kwargs), path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(RuntimeError, "collides"):
                analysis_index.queue(
                    {"analysis_id": "analysis-1", "response": {"ok": False}},
                    queue_dir,
                    **kwargs,
                )

    def test_post_requires_receipt_bound_to_exact_submission(self) -> None:
        payload = {"analysis_id": "analysis-1", "response": {"ok": True}}
        body = json.dumps(payload, separators=(",", ":")).encode()
        receipt = {
            "ok": True,
            "analysis_id": "analysis-1",
            "submission_sha256": hashlib.sha256(body).hexdigest(),
            "stored_response_sha256": "a" * 64,
            "idempotent": False,
        }

        def read_json(stream, *, max_bytes):
            self.assertEqual(max_bytes, 4096)
            return json.loads(stream.read())

        with mock.patch.object(
            analysis_index.urllib.request,
            "urlopen",
            return_value=io.BytesIO(json.dumps(receipt).encode()),
        ):
            result = analysis_index.post(
                payload,
                "http://127.0.0.1:8787",
                timeout=10,
                max_response_bytes=4096,
                read_bounded_json=read_json,
                submission_error=SubmissionError,
                environment={},
                evaluation_mode_env="MODE",
                evaluation_token_env="TOKEN",
                evaluation_token_header="X-Test-Token",
                evaluation_token_pattern=re.compile(r"[a-f0-9]{64}"),
                fallback_evaluation_token=None,
            )
        self.assertEqual(result["stored_response_sha256"], "a" * 64)

        receipt["analysis_id"] = "wrong"
        with (
            mock.patch.object(
                analysis_index.urllib.request,
                "urlopen",
                return_value=io.BytesIO(json.dumps(receipt).encode()),
            ),
            self.assertRaises(SubmissionError) as raised,
        ):
            analysis_index.post(
                payload,
                "http://127.0.0.1:8787",
                timeout=10,
                max_response_bytes=4096,
                read_bounded_json=read_json,
                submission_error=SubmissionError,
                environment={},
                evaluation_mode_env="MODE",
                evaluation_token_env="TOKEN",
                evaluation_token_header="X-Test-Token",
                evaluation_token_pattern=re.compile(r"[a-f0-9]{64}"),
                fallback_evaluation_token=None,
            )
        self.assertTrue(raised.exception.retryable)

    def test_retryable_failure_stops_ordered_replay_without_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            queue_dir = root / "queue"
            private_json(queue_dir / "a.json", {"analysis_id": "a", "response": {}})
            private_json(queue_dir / "b.json", {"analysis_id": "b", "response": {}})
            promoted: list[str] = []

            def transient(_payload, _url):
                raise SubmissionError("unavailable", retryable=True)

            result = analysis_index.flush(
                "http://127.0.0.1:8787",
                queue_dir=queue_dir,
                quarantine_dir=root / "quarantine",
                memory_pending_dir=root / "pending",
                memory_committed_dir=root / "committed",
                memory_receipt_dir=root / "receipts",
                limit=100,
                memory_writeback_enabled=False,
                submission_error=SubmissionError,
                load_json=lambda path: json.loads(path.read_text()),
                post_result=transient,
                canonical_digest=digest,
                mark_memory_committed=lambda identity, **_kwargs: promoted.append(identity),
                process_committed_memory=lambda *_args, **_kwargs: ({}, None),
                resume_committed_memory=lambda **_kwargs: (0, 0),
                quarantine_result=lambda *_args, **_kwargs: root / "rejected",
                discard_pending_memory=lambda *_args, **_kwargs: None,
            )
            self.assertEqual(result, (0, 1, 0))
            self.assertEqual(promoted, [])
            self.assertEqual(len(list(queue_dir.glob("*.json"))), 2)


if __name__ == "__main__":
    unittest.main()
