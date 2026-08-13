"""Characterize ordered analysis-index spool replay and memory settlement."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.persistence import analysis_index  # noqa: E402


class SubmissionError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


def write_payload(path: Path, analysis_id: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"analysis_id": analysis_id, "response": {"id": analysis_id}}),
        encoding="utf-8",
    )


def base_kwargs(root: Path) -> dict[str, object]:
    return {
        "queue_dir": root / "queue",
        "quarantine_dir": root / "quarantine",
        "memory_pending_dir": root / "pending",
        "memory_committed_dir": root / "committed",
        "memory_receipt_dir": root / "receipts",
        "limit": 100,
        "memory_writeback_enabled": False,
        "submission_error": SubmissionError,
        "load_json": lambda path: json.loads(path.read_text(encoding="utf-8")),
        "post_result": lambda _payload, _url: {},
        "canonical_digest": lambda value: "digest:" + str(value.get("id")),
        "mark_memory_committed": lambda *_args, **_kwargs: None,
        "process_committed_memory": lambda *_args, **_kwargs: ({}, None),
        "resume_committed_memory": lambda **_kwargs: (0, 0),
        "quarantine_result": lambda *_args, **_kwargs: root / "rejected",
        "discard_pending_memory": lambda *_args, **_kwargs: None,
    }


class AnalysisIndexFlushCharacterizationTests(unittest.TestCase):
    def test_recovery_precedes_missing_queue_check_only_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            calls: list[tuple[object, ...]] = []
            kwargs = base_kwargs(root)
            kwargs.update(
                memory_writeback_enabled=True,
                limit=-3,
                resume_committed_memory=lambda **values: calls.append(
                    ("resume", values)
                ),
            )
            self.assertEqual(analysis_index.flush("store", **kwargs), (0, 0, 0))
            self.assertEqual(
                calls,
                [
                    (
                        "resume",
                        {
                            "committed_dir": root / "committed",
                            "receipt_dir": root / "receipts",
                            "limit": -3,
                        },
                    )
                ],
            )

            kwargs["memory_writeback_enabled"] = False
            self.assertEqual(analysis_index.flush("store", **kwargs), (0, 0, 0))
            self.assertEqual(len(calls), 1)

    def test_success_is_sorted_limited_and_unlinks_before_optional_processing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            queue = root / "queue"
            write_payload(queue / "b.json", "b")
            write_payload(queue / "a.json", "a")
            write_payload(queue / "ignored.txt", "ignored")
            calls: list[tuple[object, ...]] = []
            original_unlink = Path.unlink

            def traced_unlink(path: Path, *args: object, **kwargs: object) -> None:
                calls.append(("unlink", path.name, kwargs.get("missing_ok")))
                original_unlink(path, *args, **kwargs)

            def load(path: Path) -> dict[str, object]:
                calls.append(("load", path.name))
                return json.loads(path.read_text(encoding="utf-8"))

            def post(payload: dict[str, object], url: str) -> dict[str, object]:
                calls.append(("post", payload["analysis_id"], url))
                return {}

            def digest(value: object) -> str:
                calls.append(("digest", value))
                return "bound-digest"

            def mark(identity: str, **values: object) -> Path:
                calls.append(("mark", identity, values))
                return root / f"{identity}.task"

            def process(task: Path, **values: object) -> tuple[dict, None]:
                calls.append(("process", task.name, values))
                raise RuntimeError("post-commit memory failure")

            kwargs = base_kwargs(root)
            kwargs.update(
                limit=1,
                memory_writeback_enabled=True,
                load_json=load,
                post_result=post,
                canonical_digest=digest,
                mark_memory_committed=mark,
                process_committed_memory=process,
                resume_committed_memory=lambda **values: calls.append(
                    ("resume", values)
                ),
            )
            with mock.patch.object(Path, "unlink", traced_unlink):
                result = analysis_index.flush("http://store///", **kwargs)

            self.assertEqual(result, (1, 0, 0))
            self.assertEqual(
                [call[0] for call in calls],
                ["resume", "load", "post", "digest", "mark", "unlink", "process"],
            )
            self.assertEqual(calls[1], ("load", "a.json"))
            self.assertEqual(calls[2], ("post", "a", "http://store///"))
            self.assertEqual(calls[4][1], "a")
            self.assertEqual(
                calls[4][2],
                {
                    "expected_response_digest": "bound-digest",
                    "pending_dir": root / "pending",
                    "committed_dir": root / "committed",
                },
            )
            self.assertEqual(calls[5], ("unlink", "a.json", True))
            self.assertEqual(
                calls[6],
                ("process", "a.task", {"receipt_dir": root / "receipts"}),
            )
            self.assertFalse((queue / "a.json").exists())
            self.assertTrue((queue / "b.json").exists())
            self.assertTrue((queue / "ignored.txt").exists())

    def test_deterministic_rejection_quarantines_discards_and_continues(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            queue = root / "queue"
            write_payload(queue / "a.json", "a")
            write_payload(queue / "b.json", "b")
            calls: list[tuple[object, ...]] = []
            rejection = SubmissionError("rejected", retryable=False)

            def post(payload: dict[str, object], url: str) -> dict[str, object]:
                calls.append(("post", payload["analysis_id"], url))
                if payload["analysis_id"] == "a":
                    raise rejection
                return {}

            def quarantine(
                path: Path,
                payload: dict[str, object],
                error: Exception,
                **values: object,
            ) -> Path:
                calls.append(("quarantine", path.name, payload, error, values))
                path.unlink()
                return root / "rejected"

            kwargs = base_kwargs(root)
            kwargs.update(
                post_result=post,
                quarantine_result=quarantine,
                discard_pending_memory=lambda identity, **values: calls.append(
                    ("discard", identity, values)
                ),
                mark_memory_committed=lambda identity, **_values: calls.append(
                    ("mark", identity)
                ),
            )
            result = analysis_index.flush("store", **kwargs)

            self.assertEqual(result, (1, 0, 1))
            self.assertEqual(
                [call[0] for call in calls],
                ["post", "quarantine", "discard", "post", "mark"],
            )
            self.assertIs(calls[1][3], rejection)
            self.assertEqual(calls[1][4], {"quarantine_dir": root / "quarantine"})
            self.assertEqual(calls[2], ("discard", "a", {"pending_dir": root / "pending"}))
            self.assertFalse((queue / "a.json").exists())
            self.assertFalse((queue / "b.json").exists())

    def test_retryable_or_unclassified_failure_stops_later_work(self) -> None:
        for failure in (
            SubmissionError("retry", retryable=True),
            RuntimeError("dependency defect"),
        ):
            with self.subTest(failure=type(failure).__name__):
                with tempfile.TemporaryDirectory() as temp_name:
                    root = Path(temp_name)
                    queue = root / "queue"
                    write_payload(queue / "a.json", "a")
                    write_payload(queue / "b.json", "b")
                    calls: list[str] = []

                    def post(payload: dict[str, object], _url: str) -> dict:
                        calls.append(str(payload["analysis_id"]))
                        raise failure

                    kwargs = base_kwargs(root)
                    kwargs["post_result"] = post
                    self.assertEqual(
                        analysis_index.flush("store", **kwargs),
                        (0, 1, 0),
                    )
                    self.assertEqual(calls, ["a"])
                    self.assertTrue((queue / "a.json").exists())
                    self.assertTrue((queue / "b.json").exists())

    def test_quarantine_failure_propagates_without_discard_or_counter_return(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            write_payload(root / "queue" / "a.json", "a")
            calls: list[str] = []
            rejection = SubmissionError("rejected", retryable=False)
            quarantine_failure = OSError("quarantine failed")
            kwargs = base_kwargs(root)
            kwargs.update(
                post_result=lambda *_args: (_ for _ in ()).throw(rejection),
                quarantine_result=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    quarantine_failure
                ),
                discard_pending_memory=lambda *_args, **_kwargs: calls.append(
                    "discard"
                ),
            )
            with self.assertRaises(OSError) as raised:
                analysis_index.flush("store", **kwargs)
            self.assertIs(raised.exception, quarantine_failure)
            self.assertEqual(calls, [])
            self.assertTrue((root / "queue" / "a.json").exists())


if __name__ == "__main__":
    unittest.main()
