"""Characterize pre-commit agent-memory intent staging."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.persistence import memory_journal  # noqa: E402


def base_kwargs(root: Path) -> dict[str, object]:
    return {
        "analysis_id": "analysis-1",
        "response_digest": "A" * 64,
        "agent_role": "soc-analyst",
        "role_memory_file": root / "role.md",
        "shared_memory_file": root / "shared.md",
        "source_artifact": "/synthetic/result.json",
        "primary_candidates": [{"finding": "primary"}],
        "primary_allowed": True,
        "primary_reason": "eligible",
        "reviewer_candidates": [{"finding": "reviewer"}],
        "reviewer_allowed": True,
        "reviewer_reason": "independently eligible",
        "pending_dir": root / "pending",
        "schema": "memory-task-v1",
        "max_bytes": 64 * 1024,
        "normalize_candidates": lambda value: list(value),
        "canonical_digest": lambda value: "digest:" + json.dumps(value, sort_keys=True),
        "safe_filename": str,
        "load_json": lambda path, _maximum: json.loads(path.read_text()),
        "atomic_write_private_json": lambda path, value: None,
    }


class MemoryJournalStageCharacterizationTests(unittest.TestCase):
    def test_identity_and_digest_fail_before_candidate_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            calls: list[object] = []
            for analysis_id, response_digest, message in (
                ("", "a" * 64, "analysis identity"),
                ("x" * 129, "a" * 64, "analysis identity"),
                ("analysis-1", " a" * 32, "response digest"),
                ("analysis-1", "g" * 64, "response digest"),
            ):
                with self.subTest(message=message):
                    kwargs = base_kwargs(root)
                    kwargs.update(
                        analysis_id=analysis_id,
                        response_digest=response_digest,
                        normalize_candidates=lambda value: calls.append(value),
                    )
                    with self.assertRaisesRegex(RuntimeError, message):
                        memory_journal.stage(**kwargs)
            self.assertEqual(calls, [])

    def test_only_allowed_lanes_normalize_in_primary_reviewer_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            calls: list[tuple[str, object]] = []
            primary = [{"finding": "blocked"}]
            reviewer = [{"finding": "empty after normalization"}]

            def normalize(value: object) -> list[dict]:
                calls.append(("normalize", value))
                return []

            kwargs = base_kwargs(root)
            kwargs.update(
                primary_candidates=primary,
                primary_allowed=False,
                reviewer_candidates=reviewer,
                reviewer_allowed=True,
                normalize_candidates=normalize,
                safe_filename=lambda value: calls.append(("safe", value)),
                canonical_digest=lambda value: calls.append(("digest", value)),
                atomic_write_private_json=lambda *_args: calls.append(("write", None)),
            )
            self.assertIsNone(memory_journal.stage(**kwargs))
            self.assertEqual(calls, [("normalize", reviewer)])

    def test_task_projection_size_filename_and_atomic_write_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            calls: list[tuple[object, ...]] = []
            primary_input = [{"finding": "primary"}]
            reviewer_input = [{"finding": "reviewer"}]
            original_primary = copy.deepcopy(primary_input)
            original_reviewer = copy.deepcopy(reviewer_input)

            def normalize(value: object) -> list[dict]:
                calls.append(("normalize", value))
                return copy.deepcopy(value)

            def digest(value: object) -> str:
                calls.append(("digest", value))
                return "digest:" + json.dumps(value, sort_keys=True)

            def safe(value: object) -> str:
                calls.append(("safe", value))
                return "safe-analysis"

            written: list[tuple[Path, dict]] = []

            def write(path: Path, value: dict) -> None:
                calls.append(("write", path, value))
                written.append((path, copy.deepcopy(value)))

            kwargs = base_kwargs(root)
            kwargs.update(
                primary_candidates=primary_input,
                primary_reason="p" * 600,
                reviewer_candidates=reviewer_input,
                reviewer_reason="reviewed",
                normalize_candidates=normalize,
                canonical_digest=digest,
                safe_filename=safe,
                atomic_write_private_json=write,
            )
            path = memory_journal.stage(**kwargs)

            self.assertEqual(path, root / "pending" / "safe-analysis.json")
            self.assertEqual(primary_input, original_primary)
            self.assertEqual(reviewer_input, original_reviewer)
            self.assertEqual(
                [call[0] for call in calls],
                ["normalize", "normalize", "digest", "digest", "safe", "write"],
            )
            self.assertEqual(len(written), 1)
            task = written[0][1]
            self.assertEqual(
                task,
                {
                    "schema": "memory-task-v1",
                    "analysis_id": "analysis-1",
                    "submitted_response_sha256": "a" * 64,
                    "agent_role": "soc-analyst",
                    "role_memory_file": str(root / "role.md"),
                    "shared_memory_file": str(root / "shared.md"),
                    "source_artifact": "/synthetic/result.json",
                    "primary": {
                        "allowed": True,
                        "reason": "p" * 500,
                        "candidates": primary_input,
                        "candidate_manifest_digest": "digest:"
                        + json.dumps(primary_input, sort_keys=True),
                    },
                    "reviewer": {
                        "allowed": True,
                        "reason": "reviewed",
                        "candidates": reviewer_input,
                        "candidate_manifest_digest": "digest:"
                        + json.dumps(reviewer_input, sort_keys=True),
                    },
                },
            )

    def test_exact_compact_json_byte_limit_precedes_filename_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            calls: list[tuple[str, object]] = []
            captured: list[dict] = []

            def digest(value: object) -> str:
                if isinstance(value, list):
                    return "d" * 64
                raise AssertionError("unexpected digest")

            kwargs = base_kwargs(root)
            kwargs.update(
                primary_candidates=[{"finding": "snowman-☃"}],
                reviewer_allowed=False,
                canonical_digest=digest,
                atomic_write_private_json=lambda _path, task: captured.append(task),
            )
            memory_journal.stage(**kwargs)
            encoded_size = len(
                json.dumps(
                    captured[0], sort_keys=True, separators=(",", ":")
                ).encode()
            )
            kwargs.update(
                max_bytes=encoded_size - 1,
                safe_filename=lambda value: calls.append(("safe", value)),
                atomic_write_private_json=lambda *_args: calls.append(("write", None)),
            )
            with self.assertRaisesRegex(RuntimeError, "byte limit"):
                memory_journal.stage(**kwargs)
            self.assertEqual(calls, [])

    def test_existing_task_digest_comparison_is_ordered_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            calls: list[tuple[object, ...]] = []
            pending = root / "pending"
            pending.mkdir()
            path = pending / "analysis-1.json"
            path.write_text("{}", encoding="utf-8")
            task_holder: list[dict] = []

            def load(existing_path: Path, maximum: int) -> dict:
                calls.append(("load", existing_path, maximum))
                return task_holder[0]

            def digest(value: object) -> str:
                calls.append(("digest", value))
                return json.dumps(value, sort_keys=True)

            kwargs = base_kwargs(root)
            kwargs.update(
                load_json=load,
                canonical_digest=digest,
                atomic_write_private_json=lambda _path, task: task_holder.append(
                    copy.deepcopy(task)
                ),
            )
            path.unlink()
            created = memory_journal.stage(**kwargs)
            self.assertEqual(created, path)
            path.write_text("{}", encoding="utf-8")
            calls.clear()
            self.assertEqual(memory_journal.stage(**kwargs), path)
            self.assertEqual(
                [call[0] for call in calls],
                ["digest", "digest", "load", "digest", "digest"],
            )

            original_task = task_holder[0]
            task_holder[0] = {**original_task, "agent_role": "different"}
            with self.assertRaisesRegex(RuntimeError, "collides"):
                memory_journal.stage(**kwargs)


if __name__ == "__main__":
    unittest.main()
