"""Characterize committed agent-memory task manifest admission."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.persistence import memory_journal  # noqa: E402


class FakeTaskPath:
    def __init__(self, name: str, *, symlink: bool, regular: bool) -> None:
        self.name = name
        self.symlink = symlink
        self.regular = regular
        self.calls: list[str] = []

    def is_symlink(self) -> bool:
        self.calls.append("is_symlink")
        return self.symlink

    def is_file(self) -> bool:
        self.calls.append("is_file")
        return self.regular


def valid_task() -> dict[str, object]:
    return {
        "schema": "memory-v1",
        "analysis_id": "analysis-1",
        "submitted_response_sha256": "A" * 64,
        "primary": {
            "candidates": [{"finding": "primary"}],
            "candidate_manifest_digest": "digest:primary",
        },
        "reviewer": {
            "candidates": [{"finding": "reviewer"}],
            "candidate_manifest_digest": "digest:reviewer",
        },
    }


class MemoryJournalValidatedTaskCharacterizationTests(unittest.TestCase):
    def test_file_probes_short_circuit_before_loading(self) -> None:
        for symlink, regular, expected_calls in (
            (True, True, ["is_symlink"]),
            (False, False, ["is_symlink", "is_file"]),
        ):
            with self.subTest(symlink=symlink, regular=regular):
                path = FakeTaskPath(
                    "analysis-1.json", symlink=symlink, regular=regular
                )
                loads: list[object] = []
                with self.assertRaisesRegex(RuntimeError, "regular file"):
                    memory_journal._validated_task(
                        path,
                        schema="memory-v1",
                        max_bytes=-7,
                        safe_filename=lambda value: str(value),
                        load_json=lambda *_args: loads.append(True),
                        canonical_digest=lambda _value: "unused",
                    )
                self.assertEqual(path.calls, expected_calls)
                self.assertEqual(loads, [])

    def test_schema_filename_and_response_digest_precedence_is_exact(self) -> None:
        path = FakeTaskPath(
            "analysis-1.json", symlink=False, regular=True
        )
        calls: list[tuple[object, ...]] = []
        task = valid_task()

        def load(_path: object, maximum: int) -> dict[str, object]:
            calls.append(("load", maximum))
            return task

        def safe(value: object) -> str:
            calls.append(("safe", value))
            return str(value)

        kwargs = {
            "schema": "memory-v1",
            "max_bytes": -7,
            "safe_filename": safe,
            "load_json": load,
            "canonical_digest": lambda value: calls.append(("digest", value)),
        }

        task["schema"] = "wrong"
        with self.assertRaisesRegex(RuntimeError, "schema"):
            memory_journal._validated_task(path, **kwargs)
        self.assertEqual(calls, [("load", -7)])

        task["schema"] = "memory-v1"
        task["analysis_id"] = "other"
        calls.clear()
        with self.assertRaisesRegex(RuntimeError, "identity"):
            memory_journal._validated_task(path, **kwargs)
        self.assertEqual(calls, [("load", -7), ("safe", "other")])

        task["analysis_id"] = "analysis-1"
        task["submitted_response_sha256"] = " a" * 32
        calls.clear()
        with self.assertRaisesRegex(RuntimeError, "response digest"):
            memory_journal._validated_task(path, **kwargs)
        self.assertEqual(calls, [("load", -7), ("safe", "analysis-1")])

    def test_lane_shape_and_manifest_checks_short_circuit_in_order(self) -> None:
        path = FakeTaskPath(
            "analysis-1.json", symlink=False, regular=True
        )
        task = valid_task()
        calls: list[object] = []

        def digest(value: object) -> str:
            calls.append(value)
            if value == task["primary"]["candidates"]:
                return "digest:primary"
            return "digest:reviewer"

        kwargs = {
            "schema": "memory-v1",
            "max_bytes": 99,
            "safe_filename": lambda _value: "analysis-1",
            "load_json": lambda *_args: task,
            "canonical_digest": digest,
        }

        task["primary"] = []
        with self.assertRaisesRegex(RuntimeError, "lanes"):
            memory_journal._validated_task(path, **kwargs)
        self.assertEqual(calls, [])

        task.update(valid_task())
        task["primary"]["candidates"] = "not-a-list"
        with self.assertRaisesRegex(RuntimeError, "candidate manifest"):
            memory_journal._validated_task(path, **kwargs)
        self.assertEqual(calls, [])

        task.update(valid_task())
        task["primary"]["candidate_manifest_digest"] = "wrong"
        with self.assertRaisesRegex(RuntimeError, "candidate manifest"):
            memory_journal._validated_task(path, **kwargs)
        self.assertEqual(calls, [task["primary"]["candidates"]])

    def test_success_returns_loaded_task_and_lane_objects_unchanged(self) -> None:
        path = FakeTaskPath(
            "analysis-1.json", symlink=False, regular=True
        )
        task = valid_task()
        primary = task["primary"]
        reviewer = task["reviewer"]
        calls: list[tuple[str, object]] = []

        def digest(value: object) -> str:
            calls.append(("digest", value))
            return "digest:primary" if value is primary["candidates"] else "digest:reviewer"

        result = memory_journal._validated_task(
            path,
            schema="memory-v1",
            max_bytes=123,
            safe_filename=lambda value: calls.append(("safe", value)) or str(value),
            load_json=lambda loaded_path, maximum: calls.append(
                ("load", (loaded_path, maximum))
            )
            or task,
            canonical_digest=digest,
        )
        self.assertIs(result[0], task)
        self.assertIs(result[1], primary)
        self.assertIs(result[2], reviewer)
        self.assertEqual(
            calls,
            [
                ("load", (path, 123)),
                ("safe", "analysis-1"),
                ("digest", primary["candidates"]),
                ("digest", reviewer["candidates"]),
            ],
        )


if __name__ == "__main__":
    unittest.main()
