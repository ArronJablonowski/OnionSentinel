#!/usr/bin/env python3
"""Characterize fail-closed harness maintenance integrity proofs."""
from __future__ import annotations

import ast
import copy
import datetime as dt
import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))


def load_integrity():
    path = BIN_DIR / "harness_maintenance_integrity.py"
    spec = importlib.util.spec_from_file_location("maintenance_integrity_phases", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


INTEGRITY = load_integrity()


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(
        (BIN_DIR / "harness_maintenance_integrity.py").read_text(
            encoding="utf-8"
        )
    )
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.Assert)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class TracedRow(dict):
    def __init__(self, values: dict[str, Any]) -> None:
        super().__init__(values)
        self.events: list[str] = []

    def __getitem__(self, key: str) -> Any:
        self.events.append(key)
        return super().__getitem__(key)


def event_row(
    *,
    run_id: str,
    sequence: int,
    event_type: str,
    stage: str,
    payload_json: str,
    previous: str,
) -> TracedRow:
    payload_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    body = {
        "run_id": run_id,
        "sequence": sequence,
        "idempotency_key": f"key-{sequence}",
        "event_type": event_type,
        "stage": stage,
        "created_at": f"time-{sequence}",
        "payload_sha256": payload_digest,
        "previous_event_sha256": previous,
    }
    event_digest = INTEGRITY.digest_json(body)
    return TracedRow(
        {
            "sequence": sequence,
            "payload_json": payload_json,
            "idempotency_key": f"key-{sequence}",
            "event_type": event_type,
            "stage": stage,
            "created_at": f"time-{sequence}",
            "payload_sha256": payload_digest,
            "previous_event_sha256": previous,
            "event_sha256": event_digest,
            "event_id": f"evt-{event_digest[:32]}",
        }
    )


class FakeCursor:
    def __init__(self, *, one: Any = None, all_rows: Any = None) -> None:
        self.one = one
        self.all_rows = [] if all_rows is None else all_rows

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.all_rows


class FakeConnection:
    def __init__(self, responses: list[FakeCursor]) -> None:
        self.responses = responses
        self.events: list[tuple[str, Any]] = []

    def execute(self, query: str, parameters: Any = None) -> FakeCursor:
        normalized = " ".join(query.split())
        self.events.append((normalized, parameters))
        if not self.responses:
            raise AssertionError(f"unexpected query: {normalized}")
        return self.responses.pop(0)


class HarnessMaintenanceIntegrityPhasesCharacterizationTests(unittest.TestCase):
    def test_changed_integrity_phases_stay_within_architecture_budget(self) -> None:
        functions = (
            "_verify_run_event_chain",
            "_event_chain_digests",
            "_event_chain_row_is_valid",
            "database_snapshot",
            "_validated_database_health",
            "_database_page_state",
            "_database_run_counts",
            "_verify_backup_bundle",
            "_backup_verification_result",
            "_backup_files_are_admissible",
            "_verified_backup_snapshot",
            "_backup_snapshot_matches_manifest",
            "_backup_age_seconds",
        )
        for name in functions:
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_event_chain_preserves_row_access_and_digest_order(self) -> None:
        run_id = "run-1"
        first = event_row(
            run_id=run_id,
            sequence=1,
            event_type="run.started",
            stage="created",
            payload_json='{"one":1}',
            previous="0" * 64,
        )
        second = event_row(
            run_id=run_id,
            sequence=2,
            event_type="run.succeeded",
            stage="completed",
            payload_json='{"two":2}',
            previous=first["event_sha256"],
        )
        first.events.clear()
        second.events.clear()
        digest_bodies: list[dict[str, Any]] = []
        original_digest = INTEGRITY.digest_json

        def digest(value: dict[str, Any]) -> str:
            digest_bodies.append(copy.deepcopy(value))
            return original_digest(value)

        with mock.patch.object(INTEGRITY, "digest_json", side_effect=digest):
            self.assertTrue(
                INTEGRITY._verify_run_event_chain(
                    run_id,
                    "succeeded",
                    [first, second],
                )
            )

        body_access = [
            "sequence", "payload_json", "idempotency_key", "event_type",
            "stage", "created_at", "payload_sha256", "previous_event_sha256",
            "payload_sha256", "previous_event_sha256", "event_sha256",
            "event_id", "event_sha256",
        ]
        self.assertEqual(first.events, body_access)
        self.assertEqual(second.events, ["event_type", *body_access])
        self.assertEqual([body["sequence"] for body in digest_bodies], [1, 2])
        self.assertEqual(digest_bodies[0]["previous_event_sha256"], "0" * 64)

    def test_event_chain_admission_and_validation_short_circuit_exactly(self) -> None:
        row = event_row(
            run_id="run-1",
            sequence=1,
            event_type="run.succeeded",
            stage="completed",
            payload_json="{}",
            previous="0" * 64,
        )
        row.events.clear()
        self.assertFalse(INTEGRITY._verify_run_event_chain("run-1", "running", [row]))
        self.assertEqual(row.events, [])

        self.assertFalse(INTEGRITY._verify_run_event_chain("run-1", "succeeded", []))
        row["sequence"] = 2
        row.events.clear()
        self.assertFalse(INTEGRITY._verify_run_event_chain("run-1", "succeeded", [row]))
        self.assertEqual(
            row.events,
            [
                "event_type", "sequence", "payload_json", "idempotency_key",
                "event_type", "stage", "created_at", "payload_sha256",
                "previous_event_sha256",
            ],
        )

    def test_event_chain_catches_documented_native_failures_only(self) -> None:
        malformed = TracedRow({"event_type": "run.succeeded", "sequence": "bad"})
        self.assertFalse(
            INTEGRITY._verify_run_event_chain(
                "run-1",
                "succeeded",
                [malformed],
            )
        )

        class ExplodingRow(TracedRow):
            def __getitem__(self, key: str) -> Any:
                if key == "payload_json":
                    raise RuntimeError("unexpected row failure")
                return super().__getitem__(key)

        exploding = ExplodingRow({"event_type": "run.succeeded", "sequence": 1})
        with self.assertRaisesRegex(RuntimeError, "^unexpected row failure$"):
            INTEGRITY._verify_run_event_chain(
                "run-1",
                "succeeded",
                [exploding],
            )

    def successful_connection(self) -> FakeConnection:
        return FakeConnection(
            [
                FakeCursor(one=("ok",)),
                FakeCursor(
                    all_rows=[(name,) for name in sorted(INTEGRITY.REQUIRED_TABLES)]
                ),
                FakeCursor(all_rows=[]),
                FakeCursor(one=(4096,)),
                FakeCursor(one=(10,)),
                FakeCursor(one=(2,)),
                FakeCursor(one=("wal",)),
                FakeCursor(one=(2,)),
                FakeCursor(one=(7, 5, 2)),
            ]
        )

    def test_database_snapshot_preserves_query_failure_and_result_order(self) -> None:
        connection = self.successful_connection()
        accounting_calls: list[Path] = []

        def accounting(path: Path) -> dict[str, int]:
            accounting_calls.append(path)
            return {"logical_file_bytes": 123, "allocated_disk_bytes": 512}

        path = Path("/synthetic/harness.sqlite3")
        with mock.patch.object(INTEGRITY, "sqlite_file_accounting", side_effect=accounting):
            result = INTEGRITY.database_snapshot(connection, path)

        self.assertEqual(
            [query for query, _params in connection.events],
            [
                "PRAGMA quick_check",
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                "PRAGMA foreign_key_check",
                "PRAGMA page_size",
                "PRAGMA page_count",
                "PRAGMA freelist_count",
                "PRAGMA journal_mode",
                "PRAGMA auto_vacuum",
                "SELECT COUNT(*) AS total, SUM(CASE WHEN status IN (?, ?, ?) THEN 1 ELSE 0 END) AS terminal, SUM(CASE WHEN status NOT IN (?, ?, ?) THEN 1 ELSE 0 END) AS active FROM harness_runs",
            ],
        )
        self.assertEqual(accounting_calls, [path])
        self.assertEqual(
            list(result),
            [
                "quick_check", "foreign_key_check_rows", "journal_mode",
                "auto_vacuum", "page_size", "page_count", "freelist_pages",
                "live_page_bytes", "reclaimable_page_bytes", "run_counts",
                "logical_file_bytes", "allocated_disk_bytes",
            ],
        )
        self.assertEqual(result["run_counts"], {"total": 7, "terminal": 5, "active": 2})
        self.assertEqual(result["live_page_bytes"], 8 * 4096)
        self.assertEqual(result["journal_mode"], "wal")

    def test_database_snapshot_fails_before_later_queries_and_accounting(self) -> None:
        connection = FakeConnection([FakeCursor(one=("corrupt",))])
        with (
            mock.patch.object(INTEGRITY, "sqlite_file_accounting") as accounting,
            self.assertRaisesRegex(
                INTEGRITY.MaintenanceError,
                "^harness SQLite quick_check failed: corrupt$",
            ),
        ):
            INTEGRITY.database_snapshot(connection, Path("db"))
        accounting.assert_not_called()
        self.assertEqual(connection.events, [("PRAGMA quick_check", None)])

        connection = FakeConnection(
            [
                FakeCursor(one=("ok",)),
                FakeCursor(all_rows=[("harness_runs",)]),
            ]
        )
        with self.assertRaisesRegex(
            INTEGRITY.MaintenanceError,
            r"^harness SQLite is missing table\(s\): "
            r"harness_budget_reservations, harness_decisions, harness_events, "
            r"harness_evidence, harness_hypotheses, harness_metadata, "
            r"harness_model_calls, harness_tool_calls$",
        ):
            INTEGRITY.database_snapshot(connection, Path("db"))
        self.assertEqual(len(connection.events), 2)

    def backup_fixture(self, root: Path) -> tuple[Path, Path, Path]:
        bundle = root / "bundle-1"
        bundle.mkdir(mode=0o700)
        manifest = bundle / "manifest.json"
        snapshot = bundle / "investigation-harness.sqlite3"
        manifest.write_text("{}", encoding="utf-8")
        snapshot.write_bytes(b"sqlite")
        os.chmod(manifest, 0o600)
        os.chmod(snapshot, 0o600)
        return bundle, manifest, snapshot

    def test_backup_bundle_preserves_proof_order_and_result_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, manifest_path, snapshot_path = self.backup_fixture(Path(temporary))
            now = dt.datetime(2026, 8, 12, tzinfo=dt.timezone.utc)
            created = now - dt.timedelta(seconds=90)
            digest = "a" * 64
            manifest = {"harness_runs": 3}
            harness_manifest = {"present": True, "rows": 3}
            file_manifest = {"sha256": digest}
            required = ("run-2", "run-1")
            before = copy.deepcopy((manifest, harness_manifest, file_manifest, required))
            events: list[Any] = []

            def owner(path: Path) -> bool:
                events.append(("owner", path.name))
                return True

            def metadata(path: Path):
                events.append(("metadata", path.name))
                return manifest, created, harness_manifest, file_manifest

            def age(*args: Any) -> bool:
                events.append(("age", args))
                return True

            def sha(path: Path) -> str:
                events.append(("sha", path.name))
                return digest

            def inspect(path: Path, run_ids: tuple[str, ...]):
                events.append(("inspect", path.name, run_ids))
                return 3, {"run-1", "run-2"}, True

            with (
                mock.patch.object(INTEGRITY, "owner_only_regular_file", side_effect=owner),
                mock.patch.object(INTEGRITY, "_load_backup_metadata", side_effect=metadata),
                mock.patch.object(INTEGRITY, "_backup_age_is_valid", side_effect=age),
                mock.patch.object(INTEGRITY, "sha256_file", side_effect=sha),
                mock.patch.object(INTEGRITY, "_inspect_backup_database", side_effect=inspect),
            ):
                result = INTEGRITY._verify_backup_bundle(
                    bundle,
                    now=now,
                    max_age_seconds=3600,
                    required_run_ids=required,
                )

            self.assertEqual(
                [event[0] for event in events],
                ["owner", "owner", "metadata", "age", "sha", "inspect"],
            )
            self.assertEqual(events[0][1], manifest_path.name)
            self.assertEqual(events[1][1], snapshot_path.name)
            self.assertEqual(events[-1][2], required)
            self.assertEqual(
                result,
                {
                    "verified": True,
                    "bundle": "bundle-1",
                    "age_seconds": 90,
                    "sha256": digest,
                    "run_rows": 3,
                    "covered_retention_candidates": 2,
                    "candidate_event_chains_valid": True,
                    "_covered_run_ids": ("run-1", "run-2"),
                },
            )
            self.assertEqual(
                (manifest, harness_manifest, file_manifest, required),
                before,
            )

    def test_backup_bundle_short_circuits_each_fail_closed_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle, _manifest, _snapshot = self.backup_fixture(Path(temporary))
            now = dt.datetime(2026, 8, 12, tzinfo=dt.timezone.utc)
            with (
                mock.patch.object(INTEGRITY, "owner_only_regular_file", return_value=False) as owner,
                mock.patch.object(INTEGRITY, "_load_backup_metadata") as metadata,
            ):
                self.assertIsNone(
                    INTEGRITY._verify_backup_bundle(
                        bundle,
                        now=now,
                        max_age_seconds=3600,
                        required_run_ids=(),
                    )
                )
            self.assertEqual(owner.call_count, 1)
            metadata.assert_not_called()

            metadata_value = (
                {"harness_runs": 1},
                now,
                {"present": True, "rows": 1},
                {"sha256": "short"},
            )
            with (
                mock.patch.object(INTEGRITY, "owner_only_regular_file", return_value=True),
                mock.patch.object(INTEGRITY, "_load_backup_metadata", return_value=metadata_value),
                mock.patch.object(INTEGRITY, "_backup_age_is_valid", return_value=True),
                mock.patch.object(INTEGRITY, "sha256_file") as sha,
                mock.patch.object(INTEGRITY, "_inspect_backup_database") as inspect,
            ):
                self.assertIsNone(
                    INTEGRITY._verify_backup_bundle(
                        bundle,
                        now=now,
                        max_age_seconds=3600,
                        required_run_ids=(),
                    )
                )
            sha.assert_not_called()
            inspect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
