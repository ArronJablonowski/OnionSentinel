"""Characterize the private replay export entrypoint orchestration."""

from __future__ import annotations

import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.test_adjudicated_replay_case_architecture import function_metrics


ROOT = Path(__file__).resolve().parents[1]
EXPORTER_PATH = ROOT / "n8n/bin/export-adjudicated-analysis-replays.py"
SPEC = importlib.util.spec_from_file_location(
    "adjudicated_replay_export_orchestration", EXPORTER_PATH
)
exporter = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(exporter)
REAL_DATETIME = dt.datetime


class FrozenDatetime(REAL_DATETIME):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 8, 13, 1, 2, 3, 456789, tzinfo=tz)


class FakeConnection:
    def __init__(self, events: list[object]) -> None:
        self.events = events
        self.row_factory = None

    def close(self) -> None:
        self.events.append("close")


class AdjudicatedReplayExportOrchestrationTests(unittest.TestCase):
    def test_orchestration_phases_meet_architecture_contract(self) -> None:
        for name in (
            "_load_export_rows",
            "_project_replay_cases",
            "_export_payload",
            "_write_export",
            "main",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def _args(self, root: Path) -> SimpleNamespace:
        database = root / "alerts.sqlite3"
        database.touch()
        return SimpleNamespace(
            db=database,
            analysis_dir=root / "analysis",
            prompt_dir=root / "prompts",
            runner=root / "runner.py",
            out=root / "private/replays.json",
            limit=17,
            since="2026-08-01T00:00:00Z",
        )

    def _run_main(
        self,
        args: SimpleNamespace,
        items: list[dict[str, object]],
        replay_errors: dict[str, BaseException] | None = None,
    ) -> tuple[int, list[object], dict[str, object], str]:
        events: list[object] = []
        connection = FakeConnection(events)
        captured_payload: dict[str, object] = {}
        replay_errors = replay_errors or {}

        def connect(database: str, *, uri: bool = False, **kwargs):
            events.append(("connect", database, uri, kwargs))
            return connection

        def latest(conn, since, limit):
            events.append(("latest", conn.row_factory, since, limit))
            return items

        def replay(runner, item, *, analysis_root, prompt_root):
            identifier = str(item["adjudication_id"])
            events.append(
                ("replay", runner, identifier, analysis_root, prompt_root)
            )
            error = replay_errors.get(identifier)
            if error is not None:
                raise error
            return {"case_id": f"case-{identifier}"}

        def write(path: Path, payload: dict[str, object]) -> None:
            events.append(("write", path, tuple(payload)))
            captured_payload.update(payload)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}", encoding="utf-8")
            os.chmod(path, 0o600)

        runner = object()
        stdout = io.StringIO()
        with (
            mock.patch.object(exporter, "parse_args", return_value=args),
            mock.patch.object(
                exporter,
                "load_runner",
                side_effect=lambda path: events.append(("runner", path)) or runner,
            ),
            mock.patch.object(exporter.sqlite3, "connect", side_effect=connect),
            mock.patch.object(exporter, "latest_adjudications", side_effect=latest),
            mock.patch.object(exporter, "replay_case", side_effect=replay),
            mock.patch.object(exporter, "atomic_private_json", side_effect=write),
            mock.patch.object(exporter.dt, "datetime", FrozenDatetime),
            contextlib.redirect_stdout(stdout),
        ):
            result = exporter.main()
        return result, events, captured_payload, stdout.getvalue()

    def test_success_preserves_read_only_order_payload_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self._args(Path(directory))
            result, events, payload, stdout = self._run_main(
                args,
                [
                    {"adjudication_id": "first"},
                    {"adjudication_id": "second"},
                ],
            )

        runner = events[4][1]
        self.assertIs(runner, events[5][1])
        self.assertEqual(result, 0)
        self.assertEqual(
            events,
            [
                ("runner", args.runner),
                ("connect", f"file:{args.db}?mode=ro", True, {}),
                ("latest", sqlite3.Row, args.since, args.limit),
                "close",
                ("replay", runner, "first", args.analysis_dir, args.prompt_dir),
                ("replay", runner, "second", args.analysis_dir, args.prompt_dir),
                (
                    "write",
                    args.out,
                    (
                        "schema",
                        "version",
                        "suite_name",
                        "generated_at",
                        "sensitive_local_artifact",
                        "source_database",
                        "cases",
                        "skipped",
                    ),
                ),
            ],
        )
        self.assertEqual(
            payload,
            {
                "schema": exporter.REPLAY_SCHEMA,
                "version": 1,
                "suite_name": "private-analyst-adjudications",
                "generated_at": "2026-08-13T01:02:03.456789Z",
                "sensitive_local_artifact": True,
                "source_database": args.db.name,
                "cases": [
                    {"case_id": "case-first"},
                    {"case_id": "case-second"},
                ],
                "skipped": [],
            },
        )
        self.assertEqual(
            json.loads(stdout),
            {
                "out": str(args.out),
                "exported_cases": 2,
                "skipped_cases": 0,
                "mode": "0o600",
            },
        )

    def test_handled_case_errors_preserve_skip_projection(self) -> None:
        handled = (
            OSError("o" * 600),
            UnicodeError("unicode failure"),
            ValueError("value failure"),
            json.JSONDecodeError("json failure", "x", 0),
        )
        for error in handled:
            with self.subTest(error=type(error).__name__):
                with tempfile.TemporaryDirectory() as directory:
                    args = self._args(Path(directory))
                    identifier = "a" * 200
                    result, _, payload, stdout = self._run_main(
                        args,
                        [{"adjudication_id": identifier}],
                        {identifier: error},
                    )
                self.assertEqual(result, 0)
                self.assertEqual(payload["cases"], [])
                self.assertEqual(
                    payload["skipped"],
                    [
                        {
                            "adjudication_id": identifier[:160],
                            "reason": str(error)[:500],
                        }
                    ],
                )
                self.assertEqual(json.loads(stdout)["skipped_cases"], 1)

    def test_unhandled_case_error_propagates_after_connection_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self._args(Path(directory))
            with self.assertRaisesRegex(TypeError, "unhandled"):
                self._run_main(
                    args,
                    [{"adjudication_id": "bad"}],
                    {"bad": TypeError("unhandled")},
                )

    def test_missing_database_fails_before_loading_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self._args(Path(directory))
            args.db.unlink()
            with (
                mock.patch.object(exporter, "parse_args", return_value=args),
                mock.patch.object(exporter, "load_runner") as load_runner,
                self.assertRaisesRegex(
                    SystemExit,
                    f"^alert-store database not found: {args.db}$",
                ),
            ):
                exporter.main()
        load_runner.assert_not_called()

    def test_schema_error_is_projected_and_connection_is_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self._args(Path(directory))
            events: list[object] = []
            connection = FakeConnection(events)
            with (
                mock.patch.object(exporter, "parse_args", return_value=args),
                mock.patch.object(exporter, "load_runner", return_value=object()),
                mock.patch.object(
                    exporter.sqlite3, "connect", return_value=connection
                ),
                mock.patch.object(
                    exporter,
                    "latest_adjudications",
                    side_effect=sqlite3.OperationalError("missing table"),
                ),
                self.assertRaisesRegex(
                    SystemExit,
                    "^analyst adjudication schema is unavailable: missing table$",
                ),
            ):
                exporter.main()
        self.assertEqual(events, ["close"])


if __name__ == "__main__":
    unittest.main()
