from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))

from scheduler_terminal_recovery import (  # noqa: E402
    RecoveryJob,
    RecoveryRun,
    _run_identity_matches,
)


class RecordingPayload(dict[str, Any]):
    def __init__(self, values: dict[str, Any]) -> None:
        super().__init__(values)
        self.calls: list[tuple[str, object]] = []

    def get(self, key: str, default: object = None) -> object:
        self.calls.append(("get", key))
        return super().get(key, default)


class SchedulerTerminalIdentityProjectionTests(unittest.TestCase):
    def job(self, payload: RecordingPayload) -> RecoveryJob:
        return RecoveryJob(
            job_id=7,
            job_type="ai_analysis",
            group_id="group-1",
            lease_token="lease-1",
            processing_started_at="2026-08-08T10:00:00Z",
            expected_role="soc-analyst",
            payload=payload,
        )

    @staticmethod
    def recovery_run(
        *,
        run_id: str = "run-1",
        alert_id: str = "alert-1",
        route: str = "codex-cli:gpt-5.5:high",
    ) -> RecoveryRun:
        return RecoveryRun(
            run_id=run_id,
            case_id="",
            alert_id=alert_id,
            assigned_route=route,
        )

    def assert_projection(
        self,
        payload_values: dict[str, Any],
        expected: bool,
        expected_calls: list[tuple[str, object]],
        *,
        run: RecoveryRun | None = None,
        lane: str = "cli",
    ) -> None:
        payload = RecordingPayload(payload_values)
        self.assertIs(
            _run_identity_matches(
                self.job(payload),
                run or self.recovery_run(),
                lane,
            ),
            expected,
        )
        self.assertEqual(payload.calls, expected_calls)

    def test_missing_run_or_alert_rejects_before_payload_access(self) -> None:
        for run in (
            self.recovery_run(run_id=""),
            self.recovery_run(alert_id=""),
        ):
            with self.subTest(run=run):
                self.assert_projection(
                    {"expected_assigned_route": run.assigned_route},
                    False,
                    [],
                    run=run,
                )

    def test_provider_lane_rejects_before_payload_access(self) -> None:
        for lane, route in (
            ("cli", "ollama:qwen3:30b"),
            ("ollama", "codex-cli:gpt-5.5:high"),
            ("any", "codex-cli:gpt-5.5:high"),
        ):
            with self.subTest(lane=lane, route=route):
                self.assert_projection(
                    {"expected_assigned_route": route},
                    False,
                    [],
                    run=self.recovery_run(route=route),
                    lane=lane,
                )

    def test_expected_route_precedence_and_short_circuit_are_exact(self) -> None:
        calls = [("get", "expected_assigned_route")]
        self.assert_projection(
            {
                "expected_assigned_route": "codex-cli:other:high",
                "assigned_route": "codex-cli:gpt-5.5:high",
                "alert_id": "alert-1",
            },
            False,
            calls,
        )
        self.assert_projection(
            {
                "expected_assigned_route": "",
                "assigned_route": "codex-cli:other:high",
                "alert_id": "alert-1",
            },
            False,
            calls + [("get", "assigned_route")],
        )

    def test_empty_route_pins_allow_optional_empty_alert_pins(self) -> None:
        self.assert_projection(
            {},
            True,
            [
                ("get", "expected_assigned_route"),
                ("get", "assigned_route"),
                ("get", "alert_id"),
                ("get", "representative_alert_id"),
            ],
        )

    def test_alert_pin_set_must_equal_exact_run_alert(self) -> None:
        cases = [
            ({"alert_id": "alert-1"}, True),
            ({"representative_alert_id": "alert-1"}, True),
            ({"alert_id": "alert-1", "representative_alert_id": "alert-1"}, True),
            ({"alert_id": "different"}, False),
            ({"alert_id": "alert-1", "representative_alert_id": "different"}, False),
            ({"alert_id": "  alert-1  "}, True),
        ]
        for values, expected in cases:
            with self.subTest(values=values):
                expected_calls = [
                    ("get", "expected_assigned_route"),
                    ("get", "assigned_route"),
                    ("get", "alert_id"),
                ]
                if str(values.get("alert_id") or "").strip():
                    expected_calls.append(("get", "alert_id"))
                expected_calls.append(("get", "representative_alert_id"))
                if str(values.get("representative_alert_id") or "").strip():
                    expected_calls.append(("get", "representative_alert_id"))
                self.assert_projection(
                    values,
                    expected,
                    expected_calls,
                )


if __name__ == "__main__":
    unittest.main()
