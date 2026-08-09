from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_controlled_terminal_proof import (  # noqa: E402
    ControlledTerminalProofSources,
    prove_controlled_terminal_success,
)


class Result:
    def __init__(self, row: object) -> None:
        self.row = row

    def fetchone(self) -> object:
        return self.row


class FakeConnection:
    def __init__(self, rows: list[object]) -> None:
        self.rows = iter(rows)
        self.closed = False

    def execute(self, *_args: object) -> Result:
        if len(_args) == 1 and _args[0] == "BEGIN":
            return Result(None)
        return Result(next(self.rows))

    def close(self) -> None:
        self.closed = True


class SchedulerControlledTerminalProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = {
            "cohort_id": "cohort-1",
            "dispatch_id": "dispatch-1",
            "release_id": "a" * 40,
            "representative_alert_id": "alert-1",
            "stable_group_id": "group-1",
            "stable_group_key": "v2|group-1",
            "agent_role": "soc-analyst",
            "reanalysis_attempt_id": "",
        }
        self.job_payload = {
            **self.identity,
            "alert_id": "alert-1",
            "group_id": "group-1",
            "stable_group_id": "group-1",
        }
        self.response = {
            "_analysis_controlled_claim_sha256": "b" * 64,
        }
        self.job = {
            "id": 7,
            "status": "completed",
            "lease_token": None,
            "lease_expires_at": None,
            "rerun_requested": 0,
            "payload_json": json.dumps(self.job_payload),
        }
        self.accepted = {
            "group_id": "group-1",
            "alert_id": "alert-1",
            "agent_role": "soc-analyst",
            "response_json": json.dumps(self.response),
        }
        self.recovery = {
            "analysis_id": "analysis-1",
            "job_id": 7,
            "job_type": "ai_analysis",
            "stable_group_id": "group-1",
            "response_digest": "c" * 64,
            "stored_response_fallback_digest": "d" * 64,
            "accepted_fields": {"model": "model-1"},
            "claim_digest": "b" * 64,
            "identity": self.identity,
        }
        self.connection = FakeConnection(
            [self.job, self.accepted, None]
        )
        self.sources = ControlledTerminalProofSources(
            open_readonly_database=mock.Mock(return_value=self.connection),
            accepted_fields_match=mock.Mock(return_value=True),
            storage_canonical_digest=mock.Mock(return_value="d" * 64),
            valid_digest=mock.Mock(return_value=True),
        )

    def prove(self) -> bool:
        return prove_controlled_terminal_success(
            self.sources,
            Path("/synthetic/alerts.sqlite3"),
            self.recovery,
        )

    def test_soc_terminal_proof_requires_no_incident_attempt(self) -> None:
        self.assertTrue(self.prove())
        self.assertTrue(self.connection.closed)
        self.sources.accepted_fields_match.assert_called_once_with(
            self.accepted,
            self.recovery["accepted_fields"],
        )

    def test_ir_terminal_proof_requires_exact_completed_attempt(self) -> None:
        self.identity["agent_role"] = "incident-responder"
        self.identity["reanalysis_attempt_id"] = "attempt-1"
        self.job_payload.update(
            {
                "agent_role": "incident-responder",
                "reanalysis_run_id": "run-1",
                "case_id": "case-1",
            }
        )
        self.job["payload_json"] = json.dumps(self.job_payload)
        self.accepted["agent_role"] = "incident-responder"
        self.recovery["job_type"] = "incident_response_analysis"
        attempt = {
            "attempt_id": "attempt-1",
            "run_id": "run-1",
            "case_id": "case-1",
            "group_id": "group-1",
            "status": "completed",
            "analysis_id": "analysis-1",
        }
        self.connection = FakeConnection(
            [self.job, self.accepted, attempt]
        )
        self.sources = ControlledTerminalProofSources(
            open_readonly_database=mock.Mock(return_value=self.connection),
            accepted_fields_match=mock.Mock(return_value=True),
            storage_canonical_digest=mock.Mock(return_value="d" * 64),
            valid_digest=mock.Mock(return_value=True),
        )

        self.assertTrue(self.prove())

        attempt["status"] = "failed"
        self.connection = FakeConnection(
            [self.job, self.accepted, attempt]
        )
        self.sources = ControlledTerminalProofSources(
            open_readonly_database=mock.Mock(return_value=self.connection),
            accepted_fields_match=mock.Mock(return_value=True),
            storage_canonical_digest=mock.Mock(return_value="d" * 64),
            valid_digest=mock.Mock(return_value=True),
        )
        self.assertFalse(self.prove())

    def test_active_lease_or_rerun_request_rejects_proof(self) -> None:
        for field, value in (
            ("lease_token", "still-owned"),
            ("lease_expires_at", "2026-08-08T12:00:00Z"),
            ("rerun_requested", 1),
        ):
            with self.subTest(field=field):
                changed = dict(self.job)
                changed[field] = value
                self.connection = FakeConnection(
                    [changed, self.accepted, None]
                )
                self.sources = ControlledTerminalProofSources(
                    open_readonly_database=mock.Mock(
                        return_value=self.connection
                    ),
                    accepted_fields_match=mock.Mock(return_value=True),
                    storage_canonical_digest=mock.Mock(
                        return_value="d" * 64
                    ),
                    valid_digest=mock.Mock(return_value=True),
                )
                self.assertFalse(self.prove())

    def test_response_digest_or_claim_mismatch_rejects_proof(self) -> None:
        self.sources.storage_canonical_digest.return_value = "e" * 64
        self.assertFalse(self.prove())

    def test_malformed_database_json_returns_no_proof(self) -> None:
        self.job["payload_json"] = "{"
        self.assertFalse(self.prove())
        self.assertTrue(self.connection.closed)


if __name__ == "__main__":
    unittest.main()
