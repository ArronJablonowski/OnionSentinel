from __future__ import annotations

import contextlib
import hashlib
import inspect
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import harness_store_trace_repository as trace_repository
import harness_store_trace_verification as trace_verification
from harness_contracts import JobEnvelope, ledger_manifest
from harness_policy import (
    LEDGER_MANIFEST_SCHEMA_V1,
    HarnessIntegrityError,
    HarnessPolicy,
    RunStatus,
    Stage,
    canonical_json,
    digest_json,
)
from harness_store_foundation import _connect
from onion_sentinel_harness import HarnessStore


class HarnessTraceVerificationArchitectureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "state" / "harness.sqlite3"
        self.log_path = self.root / "logs" / "harness.jsonl"
        self.store = HarnessStore(self.db_path, log_path=self.log_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def prompt_package() -> dict:
        return {
            "alert": {
                "alert_id": "alert-194",
                "rule_name": "Trace verification characterization",
            },
            "group_id": "group-194",
            "evidence_reference_contract": {
                "schema": "onion-sentinel-evidence-reference-contract-v1",
                "references": [],
            },
        }

    def start_run(self, run_id: str) -> None:
        envelope = JobEnvelope.from_prompt(
            run_id=run_id,
            prompt_package=self.prompt_package(),
            role="soc-analyst",
            assigned_route="codex-cli:gpt-5.6-sol:high",
            configuration={
                "query_mode": "read-only",
                "reviewer_route": "codex-cli:gpt-5.6-terra:high",
            },
        )
        self.store.start_run(envelope, HarnessPolicy.disabled_default())

    def append_event(self, run_id: str, *, ordinal: int = 1) -> None:
        self.store.append_event(
            run_id,
            "verification.probe",
            Stage.POST_PROCESSING.value,
            {"ordinal": ordinal},
            idempotency_key=f"verification.probe:{ordinal}",
        )

    def rewrite_chain(
        self,
        run_id: str,
        payload_rewriter,
    ) -> None:
        """Rewrite selected payloads while keeping the event chain coherent."""
        with _connect(self.db_path) as connection:
            rows = connection.execute(
                "SELECT * FROM harness_events WHERE run_id = ? ORDER BY sequence",
                (run_id,),
            ).fetchall()
            previous = "0" * 64
            for row in rows:
                payload_json = payload_rewriter(row, str(row["payload_json"]))
                payload_sha256 = hashlib.sha256(
                    payload_json.encode("utf-8")
                ).hexdigest()
                body = {
                    "run_id": run_id,
                    "sequence": int(row["sequence"]),
                    "idempotency_key": row["idempotency_key"],
                    "event_type": row["event_type"],
                    "stage": row["stage"],
                    "created_at": row["created_at"],
                    "payload_sha256": payload_sha256,
                    "previous_event_sha256": previous,
                }
                event_sha256 = digest_json(body)
                connection.execute(
                    """
                    UPDATE harness_events
                    SET payload_json = ?, payload_sha256 = ?,
                        previous_event_sha256 = ?, event_sha256 = ?, event_id = ?
                    WHERE run_id = ? AND sequence = ?
                    """,
                    (
                        payload_json,
                        payload_sha256,
                        previous,
                        event_sha256,
                        f"evt-{event_sha256[:32]}",
                        run_id,
                        row["sequence"],
                    ),
                )
                previous = event_sha256

    def replace_terminal_manifest(
        self,
        run_id: str,
        manifest: object,
        *,
        legacy_identity: bool = False,
    ) -> None:
        def rewrite(row, payload_json: str) -> str:
            payload = json.loads(payload_json)
            if legacy_identity and row["event_type"] == "run.started":
                payload.pop("assigned_reviewer_route", None)
            if row["event_type"] == "run.succeeded":
                payload["ledger_manifest"] = manifest
            return canonical_json(payload)

        self.rewrite_chain(run_id, rewrite)

    @staticmethod
    @contextlib.contextmanager
    def query_only_connection(path: Path):
        uri = f"{path.resolve().as_uri()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5.0)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            yield connection
        finally:
            connection.close()

    def test_verify_chain_signature_unknown_run_and_query_only_contract(self) -> None:
        self.assertEqual(
            str(inspect.signature(trace_repository.HarnessStoreTraceRepository.verify_chain)),
            "(self, run_id: 'str') -> 'dict[str, Any]'",
        )
        with self.assertRaisesRegex(HarnessIntegrityError, "unknown harness run"):
            self.store.verify_chain("missing-run")

        self.start_run("query-only-run")
        self.append_event("query-only-run")
        with mock.patch.object(
            trace_repository,
            "_connect",
            side_effect=self.query_only_connection,
        ):
            verification = self.store.verify_chain("query-only-run")
        self.assertEqual(
            verification,
            {
                "run_id": "query-only-run",
                "valid": True,
                "event_count": 2,
                "head_sha256": verification["head_sha256"],
                "ledger_manifest_bound": False,
                "ledger_manifest_schema": "",
                "errors": [],
            },
        )
        self.assertRegex(verification["head_sha256"], r"^[0-9a-f]{64}$")

    def test_verification_owner_is_inward_and_facade_is_bounded(self) -> None:
        source = inspect.getsource(trace_verification)
        self.assertNotIn("import harness_store_trace_repository", source)
        self.assertNotIn("from harness_store_trace_repository", source)
        self.assertNotIn("import harness_store_foundation", source)
        self.assertNotIn("from harness_store_foundation", source)
        self.assertIn("hmac.compare_digest", source)
        facade = inspect.getsource(
            trace_repository.HarnessStoreTraceRepository.verify_chain
        )
        self.assertLessEqual(len(facade.splitlines()), 8)

    def test_event_chain_error_projection_and_order_are_exact(self) -> None:
        run_id = "event-errors-run"
        self.start_run(run_id)
        self.append_event(run_id)
        with _connect(self.db_path) as connection:
            connection.execute(
                """
                UPDATE harness_events
                SET sequence = 4, payload_json = '{"tampered":true}',
                    payload_sha256 = 'payload-bad',
                    previous_event_sha256 = 'previous-bad',
                    event_sha256 = 'event-bad', event_id = 'event-id-bad'
                WHERE run_id = ? AND sequence = 2
                """,
                (run_id,),
            )
        verification = self.store.verify_chain(run_id)
        self.assertEqual(
            verification,
            {
                "run_id": run_id,
                "valid": False,
                "event_count": 2,
                "head_sha256": "event-bad",
                "ledger_manifest_bound": False,
                "ledger_manifest_schema": "",
                "errors": [
                    "sequence gap at 4",
                    "payload digest mismatch at 4",
                    "previous hash mismatch at 4",
                    "event hash mismatch at 4",
                    "event id mismatch at 4",
                ],
            },
        )

    def test_empty_and_hypothesis_manifest_projections_are_exact(self) -> None:
        empty_run = "empty-run"
        self.start_run(empty_run)
        with _connect(self.db_path) as connection:
            connection.execute(
                "DELETE FROM harness_events WHERE run_id = ?",
                (empty_run,),
            )
        self.assertEqual(
            self.store.verify_chain(empty_run),
            {
                "run_id": empty_run,
                "valid": False,
                "event_count": 0,
                "head_sha256": "",
                "ledger_manifest_bound": False,
                "ledger_manifest_schema": "",
                "errors": [],
            },
        )

        malformed_run = "malformed-hypothesis-run"
        self.start_run(malformed_run)
        self.store.append_event(
            malformed_run,
            "hypotheses.updated",
            Stage.POST_PROCESSING.value,
            {"manifest_digest": "placeholder"},
            idempotency_key="hypotheses.updated:1",
        )
        self.rewrite_chain(
            malformed_run,
            lambda row, payload: (
                "{"
                if row["event_type"] == "hypotheses.updated"
                else payload
            ),
        )
        malformed = self.store.verify_chain(malformed_run)
        self.assertEqual(
            malformed["errors"],
            ["latest hypothesis event has no manifest digest"],
        )

        mismatch_run = "hypothesis-mismatch-run"
        self.start_run(mismatch_run)
        self.store.append_event(
            mismatch_run,
            "hypotheses.updated",
            Stage.POST_PROCESSING.value,
            {"manifest_digest": "not-the-empty-manifest"},
            idempotency_key="hypotheses.updated:1",
        )
        mismatch = self.store.verify_chain(mismatch_run)
        self.assertEqual(mismatch["errors"], ["hypothesis ledger manifest mismatch"])

    def test_terminal_manifest_compatibility_matrix_is_exact(self) -> None:
        run_id = "terminal-run"
        self.start_run(run_id)
        self.store.finish(run_id, status=RunStatus.SUCCEEDED.value)
        current = self.store.verify_chain(run_id)
        self.assertTrue(current["valid"])
        self.assertTrue(current["ledger_manifest_bound"])
        self.assertEqual(
            current["ledger_manifest_schema"],
            "onion-sentinel-harness-ledger-manifest-v2",
        )

        cases = (
            (
                "missing",
                None,
                False,
                ["terminal ledger manifest is missing or malformed"],
                "",
                False,
            ),
            (
                "unsupported",
                {"schema": "unsupported-ledger-manifest-v99"},
                False,
                ["unsupported terminal ledger manifest schema"],
                "unsupported-ledger-manifest-v99",
                False,
            ),
            (
                "downgrade",
                {"schema": LEDGER_MANIFEST_SCHEMA_V1},
                False,
                ["terminal ledger manifest schema downgrade"],
                LEDGER_MANIFEST_SCHEMA_V1,
                False,
            ),
        )
        for label, manifest, legacy, errors, schema, bound in cases:
            with self.subTest(label=label):
                self.replace_terminal_manifest(
                    run_id,
                    manifest,
                    legacy_identity=legacy,
                )
                result = self.store.verify_chain(run_id)
                self.assertEqual(result["errors"], errors)
                self.assertEqual(result["ledger_manifest_schema"], schema)
                self.assertEqual(result["ledger_manifest_bound"], bound)

        with _connect(self.db_path) as connection:
            legacy = ledger_manifest(
                connection,
                run_id,
                schema=LEDGER_MANIFEST_SCHEMA_V1,
            )
        self.replace_terminal_manifest(run_id, legacy, legacy_identity=True)
        accepted = self.store.verify_chain(run_id)
        self.assertTrue(accepted["valid"])
        self.assertTrue(accepted["ledger_manifest_bound"])
        self.assertEqual(accepted["ledger_manifest_schema"], LEDGER_MANIFEST_SCHEMA_V1)

        tampered = dict(legacy)
        tampered["run_identity_sha256"] = "0" * 64
        self.replace_terminal_manifest(run_id, tampered, legacy_identity=True)
        mismatch = self.store.verify_chain(run_id)
        self.assertEqual(mismatch["errors"], ["terminal ledger manifest mismatch"])


if __name__ == "__main__":
    unittest.main()
