from __future__ import annotations

import dataclasses
import importlib
import inspect
import json
import sqlite3
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

CONTRACTS = importlib.import_module("harness_contracts")


class HarnessContractsArchitectureTests(unittest.TestCase):
    def test_compatibility_surface_signatures_and_dataclass_are_stable(self) -> None:
        expected_names = {
            "AgentRole", "DIGEST_RE", "HARNESS_SCHEMA",
            "HarnessIntegrityError", "HarnessPolicyError", "IDENTIFIER_RE",
            "INVESTIGATION_SKILL_ADVISORY_MODE",
            "INVESTIGATION_SKILL_UNAVAILABLE_MODE",
            "LEDGER_MANIFEST_SCHEMA", "LEDGER_MANIFEST_SCHEMA_V1",
            "LEDGER_TABLE_ORDERS", "LEGACY_RUN_IDENTITY_COLUMNS_V1",
            "MAX_ATTESTED_INVESTIGATION_SKILLS", "MAX_EVENT_ITEMS",
            "MAX_EVENT_PAYLOAD_BYTES", "MAX_EVENT_STRING",
            "RUN_IDENTITY_COLUMNS", "SECRET_KEY_RE", "SECRET_VALUE_PATTERNS",
            "SUPPORTED_LEDGER_MANIFEST_SCHEMAS", "JobEnvelope",
            "_model_route", "_redacted_string", "_valid_identifier",
            "approximate_evidence_rows", "bounded_metadata", "canonical_json",
            "digest_json", "hypothesis_manifest_digest",
            "investigation_skill_selection_attestation", "ledger_manifest",
            "sanitize_metadata", "task_kind_for_role", "utc_now",
        }
        self.assertFalse(expected_names.difference(vars(CONTRACTS)))
        expected_signatures = {
            "_redacted_string": "(value: 'object', maximum: 'int' = 4000) -> 'str'",
            "sanitize_metadata": "(value: 'Any', *, depth: 'int' = 0, item_budget: 'list[int] | None' = None) -> 'Any'",
            "bounded_metadata": "(value: 'Any') -> 'dict[str, Any]'",
            "investigation_skill_selection_attestation": "(prompt_package: 'Mapping[str, Any]') -> 'dict[str, Any]'",
            "hypothesis_manifest_digest": "(rows: 'Iterable[Mapping[str, Any]]') -> 'str'",
            "ledger_manifest": "(connection: 'sqlite3.Connection', run_id: 'str', *, schema: 'str' = 'onion-sentinel-harness-ledger-manifest-v2') -> 'dict[str, Any]'",
            "approximate_evidence_rows": "(value: 'Any', *, depth: 'int' = 0) -> 'int'",
            "JobEnvelope.from_prompt": "(*, run_id: 'str', prompt_package: 'Mapping[str, Any]', role: 'str', assigned_route: 'str', configuration: 'Mapping[str, Any]', reanalysis_attempt_id: 'str' = '') -> \"'JobEnvelope'\"",
        }
        for name, expected in expected_signatures.items():
            target = (
                CONTRACTS.JobEnvelope.from_prompt
                if name == "JobEnvelope.from_prompt"
                else getattr(CONTRACTS, name)
            )
            with self.subTest(name=name):
                self.assertEqual(str(inspect.signature(target)), expected)
        self.assertTrue(dataclasses.is_dataclass(CONTRACTS.JobEnvelope))
        self.assertEqual(
            CONTRACTS.JobEnvelope.__dataclass_params__.frozen,
            True,
        )
        self.assertEqual(
            [field.name for field in dataclasses.fields(CONTRACTS.JobEnvelope)],
            [
                "run_id", "trace_id", "correlation_id", "case_id",
                "alert_id", "role", "task_kind", "assigned_route",
                "assigned_reviewer_route", "prompt_digest",
                "evidence_manifest_digest", "configuration_digest",
                "skill_selection_attestation", "parent_run_id", "created_at",
            ],
        )

    def test_metadata_projection_is_bounded_ordered_and_secret_safe(self) -> None:
        projected = CONTRACTS.sanitize_metadata(
            {
                "token": "do-not-export",
                "safe": "Bearer abcdefghijklmnop",
                "nested": [{"v": "ok"}, {"password": "hidden"}],
            }
        )
        self.assertEqual(
            projected,
            {
                "token": "[redacted-sensitive-field]",
                "safe": "[redacted-sensitive-value]",
                "nested": [
                    {"v": "ok"},
                    {"password": "[redacted-sensitive-field]"},
                ],
            },
        )
        self.assertEqual(len(CONTRACTS.sanitize_metadata(list(range(300)))), 255)
        self.assertEqual(
            CONTRACTS.sanitize_metadata({"a": {"b": {"c": 1}}}, depth=8),
            {"a": "[truncated]"},
        )
        oversized = CONTRACTS.bounded_metadata(
            {f"field_{index}": "x" * 4_000 for index in range(64)}
        )
        self.assertEqual(set(oversized), {"payload_omitted", "original_bytes", "sha256"})
        self.assertTrue(oversized["payload_omitted"])
        self.assertEqual(len(oversized["sha256"]), 64)

    @staticmethod
    def skill_selection() -> dict[str, object]:
        return {
            "mode": "shadow",
            "enforcement": "advisory_only",
            "registry_version": 1,
            "registry_sha256": "a" * 64,
            "selected": [
                {"id": "z-skill", "version": 2, "skill_sha256": "c" * 64},
                {"id": "a-skill", "version": 1, "skill_sha256": "b" * 64},
            ],
            "selected_count": 2,
            "truncated": False,
        }

    def test_skill_attestation_is_content_free_sorted_and_fail_closed(self) -> None:
        selected = self.skill_selection()
        selected["selected"][0]["guidance"] = "secret body"
        selected["selected"][1]["telemetry"] = {"source_ip": "192.0.2.10"}
        self.assertEqual(
            CONTRACTS.investigation_skill_selection_attestation(
                {"investigation_skills": selected}
            ),
            {
                "registry_version": 1,
                "registry_sha256": "a" * 64,
                "selected": [
                    {"id": "a-skill", "version": 1, "skill_sha256": "b" * 64},
                    {"id": "z-skill", "version": 2, "skill_sha256": "c" * 64},
                ],
                "selected_count": 2,
                "truncated": False,
                "advisory_mode": "advisory_only",
            },
        )
        self.assertEqual(
            CONTRACTS.investigation_skill_selection_attestation({}),
            {
                "registry_version": 0,
                "registry_sha256": "",
                "selected": [],
                "selected_count": 0,
                "truncated": False,
                "advisory_mode": "unavailable",
            },
        )
        invalid_cases = (
            ([], "selection must be an object"),
            ({**self.skill_selection(), "registry_version": True}, "registry version is invalid"),
            ({**self.skill_selection(), "mode": "enforced"}, "advisory-only"),
            ({**self.skill_selection(), "selected_count": 1}, "selected count does not match"),
        )
        for raw, message in invalid_cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                CONTRACTS.HarnessIntegrityError,
                message,
            ):
                CONTRACTS.investigation_skill_selection_attestation(
                    {"investigation_skills": raw}
                )

    def test_manifest_and_evidence_accounting_outputs_are_stable(self) -> None:
        rows = [
            {
                "hypothesis_id": "h2", "statement_digest": "b" * 64,
                "status": "open", "supporting_refs_json": "[]",
                "contradicting_refs_json": "[]",
                "next_discriminator": "next 2", "revision": 2,
            },
            {
                "hypothesis_id": "h1", "statement_digest": "a" * 64,
                "status": "supported", "supporting_refs_json": '["e1"]',
                "contradicting_refs_json": "[]",
                "next_discriminator": "next 1", "revision": 1,
            },
        ]
        self.assertEqual(
            CONTRACTS.hypothesis_manifest_digest(rows),
            "a046dd4ac63e0b891f62879281be76fe23afd871a284933fac6ed0ef01dad540",
        )
        self.assertEqual(
            CONTRACTS.approximate_evidence_rows(
                {
                    "results": [{"rows": [1, 2]}, {"hits": [3]}],
                    "samples": [1, 2, 3],
                    "nested": {"records": [1]},
                }
            ),
            9,
        )
        self.assertEqual(
            CONTRACTS.approximate_evidence_rows({"rows": [1]}, depth=13),
            0,
        )

    def test_job_envelope_projection_digest_and_error_order_are_stable(self) -> None:
        prompt = {
            "alert": {"alert_id": "alert-1"},
            "group_id": "group-1",
            "evidence_reference_contract": {"references": [{"ref": "x"}]},
            "investigation_skills": self.skill_selection(),
            "parent_analysis_id": "parent-1",
        }
        configuration = {
            "reviewer_route": "codex-cli:gpt-5.6-terra:high",
            "query_mode": "read-only",
        }
        with mock.patch.object(
            CONTRACTS,
            "utc_now",
            return_value="2026-08-12T00:00:00Z",
        ):
            envelope = CONTRACTS.JobEnvelope.from_prompt(
                run_id="run-1",
                prompt_package=prompt,
                role="soc-analyst",
                assigned_route="codex-cli:gpt-5.6-sol:high",
                configuration=configuration,
            )
        self.assertEqual(envelope.trace_id, "1d454ca1b5d8aa845269a123d2e925b0")
        self.assertEqual(envelope.task_kind, "alert-triage")
        self.assertEqual(envelope.case_id, "alert-1")
        self.assertEqual(envelope.correlation_id, "group-1")
        self.assertEqual(envelope.parent_run_id, "parent-1")
        self.assertEqual(
            envelope.job_digest,
            "7aebc23185a781f3f8ed8f970125694f495f8668475292659f5d26bd449443e3",
        )
        invalid = dict(
            run_id="bad id",
            prompt_package={"investigation_skills": []},
            role="not-a-role",
            assigned_route="bad route",
            configuration={},
        )
        with self.assertRaisesRegex(
            CONTRACTS.HarnessPolicyError,
            "unsupported agent role: not-a-role",
        ):
            CONTRACTS.JobEnvelope.from_prompt(**invalid)
        invalid["role"] = "soc-analyst"
        with self.assertRaisesRegex(CONTRACTS.HarnessPolicyError, "run_id"):
            CONTRACTS.JobEnvelope.from_prompt(**invalid)

    def test_ledger_schema_rejection_precedes_database_access(self) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            with self.assertRaisesRegex(
                CONTRACTS.HarnessIntegrityError,
                "unsupported ledger manifest schema: future-v9",
            ):
                CONTRACTS.ledger_manifest(
                    connection,
                    "run-1",
                    schema="future-v9",
                )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
