#!/usr/bin/env python3
"""Characterization and architecture gates for query normalization."""
from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
COMPAT_V1 = ROOT / "n8n" / "compat" / "investigation-pivots-v1"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import investigation_query_normalization as NORMALIZATION  # noqa: E402


EXPECTED_NAMESPACE = {
    "ALERT_INDEX_SCOPE", "ALLOWED_ACTOR_ROLES", "ALLOWED_AGGREGATIONS",
    "ALLOWED_DIALECTS", "ALLOWED_PURPOSES", "ALLOWED_ROLE_SEMANTICS",
    "ALLOWED_STATUSES", "Any", "EVENT_TUPLE_FIELDS", "EVENT_TUPLE_PATHS",
    "INVESTIGATION_QUERY_CONTRACT", "INVESTIGATION_QUERY_OPERATION",
    "InvestigationQueryContractError", "MAX_AUTHORIZATION_WINDOW",
    "MAX_BATCH_HITS", "MAX_BATCH_OBSERVABLES", "MAX_CONTEXT_EVENT_TUPLES",
    "MAX_CONTEXT_OBSERVABLES_PER_KIND", "MAX_DISCOVERED_OBSERVABLES",
    "MAX_QUERIES", "MAX_QUERY_HITS", "MAX_QUERY_OBSERVABLES", "MAX_WINDOW",
    "OBSERVABLE_FIELDS", "OBSERVABLE_KINDS", "PACKS", "PACK_ROLE_MODE",
    "QUERY_PREFERENCE", "SAFE_ATOM_RE", "SAFE_COMMUNITY_ID_RE",
    "SAFE_DOMAIN_RE", "SAFE_ELASTIC_ID_RE", "SAFE_ELASTIC_INDEX_RE",
    "SAFE_EVIDENCE_REF_RE", "SAFE_ID_RE", "SHA256_RE",
    "ZEEK_PROTOCOL_BASE_FIELDS", "_event_tuple_authorization",
    "_index_matches_scope", "_iso_utc", "_normalize_anchor",
    "_normalize_authorization_context", "_normalize_context_event_tuples",
    "_normalize_event_tuple", "_normalize_observable", "_normalize_observables",
    "_normalize_window", "_observable_authorizations", "_parse_utc",
    "_require_exact_keys", "_require_mapping", "_safe_id",
    "_validate_tuple_role_compatibility", "annotations", "canonical_digest",
    "dt", "fnmatch", "hashlib", "ipaddress", "json",
    "pack_event_tuple_fields", "pack_observable_fields", "re",
    "tuple_match_semantics", "validate_pack_observables",
}

EXPECTED_SIGNATURES = {
    "_event_tuple_authorization": "(requested: 'dict[str, Any]', context: 'dict[str, Any]', *, pack_name: 'str', observables: 'dict[str, list[str]]', label: 'str') -> 'dict[str, Any]'",
    "_index_matches_scope": "(index_name: 'str', index_scope: 'list[str]') -> 'bool'",
    "_iso_utc": "(value: 'dt.datetime') -> 'str'",
    "_normalize_anchor": "(value: 'object') -> 'dict[str, str]'",
    "_normalize_authorization_context": "(value: 'object') -> 'dict[str, Any]'",
    "_normalize_context_event_tuples": "(value: 'object', *, limit: 'int' = 32, reject_duplicates: 'bool' = False) -> 'list[dict[str, Any]]'",
    "_normalize_event_tuple": "(value: 'object', *, label: 'str') -> 'dict[str, Any]'",
    "_normalize_observable": "(kind: 'str', value: 'object') -> 'str'",
    "_normalize_observables": "(value: 'object', *, per_kind_limit: 'int', total_limit: 'int', require_one: 'bool', label: 'str') -> 'dict[str, list[str]]'",
    "_normalize_window": "(value: 'object', *, label: 'str', max_duration: 'dt.timedelta') -> 'tuple[dict[str, str], dt.datetime, dt.datetime]'",
    "_observable_authorizations": "(context: 'dict[str, Any]') -> 'dict[tuple[str, str], dict[str, str]]'",
    "_parse_utc": "(value: 'object', label: 'str') -> 'dt.datetime'",
    "_require_exact_keys": "(value: 'dict[str, Any]', *, allowed: 'set[str]', required: 'set[str]', label: 'str') -> 'None'",
    "_require_mapping": "(value: 'object', label: 'str') -> 'dict[str, Any]'",
    "_safe_id": "(value: 'object', label: 'str') -> 'str'",
    "_validate_tuple_role_compatibility": "(event_tuple: 'dict[str, Any]', *, pack_name: 'str', role_semantics: 'str', label: 'str') -> 'None'",
    "pack_event_tuple_fields": "(pack_name: 'str') -> 'dict[str, str]'",
    "pack_observable_fields": "(pack_name: 'str') -> 'dict[str, list[str]]'",
    "tuple_match_semantics": "(pack_name: 'str', event_tuple: 'dict[str, Any] | None', role_semantics: 'str | None') -> 'str'",
    "validate_pack_observables": "(observables: 'dict[str, list[str]]', pack_name: 'str', *, label: 'str') -> 'None'",
}

FROZEN_V1_DIGESTS = {
    "collect-investigation-pivots.py": "3caafe863d2c00dea88d02b6f2cb6c91db69239f5a2f9a89faeefc8b5dcc5cd0",
    "investigation_query_contract.py": "29864594edb87030f30d7220ad63c97f477522544958b0fda5b1ba84d6ae6aa7",
    "manifest.json": "b6c4a68b617e1286cbc03928f8796d330e3f83d3cdb0946e145d706d3147d380",
}

OWNER_MODULES = (
    "investigation_query_normalization_primitives.py",
    "investigation_query_observable_normalization.py",
    "investigation_query_event_tuple_normalization.py",
    "investigation_query_authorization_normalization.py",
)
FLAT_RUNTIME_MODULES = (
    "investigation_query_schema.py",
    *OWNER_MODULES,
    "investigation_query_normalization.py",
)


def authorization_context() -> dict:
    return {
        "context_id": "context-1",
        "case_id": "case-1",
        "group_id": "group-1",
        "actor_role": "incident_responder",
        "anchor": {
            "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
            "id": "anchor-1",
        },
        "anchor_time": "2026-07-24T12:00:00Z",
        "time_envelope": {
            "start": "2026-07-24T10:00:00Z",
            "end": "2026-07-24T16:00:00Z",
        },
        "permitted_observables": {
            "ips": ["192.0.2.10", "198.51.100.20"],
            "domains": ["Example.TEST."],
            "hosts": [],
            "users": [],
        },
        "discovered_observables": [{
            "kind": "domains",
            "value": "evidence.test",
            "evidence_ref": "elastic:query-1:hit-1",
        }],
        "permitted_event_tuples": [{
            "event_tuple": {
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "source_port": "49152",
                "destination_port": 443,
                "transport": "TCP",
                "protocol": "TLS",
                "community_id": "1:trusted-flow=",
                "rule_id": "2016150",
            },
            "role_semantics": "packet_direction",
            "source": "trusted_context",
            "evidence_ref": "context:event-tuple:trusted-flow",
        }],
    }


class InvestigationQueryNormalizationCharacterizationTests(unittest.TestCase):
    def test_namespace_signatures_and_canonical_error_identity_are_stable(self) -> None:
        names = {name for name in vars(NORMALIZATION) if not name.startswith("__")}
        self.assertEqual(names, EXPECTED_NAMESPACE)
        self.assertEqual(
            {
                name: str(inspect.signature(getattr(NORMALIZATION, name)))
                for name in EXPECTED_SIGNATURES
            },
            EXPECTED_SIGNATURES,
        )
        self.assertIs(
            NORMALIZATION.InvestigationQueryContractError,
            sys.modules["investigation_query_schema"].InvestigationQueryContractError,
        )

    def test_observable_normalization_preserves_order_deduplication_and_bounds(self) -> None:
        normalized = NORMALIZATION._normalize_observables(
            {
                "ips": ["192.0.2.10", "192.0.2.10"],
                "domains": ["Example.TEST.", "example.test"],
                "hosts": ["Host-A"],
                "users": ["analyst@example"],
            },
            per_kind_limit=4,
            total_limit=4,
            require_one=True,
            label="query observables",
        )
        self.assertEqual(normalized, {
            "ips": ["192.0.2.10"],
            "domains": ["example.test"],
            "hosts": ["Host-A"],
            "users": ["analyst@example"],
        })
        with self.assertRaisesRegex(
            NORMALIZATION.InvestigationQueryContractError,
            "query observables.ips exceeds its 1-value limit",
        ):
            NORMALIZATION._normalize_observables(
                {"ips": ["192.0.2.10", "198.51.100.20"]},
                per_kind_limit=1,
                total_limit=4,
                require_one=True,
                label="query observables",
            )

    def test_event_tuple_normalization_preserves_field_order_and_error_order(self) -> None:
        normalized = NORMALIZATION._normalize_event_tuple(
            {
                "rule_id": "2016150",
                "transport": " TCP ",
                "destination_port": "443",
                "source_ip": "192.0.2.10",
                "community_id": "1:trusted-flow=",
            },
            label="query event_tuple",
        )
        self.assertEqual(list(normalized), [
            "source_ip", "destination_port", "transport", "community_id", "rule_id",
        ])
        self.assertEqual(normalized["destination_port"], 443)
        self.assertEqual(normalized["transport"], "tcp")
        with self.assertRaisesRegex(
            NORMALIZATION.InvestigationQueryContractError,
            "query event_tuple contains unsupported fields: a_bad, z_bad",
        ):
            NORMALIZATION._normalize_event_tuple(
                {"z_bad": 1, "a_bad": 2}, label="query event_tuple"
            )

    def test_authorization_context_projection_and_provenance_are_exact(self) -> None:
        normalized = NORMALIZATION._normalize_authorization_context(
            authorization_context()
        )
        self.assertEqual(normalized["anchor_time"], "2026-07-24T12:00:00.000Z")
        self.assertEqual(normalized["permitted_observables"]["domains"], ["example.test"])
        self.assertEqual(normalized["permitted_event_tuples"][0]["event_tuple"], {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 443,
            "transport": "tcp",
            "protocol": "tls",
            "community_id": "1:trusted-flow=",
            "rule_id": "2016150",
        })
        self.assertEqual(
            NORMALIZATION._observable_authorizations(normalized)[
                ("domains", "evidence.test")
            ],
            {
                "kind": "domains",
                "value": "evidence.test",
                "source": "prior_evidence",
                "evidence_ref": "elastic:query-1:hit-1",
            },
        )
        self.assertEqual(
            normalized["_envelope_start"].isoformat(),
            "2026-07-24T10:00:00+00:00",
        )

    def test_tuple_authorization_is_fail_closed_and_returns_trusted_identity(self) -> None:
        normalized = NORMALIZATION._normalize_authorization_context(
            authorization_context()
        )
        trusted = normalized["permitted_event_tuples"][0]
        selected = NORMALIZATION._event_tuple_authorization(
            {"source_ip": "192.0.2.10", "destination_port": 443},
            normalized,
            pack_name="alert_context",
            observables=normalized["permitted_observables"],
            label="query event_tuple",
        )
        self.assertIs(selected, trusted)
        with self.assertRaisesRegex(
            NORMALIZATION.InvestigationQueryContractError,
            "must also be an authorized IP observable",
        ):
            NORMALIZATION._event_tuple_authorization(
                {"source_ip": "203.0.113.8"},
                normalized,
                pack_name="alert_context",
                observables=normalized["permitted_observables"],
                label="query event_tuple",
            )
        candidate = copy.deepcopy(normalized)
        candidate["permitted_event_tuples"][0]["event_tuple"]["destination_port"] = 8443
        with self.assertRaisesRegex(
            NORMALIZATION.InvestigationQueryContractError,
            "does not match one trusted role-aware event tuple",
        ):
            NORMALIZATION._event_tuple_authorization(
                {"source_ip": "192.0.2.10", "destination_port": 443},
                candidate,
                pack_name="alert_context",
                observables=candidate["permitted_observables"],
                label="query event_tuple",
            )

    def test_duplicate_tuple_policy_and_role_semantics_are_stable(self) -> None:
        row = authorization_context()["permitted_event_tuples"][0]
        self.assertEqual(
            NORMALIZATION._normalize_context_event_tuples([row, copy.deepcopy(row)]),
            NORMALIZATION._normalize_context_event_tuples([row]),
        )
        with self.assertRaisesRegex(
            NORMALIZATION.InvestigationQueryContractError,
            "authorization event tuple is duplicated",
        ):
            NORMALIZATION._normalize_context_event_tuples(
                [row, copy.deepcopy(row)], reject_duplicates=True
            )
        self.assertEqual(
            NORMALIZATION.tuple_match_semantics("alert_context", {}, None),
            "observable_exact_any_field",
        )
        self.assertEqual(
            NORMALIZATION.tuple_match_semantics(
                "alert_context", {"source_ip": "192.0.2.10"}, "packet_direction"
            ),
            "packet_direction_exact",
        )

    def test_frozen_v1_bundle_bytes_are_unchanged(self) -> None:
        self.assertEqual(
            {
                name: hashlib.sha256((COMPAT_V1 / name).read_bytes()).hexdigest()
                for name in FROZEN_V1_DIGESTS
            },
            FROZEN_V1_DIGESTS,
        )

    def test_facade_and_owners_remain_bounded_and_acyclic(self) -> None:
        facade = BIN / "investigation_query_normalization.py"
        self.assertLessEqual(len(facade.read_text(encoding="utf-8").splitlines()), 250)
        for name in OWNER_MODULES:
            path = BIN / name
            self.assertLess(len(path.read_text(encoding="utf-8").splitlines()), 800)
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imported = {
                node.module
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            }
            self.assertNotIn("investigation_query_normalization", imported)

    def test_facade_imports_from_an_isolated_flat_bin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in FLAT_RUNTIME_MODULES:
                (root / name).write_bytes((BIN / name).read_bytes())
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    (
                        "import sys; sys.path.insert(0, sys.argv[1]); "
                        "import investigation_query_normalization as module; "
                        "assert callable(module._event_tuple_authorization)"
                    ),
                    directory,
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
