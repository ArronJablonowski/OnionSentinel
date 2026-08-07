"""Direct contracts for role-aware investigation event tuples."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query import event_tuple  # noqa: E402


class QueryContractError(ValueError):
    pass


def digest(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode()).hexdigest()


def dependencies(fields: tuple[str, ...] | None = None) -> event_tuple.Dependencies:
    return event_tuple.Dependencies(
        canonical_digest=digest,
        pack_fields=lambda _pack: fields or event_tuple.FIELDS,
        match_semantics=lambda pack, _value, role: f"{pack}:{role}",
    )


def trusted_entry(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "event_tuple": {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 443,
            "transport": "tcp",
            "protocol": "tls",
            "community_id": "1:trusted-flow=",
            "rule_id": "2016150",
        },
        "role_semantics": "packet_direction",
        "source": "trusted_context",
        "evidence_ref": "context:event-tuple:flow-1",
    }
    value.update(overrides)
    return value


class QueryEventTuplePackageTests(unittest.TestCase):
    def test_normalize_canonicalizes_types_and_rejects_unknown_fields(self) -> None:
        normalized = event_tuple.normalize(
            {
                "source_ip": "2001:0db8::1",
                "destination_port": "443",
                "transport": "TCP",
                "protocol": "TLS",
            },
            error_type=QueryContractError,
        )
        self.assertEqual(normalized, {
            "source_ip": "2001:db8::1",
            "destination_port": 443,
            "transport": "tcp",
            "protocol": "tls",
        })
        with self.assertRaisesRegex(QueryContractError, "unsupported fields"):
            event_tuple.normalize(
                {"source_ip": "192.0.2.10", "query": "*"},
                error_type=QueryContractError,
            )

    def test_normalize_rejects_invalid_ips_ports_and_atoms(self) -> None:
        invalid = (
            {"source_ip": "not-an-ip"},
            {"source_port": True},
            {"destination_port": 65536},
            {"transport": "tcp OR *"},
            {"community_id": "unsafe value"},
            {"rule_id": "rule/value"},
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(QueryContractError):
                event_tuple.normalize(value, error_type=QueryContractError)

    def test_projection_requires_one_complete_trusted_tuple_match(self) -> None:
        entry = trusted_entry()
        context = {"permitted_event_tuples": [entry]}
        with self.assertRaisesRegex(QueryContractError, "trusted role-aware tuple"):
            event_tuple.project(
                {"source_ip": "192.0.2.10", "destination_port": 8443},
                pack="zeek_tls", authorization_context=context,
                dependencies=dependencies(), error_type=QueryContractError,
            )

        projected, _audit = event_tuple.project(
            {"source_ip": "192.0.2.10", "destination_port": 443},
            pack="zeek_tls", authorization_context=context,
            dependencies=dependencies(), error_type=QueryContractError,
        )
        self.assertEqual(
            projected, {"source_ip": "192.0.2.10", "destination_port": 443}
        )

    def test_projection_drops_pack_unavailable_fields_without_leaking_values(self) -> None:
        entry = trusted_entry()
        requested = dict(entry["event_tuple"])
        projected, audit = event_tuple.project(
            requested,
            pack="zeek_tls",
            authorization_context={"permitted_event_tuples": [entry]},
            dependencies=dependencies(tuple(
                field for field in event_tuple.FIELDS if field != "rule_id"
            )),
            error_type=QueryContractError,
        )
        self.assertNotIn("rule_id", projected)
        self.assertEqual(audit["dropped_pack_unavailable_fields"], ["rule_id"])
        self.assertEqual(audit["match_semantics"], "zeek_tls:packet_direction")
        serialized = json.dumps(audit, sort_keys=True)
        for hidden in ("192.0.2.10", "198.51.100.20", "1:trusted-flow="):
            self.assertNotIn(hidden, serialized)

    def test_candidate_selection_is_deterministic_by_provenance_digest(self) -> None:
        first = trusted_entry(source="source-z")
        second = trusted_entry(source="source-a")
        expected = min((first, second), key=digest)
        _projected, audit = event_tuple.project(
            {"source_ip": "192.0.2.10", "destination_ip": "198.51.100.20"},
            pack="network_flow",
            authorization_context={"permitted_event_tuples": [second, first]},
            dependencies=dependencies(), error_type=QueryContractError,
        )
        self.assertEqual(audit["trusted_source"], expected["source"])
        self.assertEqual(audit["trusted_provenance_digest"], digest(expected))

    def test_projection_must_retain_an_authenticated_ip_role(self) -> None:
        with self.assertRaisesRegex(QueryContractError, "retain a trusted"):
            event_tuple.project(
                {"source_ip": "192.0.2.10", "transport": "tcp"},
                pack="no-ip-pack",
                authorization_context={"permitted_event_tuples": [trusted_entry()]},
                dependencies=dependencies(("transport",)),
                error_type=QueryContractError,
            )


if __name__ == "__main__":
    unittest.main()
