"""Direct contracts for live endpoint authorization and evidence custody."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query import live_endpoint  # noqa: E402


class ClientError(ValueError):
    pass


POLICY = live_endpoint.Policy(
    schema="live-v1",
    support_schema="support-v1",
    maximum_rounds=2,
    maximum_queries=3,
)
DEPENDENCIES = live_endpoint.Dependencies(
    text=lambda value, limit: str(value or "").strip()[:limit],
    normalize_query=lambda value: " ".join(str(value or "").split()),
    now=lambda: "2026-08-09T12:00:00Z",
    client_error=ClientError,
)


def package() -> dict:
    return {
        "_local_investigation_query_context": {
            "permitted_observables": {
                "ips": ["192.0.2.10", "invalid"],
                "hosts": ["Endpoint.EXAMPLE."],
                "domains": ["Example.TEST."],
                "users": ["Alice"],
            },
            "permitted_event_tuples": [{
                "event_tuple": {
                    "source_ip": "2001:db8::1",
                    "destination_ip": "198.51.100.9",
                    "source_port": 443,
                    "destination_port": "8443",
                },
            }],
        },
    }


class LiveEndpointPackageTests(unittest.TestCase):
    def test_authorizes_only_canonical_collector_observables(self) -> None:
        values = live_endpoint.authorized_observables(package())
        self.assertEqual(values["ips"], {
            "192.0.2.10", "2001:db8::1", "198.51.100.9",
        })
        self.assertEqual(values["hosts"], {"endpoint.example"})
        self.assertEqual(values["domains"], {"example.test"})
        self.assertEqual(values["users"], {"alice"})
        self.assertEqual(values["ports"], {"443", "8443"})

    def test_target_and_positive_rows_require_case_binding(self) -> None:
        config = {"target_bindings": {
            "asset-a": {"hosts": ["endpoint.example"]},
            "asset-b": {"ips": ["203.0.113.7"]},
        }}
        self.assertTrue(live_endpoint.target_bound(
            package(), "ASSET-A", config, dependencies=DEPENDENCIES,
        ))
        self.assertFalse(live_endpoint.target_bound(
            package(), "asset-b", config, dependencies=DEPENDENCIES,
        ))
        bindings = live_endpoint.support_bindings(
            package(),
            {
                "target_alias": "asset-a",
                "query_digest": "query-digest",
                "query": "SELECT * FROM process_open_sockets;",
                "rows": [{
                    "remote_address": "192.0.2.10",
                    "remote_port": "443",
                    "pid": "22",
                    "local_address": "203.0.113.7",
                }],
            },
            config,
            policy=POLICY,
            dependencies=DEPENDENCIES,
        )
        self.assertEqual(
            [(item["column"], item["observable_kind"]) for item in bindings],
            [("remote_address", "ip"), ("remote_port", "port")],
        )
        self.assertEqual(
            bindings[0]["observable_digest"],
            hashlib.sha256(b"ips\x00192.0.2.10").hexdigest(),
        )
        self.assertNotIn("observable", bindings[0])

    def test_accumulator_deep_copies_and_preserves_monotonic_custody(self) -> None:
        prompt: dict = {}
        results = [{"rows": [{"pid": "1"}]}]
        live_endpoint.append_batch(
            prompt,
            case_id="case-1",
            generated_at="time-1",
            results=results,
            complete=False,
            partial=True,
            validated=False,
            control_plane_write_status="possible",
            collection_error="timeout",
            policy=POLICY,
            dependencies=DEPENDENCIES,
        )
        results[0]["rows"][0]["pid"] = "changed"
        live_endpoint.append_batch(
            prompt,
            case_id="case-1",
            generated_at="time-2",
            results=[],
            complete=True,
            partial=False,
            validated=True,
            control_plane_write_status="none",
            collection_error="",
            policy=POLICY,
            dependencies=DEPENDENCIES,
        )
        evidence = prompt["_live_osquery_evidence_accumulator"]
        self.assertEqual(evidence["results"][0]["rows"][0]["pid"], "1")
        self.assertEqual(evidence["control_plane_write_status"], "possible")
        self.assertTrue(evidence["control_plane_writes"])
        self.assertFalse(evidence["complete"])
        self.assertTrue(evidence["partial"])
        self.assertEqual(evidence["collection_error"], "timeout")
        with self.assertRaisesRegex(ClientError, "round limit"):
            live_endpoint.append_batch(
                prompt, case_id="case-1", generated_at="time-3", results=[],
                complete=True, partial=False, validated=True,
                control_plane_write_status="confirmed", collection_error="",
                policy=POLICY, dependencies=DEPENDENCIES,
            )

    def test_failure_records_normalized_query_identity(self) -> None:
        prompt: dict = {}
        requests = [{
            "target_alias": " asset-a ",
            "query": "SELECT  *\nFROM users;",
            "purpose": " owner check ",
        }]
        original = copy.deepcopy(requests)
        live_endpoint.accumulate_failure(
            prompt,
            case_id="case-2",
            requests=requests,
            error="unavailable",
            dispatch_possible=True,
            policy=POLICY,
            dependencies=DEPENDENCIES,
        )
        result = prompt["_live_osquery_evidence_accumulator"]["results"][0]
        self.assertEqual(requests, original)
        self.assertEqual(result["query"], "SELECT * FROM users;")
        self.assertEqual(
            result["query_digest"],
            hashlib.sha256(b"SELECT * FROM users;").hexdigest(),
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(
            prompt["_live_osquery_evidence_accumulator"]
            ["control_plane_write_status"],
            "possible",
        )


if __name__ == "__main__":
    unittest.main()
