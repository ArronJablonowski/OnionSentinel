#!/usr/bin/env python3
"""Fail-closed coverage for the reviewed Suricata-to-Zeek role reversal."""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"


def load_module(name: str, filename: str):
    if str(BIN) not in sys.path:
        sys.path.insert(0, str(BIN))
    spec = importlib.util.spec_from_file_location(name, BIN / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AuthorizedReverseFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = load_module(
            "authorized_reverse_builder",
            "build-ai-investigation-prompt.py",
        )
        cls.runner = load_module(
            "authorized_reverse_runner",
            "run-local-ai-analysis.py",
        )

    def row(self) -> dict:
        return {
            "alert_id": (
                ".ds-logs-suricata.alerts-so-2026.07.31-000001:"
                "authorized-tls-response"
            ),
            "alert_json": json.dumps({
                "elastic_index": (
                    ".ds-logs-suricata.alerts-so-2026.07.31-000001"
                ),
                "elastic_id": "authorized-tls-response",
                "event": {"dataset": "suricata.alert"},
                "source": {"ip": "208.70.182.111", "port": 443},
                "destination": {"ip": "10.77.7.222", "port": 57749},
                "network": {
                    "transport": "tcp",
                    "protocol": "tls",
                    "community_id": "1:authorized-tls-flow=",
                },
                "rule": {"id": "2029340"},
            }),
            "raw_event_json": "{}",
            "event_dataset": "suricata.alert",
            "source_ip": "208.70.182.111",
            "source_port": 443,
            "destination_ip": "10.77.7.222",
            "destination_port": 57749,
            "transport_protocol": "tcp",
            "network_protocol": "tls",
            "rule_id": "2029340",
            "timestamp": "2026-07-31T22:31:13.715Z",
            "first_seen": "2026-07-31T22:31:13.715Z",
            "last_seen": "2026-07-31T22:31:13.715Z",
        }

    def authorization(self, alert_id: str) -> dict:
        policy = "authorized-tls-scan-responses-10-77-7-222"
        return {
            "status": "operator_authorized",
            "selected_alert_id": alert_id,
            "campaign_id": "campaign-reviewed-tls-response",
            "policy_id": policy,
            "campaign_window": {
                "start": "2026-07-31T22:30:00Z",
                "end": "2026-07-31T22:45:00Z",
            },
            "authorization": {
                "status": "operator_authorized",
                "policy_id": policy,
                "source_ips": [],
                "destination_ips": ["10.77.7.222"],
                "source_ports": [443, 8443],
                "destination_ports": [],
                "destination_port_ranges": [[49152, 65535]],
                "transport_protocols": ["tcp"],
                "rule_ids": ["2029340"],
                "authorization_start": "2026-07-31T22:15:00Z",
                "authorization_end": "2026-08-05T05:59:59Z",
            },
            "observations": [{"alert_id": alert_id}],
        }

    def context(self, row: dict, authorization: dict | None):
        return self.builder.investigation_query_context(
            row,
            [row],
            "authorized-tls-group",
            "incident-responder",
            False,
            authorization,
        )

    def reverse_entries(self, local: dict) -> list[dict]:
        return [
            item
            for item in local["permitted_event_tuples"]
            if item.get("source") == "trusted_authorization_reverse_flow"
        ]

    def test_exact_native_policy_adds_packet_and_digest_bound_reverse_tuple(
        self,
    ) -> None:
        row = self.row()
        capability, local = self.context(
            row,
            self.authorization(row["alert_id"]),
        )

        self.assertEqual(len(local["permitted_event_tuples"]), 2)
        reverse = self.reverse_entries(local)
        self.assertEqual(len(reverse), 1)
        self.assertEqual(
            reverse[0]["event_tuple"],
            {
                "source_ip": "10.77.7.222",
                "destination_ip": "208.70.182.111",
                "source_port": 57749,
                "destination_port": 443,
                "transport": "tcp",
                "community_id": "1:authorized-tls-flow=",
            },
        )
        self.assertEqual(
            reverse[0]["role_semantics"],
            "zeek_originator_responder",
        )
        self.assertRegex(
            reverse[0]["evidence_ref"],
            r"^authorization:reverse-flow:[0-9a-f]{20}$",
        )
        self.assertIn(
            {
                "event_tuple": reverse[0]["event_tuple"],
                "role_semantics": "zeek_originator_responder",
            },
            capability["permitted_event_tuples"],
        )

    def test_reverse_tuple_fails_closed_for_every_unverified_dimension(
        self,
    ) -> None:
        base_row = self.row()
        base_auth = self.authorization(base_row["alert_id"])
        cases: list[tuple[str, dict, dict | None]] = []
        cases.append(("missing authorization", copy.deepcopy(base_row), None))

        wrong_membership = copy.deepcopy(base_auth)
        wrong_membership["observations"] = [{"alert_id": "other-alert"}]
        cases.append(("membership", copy.deepcopy(base_row), wrong_membership))

        wrong_policy = copy.deepcopy(base_auth)
        wrong_policy["policy_id"] = "other-policy"
        cases.append(("policy", copy.deepcopy(base_row), wrong_policy))

        wrong_ip = copy.deepcopy(base_row)
        wrong_ip["destination_ip"] = "10.77.7.223"
        cases.append(("ip", wrong_ip, copy.deepcopy(base_auth)))

        wrong_port = copy.deepcopy(base_row)
        wrong_port["source_port"] = 444
        cases.append(("port", wrong_port, copy.deepcopy(base_auth)))

        wrong_rule = copy.deepcopy(base_row)
        wrong_rule["rule_id"] = "2029341"
        cases.append(("rule", wrong_rule, copy.deepcopy(base_auth)))

        wrong_transport = copy.deepcopy(base_row)
        wrong_transport["transport_protocol"] = "udp"
        cases.append(("transport", wrong_transport, copy.deepcopy(base_auth)))

        wrong_time = copy.deepcopy(base_row)
        wrong_time["timestamp"] = "2026-08-06T22:31:13.715Z"
        cases.append(("time", wrong_time, copy.deepcopy(base_auth)))

        wrong_dataset = copy.deepcopy(base_row)
        wrong_dataset["event_dataset"] = "zeek.ssl"
        alert = json.loads(wrong_dataset["alert_json"])
        alert["event"]["dataset"] = "zeek.ssl"
        wrong_dataset["alert_json"] = json.dumps(alert)
        cases.append(("dataset", wrong_dataset, copy.deepcopy(base_auth)))

        wrong_auth_selector = copy.deepcopy(base_auth)
        wrong_auth_selector["authorization"]["source_ports"] = [443]
        cases.append((
            "authorization selectors",
            copy.deepcopy(base_row),
            wrong_auth_selector,
        ))

        conflicting_source_ip = copy.deepcopy(base_row)
        alert = json.loads(conflicting_source_ip["alert_json"])
        alert["source"]["ip"] = "208.70.182.112"
        conflicting_source_ip["alert_json"] = json.dumps(alert)
        cases.append((
            "conflicting source IP representations",
            conflicting_source_ip,
            copy.deepcopy(base_auth),
        ))

        conflicting_destination_ip = copy.deepcopy(base_row)
        alert = json.loads(conflicting_destination_ip["alert_json"])
        alert["destination"]["ip"] = "10.77.7.223"
        conflicting_destination_ip["alert_json"] = json.dumps(alert)
        cases.append((
            "conflicting destination IP representations",
            conflicting_destination_ip,
            copy.deepcopy(base_auth),
        ))

        conflicting_source_port = copy.deepcopy(base_row)
        alert = json.loads(conflicting_source_port["alert_json"])
        alert["source"]["port"] = 8443
        conflicting_source_port["alert_json"] = json.dumps(alert)
        cases.append((
            "conflicting source port representations",
            conflicting_source_port,
            copy.deepcopy(base_auth),
        ))

        conflicting_destination_port = copy.deepcopy(base_row)
        alert = json.loads(conflicting_destination_port["alert_json"])
        alert["destination"]["port"] = 57750
        conflicting_destination_port["alert_json"] = json.dumps(alert)
        cases.append((
            "conflicting destination port representations",
            conflicting_destination_port,
            copy.deepcopy(base_auth),
        ))

        conflicting_transport = copy.deepcopy(base_row)
        alert = json.loads(conflicting_transport["alert_json"])
        alert["network"]["transport"] = "udp"
        conflicting_transport["alert_json"] = json.dumps(alert)
        cases.append((
            "conflicting transport representations",
            conflicting_transport,
            copy.deepcopy(base_auth),
        ))

        conflicting_rule = copy.deepcopy(base_row)
        alert = json.loads(conflicting_rule["alert_json"])
        alert["rule"]["id"] = "2029341"
        conflicting_rule["alert_json"] = json.dumps(alert)
        cases.append((
            "conflicting rule ID representations",
            conflicting_rule,
            copy.deepcopy(base_auth),
        ))

        conflicting_community = copy.deepcopy(base_row)
        conflicting_community["community_id"] = "1:other-flow="
        cases.append((
            "conflicting Community ID representations",
            conflicting_community,
            copy.deepcopy(base_auth),
        ))

        for name, row, authorization in cases:
            with self.subTest(name=name):
                _capability, local = self.context(row, authorization)
                self.assertEqual(self.reverse_entries(local), [])

    def test_deterministic_zeek_pivots_use_reviewed_originator_tuple(self) -> None:
        row = self.row()
        capability, local = self.context(
            row,
            self.authorization(row["alert_id"]),
        )
        package = {
            "agent_role": "incident-responder",
            "alert": {
                "timestamp": row["timestamp"],
                "rule_name": "ET INFO TLS Handshake Failure",
                "source_ip": row["source_ip"],
                "source_port": row["source_port"],
                "destination_ip": row["destination_ip"],
                "destination_port": row["destination_port"],
                "transport_protocol": row["transport_protocol"],
                "rule_id": row["rule_id"],
                "community_id": "1:authorized-tls-flow=",
                "rule_context": {"deployed_rule": {"protocol": "tls"}},
            },
            "investigation_query_capability": capability,
            "_local_investigation_query_context": local,
        }

        plan = self.runner.deterministic_incident_pivot_requests(package)

        self.assertEqual(
            [item["query_id"] for item in plan],
            ["deterministic-zeek_tls", "deterministic-zeek_anomalies"],
        )
        for request in plan:
            self.assertEqual(
                request["parameters"]["event_tuple"],
                {
                    "source_ip": "10.77.7.222",
                    "destination_ip": "208.70.182.111",
                    "source_port": 57749,
                    "destination_port": 443,
                    "transport": "tcp",
                    "community_id": "1:authorized-tls-flow=",
                },
            )

        reverse_ref = self.reverse_entries(local)[0]["evidence_ref"]
        self.assertNotIn(
            reverse_ref,
            json.dumps(self.runner.model_safe_copy(package), sort_keys=True),
        )
        citation_refs = {
            item["ref"]
            for item in self.runner.evidence_reference_contract(package)[
                "references"
            ]
        }
        # This is query-authority provenance, not returned evidence. Keep it
        # out of the model citation allowlist while retaining it in the
        # broker-owned tuple-projection audit below.
        self.assertNotIn(reverse_ref, citation_refs)
        normalized = self.runner.normalize_investigation_query_request(
            plan[0],
            round_number=1,
            position=1,
            time_envelope=local["time_envelope"],
            authorization_context=local,
        )
        projection = normalized["normalization"]["event_tuple_projection"]
        self.assertEqual(projection["trusted_evidence_ref"], reverse_ref)
        self.assertRegex(
            projection["trusted_provenance_digest"],
            r"^[0-9a-f]{64}$",
        )

        non_zeek = copy.deepcopy(package)
        non_zeek["alert"]["rule_context"]["deployed_rule"]["protocol"] = "tcp"
        other_plan = self.runner.deterministic_incident_pivot_requests(non_zeek)
        self.assertEqual(
            other_plan[0]["parameters"]["event_tuple"]["source_ip"],
            "208.70.182.111",
        )
        self.assertEqual(
            other_plan[0]["parameters"]["event_tuple"]["source_port"],
            443,
        )


if __name__ == "__main__":
    unittest.main()
