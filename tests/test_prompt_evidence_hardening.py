import base64
import copy
import importlib.util
import json
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "n8n" / "bin"
MODULE_PATH = BIN_DIR / "build-ai-investigation-prompt.py"
SPEC = importlib.util.spec_from_file_location("prompt_evidence_hardening", MODULE_PATH)
builder = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.path.insert(0, str(BIN_DIR))
SPEC.loader.exec_module(builder)


def alert_row():
    packet = b"\x00" * 14 + b"\x45" + b"\x00" * 63
    rule = (
        'alert icmp any any -> any any '
        '(msg:"fixture"; itype:0; content:"X:"; offset:16; sid:999999; rev:3;)'
    )
    raw_message = {
        "alert": {
            "signature_id": 999999,
            "rev": 3,
            "signature": "fixture",
            "rule": rule,
        },
        "packet": base64.b64encode(packet).decode("ascii"),
        "packet_info": {"linktype": 1},
    }
    raw = {
        "rule": {"rule": rule, "rev": 3, "ruleset": "fixture"},
        "message": json.dumps(raw_message),
    }
    alert = {
        "rule_id": "999999",
        "rule_name": "fixture",
        "rule_ruleset": "fixture",
        "message": json.dumps(raw_message),
        "source": {"mac": "00:11:22:33:44:55"},
        "destination": {"mac": "00:11:22:33:44:66"},
        "host": {"hostname": "workstation.example.test"},
        "triage": {"reasons": ["fixture"]},
    }
    return {
        "alert_id": "fixture-alert",
        "timestamp": "2026-07-24  12:00:00-06:00",
        "first_seen": "2026-07-24  12:00:00-06:00",
        "last_seen": "2026-07-24  12:00:00-06:00",
        "seen_count": 1,
        "total_seen_count": 1,
        "rule_id": "999999",
        "rule_name": "fixture",
        "event_dataset": "suricata.alert",
        "severity": 2,
        "severity_label": "medium",
        "source_ip": "192.0.2.8",
        "destination_ip": "192.0.2.53",
        "destination_port": 53,
        "transport_protocol": "udp",
        "traffic_direction": "internal",
        "triage_score": 50,
        "triage_level": "medium",
        "routing": "review",
        "filter_status": "accepted",
        "filter_reason": "",
        "suppression_key": "fixture",
        "stable_group_id": "abcdef1234567890abcd",
        "raw_event_json": json.dumps(raw),
        "alert_json": json.dumps(alert),
    }


class PromptEvidenceHardeningTests(unittest.TestCase):
    def test_execution_lineage_uses_stable_group_and_blind_rerun_flag(self):
        lineage = builder.execution_lineage(
            alert_row(),
            blind_reanalysis=True,
        )

        self.assertEqual(lineage["group_id"], "abcdef1234567890abcd")
        self.assertIs(lineage["manual_reanalysis"], True)

    def test_execution_lineage_has_deterministic_legacy_group_fallback(self):
        selected = alert_row()
        selected["stable_group_id"] = ""

        lineage = builder.execution_lineage(
            selected,
            blind_reanalysis=False,
        )

        self.assertEqual(
            lineage["group_id"],
            builder.alert_group_id(builder.alert_group_key(selected)),
        )
        self.assertIs(lineage["manual_reanalysis"], False)

    def test_build_package_propagates_execution_lineage_for_manual_and_automatic_runs(self):
        args = SimpleNamespace(
            agent_role="soc-analyst",
            blind_reanalysis=False,
            rollup_dir=Path("/unused"),
            rollup_bytes=1,
            related_limit=1,
            include_tests=False,
            pcap_analysis_dir=Path("/unused"),
            pcap_analysis_limit=1,
            correlation_limit=1,
            correlation_min_score=1,
            detection_playbooks=Path("/unused"),
            asset_inventory_file=Path("/unused"),
            agent_memory_file=Path("/unused"),
            shared_memory_file=Path("/unused"),
            memory_bytes=1,
            incident_evidence_file=None,
            system_prompt_file=Path("/unused"),
            second_opinion_prompt_file=Path("/unused"),
            analysis_dir=Path("/unused"),
        )
        replacements = {
            "latest_rollup": {},
            "grouped_alert_context": {},
            "pcap_evidence_context": {"parsed_evidence": []},
            "public_enrichment_context": {},
            "analyst_state_context": {"group_id": "dashboard-group"},
            "correlated_alert_context": {},
            "compact_alert": {},
            "alert_group_rows": [],
            "parse_alert_json": {},
            "parse_json_object": {},
            "extract_rule_context": {},
            "exact_detection_group_rows": (
                [],
                {"input_truncated": False},
            ),
            "load_detection_playbooks": {},
            "resolve_detection_playbook": None,
            "marker_specs": [],
            "extract_group_packet_features": {},
            "build_detection_validation": {},
            "load_asset_inventory": {},
            "asset_observables_and_events": ([], []),
            "resolve_asset_context": {},
            "investigation_query_context": ({}, {}),
            "build_agent_memory_context": {},
            "blind_model_authored_context": ({}, {}),
            "model_policy": {},
            "load_system_prompt": "",
            "related_alerts": [],
            "notification_context": [],
            "prior_analysis_context": {},
        }
        with ExitStack() as stack:
            for name, value in replacements.items():
                stack.enter_context(
                    mock.patch.object(
                        builder,
                        name,
                        return_value=value,
                    )
                )
            for blind_reanalysis in (False, True):
                with self.subTest(blind_reanalysis=blind_reanalysis):
                    args.blind_reanalysis = blind_reanalysis
                    package = builder.build_package(None, alert_row(), args)
                    self.assertEqual(
                        package["group_id"],
                        "abcdef1234567890abcd",
                    )
                    self.assertIs(
                        package["manual_reanalysis"],
                        blind_reanalysis,
                    )

    def test_each_specialist_role_has_a_bounded_role_specific_objective(self):
        expectations = {
            "incident-responder": "incident-response investigation",
            "siem-engineer": "detection-engineering assessment",
            "cyber-threat-intel": "threat-intelligence assessment",
            "threat-hunter": "threat-hunting assessment",
        }
        for role, phrase in expectations.items():
            with self.subTest(role=role):
                task = builder.agent_task(role)
                self.assertIn(phrase, task)
                self.assertIn("never claim", task.lower())

    def test_compact_alert_retains_rule_context_but_not_packet_message(self):
        compact = builder.compact_alert(alert_row())
        self.assertEqual(compact["rule_context"]["sid"], "999999")
        self.assertEqual(compact["rule_context"]["record_rule_id"], "999999")
        self.assertEqual(compact["rule_context"]["revision"], 3)
        deployed = compact["rule_context"]["deployed_rule"]
        self.assertEqual(deployed["protocol"], "icmp")
        self.assertEqual(deployed["content_predicates"][0]["length"], 2)
        self.assertNotIn('"X:"', json.dumps(deployed))
        self.assertNotIn("583a", json.dumps(deployed))
        self.assertIsNone(compact["raw_alert_subset"]["message"])
        serialized = json.dumps(compact)
        self.assertNotIn('"packet"', serialized)
        raw_packet = json.loads(
            json.loads(alert_row()["raw_event_json"])["message"]
        )["packet"]
        self.assertNotIn(raw_packet, serialized)

    def test_asset_inputs_use_only_explicit_endpoint_fields(self):
        observables, events = builder.asset_observables_and_events([alert_row()])
        values = {(item["type"], item["value"], item["role"]) for item in observables}
        self.assertIn(("ip", "192.0.2.8", "source"), values)
        self.assertIn(("ip", "192.0.2.53", "destination"), values)
        self.assertIn(("hostname", "workstation.example.test", "host"), values)
        self.assertNotIn(("hostname", "fixture", "observer"), values)
        self.assertEqual(events[0]["destination_port"], 53)

    def test_packet_validation_rows_are_bound_to_exact_rule_identity(self):
        selected = alert_row()
        selected_alert = json.loads(selected["alert_json"])
        selected_raw = json.loads(selected["raw_event_json"])
        context = builder.extract_rule_context(
            selected_alert,
            selected_raw,
            selected["rule_id"],
        )
        other = copy.deepcopy(selected)
        other_rule = (
            'alert icmp any any -> any any '
            '(msg:"other"; itype:0; sid:888888; rev:1;)'
        )
        other_alert = json.loads(other["alert_json"])
        other_alert["rule_id"] = "888888"
        other["rule_id"] = "888888"
        other["alert_json"] = json.dumps(other_alert)
        other_raw = json.loads(other["raw_event_json"])
        other_message = json.loads(other_raw["message"])
        other_message["alert"].update(
            {"signature_id": 888888, "rev": 1, "rule": other_rule}
        )
        other_raw["message"] = json.dumps(other_message)
        other_raw["rule"] = {
            "rule": other_rule,
            "rev": 1,
            "ruleset": "fixture",
        }
        other["raw_event_json"] = json.dumps(other_raw)

        rows, scope = builder.exact_detection_group_rows(
            [selected, other],
            context,
        )

        self.assertEqual([row["rule_id"] for row in rows], ["999999"])
        self.assertEqual(scope["excluded_nonmatching_rows"], 1)

    def test_packet_validation_accepts_security_onion_rule_uuid_with_matching_sid(self):
        selected = alert_row()
        rule_uuid = "93fcfa6f-e11d-4c24-9f55-0c83593fd3b5"
        selected["rule_id"] = rule_uuid
        selected_alert = json.loads(selected["alert_json"])
        selected_alert["rule_id"] = rule_uuid
        selected["alert_json"] = json.dumps(selected_alert)
        selected_raw = json.loads(selected["raw_event_json"])
        selected_raw["rule"]["id"] = rule_uuid
        selected["raw_event_json"] = json.dumps(selected_raw)
        context = builder.extract_rule_context(
            selected_alert,
            selected_raw,
            selected["rule_id"],
        )

        rows, scope = builder.exact_detection_group_rows([selected], context)

        self.assertEqual(context["sid"], "999999")
        self.assertEqual(context["identity_conflicts"]["sid"], [])
        self.assertEqual([row["rule_id"] for row in rows], [rule_uuid])
        self.assertEqual(scope["exact_rule_rows"], 1)

    def test_compact_pcap_retains_safe_icmp_semantics_and_detection_context(self):
        compact = builder.compact_pcap_analysis(
            {
                "request": {"request_id": "pcap-fixture"},
                "tshark": {
                    "available": True,
                    "icmp_semantics": {
                        "raw_payloads_included": False,
                        "type_code_counts": [{"type": "0", "code": "0", "count": 3}],
                    },
                },
                "detection_context": {
                    "rule": {"sid": "999999", "revision": 3},
                    "playbook": None,
                },
            }
        )
        self.assertFalse(compact["tshark"]["icmp_semantics"]["raw_payloads_included"])
        self.assertEqual(compact["detection_context"]["rule"]["sid"], "999999")

    def test_prompt_budget_uses_lossless_compact_json_before_reducing_evidence(self):
        package = {
            "instructions": ["bounded-evidence"] * 20_000,
            "prior_analyses": [{"id": value} for value in range(3)],
            "related_alerts": [{"id": value} for value in range(10)],
            "recent_notifications": [{"id": value} for value in range(10)],
            "grouped_alert_context": {
                "timeline_sample": [{"id": value} for value in range(12)],
            },
            "incident_response_evidence": {
                "security_onion_response": {"results": []},
            },
        }
        pretty_bytes = len(
            json.dumps(
                {
                    **package,
                    "package_budget": {
                        "max_bytes": 450_000,
                        "compacted": False,
                        "compaction_steps": [],
                        "serialization": "pretty",
                    },
                },
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
        )
        self.assertGreater(pretty_bytes, 450_000)

        compacted, output = builder.compact_package_to_budget(
            package,
            450_000,
        )

        self.assertLessEqual(len(output.encode("utf-8")), 450_000)
        self.assertEqual(json.loads(output), compacted)
        self.assertEqual(
            compacted["package_budget"]["serialization"],
            "compact",
        )
        self.assertIn(
            "json_whitespace",
            compacted["package_budget"]["compaction_steps"],
        )
        self.assertEqual(
            compacted["instructions"],
            ["bounded-evidence"] * 20_000,
        )
        self.assertEqual(len(compacted["prior_analyses"]), 3)
        self.assertEqual(len(compacted["related_alerts"]), 10)
        self.assertEqual(len(compacted["recent_notifications"]), 10)
        self.assertEqual(
            len(compacted["grouped_alert_context"]["timeline_sample"]),
            12,
        )
        self.assertEqual(
            compacted["package_budget"]["serialized_bytes"],
            len(output.encode("utf-8")),
        )

    def test_prompt_budget_keeps_pretty_json_when_it_already_fits(self):
        package = {"instructions": ["small"]}

        compacted, output = builder.compact_package_to_budget(
            package,
            262_144,
        )

        self.assertEqual(
            compacted["package_budget"]["serialization"],
            "pretty",
        )
        self.assertNotIn(
            "json_whitespace",
            compacted["package_budget"]["compaction_steps"],
        )
        self.assertIn("\n  ", output)
        self.assertEqual(json.loads(output), compacted)
        self.assertEqual(
            compacted["package_budget"]["serialized_bytes"],
            len(output.encode("utf-8")),
        )

    def test_prompt_budget_compacts_when_size_metadata_crosses_boundary(self):
        compacted, output = builder.compact_package_to_budget(
            {"x": ""},
            148,
        )

        self.assertLessEqual(len(output.encode("utf-8")), 148)
        self.assertEqual(
            compacted["package_budget"]["serialization"],
            "compact",
        )
        self.assertEqual(json.loads(output), compacted)
        self.assertEqual(
            compacted["package_budget"]["serialized_bytes"],
            len(output.encode("utf-8")),
        )

    def test_prompt_budget_compact_output_is_deterministic_with_unicode(self):
        source = {
            "instructions": ["évidence"] * 20_000,
            "prior_analyses": [{"id": "α"}, {"id": "β"}],
        }

        first_package, first_output = builder.compact_package_to_budget(
            copy.deepcopy(source),
            500_000,
        )
        second_package, second_output = builder.compact_package_to_budget(
            copy.deepcopy(source),
            500_000,
        )

        self.assertEqual(first_output, second_output)
        self.assertEqual(first_package, second_package)
        self.assertEqual(
            first_package["package_budget"]["serialized_bytes"],
            len(first_output.encode("utf-8")),
        )


if __name__ == "__main__":
    unittest.main()
