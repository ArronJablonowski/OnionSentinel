"""Direct contracts for bounded independent-review evidence catalogs."""
from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.review import catalogs  # noqa: E402


IPV4 = re.compile(
    r"(?<![A-Za-z0-9])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![A-Za-z0-9])"
)
DOMAIN = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![A-Za-z0-9_-])"
)


def policy(observable_max: int = 256) -> catalogs.Policy:
    return catalogs.Policy(
        observable_max=observable_max,
        observable_kinds=frozenset({"ip", "domain", "host", "user", "community_id"}),
        ipv4_pattern=IPV4,
        domain_pattern=DOMAIN,
        taxonomy_field_paths=frozenset({
            "data_stream_dataset", "data_stream_type", "event_dataset", "event_module",
        }),
        artifact_field_paths=frozenset({
            "command", "executable", "path", "process_command_line",
            "process_executable", "process_path", "script",
        }),
        artifact_suffixes=frozenset({"sh"}),
        rule_label_field_paths=frozenset({"alert_signature", "rule_name", "signature"}),
    )


DEPENDENCIES = catalogs.Dependencies(
    bounded_reference=lambda value: str(value or "")[:400],
    reviewer_safe_copy=lambda value: value,
)


class ReviewCatalogsPackageTests(unittest.TestCase):
    def test_observables_admit_typed_local_and_narrative_ips_canonically(self) -> None:
        package = {
            "_local_investigation_query_context": {
                "permitted_observables": {"domains": ["EXAMPLE.TEST"]},
                "permitted_event_tuples": [{
                    "event_tuple": {"source_ip": "10.0.0.1", "community_id": "1:test"},
                }],
            },
            "alert": {
                "host_name": "SENSOR.ONE", "summary": "peer was 10.0.0.2",
            },
        }
        self.assertEqual(
            catalogs.observables(package, policy(), DEPENDENCIES),
            [
                {"kind": "community_id", "value": "1:test"},
                {"kind": "domain", "value": "example.test"},
                {"kind": "host", "value": "sensor.one"},
                {"kind": "ip", "value": "10.0.0.1"},
                {"kind": "ip", "value": "10.0.0.2"},
            ],
        )

    def test_observable_cap_is_enforced_before_foreign_growth(self) -> None:
        package = {"alert": {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2"}}
        result = catalogs.observables(package, policy(observable_max=1), DEPENDENCIES)
        self.assertEqual(len(result), 1)

    def test_taxonomy_never_launders_arbitrary_dotted_prose(self) -> None:
        package = {
            "alert": {
                "event": {"dataset": "suricata.alert"},
                "summary": "foreign.example appeared in prose",
            }
        }
        self.assertEqual(catalogs.taxonomy(package, policy(), DEPENDENCIES), ["suricata.alert"])

    def test_artifacts_require_collector_owned_command_or_path_field(self) -> None:
        package = {
            "alert": {
                "process": {"command_line": "/tmp/collect.sh --safe"},
                "summary": "foreign.sh appeared in prose",
            }
        }
        self.assertEqual(catalogs.artifacts(package, policy(), DEPENDENCIES), ["collect.sh"])

    def test_rule_shorthand_requires_uppercase_typed_namespace(self) -> None:
        package = {
            "alert": {
                "signature": "ET MALWARE BPFDoor Heartbeat",
                "summary": "XX Foreign appears in prose",
            },
            "detection_validation": {"rule_name": "et lowercase ignored"},
        }
        result = catalogs.rule_shorthands(package, policy(), DEPENDENCIES)
        self.assertIn("et.bpfdoor", result)
        self.assertNotIn("xx.foreign", result)
        self.assertFalse(any(value.startswith("et.lowercase") for value in result))

    def test_exact_dotted_rule_value_is_not_exempted(self) -> None:
        package = {"alert": {"signature": "ET.BPFDoor"}}
        self.assertNotIn(
            "et.bpfdoor", catalogs.rule_shorthands(package, policy(), DEPENDENCIES),
        )

    def test_package_has_no_io_primitives(self) -> None:
        source = (ROOT / "n8n/onion_sentinel/analysis/review/catalogs.py").read_text()
        for primitive in ("subprocess", "urlopen", "requests.", "open("):
            self.assertNotIn(primitive, source)


if __name__ == "__main__":
    unittest.main()
