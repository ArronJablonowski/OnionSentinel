"""Exhaustive characterization for incident-evidence observable provenance."""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "n8n" / "bin"
SCRIPT = BIN_DIR / "collect-incident-evidence.py"


def load_module():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location("incident_evidence_observables", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


collector = load_module()


def set_nested(document: dict, path: str, value: object) -> None:
    current = document
    parts = path.split(".")
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


def row(document: dict, **values: object) -> dict:
    return {
        "alert_id": "logs-detections.alerts-so:synthetic",
        "event_dataset": "sigma.alert",
        "source_ip": "",
        "destination_ip": "",
        "alert_json": json.dumps(document),
        "raw_event_json": "{}",
        **values,
    }


class IncidentEvidenceObservableCharacterization(unittest.TestCase):
    def test_public_surface_and_signature_are_exact(self) -> None:
        names = sorted(name for name in dir(collector) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (53, "2f885f63c1abbdea61adfc088b452bb5c4cb24e72135d23f3e741039f2c20ecc"),
        )
        self.assertEqual(
            str(inspect.signature(collector.observables)),
            "(grouped: 'list[sqlite3.Row]') -> 'dict[str, list[str]]'",
        )

    def test_stable_endpoints_precede_all_primary_ecs_ip_paths(self) -> None:
        document: dict = {}
        paths = ("source.ip", "destination.ip", "client.ip", "server.ip")
        values = ["192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"]
        for path, value in zip(paths, values):
            set_nested(document, path, value)
        result = collector.observables(
            [
                row(document, source_ip="192.0.2.1", destination_ip="192.0.2.2"),
                row({}, source_ip="192.0.2.2", destination_ip="192.0.2.7"),
            ]
        )
        self.assertEqual(
            result["ips"],
            [
                "192.0.2.1",
                "192.0.2.2",
                "192.0.2.7",
                "192.0.2.3",
                "192.0.2.4",
                "192.0.2.5",
                "192.0.2.6",
            ],
        )

    def test_all_address_paths_classify_ips_and_domains_in_path_order(self) -> None:
        document: dict = {}
        values = (
            ("source.address", "192.0.2.10"),
            ("destination.address", "destination.example."),
            ("client.address", "198.51.100.10"),
            ("server.address", "server.example"),
        )
        for path, value in values:
            set_nested(document, path, value)
        result = collector.observables([row(document)])
        self.assertEqual(result["ips"], ["192.0.2.10", "198.51.100.10"])
        self.assertEqual(
            result["domains"],
            ["destination.example", "server.example"],
        )

    def test_supplemental_ip_paths_follow_host_ip_for_endpoint_events(self) -> None:
        document = {
            "host": {"ip": ["192.0.2.20"]},
            "dns": {"resolved_ip": ["192.0.2.21"]},
            "related": {"ip": ["192.0.2.22"]},
        }
        self.assertEqual(
            collector.observables([row(document)])["ips"],
            ["192.0.2.20", "192.0.2.21", "192.0.2.22"],
        )

    def test_every_domain_path_is_admitted_in_declaration_order(self) -> None:
        paths = (
            "dns.question.name",
            "dns.query.name",
            "url.domain",
            "tls.server.name",
            "ssl.server_name",
            "http.virtual_host",
            "quic.server_name",
            "source.domain",
            "destination.domain",
            "client.domain",
            "server.domain",
        )
        first: dict = {}
        for index, path in enumerate(paths[:8], 1):
            set_nested(first, path, f"domain-{index}.example")
        second: dict = {}
        for index, path in enumerate(paths[8:], 9):
            set_nested(second, path, f"domain-{index}.example")
        self.assertEqual(
            collector.observables([row(first)])["domains"],
            [f"domain-{index}.example" for index in range(1, 9)],
        )
        self.assertEqual(
            collector.observables([row(second)])["domains"],
            [f"domain-{index}.example" for index in range(9, 12)],
        )

    def test_every_host_path_is_admitted_in_declaration_order(self) -> None:
        paths = (
            "host.hostname",
            "host.name",
            "host.id",
            "agent.id",
            "agent.name",
            "related.hosts",
        )
        first: dict = {}
        for index, path in enumerate(paths[:4], 1):
            set_nested(first, path, f"host-{index}")
        second: dict = {}
        for index, path in enumerate(paths[4:], 5):
            set_nested(second, path, [f"host-{index}"])
        self.assertEqual(
            collector.observables([row(first)])["hosts"],
            ["host-1", "host-2", "host-3", "host-4"],
        )
        self.assertEqual(
            collector.observables([row(second)])["hosts"],
            ["host-5", "host-6"],
        )

    def test_every_user_path_is_admitted_in_declaration_order(self) -> None:
        paths = (
            "user.name",
            "source.user.name",
            "destination.user.name",
            "client.user.name",
            "user.id",
            "related.user",
        )
        first: dict = {}
        for index, path in enumerate(paths[:4], 1):
            set_nested(first, path, f"user-{index}")
        second: dict = {}
        for index, path in enumerate(paths[4:], 5):
            set_nested(second, path, [f"user-{index}"])
        self.assertEqual(
            collector.observables([row(first)])["users"],
            ["user-1", "user-2", "user-3", "user-4"],
        )
        self.assertEqual(
            collector.observables([row(second)])["users"],
            ["user-5", "user-6"],
        )

    def test_zeek_identity_excludes_host_identity_but_retains_other_context(self) -> None:
        document = {
            "host": {"ip": ["192.0.2.30"], "name": "sensor-host"},
            "dns": {
                "resolved_ip": ["192.0.2.31"],
                "question": {"name": "observed.example"},
            },
            "user": {"name": "observed-user"},
        }
        result = collector.observables(
            [
                row(
                    document,
                    alert_id="logs-zeek-default:synthetic",
                    event_dataset="",
                )
            ]
        )
        self.assertEqual(result["ips"], ["192.0.2.31"])
        self.assertEqual(result["domains"], ["observed.example"])
        self.assertEqual(result["hosts"], [])
        self.assertEqual(result["users"], ["observed-user"])

    def test_exact_per_kind_and_global_budget_preserves_kind_priority(self) -> None:
        document = {
            "source": {"ip": [f"192.0.2.{value}" for value in range(1, 9)]},
            "dns": {
                "question": {
                    "name": [f"domain-{value}.example" for value in range(1, 9)]
                }
            },
            "host": {"name": [f"host-{value}" for value in range(1, 5)]},
            "user": {"name": [f"user-{value}" for value in range(1, 5)]},
        }
        result = collector.observables([row(document)])
        self.assertEqual(
            {kind: len(values) for kind, values in result.items()},
            {"ips": 8, "domains": 8, "hosts": 4, "users": 4},
        )
        self.assertEqual(sum(map(len, result.values())), 24)
        self.assertEqual(list(result), ["ips", "domains", "hosts", "users"])

    def test_normalization_validation_and_first_seen_deduplication_are_exact(self) -> None:
        document = {
            "source": {"ip": [" 192.0.2.40. ", "invalid", "192.0.2.40"]},
            "dns": {
                "question": {
                    "name": [" Example.COM. ", "invalid_domain", "Example.COM"]
                }
            },
            "host": {"name": [" host-1. ", "unsafe/host", "host-1"]},
            "user": {"name": [" user-1. ", "unsafe user", "user-1"]},
        }
        result = collector.observables([row(document)])
        self.assertEqual(result["ips"], ["192.0.2.40"])
        self.assertEqual(result["domains"], ["Example.COM"])
        self.assertEqual(result["hosts"], ["host-1"])
        self.assertEqual(result["users"], ["user-1"])


if __name__ == "__main__":
    unittest.main()
