from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
COLLECTION_PATH = DASHBOARD / "ac_hunter_collection.py"
BASELINE = ROOT / "operations/quality/module-quality-baseline.json"
PULLED_AT = "2026-08-12T14:30:00Z"


def load_collection():
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    spec = importlib.util.spec_from_file_location(
        "ac_hunter_collection_architecture", COLLECTION_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("AC Hunter collection owner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AcHunterCollectionArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.collection = load_collection()

    def statuses(self, **overrides: dict[str, object]):
        values = {
            name: {"status": "ok", "http_status": 200, "error": ""}
            for name, _params, _optional in self.collection.COLLECTION_OPERATIONS
        }
        values.update(overrides)
        return values

    def test_signature_operation_policy_and_module_boundaries_are_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(self.collection.normalize_collection)),
            "(raw: 'Mapping[str, object]', *, pulled_at: 'str', "
            "source_statuses: 'Mapping[str, Mapping[str, object]]') -> "
            "'Dict[str, Any]'",
        )
        self.assertEqual(len(self.collection.COLLECTION_OPERATIONS), 16)
        self.assertEqual(
            [item[0] for item in self.collection.COLLECTION_OPERATIONS],
            [
                "database",
                "dashboard",
                "dashboard_count",
                "dashboard_c2flag",
                "beacons_count",
                "beacons",
                "beacons_sni",
                "beacons_proxy",
                "long_connections",
                "dns",
                "strobe",
                "blacklist_ip",
                "certificate_count",
                "useragent_count_false",
                "useragent_count_true",
                "unexpected_ports",
            ],
        )
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertNotIn(
            "onion-sentinel-dashboard/ac_hunter_collection.py::normalize_collection",
            baseline["functions"],
        )
        modules = [
            COLLECTION_PATH,
            DASHBOARD / "ac_hunter_collection_findings.py",
            DASHBOARD / "ac_hunter_collection_hosts.py",
            DASHBOARD / "ac_hunter_collection_projection.py",
        ]
        self.assertLessEqual(len(COLLECTION_PATH.read_text().splitlines()), 250)
        for module in modules[1:]:
            self.assertLessEqual(len(module.read_text().splitlines()), 600)
            self.assertNotIn("from ac_hunter_collection import", module.read_text())
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text()
        for module in modules:
            self.assertIn(f'{module.name}" "$DASHBOARD_RUNTIME_DIR/', installer)

    def test_empty_projection_is_exact_and_keeps_behavioral_disclaimer(self) -> None:
        raw: dict[str, object] = {}
        statuses = self.statuses()
        before_raw = copy.deepcopy(raw)
        before_statuses = copy.deepcopy(statuses)
        result = self.collection.normalize_collection(
            raw, pulled_at=PULLED_AT, source_statuses=statuses
        )
        self.assertEqual(
            digest(result),
            "389b022dcdd2b0233ee6ae92e3f7616b28d098b4e79d7a4cac251755720d3937",
        )
        self.assertEqual(raw, before_raw)
        self.assertEqual(statuses, before_statuses)
        self.assertEqual(result["top_hosts"], [])
        self.assertEqual(result["correlated_hosts"], [])
        self.assertEqual(result["verdict_counts"], {
            "Informational": 0,
            "Likely benign": 0,
            "Needs review": 0,
            "High concern": 0,
        })
        self.assertEqual(result["analyst_notes"][0]["id"], "no-priority-findings")
        self.assertIn("do not by themselves establish", result["disclaimer"])

    def test_representative_aliases_correlation_statuses_and_counts_are_exact(self) -> None:
        source = "10.66.6.209"
        raw = {
            "database": [{"ts_range": {"min": "2026-08-11T00:00:00Z", "max": PULLED_AT}}],
            "dashboard": {
                "hosts": [
                    {"source_ip": source, "score": 0.99, "count": 12},
                    {"source_ip": "10.0.0.9", "score": 0.96, "count": 2},
                ]
            },
            "beacons": {"data": [{"src": source, "dst": "208.70.182.48", "port": 1610, "protocol": "TLS/unknown", "score": 0.97}]},
            "beacons_sni": {"results": [{"source": source, "sni": "rare.example", "responding_ips": ["203.0.113.50"], "score": 0.91}]},
            "beacons_proxy": {"items": [{"source_ip": source, "destination_ip": "198.51.100.7", "score": 0.51}]},
            "long_connections": {"rows": [{"orig_h": source, "resp_h": "98.84.79.102", "duration": 20000, "tuples": [{"resp_p": 443, "transport": "tcp"}]}]},
            "dns": {"records": [{"source_ip": source, "domain": "rare.example", "subdomains": 150}]},
            "unexpected_ports": {"findings": [{"source": source, "destination": "208.70.182.48", "port": 1610, "protocol": "TLS/unknown", "count": 5}]},
            "blacklist_ip": None,
            "strobe": None,
            "useragent_count_false": [{"source_ip": source, "count": 7}],
            "useragent_count_true": [{"source_ip": source, "count": 5}],
            "dashboard_count": {"count": 9},
            "dashboard_c2flag": {"total": 2},
            "beacons_count": 6,
            "certificate_count": {"value": 4},
        }
        statuses = self.statuses(
            dns={"status": "error", "http_status": "503", "error": "Authorization: Bearer hidden"},
            unexpected_ports={"status": "unavailable", "http_status": None, "error": "optional source unavailable"},
        )
        before_raw = copy.deepcopy(raw)
        before_statuses = copy.deepcopy(statuses)
        result = self.collection.normalize_collection(
            raw, pulled_at=PULLED_AT, source_statuses=statuses
        )
        self.assertEqual(
            digest(result),
            "82861f48da7d23195e7fa852f169086d53020c939ff27b325c1b5efba207a261",
        )
        self.assertEqual(raw, before_raw)
        self.assertEqual(statuses, before_statuses)
        correlation = result["correlated_hosts"][0]
        self.assertEqual(correlation["source_ip"], source)
        self.assertEqual(correlation["module_count"], 6)
        self.assertEqual(result["top_hosts"][0]["source_ip"], source)
        self.assertFalse(result["metadata"]["complete"])
        self.assertNotIn("hidden", json.dumps(result))
        self.assertEqual(result["counts"], {
            "dashboard": 9,
            "c2_flags": 2,
            "beacons": 6,
            "certificates": 4,
            "user_agents_without_ja3": 0,
            "user_agents_with_ja3": 0,
        })

    def test_row_cap_dashboard_top_25_and_status_completeness_exception(self) -> None:
        maximum = self.collection.MAX_FINDINGS_PER_MODULE
        raw = {
            "beacons": [
                {"source_ip": f"10.20.0.{index + 1}", "score": index / 1000}
                for index in range(maximum + 7)
            ],
            "dashboard": [
                {"source_ip": f"10.30.0.{index + 1}", "score": 1 - index / 1000, "count": index}
                for index in range(30)
            ],
        }
        statuses = self.statuses(
            unexpected_ports={"status": "error", "http_status": 500, "error": "optional"}
        )
        result = self.collection.normalize_collection(
            raw, pulled_at=PULLED_AT, source_statuses=statuses
        )
        self.assertEqual(len(result["modules"]["beacons"]["findings"]), maximum)
        self.assertEqual(len(result["top_hosts"]), 25)
        self.assertTrue(result["metadata"]["complete"])

    def test_non_mapping_row_envelopes_remain_empty_without_errors(self) -> None:
        raw = {
            "beacons": "not rows",
            "beacons_sni": 7,
            "beacons_proxy": True,
            "long_connections": {"data": "not rows"},
            "dns": {"results": None},
            "unexpected_ports": {"findings": [None, "bad", 1]},
            "blacklist_ip": [],
            "strobe": {},
        }
        result = self.collection.normalize_collection(
            raw, pulled_at=PULLED_AT, source_statuses={}
        )
        self.assertTrue(all(item["count"] == 0 for item in result["modules"].values()))
        self.assertEqual(result["analyst_notes"][0]["id"], "no-priority-findings")
        self.assertEqual(
            digest(result),
            "4b86363e129f6f15873fb1c003122234e6176dbb53720aa3c4f9a32a8f7a68ca",
        )


if __name__ == "__main__":
    unittest.main()
