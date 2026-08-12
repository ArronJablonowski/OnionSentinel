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
NORMALIZATION_PATH = DASHBOARD / "ac_hunter_normalization.py"
FINDING_NORMALIZATION_PATH = DASHBOARD / "ac_hunter_finding_normalization.py"
BASELINE = ROOT / "operations/quality/module-quality-baseline.json"


def load_normalization():
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    spec = importlib.util.spec_from_file_location(
        "ac_hunter_normalization_architecture", NORMALIZATION_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("AC Hunter normalization owner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AcHunterNormalizationArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.normalization = load_normalization()

    def normalized(
        self,
        module: str,
        row: dict[str, object],
    ) -> dict[str, object]:
        before = copy.deepcopy(row)
        result = self.normalization._normalize_finding(module, row)
        self.assertIsNot(result, row)
        self.assertEqual(row, before)
        self.assertEqual(
            list(result),
            [
                "source_ip",
                "destination_ip",
                "fqdn",
                "module",
                "score",
                "count",
                "duration",
                "duration_seconds",
                "port",
                "protocol",
                "timing_mode",
                "data_size_mode",
                "responding_ips",
                "evidence",
                "id",
            ],
        )
        return result

    def test_signature_quality_debt_and_module_boundaries_are_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(self.normalization._normalize_finding)),
            "(module: 'str', row: 'Mapping[str, Any]') -> 'Dict[str, Any]'",
        )
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertNotIn(
            "onion-sentinel-dashboard/ac_hunter_normalization.py::_normalize_finding",
            baseline["functions"],
        )
        self.assertLessEqual(len(NORMALIZATION_PATH.read_text().splitlines()), 250)
        self.assertLessEqual(
            len(FINDING_NORMALIZATION_PATH.read_text().splitlines()), 600
        )
        self.assertNotIn(
            "from ac_hunter_normalization import",
            FINDING_NORMALIZATION_PATH.read_text(),
        )
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text()
        facade_copy = (
            'ac_hunter_normalization.py" '
            '"$DASHBOARD_RUNTIME_DIR/ac_hunter_normalization.py"'
        )
        owner_copy = (
            'ac_hunter_finding_normalization.py" '
            '"$DASHBOARD_RUNTIME_DIR/ac_hunter_finding_normalization.py"'
        )
        self.assertIn(facade_copy, installer)
        self.assertIn(owner_copy, installer)
        self.assertLess(installer.index(owner_copy), installer.index(facade_copy))

    def test_empty_modules_preserve_exact_defaults_and_stable_ids(self) -> None:
        outputs = [
            self.normalized(module, {})
            for module in (
                "beacons",
                "blacklist",
                "dns_anomalies",
                "unexpected_ports",
            )
        ]
        self.assertEqual(
            digest(outputs),
            "5f4e6bf69c23b27b803b6290843c4044bd819812263893cf996eab7574e99ec1",
        )
        self.assertEqual(
            [item["id"] for item in outputs],
            [
                "78552516eda11d20a4a9",
                "6cfafabda280e7fcf43e",
                "96459be5acd63500c7ab",
                "d588f1715c20d5db756e",
            ],
        )
        for output in outputs:
            self.assertEqual(output["evidence"], {})
            self.assertEqual(output["responding_ips"], [])
            self.assertEqual(output["duration"], output["duration_seconds"])

    def test_alias_precedence_bounding_and_evidence_projection_are_exact(self) -> None:
        row = {
            "source_ip": " 10.0.0.5 ",
            "src_ip": "10.0.0.6",
            "server_ip": "203.0.113.9",
            "fqdn": "rare.example",
            "domain": "ignored.example",
            "responding_ips": "1.1.1.1,bad,2001:db8::1,1.1.1.1",
            "score": "0.987654321",
            "count": {"count": "3"},
            "duration": "1 days 02:03:04.5",
            "port": "443",
            "protocol": "tls",
            "timing_mode": " periodic ",
            "data_size_mode": "stable",
            "bytes": "1,024",
            "network_name": "internal",
            "dst_network_name": "external",
            "ptr": "host.compute.amazonaws.com",
            "open": True,
            "unrelated": {"keep": [1, 2]},
        }
        result = self.normalized("beacons", row)
        self.assertEqual(
            digest(result),
            "ed15afc6074aff81edd1bc14747d1e17c87ee589f447b845ffa13d2128a1e318",
        )
        self.assertEqual(result["source_ip"], "10.0.0.5")
        self.assertEqual(result["destination_ip"], "203.0.113.9")
        self.assertEqual(result["fqdn"], "rare.example")
        self.assertEqual(result["responding_ips"], ["1.1.1.1", "2001:db8::1"])
        self.assertEqual(result["score"], 0.987654)
        self.assertEqual(result["duration_seconds"], 93_784.5)
        self.assertEqual(
            result["evidence"],
            {
                "timing_mode": "periodic",
                "data_size_mode": "stable",
                "bytes": 1024,
                "network": "internal",
                "destination_network": "external",
                "ptr": "host.compute.amazonaws.com",
                "open": True,
            },
        )

    def test_blacklist_and_dns_source_fallbacks_are_exact(self) -> None:
        outputs = [
            self.normalized("blacklist", {"host": "10.0.0.8"}),
            self.normalized("blacklist", {"host": "8.8.8.8"}),
            self.normalized(
                "blacklist",
                {
                    "source_ip": "10.0.0.9",
                    "destination_ip": "9.9.9.9",
                    "host": "8.8.8.8",
                },
            ),
            self.normalized(
                "dns_anomalies",
                {
                    "queries": [
                        {"ip": "bad"},
                        {"source_ip": "10.2.3.4"},
                        {"src": "10.5.6.7"},
                    ]
                },
            ),
            self.normalized(
                "dns_anomalies",
                {"source_ip": "10.9.8.7", "queries": [{"ip": "10.2.3.4"}]},
            ),
        ]
        self.assertEqual(
            digest(outputs),
            "70c2dad7376673b5b01d156c565459797fd4403ca36b613f194abedd552c7186",
        )
        self.assertEqual(outputs[0]["source_ip"], "10.0.0.8")
        self.assertEqual(outputs[0]["destination_ip"], "10.0.0.8")
        self.assertEqual(outputs[1]["source_ip"], "")
        self.assertEqual(outputs[1]["destination_ip"], "8.8.8.8")
        self.assertEqual(outputs[3]["source_ip"], "10.2.3.4")
        self.assertEqual(outputs[4]["source_ip"], "10.9.8.7")

    def test_tuple_duration_port_and_queried_fqdn_fallbacks_are_exact(self) -> None:
        outputs = [
            self.normalized(
                "long_connections",
                {
                    "tuples": [
                        {"resp_p": 8443, "transport": "tcp"},
                        {"resp_p": 443},
                    ],
                    "duration": "02:03:04.5",
                },
            ),
            self.normalized(
                "long_connections",
                {
                    "connections": [1, 2, 3],
                    "port": 65536,
                    "protocol": "udp",
                    "tuples": [{"resp_p": 53, "transport": "tcp"}],
                    "duration": "2 days 01:02:03",
                },
            ),
            self.normalized(
                "other",
                {
                    "duration": "18000",
                    "port": -1,
                    "queried_fqdns": ["first.example", "second.example"],
                },
            ),
            self.normalized(
                "other",
                {
                    "duration": "bad",
                    "port": 65535,
                    "answers": [
                        {"ip": "192.0.2.1"},
                        {"address": "bad"},
                        {"value": "2001:db8::2"},
                    ],
                },
            ),
        ]
        self.assertEqual(
            digest(outputs),
            "cf4d302e4e6489df53d6a2573db4c37a38064c13223bfe25923caf7e6a481af0",
        )
        self.assertEqual(
            (outputs[0]["count"], outputs[0]["port"], outputs[0]["protocol"]),
            (2, 8443, "TCP"),
        )
        self.assertEqual(
            (outputs[1]["count"], outputs[1]["port"], outputs[1]["protocol"]),
            (3, 53, "UDP"),
        )
        self.assertEqual(outputs[2]["fqdn"], "first.example")
        self.assertEqual(outputs[3]["responding_ips"], ["192.0.2.1", "2001:db8::2"])

    def test_malformed_scalar_and_collection_values_remain_exact(self) -> None:
        values = [
            None,
            False,
            True,
            -1,
            0,
            1,
            0.5,
            "",
            "bad",
            [],
            [1, 2],
            {},
            {"count": "7"},
        ]
        outputs = []
        for value in values:
            row = {
                name: copy.deepcopy(value)
                for name in (
                    "source",
                    "destination",
                    "fqdn",
                    "score",
                    "count",
                    "duration",
                    "port",
                    "protocol",
                    "responding_ips",
                    "open",
                )
            }
            outputs.append(self.normalized("other", row))
        self.assertEqual(len(outputs), 13)
        self.assertEqual(
            digest(outputs),
            "33c12e2217985a8c6122ce0c2c87f012fd38ee741c62d5ed79ddc888a62ff715",
        )


if __name__ == "__main__":
    unittest.main()
