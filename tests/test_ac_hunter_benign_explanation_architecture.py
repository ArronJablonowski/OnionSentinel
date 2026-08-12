from __future__ import annotations

import ast
import copy
import importlib
import inspect
import ipaddress
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
SCORING_PATH = DASHBOARD / "ac_hunter_scoring.py"


def load_scoring():
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    return importlib.import_module("ac_hunter_scoring")


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(SCORING_PATH.read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.IfExp):
            complexity += 1
    return target.end_lineno - target.lineno + 1, complexity


class TrackingMapping(dict):
    def __init__(self, *args, trace: list[object], fail_key=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.trace = trace
        self.fail_key = fail_key

    def get(self, key, default=None):
        self.trace.append(["get", key])
        if key == self.fail_key:
            raise RuntimeError("synthetic get failure")
        return super().get(key, default)


class AcHunterBenignExplanationArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scoring = load_scoring()

    def test_signature_current_debt_and_scoring_callback_are_exact(self) -> None:
        signature = inspect.signature(self.scoring._known_benign_explanation)
        self.assertEqual(list(signature.parameters), ["finding"])
        self.assertEqual(str(signature.return_annotation), "str")
        for name in (
            "_known_domain_explanation",
            "_known_network_explanation",
            "_known_service_explanation",
            "_known_benign_explanation",
        ):
            lines, complexity = function_metrics(name)
            self.assertLessEqual(lines, 50)
            self.assertLessEqual(complexity, 10)
        captured = []

        def policy(*args):
            captured.append(args)
            return {"ok": True}

        finding = {"module": "beacons"}
        with mock.patch.object(self.scoring, "apply_scoring_policy", policy):
            result = self.scoring._score_finding(finding, 2, 3)
        self.assertEqual(result, {"ok": True})
        self.assertEqual(captured[0][:3], (finding, 2, 3))
        self.assertIs(captured[0][3], self.scoring._known_benign_explanation)
        self.assertLessEqual(len(SCORING_PATH.read_text().splitlines()), 600)

    def test_hostname_normalization_domain_order_and_short_circuit_are_exact(self) -> None:
        domains = (
            ("example.invalid", "first explanation"),
            ("sub.example.invalid", "more specific but later"),
        )
        cases = [
            ({"fqdn": " EXAMPLE.INVALID. "}, "first explanation"),
            ({"fqdn": "Host.Sub.Example.Invalid."}, "first explanation"),
            ({"fqdn": "notexample.invalid"}, ""),
            ({"fqdn": "-bad.example.invalid"}, ""),
            ({"fqdn": "a" * 254 + ".example.invalid"}, ""),
            ({"evidence": {"ptr": "ptr.example.invalid."}}, "first explanation"),
            (
                {
                    "fqdn": "fqdn.example.invalid",
                    "evidence": {"ptr": "ptr.example.invalid"},
                },
                "first explanation",
            ),
        ]
        with mock.patch.object(self.scoring, "KNOWN_BENIGN_DOMAINS", domains), mock.patch.object(
            self.scoring, "KNOWN_BENIGN_NETWORKS", ()
        ):
            for finding, expected in cases:
                with self.subTest(finding=finding):
                    before = copy.deepcopy(finding)
                    self.assertEqual(
                        self.scoring._known_benign_explanation(finding), expected
                    )
                    self.assertEqual(finding, before)

    def test_access_and_sanitization_order_precede_domain_network_and_port(self) -> None:
        trace: list[object] = []
        finding = TrackingMapping(
            {
                "fqdn": "known.example.invalid",
                "evidence": {"ptr": "ptr.example.invalid"},
                "destination_ip": "192.0.2.5",
                "port": 123,
                "protocol": "udp",
            },
            trace=trace,
        )

        def safe_text(value, maximum):
            trace.append(["safe", value, maximum])
            return str(value or "")

        with mock.patch.object(self.scoring, "_safe_text", safe_text), mock.patch.object(
            self.scoring,
            "KNOWN_BENIGN_DOMAINS",
            (("example.invalid", "domain match"),),
        ), mock.patch.object(self.scoring, "KNOWN_BENIGN_NETWORKS", ()):
            self.assertEqual(
                self.scoring._known_benign_explanation(finding), "domain match"
            )
        self.assertEqual(
            trace,
            [
                ["get", "evidence"],
                ["safe", "ptr.example.invalid", 512],
                ["get", "fqdn"],
                ["safe", "known.example.invalid", 512],
            ],
        )

    def test_network_and_service_port_precedence_is_exact(self) -> None:
        network = ipaddress.ip_network("192.0.2.0/24")
        cases = [
            ({"destination_ip": "192.0.2.5", "port": 5228}, "network match"),
            ({"destination_ip": "bad", "port": 123, "protocol": ""}, "expected NTP pool traffic"),
            ({"port": 123, "protocol": "udp"}, "expected NTP pool traffic"),
            ({"port": 123, "protocol": "ntp"}, "expected NTP pool traffic"),
            ({"port": 123, "protocol": "tcp"}, ""),
            ({"port": 5228, "protocol": "tcp"}, "common Google/Android push port"),
            ({"port": 4070}, "common Spotify service port"),
            ({"port": "4070"}, "common Spotify service port"),
        ]
        with mock.patch.object(self.scoring, "KNOWN_BENIGN_DOMAINS", ()), mock.patch.object(
            self.scoring,
            "KNOWN_BENIGN_NETWORKS",
            ((network, "network match"),),
        ):
            for finding, expected in cases:
                with self.subTest(finding=finding):
                    self.assertEqual(
                        self.scoring._known_benign_explanation(finding), expected
                    )

    def test_value_error_is_suppressed_and_other_failures_propagate_in_order(self) -> None:
        with mock.patch.object(self.scoring, "KNOWN_BENIGN_DOMAINS", ()), mock.patch.object(
            self.scoring, "KNOWN_BENIGN_NETWORKS", ()
        ), mock.patch.object(
            self.scoring.ipaddress,
            "ip_address",
            side_effect=ValueError("suppressed"),
        ):
            self.assertEqual(
                self.scoring._known_benign_explanation(
                    {"destination_ip": "bad", "port": 4070}
                ),
                "common Spotify service port",
            )

        with mock.patch.object(self.scoring, "KNOWN_BENIGN_DOMAINS", ()), mock.patch.object(
            self.scoring.ipaddress,
            "ip_address",
            side_effect=TypeError("propagated"),
        ):
            with self.assertRaisesRegex(TypeError, "propagated") as raised:
                self.scoring._known_benign_explanation(
                    {"destination_ip": "value"}
                )
            self.assertIsNone(raised.exception.__cause__)

        trace: list[object] = []
        finding = TrackingMapping({}, trace=trace, fail_key="fqdn")
        with self.assertRaisesRegex(RuntimeError, "synthetic get failure"):
            self.scoring._known_benign_explanation(finding)
        self.assertEqual(trace, [["get", "evidence"], ["get", "fqdn"]])


if __name__ == "__main__":
    unittest.main()
