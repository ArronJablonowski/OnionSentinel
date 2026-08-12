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
SCORING_PATH = DASHBOARD / "ac_hunter_scoring.py"
POLICY_PATH = DASHBOARD / "ac_hunter_scoring_policy.py"
BASELINE = ROOT / "operations/quality/module-quality-baseline.json"


def load_scoring():
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    spec = importlib.util.spec_from_file_location(
        "ac_hunter_scoring_architecture", SCORING_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("AC Hunter scoring owner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AcHunterScoringArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scoring = load_scoring()

    def scored(
        self,
        finding: dict[str, object],
        module_count: int = 1,
        rare_signature_count: int = 0,
    ) -> dict[str, object]:
        result = self.scoring._score_finding(
            finding, module_count, rare_signature_count
        )
        self.assertIs(result, finding)
        return result

    def test_signature_quality_debt_and_module_boundaries_are_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(self.scoring._score_finding)),
            "(finding: 'Dict[str, Any]', module_count: 'int', "
            "rare_signature_count: 'int' = 0) -> 'Dict[str, Any]'",
        )
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertNotIn(
            "onion-sentinel-dashboard/ac_hunter_scoring.py::_score_finding",
            baseline["functions"],
        )
        self.assertLessEqual(len(SCORING_PATH.read_text().splitlines()), 250)
        self.assertLessEqual(len(POLICY_PATH.read_text().splitlines()), 600)
        self.assertNotIn(
            "from ac_hunter_scoring import", POLICY_PATH.read_text()
        )
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text()
        scoring_copy = (
            'ac_hunter_scoring.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_scoring.py"'
        )
        policy_copy = (
            'ac_hunter_scoring_policy.py" '
            '"$DASHBOARD_RUNTIME_DIR/ac_hunter_scoring_policy.py"'
        )
        self.assertIn(scoring_copy, installer)
        self.assertIn(policy_copy, installer)
        self.assertLess(installer.index(policy_copy), installer.index(scoring_copy))

    def test_empty_and_score_thresholds_preserve_exact_reasons(self) -> None:
        outputs = [self.scored({})]
        for score in (0.499, 0.5, 0.799, 0.8, 0.949, 0.95):
            outputs.append(
                self.scored({"module": "other", "score": score})
            )
        self.assertEqual(
            digest(outputs),
            "10b6d8d2256bad9d6423dc2000367c9398467bef3fc9353e23431b33ae93d545",
        )
        self.assertEqual(outputs[0]["priority_score"], 0)
        self.assertEqual(outputs[0]["verdict"], "Informational")
        self.assertEqual(
            outputs[0]["reason"],
            "behavioral evidence is limited and requires context before escalation",
        )

    def test_additive_signal_order_watch_and_nonmutation_are_exact(self) -> None:
        finding = {
            "id": "watch-one",
            "module": "unexpected_ports",
            "source_ip": "10.66.6.209",
            "destination_ip": "208.70.182.48",
            "fqdn": "",
            "port": 1610,
            "protocol": "TLS/UNKNOWN",
            "score": 0.96,
            "duration_seconds": 20_000,
            "evidence": {"ptr": "host.compute.amazonaws.com"},
            "unrelated": {"keep": [1, 2]},
        }
        before = copy.deepcopy(finding)
        result = self.scored(finding, module_count=4, rare_signature_count=12)
        self.assertEqual(
            digest(result),
            "8caac9ec0f91b850b91083213348d085ffdd23d1a3d0d22a708f84782e9f805b",
        )
        for key, value in before.items():
            self.assertEqual(result[key], value)
        self.assertEqual(
            set(result) - set(before),
            {"priority_score", "verdict", "reason", "watch_match"},
        )
        self.assertEqual(result["priority_score"], 144)
        self.assertEqual(result["verdict"], "Needs review")
        self.assertTrue(result["watch_match"])

    def test_second_watch_and_hard_signal_verdict_precedence_are_exact(self) -> None:
        watch = self.scored(
            {
                "module": "long_connections",
                "source_ip": "10.100.4.245",
                "destination_ip": "98.84.79.102",
                "port": 443,
                "duration_seconds": 18_000,
                "score": 0.95,
            },
            module_count=3,
        )
        blacklist = self.scored(
            {
                "module": "blacklist",
                "fqdn": "updates.apple.com",
                "score": 0.95,
            }
        )
        strobe = self.scored(
            {
                "module": "strobe",
                "destination_ip": "17.1.2.3",
                "port": 123,
                "protocol": "UDP",
            }
        )
        self.assertEqual(
            digest([watch, blacklist, strobe]),
            "373a1d6d21d3027f125cfa43474bd4511b9b66bbe3e9ecbffb4e312eee71b72a",
        )
        self.assertEqual(watch["verdict"], "Needs review")
        self.assertTrue(watch["watch_match"])
        self.assertEqual(blacklist["verdict"], "High concern")
        self.assertEqual(strobe["verdict"], "Needs review")

    def test_benign_domain_network_ports_and_periodicity_floor_are_exact(self) -> None:
        findings = [
            self.scored(
                {"module": "beacons", "fqdn": "updates.apple.com", "score": 0.95}
            ),
            self.scored(
                {"module": "beacons", "destination_ip": "17.0.0.1", "score": 0.5}
            ),
            self.scored(
                {"module": "other", "port": 123, "protocol": "UDP", "score": 0.5}
            ),
            self.scored(
                {"module": "other", "port": 5228, "score": 0.5}
            ),
            self.scored(
                {"module": "other", "port": 4070, "score": 0.5}
            ),
        ]
        self.assertEqual(
            digest(findings),
            "605feb7e070680963cf47e682cbb422552ff3487a7c0d1f659956ccb52a4d642",
        )
        self.assertEqual(findings[0]["priority_score"], 25)
        self.assertEqual(findings[0]["verdict"], "Needs review")
        for finding in findings[1:]:
            self.assertIn(finding["verdict"], {"Likely benign", "Informational"})
            self.assertIn("lowered priority", finding["reason"])

    def test_malformed_values_and_bounds_remain_exact(self) -> None:
        outputs = []
        for module_count in (-5, 0, 1, 2, 5, 100):
            for rare_count in (-1, 0, 9, 10, 1_000):
                outputs.append(
                    self.scored(
                        {
                            "module": None,
                            "score": "not-a-number",
                            "duration_seconds": float("nan"),
                            "fqdn": [],
                            "source_ip": {},
                            "destination_ip": False,
                            "port": [1, 2],
                            "protocol": None,
                            "evidence": ["not", "mapping"],
                        },
                        module_count=module_count,
                        rare_signature_count=rare_count,
                    )
                )
        self.assertEqual(
            digest(outputs),
            "5e306b611f1e69b887b30fbb153a00656cccaa472501d2e9050c02a9e073ced1",
        )


if __name__ == "__main__":
    unittest.main()
