"""Characterization for dashboard AI-summary title policy and fallback."""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


RULE_CASES = (
    (
        "CINS Active Threat observed",
        "IP reputation hit observed in threat intelligence feeds. Review related SSH or external connection activity.",
    ),
    (
        "Poor Reputation destination",
        "IP reputation hit observed in threat intelligence feeds. Review related SSH or external connection activity.",
    ),
    (
        "SSH Scan Outbound behavior",
        "Outbound SSH scanning activity detected. Multiple destination attempts may indicate reconnaissance or misconfiguration.",
    ),
    (
        "Potential SSH Scan behavior",
        "SSH scanning behavior identified. Review source host, destination spread, and authentication telemetry.",
    ),
    (
        "Telegram API Certificate observed",
        "Telegram API certificate observed in traffic. Validate expected application use and possible exfiltration channel.",
    ),
    (
        "curl user-agent direct request",
        "Direct-IP curl-style traffic observed. Review process context and destination reputation.",
    ),
    (
        "Dotted Quad Host header",
        "Direct-IP curl-style traffic observed. Review process context and destination reputation.",
    ),
    (
        "Abused Hosting Domain lookup",
        "Potential abused hosting infrastructure observed. Review DNS/TLS context and related endpoint activity.",
    ),
    (
        "AzureWebsites connection",
        "Potential abused hosting infrastructure observed. Review DNS/TLS context and related endpoint activity.",
    ),
)


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "dashboard_builder_ai_summary_policy_test",
        BUILDER_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256_json(value: object) -> str:
    encoded = json.dumps(
        value,
        default=str,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def report(title: str, summary: str = "fallback summary") -> SimpleNamespace:
    return SimpleNamespace(title=title, summary=summary)


class DashboardBuilderAiSummaryPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = load_builder()

    def test_namespace_signature_and_all_rule_messages_are_exact(self) -> None:
        names = sorted(
            name for name in dir(self.builder) if not name.startswith("__")
        )
        self.assertEqual(
            (len(names), sha256_json(names)),
            (480, "75c4d9372093624308e6a2e89b821fd7ba7a4d7bee1e3bd5a355ebb8d54324bd"),
        )
        signature = str(inspect.signature(self.builder.ai_summary_for))
        self.assertEqual(
            hashlib.sha256(signature.encode("utf-8")).hexdigest(),
            "c9e09f462d08d3552358abd4d0e6c39d4b95dd52443b3211908bc588e33751dc",
        )
        for title, expected in RULE_CASES:
            with self.subTest(title=title):
                self.assertEqual(
                    self.builder.ai_summary_for(report(title)),
                    expected,
                )

    def test_case_normalization_and_overlap_precedence_are_exact(self) -> None:
        expected_reputation = RULE_CASES[0][1]
        expected_curl = RULE_CASES[5][1]
        self.assertEqual(
            self.builder.ai_summary_for(
                report("POOR REPUTATION plus SSH SCAN OUTBOUND")
            ),
            expected_reputation,
        )
        self.assertEqual(
            self.builder.ai_summary_for(
                report("CURL USER-AGENT on AZUREWEBSITES")
            ),
            expected_curl,
        )

    def test_fallback_boundaries_empty_and_unicode_are_exact(self) -> None:
        for summary, expected in (
            ("", ""),
            ("x" * 169, "x" * 169),
            ("x" * 170, "x" * 170),
            ("x" * 171, "x" * 170 + "…"),
            ("🧅" * 171, "🧅" * 170 + "…"),
        ):
            with self.subTest(length=len(summary)):
                self.assertEqual(
                    self.builder.ai_summary_for(report("unmatched", summary)),
                    expected,
                )

    def test_facade_override_reaches_all_composed_owners_and_restores(self) -> None:
        original = self.builder.ai_summary_for
        with mock.patch.object(
            self.builder,
            "ai_summary_for",
            return_value="override",
        ):
            self.assertEqual(
                self.builder.ai_summary_for(report("unmatched")),
                "override",
            )
            owners = [
                module for module in self.builder._runtime.BUILDER_MODULES
                if hasattr(module, "ai_summary_for")
            ]
            self.assertEqual(len(owners), 8)
            self.assertTrue(all(
                module.ai_summary_for is self.builder.ai_summary_for
                for module in owners
            ))
        self.assertIs(self.builder.ai_summary_for, original)


if __name__ == "__main__":
    unittest.main()
