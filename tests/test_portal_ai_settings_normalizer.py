"""Compatibility contracts for the extracted SOC AI settings normalizer."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

import report_portal as portal  # noqa: E402
from portal_ai_settings_normalizer import (  # noqa: E402
    SocAiSettingsNormalizationPolicy,
    normalize_soc_ai_settings,
)


def policy() -> SocAiSettingsNormalizationPolicy:
    return SocAiSettingsNormalizationPolicy(
        defaults=portal.default_soc_ai_settings,
        maxmind_databases=portal.MAXMIND_GEOIP_DATABASE_SETTINGS,
        codex_efforts=portal.CODEX_CLI_REASONING_EFFORTS,
        hermes_effort=portal.HERMES_AGENT_REASONING_EFFORT,
        codex_catalog=portal.CODEX_CLI_MODEL_CATALOG,
        severity_thresholds=portal.SOC_ANALYSIS_SEVERITY_THRESHOLDS,
        openclaw_ollama_urls=portal.OPENCLAW_SUPPORTED_OLLAMA_URLS,
        normalized_model_list=portal._normalized_model_list,
        boolean_setting=portal._boolean_setting,
        derive_model_mode=portal._derive_model_mode,
        valid_cli_path=portal._valid_cli_executable_path,
        valid_provider_model=portal._valid_provider_model,
        valid_openclaw_model=portal._valid_openclaw_model,
        normalize_codex_models=portal._normalize_codex_cli_models,
        enabled_routes=portal._enabled_agent_model_routes,
        normalize_primary_models=portal._normalize_agent_models,
        normalize_reviewer_models=portal._normalize_agent_second_opinion_models,
        normalize_adjudicator_models=portal._normalize_agent_adjudicator_models,
    )


class AiSettingsNormalizerTests(unittest.TestCase):
    def test_direct_normalizer_matches_portal_facade_for_representative_inputs(self) -> None:
        defaults = portal.default_soc_ai_settings()
        hybrid = portal.default_soc_ai_settings()
        hybrid.update(
            {
                "enabled_ollama_models": ["primary:latest", "fallback:latest"],
                "codex_cli_models": [
                    {
                        "model": "gpt-5.6-sol",
                        "reasoning_effort": "high",
                        "enabled": True,
                    }
                ],
                "soc_analyst_analysis_min_severity": "info",
                "pcap_capture_loss_threshold_percent": "7.125",
            }
        )
        hermes_only = portal.default_soc_ai_settings()
        hermes_only.update(
            {
                "enabled_ollama_models": [],
                "codex_cli_models": [],
                "hermes_agent_enabled": True,
            }
        )
        invalid_openclaw = portal.default_soc_ai_settings()
        invalid_openclaw.update(
            {
                "openclaw_enabled": True,
                "openclaw_model": "openai/gpt-5.6-sol",
            }
        )
        invalid_threshold = portal.default_soc_ai_settings()
        invalid_threshold["soc_analyst_incident_min_severity"] = "everything"
        for payload in (
            None,
            "malformed",
            defaults,
            hybrid,
            hermes_only,
            invalid_openclaw,
            invalid_threshold,
        ):
            with self.subTest(payload_type=type(payload).__name__):
                direct = normalize_soc_ai_settings(payload, policy())
                facade = portal.normalize_soc_ai_settings(payload)
                self.assertEqual(direct, facade)

    def test_normalizer_preserves_legacy_city_alias_without_persisting_it(self) -> None:
        payload = portal.default_soc_ai_settings()
        payload.pop("maxmind_geoip_city_db_path")
        payload["maxmind_geoip_db_path"] = "/tmp/GeoLite2-City.mmdb"

        ok, normalized = normalize_soc_ai_settings(payload, policy())

        self.assertTrue(ok)
        self.assertEqual(
            normalized["maxmind_geoip_city_db_path"],
            "/tmp/GeoLite2-City.mmdb",
        )
        self.assertNotIn("maxmind_geoip_db_path", normalized)

    def test_normalizer_clears_operator_supplied_cloud_command(self) -> None:
        payload = portal.default_soc_ai_settings()
        payload["cloud_command"] = "unsafe --operator-supplied command"

        ok, normalized = normalize_soc_ai_settings(payload, policy())

        self.assertTrue(ok)
        self.assertEqual(normalized["cloud_command"], "")

    def test_policy_is_immutable_after_construction(self) -> None:
        configured = policy()

        with self.assertRaises(FrozenInstanceError):
            configured.hermes_effort = "high"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
