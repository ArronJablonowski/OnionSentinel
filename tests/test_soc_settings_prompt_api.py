#!/usr/bin/env python3
"""Regression checks for editable SOC settings prompt helpers."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
PORTAL_PATH = REPO_ROOT / "onion-sentinel-dashboard" / "report_portal.py"


def load_portal():
    spec = importlib.util.spec_from_file_location("report_portal_settings", PORTAL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SocSettingsPromptApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.portal = load_portal()
        self.prompt_path = Path(self.tmp.name) / "config" / "incident_responder_system_prompt.md"
        self.portal.INCIDENT_RESPONDER_PROMPT_FILE = self.prompt_path
        prompt_dir = self.prompt_path.parent
        prompt_specs = {
            "/api/soc-settings/analyst-prompt": ("SOC Analyst", "soc_analyst_system_prompt.md"),
            "/api/soc-settings/analyst-second-opinion-prompt": ("SOC Analyst second-opinion", "soc_analyst_second_opinion_prompt.md"),
            "/api/soc-settings/incident-responder-prompt": ("Incident Responder", "incident_responder_system_prompt.md"),
            "/api/soc-settings/incident-responder-second-opinion-prompt": ("Incident Responder second-opinion", "incident_responder_second_opinion_prompt.md"),
            "/api/soc-settings/siem-engineer-prompt": ("SIEM Engineer", "siem_engineer_system_prompt.md"),
            "/api/soc-settings/siem-engineer-second-opinion-prompt": ("SIEM Engineer second-opinion", "siem_engineer_second_opinion_prompt.md"),
            "/api/soc-settings/cyber-threat-intel-prompt": ("Cyber Threat Intel", "cyber_threat_intel_system_prompt.md"),
            "/api/soc-settings/cyber-threat-intel-second-opinion-prompt": ("Cyber Threat Intel second-opinion", "cyber_threat_intel_second_opinion_prompt.md"),
            "/api/soc-settings/threat-hunter-prompt": ("Threat Hunter", "threat_hunter_system_prompt.md"),
            "/api/soc-settings/threat-hunter-second-opinion-prompt": ("Threat Hunter second-opinion", "threat_hunter_second_opinion_prompt.md"),
        }
        self.portal.SOC_SETTINGS_PROMPT_FILES = {
            route: (label, prompt_dir / filename)
            for route, (label, filename) in prompt_specs.items()
        }
        self.portal.SOC_SETTINGS_PROMPT_API_PATHS = frozenset(self.portal.SOC_SETTINGS_PROMPT_FILES)
        self.memory_dir = Path(self.tmp.name) / "agent-memory"
        self.memory_dir.mkdir()
        self.portal.AGENT_MEMORY_DIR = self.memory_dir
        self.portal.SOC_ANALYST_MEMORY_FILE = self.memory_dir / "soc-analyst-memory.md"
        self.portal.SHARED_AGENT_MEMORY_FILE = self.memory_dir / "shared-agent-memory.md"
        self.portal.SOC_AI_SETTINGS_FILE = Path(self.tmp.name) / "config" / "ai_model_settings.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_incident_responder_prompt_save_and_read(self) -> None:
        ok, payload = self.portal.save_incident_responder_prompt("Senior IR responder prompt")

        self.assertTrue(ok)
        self.assertEqual(payload["path"], str(self.prompt_path))
        self.assertEqual(self.prompt_path.read_text(encoding="utf-8"), "Senior IR responder prompt\n")

        read_payload = self.portal.read_incident_responder_prompt()
        self.assertTrue(read_payload["ok"])
        self.assertEqual(read_payload["prompt"], "Senior IR responder prompt\n")

    def test_incident_responder_prompt_rejects_empty_value(self) -> None:
        ok, payload = self.portal.save_incident_responder_prompt("  ")

        self.assertFalse(ok)
        self.assertIn("cannot be empty", payload["error"])
        self.assertFalse(self.prompt_path.exists())

    def test_all_primary_and_reviewer_prompt_routes_persist_separately(self) -> None:
        self.assertEqual(len(self.portal.SOC_SETTINGS_PROMPT_API_PATHS), 10)
        for index, route in enumerate(sorted(self.portal.SOC_SETTINGS_PROMPT_API_PATHS)):
            expected = f"Role-isolated prompt {index} for {route}"
            ok, payload = self.portal.save_settings_prompt(route, expected)
            self.assertTrue(ok, payload)
            self.assertEqual(payload["path"], str(self.portal.SOC_SETTINGS_PROMPT_FILES[route][1]))
            read_payload = self.portal.read_settings_prompt(route)
            self.assertTrue(read_payload["ok"])
            self.assertEqual(read_payload["prompt"], expected + "\n")

        primary = self.portal.read_settings_prompt("/api/soc-settings/analyst-prompt")["prompt"]
        reviewer = self.portal.read_settings_prompt(
            "/api/soc-settings/analyst-second-opinion-prompt"
        )["prompt"]
        self.assertNotEqual(primary, reviewer)

    def test_unknown_prompt_route_is_not_read_or_written(self) -> None:
        route = "/api/soc-settings/not-allowlisted-prompt"
        self.assertFalse(self.portal.read_settings_prompt(route)["ok"])
        ok, payload = self.portal.save_settings_prompt(route, "must not write")
        self.assertFalse(ok)
        self.assertIn("Unknown", payload["error"])

    def test_agent_memory_read_is_allowlisted_and_read_only(self) -> None:
        self.portal.SOC_ANALYST_MEMORY_FILE.write_text("# SOC Analyst Memory\n\nKnown pattern.\n", encoding="utf-8")

        status, payload = self.portal.read_agent_memory("soc-analyst")

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["read_only"])
        self.assertEqual(payload["label"], "SOC Analyst Memory")
        self.assertIn("Known pattern.", payload["content"])
        self.assertIn("  ", payload["modified_at"])

    def test_agent_memory_rejects_unknown_and_path_like_keys(self) -> None:
        for key in ("unknown", "../config/secrets", "/etc/passwd"):
            status, payload = self.portal.read_agent_memory(key)
            self.assertEqual(status, 400)
            self.assertFalse(payload["ok"])

    def test_agent_memory_rejects_symlink_escape(self) -> None:
        outside = Path(self.tmp.name) / "outside.md"
        outside.write_text("outside", encoding="utf-8")
        self.portal.SOC_ANALYST_MEMORY_FILE.symlink_to(outside)

        status, payload = self.portal.read_agent_memory("soc-analyst")

        self.assertEqual(status, 403)
        self.assertFalse(payload["ok"])

    def test_agent_memory_enforces_view_size_limit(self) -> None:
        self.portal.AGENT_MEMORY_VIEW_MAX_BYTES = 8
        self.portal.SHARED_AGENT_MEMORY_FILE.write_text("too much memory", encoding="utf-8")

        status, payload = self.portal.read_agent_memory("shared")

        self.assertEqual(status, 413)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["key"], "shared")
        self.assertEqual(payload["label"], "Shared Agent Memory")
        self.assertEqual(payload["path"], str(self.portal.SHARED_AGENT_MEMORY_FILE))
        self.assertEqual(payload["bytes"], len("too much memory"))
        self.assertTrue(payload["read_only"])

    def test_ai_settings_accept_three_safe_maxmind_paths_and_report_missing_databases(self) -> None:
        databases = {
            database_type: Path(self.tmp.name) / "geoip" / f"GeoLite2-{database_type.title()}.mmdb"
            for database_type in ("asn", "city", "country")
        }
        payload = self.portal.default_soc_ai_settings()
        for database_type, database in databases.items():
            payload[f"maxmind_geoip_{database_type}_db_path"] = str(database)

        ok, saved = self.portal.save_soc_ai_settings(payload)

        self.assertTrue(ok)
        self.assertEqual(set(saved["geoip_databases"]), {"asn", "city", "country"})
        for database_type, database in databases.items():
            self.assertEqual(saved["geoip_databases"][database_type]["state"], "missing")
            self.assertEqual(saved["geoip_databases"][database_type]["configured_path"], str(database))
            self.assertEqual(
                self.portal.read_soc_ai_settings()["settings"][f"maxmind_geoip_{database_type}_db_path"],
                str(database),
            )
        self.assertEqual(saved["geoip_database"], saved["geoip_databases"]["city"])

    def test_ai_settings_report_three_ready_maxmind_databases_without_reading_contents(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        databases = {}
        for database_type in ("asn", "city", "country"):
            database = Path(self.tmp.name) / f"GeoLite2-{database_type.title()}.mmdb"
            database.write_bytes(f"private {database_type} runtime database fixture".encode())
            settings[f"maxmind_geoip_{database_type}_db_path"] = str(database)
            databases[database_type] = database

        statuses = self.portal.maxmind_geoip_databases_status(settings)

        for database_type, database in databases.items():
            status = statuses[database_type]
            self.assertEqual(status["state"], "ready")
            self.assertEqual(status["size_bytes"], database.stat().st_size)
            self.assertNotIn("content", status)

    def test_ai_settings_migrate_legacy_city_only_path(self) -> None:
        database = Path(self.tmp.name) / "GeoLite2-City.mmdb"
        payload = self.portal.default_soc_ai_settings()
        payload.pop("maxmind_geoip_city_db_path")
        payload["maxmind_geoip_db_path"] = str(database)

        ok, settings = self.portal.normalize_soc_ai_settings(payload)

        self.assertTrue(ok)
        self.assertEqual(settings["maxmind_geoip_city_db_path"], str(database))
        self.assertNotIn("maxmind_geoip_db_path", settings)

    def test_ai_settings_reject_unsafe_or_non_mmdb_geoip_paths(self) -> None:
        for database_type in ("asn", "city", "country"):
            for configured in ("relative.mmdb", "/tmp/database.dat", "/tmp/bad\nname.mmdb"):
                settings = self.portal.default_soc_ai_settings()
                settings[f"maxmind_geoip_{database_type}_db_path"] = configured

                ok, payload = self.portal.normalize_soc_ai_settings(settings)

                self.assertFalse(ok)
                self.assertIn("MaxMind GeoIP database path", payload["error"])

    def test_ai_settings_normalize_multiple_local_models_and_gpt_cli(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings.update({
            "enabled_ollama_models": ["primary:latest", "fallback:latest", "primary:latest"],
            "codex_cli_path": "codex",
            "codex_cli_model": "gpt-5.5",
            "codex_cli_reasoning_effort": "medium",
            "codex_cli_models": [
                {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
                {"model": "gpt-5.6-terra", "reasoning_effort": "low", "enabled": True},
            ],
        })

        ok, normalized = self.portal.normalize_soc_ai_settings(settings)

        self.assertTrue(ok)
        self.assertEqual(normalized["enabled_ollama_models"], ["primary:latest", "fallback:latest"])
        self.assertEqual(normalized["ollama_model"], "primary:latest")
        self.assertEqual(normalized["mode"], "hybrid")
        self.assertTrue(normalized["gpt_cli_enabled"])
        self.assertEqual(normalized["codex_cli_model"], "gpt-5.6-sol")
        self.assertEqual(len(normalized["codex_cli_models"]), 2)
        self.assertEqual(normalized["cloud_command"], "")

    def test_ai_settings_normalize_exact_agent_assignments_and_stale_routes(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings.update({
            "enabled_ollama_models": ["primary:latest", "specialist:latest"],
            "codex_cli_models": [
                {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
            ],
            "agent_models": {
                "soc-analyst": "ollama:specialist:latest",
                "incident-responder": "gpt-cli",
                "siem-engineer": "ollama:disabled:latest",
            },
        })

        ok, normalized = self.portal.normalize_soc_ai_settings(settings)

        self.assertTrue(ok)
        self.assertEqual(normalized["agent_models"]["soc-analyst"], "ollama:specialist:latest")
        self.assertEqual(
            normalized["agent_models"]["incident-responder"],
            "codex-cli:gpt-5.6-sol:high",
        )
        self.assertEqual(normalized["agent_models"]["siem-engineer"], "ollama:primary:latest")
        self.assertEqual(set(normalized["agent_models"]), set(self.portal.CYBER_SECURITY_AGENT_ROLES))

    def test_ai_settings_reject_arbitrary_codex_executables_and_reasoning_effort(self) -> None:
        for configured, effort in (
            ("codex --dangerously-run-anything", "medium"),
            ("/tmp/not-codex", "medium"),
            ("codex", "unbounded"),
        ):
            settings = self.portal.default_soc_ai_settings()
            settings.update({
                "gpt_cli_enabled": True,
                "codex_cli_path": configured,
                "codex_cli_reasoning_effort": effort,
            })

            ok, response = self.portal.normalize_soc_ai_settings(settings)

            self.assertFalse(ok)
            self.assertIn("Codex CLI", response["error"])

    def test_codex_cli_models_are_independently_enabled_for_agent_assignment(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings["codex_cli_models"] = [
            {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
            {"model": "gpt-5.6-sol", "reasoning_effort": "xhigh", "enabled": False},
            {"model": "gpt-5.6-terra", "reasoning_effort": "low", "enabled": True},
        ]
        settings["agent_models"]["soc-analyst"] = "codex-cli:gpt-5.6-sol:high"
        settings["agent_models"]["incident-responder"] = "codex-cli:gpt-5.6-sol:xhigh"

        ok, normalized = self.portal.normalize_soc_ai_settings(settings)

        self.assertTrue(ok)
        self.assertEqual(
            normalized["agent_models"]["soc-analyst"],
            "codex-cli:gpt-5.6-sol:high",
        )
        self.assertNotEqual(
            normalized["agent_models"]["incident-responder"],
            "codex-cli:gpt-5.6-sol:xhigh",
        )
        self.assertTrue(normalized["gpt_cli_enabled"])

    def test_codex_cli_model_roster_rejects_duplicates_and_unsafe_names(self) -> None:
        for roster in (
            [
                {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
                {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": False},
            ],
            [{"model": "gpt-5.6-sol; rm", "reasoning_effort": "high", "enabled": True}],
        ):
            settings = self.portal.default_soc_ai_settings()
            settings["codex_cli_models"] = roster

            ok, response = self.portal.normalize_soc_ai_settings(settings)

            self.assertFalse(ok)
            self.assertIn("Codex CLI", response["error"])

    def test_agent_model_save_updates_only_one_role(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings.update({
            "enabled_ollama_models": ["primary:latest", "specialist:latest"],
            "agent_models": {
                role: "ollama:primary:latest" for role in self.portal.CYBER_SECURITY_AGENT_ROLES
            },
        })
        saved, _ = self.portal.save_soc_ai_settings(settings)
        self.assertTrue(saved)

        ok, response = self.portal.save_soc_agent_model({
            "role": "threat-hunter",
            "model": "ollama:specialist:latest",
        })

        self.assertTrue(ok)
        self.assertEqual(response["model_route"], "ollama:specialist:latest")
        persisted = json.loads(self.portal.SOC_AI_SETTINGS_FILE.read_text(encoding="utf-8"))
        self.assertEqual(persisted["agent_models"]["threat-hunter"], "ollama:specialist:latest")
        self.assertEqual(persisted["agent_models"]["soc-analyst"], "ollama:primary:latest")

    def test_agent_model_save_atomically_updates_optional_second_opinion(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings.update({
            "enabled_ollama_models": ["primary:latest", "reviewer:latest"],
            "agent_models": {
                role: "ollama:primary:latest" for role in self.portal.CYBER_SECURITY_AGENT_ROLES
            },
        })
        saved, _ = self.portal.save_soc_ai_settings(settings)
        self.assertTrue(saved)

        ok, response = self.portal.save_soc_agent_model({
            "role": "soc-analyst",
            "model": "ollama:primary:latest",
            "second_opinion_model": "ollama:reviewer:latest",
        })

        self.assertTrue(ok)
        self.assertEqual(response["second_opinion_model_route"], "ollama:reviewer:latest")
        persisted = json.loads(self.portal.SOC_AI_SETTINGS_FILE.read_text(encoding="utf-8"))
        self.assertEqual(
            persisted["agent_second_opinion_models"]["soc-analyst"],
            "ollama:reviewer:latest",
        )

    def test_agent_model_save_rejects_primary_as_second_opinion(self) -> None:
        saved, _ = self.portal.save_soc_ai_settings(self.portal.default_soc_ai_settings())
        self.assertTrue(saved)

        ok, response = self.portal.save_soc_agent_model({
            "role": "soc-analyst",
            "model": "ollama:devstral:latest",
            "second_opinion_model": "ollama:devstral:latest",
        })

        self.assertFalse(ok)
        self.assertIn("must differ", response["error"])

    def test_agent_model_save_rejects_unknown_role_and_disabled_route(self) -> None:
        saved, _ = self.portal.save_soc_ai_settings(self.portal.default_soc_ai_settings())
        self.assertTrue(saved)

        for payload, expected in (
            ({"role": "unknown", "model": "ollama:devstral:latest"}, "role is invalid"),
            ({"role": "soc-analyst", "model": "ollama:disabled:latest"}, "not enabled"),
        ):
            ok, response = self.portal.save_soc_agent_model(payload)
            self.assertFalse(ok)
            self.assertIn(expected, response["error"])

    def test_ai_settings_reject_disabling_every_analysis_provider(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings["enabled_ollama_models"] = []
        settings["gpt_cli_enabled"] = False

        ok, payload = self.portal.normalize_soc_ai_settings(settings)

        self.assertFalse(ok)
        self.assertIn("Enable at least one", payload["error"])

    def test_ai_settings_migrate_legacy_hybrid_configuration(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings.pop("enabled_ollama_models")
        settings.pop("gpt_cli_enabled")
        settings.pop("codex_cli_models")
        settings.update({"mode": "hybrid", "ollama_model": "legacy:latest"})

        ok, normalized = self.portal.normalize_soc_ai_settings(settings)

        self.assertTrue(ok)
        self.assertEqual(normalized["enabled_ollama_models"], ["legacy:latest"])
        self.assertTrue(normalized["gpt_cli_enabled"])
        self.assertEqual(normalized["mode"], "hybrid")

    def test_ollama_model_response_retains_configured_unavailable_models(self) -> None:
        settings = {
            **self.portal.default_soc_ai_settings(),
            "enabled_ollama_models": ["installed:latest", "offline:latest"],
        }
        with (
            mock.patch.object(self.portal, "read_soc_ai_settings", return_value={"ok": True, "settings": settings}),
            mock.patch.object(self.portal, "list_ollama_models", return_value=["installed:latest", "other:latest"]),
            mock.patch.object(
                self.portal,
                "ollama_model_compatibility",
                return_value={
                    "compatible": True,
                    "status": "compatible",
                    "reasons": [],
                    "capabilities": ["completion"],
                    "context_length": 131072,
                },
            ),
        ):
            payload = self.portal.ollama_models_response()

        self.assertEqual(payload["installed_models"], ["installed:latest", "other:latest"])
        self.assertEqual(payload["enabled_models"], ["installed:latest", "offline:latest"])
        self.assertIn("offline:latest", payload["models"])
        self.assertFalse(payload["compatibility"]["offline:latest"]["compatible"])
        self.assertEqual(payload["compatibility"]["offline:latest"]["status"], "unavailable")

    def test_ollama_compatibility_rejects_non_text_and_small_context_models(self) -> None:
        image_only = self.portal.classify_ollama_model_compatibility(
            "image-only:latest",
            {
                "capabilities": ["image"],
                "template": "{{ .Prompt }}",
                "model_info": {},
            },
        )
        small_context = self.portal.classify_ollama_model_compatibility(
            "small-context:latest",
            {
                "capabilities": ["completion"],
                "template": "{{ .Messages }}",
                "model_info": {"test.context_length": 8192},
            },
        )

        self.assertFalse(image_only["compatible"])
        self.assertIn("Image-generation only", image_only["reasons"][0])
        self.assertFalse(small_context["compatible"])
        self.assertIn("8,192-token context window", small_context["reasons"][0])

    def test_ollama_compatibility_accepts_chat_completion_at_minimum_context(self) -> None:
        assessment = self.portal.classify_ollama_model_compatibility(
            "soc-ready:latest",
            {
                "capabilities": ["completion"],
                "template": "{{ .Messages }}",
                "model_info": {"test.context_length": 32768},
            },
        )

        self.assertTrue(assessment["compatible"])
        self.assertEqual(assessment["status"], "compatible")
        self.assertEqual(assessment["context_length"], 32768)


if __name__ == "__main__":
    unittest.main()
