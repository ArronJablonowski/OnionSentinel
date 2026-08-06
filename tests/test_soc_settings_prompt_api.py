#!/usr/bin/env python3
"""Regression checks for editable SOC settings prompt helpers."""
from __future__ import annotations

import io
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


class SettingsPostRequest:
    """Minimal request stub for exercising the Settings POST route policy."""

    def __init__(self, path: str, payload: dict, *, settings_authorized: bool = True):
        body = json.dumps(payload).encode("utf-8")
        self.path = path
        self.headers = {"Content-Length": str(len(body))}
        self.rfile = io.BytesIO(body)
        self.settings_authorized = settings_authorized
        self.response: tuple[int, dict] | None = None

    def _soc_settings_write_authorized(self) -> bool:
        return self.settings_authorized

    def _send(self, status: int, body: bytes, _content_type: str = "") -> None:
        self.response = (int(status), json.loads(body.decode("utf-8")))


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

    def test_authorized_settings_save_routes_cover_every_save_family(self) -> None:
        cases = [
            (
                "/api/soc-settings/ai-model",
                {"mode": "ollama"},
                "save_soc_ai_settings",
            ),
            (
                "/api/soc-settings/agent-model",
                {"role": "soc-analyst", "model": "ollama:test"},
                "save_soc_agent_model",
            ),
            *[
                (route, {"prompt": f"Prompt for {route}"}, "save_settings_prompt")
                for route in sorted(self.portal.SOC_SETTINGS_PROMPT_API_PATHS)
            ],
        ]

        for route, payload, saver_name in cases:
            with self.subTest(route=route):
                request = SettingsPostRequest(route, payload)
                with mock.patch.object(
                    self.portal,
                    saver_name,
                    return_value=(True, {"ok": True, "message": "Saved."}),
                ) as save:
                    self.portal.PortalHandler.do_POST(request)

                self.assertEqual(request.response, (200, {"ok": True, "message": "Saved."}))
                save.assert_called_once()

    def test_shared_handler_rejects_settings_writes_without_authorization(self) -> None:
        cases = [
            (
                "/api/soc-settings/ai-model",
                {"mode": "ollama"},
                "save_soc_ai_settings",
            ),
            (
                "/api/soc-settings/agent-model",
                {"role": "soc-analyst", "model": "ollama:test"},
                "save_soc_agent_model",
            ),
            (
                "/api/soc-settings/analyst-prompt",
                {"prompt": "Test prompt"},
                "save_settings_prompt",
            ),
        ]

        for route, payload, saver_name in cases:
            with self.subTest(route=route):
                request = SettingsPostRequest(route, payload, settings_authorized=False)
                with mock.patch.object(self.portal, saver_name) as save:
                    self.portal.PortalHandler.do_POST(request)

                self.assertIsNotNone(request.response)
                status, body = request.response
                self.assertEqual(status, 403)
                self.assertFalse(body["ok"])
                self.assertIn("Sign in to Administration", body["error"])
                save.assert_not_called()

    def test_shared_handler_settings_policy_follows_admin_session(self) -> None:
        class AdminSession:
            def __init__(self, authenticated: bool):
                self.authenticated = authenticated

            def _admin_authenticated(self) -> bool:
                return self.authenticated

        for authenticated in (False, True):
            with self.subTest(authenticated=authenticated):
                self.assertEqual(
                    self.portal.PortalHandler._soc_settings_write_authorized(
                        AdminSession(authenticated)
                    ),
                    authenticated,
                )

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

    def test_enabled_openclaw_save_requires_resolvable_executable_without_running_it(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings.update({
            "openclaw_enabled": True,
            "openclaw_path": "/usr/local/absent/openclaw",
        })

        ok, response = self.portal.save_soc_ai_settings(settings)

        self.assertFalse(ok)
        self.assertIn("executable is unavailable", response["error"])
        executable = Path(self.tmp.name) / "bin" / "openclaw"
        executable.parent.mkdir()
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        executable.chmod(0o755)
        settings["openclaw_path"] = "openclaw"
        with (
            mock.patch.object(
                self.portal.shutil,
                "which",
                return_value=str(executable),
            ),
            mock.patch.object(
                self.portal.subprocess,
                "run",
                side_effect=AssertionError("settings readiness must not execute"),
            ),
        ):
            ok, response = self.portal.save_soc_ai_settings(settings)

        self.assertTrue(ok, response)

    def test_enabled_hermes_save_requires_safe_dedicated_credentials(self) -> None:
        executable = Path(self.tmp.name) / "bin" / "hermes"
        executable.parent.mkdir()
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        executable.chmod(0o755)
        auth_file = Path(self.tmp.name) / "private" / "hermes-agent" / "auth.json"
        auth_file.parent.mkdir(parents=True)
        auth_file.write_text("{}", encoding="utf-8")
        auth_file.chmod(0o600)
        settings = self.portal.default_soc_ai_settings()
        settings.update({
            "hermes_agent_enabled": True,
            "hermes_agent_path": str(executable),
        })

        with mock.patch.object(
            self.portal,
            "DEFAULT_HERMES_AUTH_FILE",
            auth_file,
        ):
            ok, response = self.portal.save_soc_ai_settings(settings)
            self.assertFalse(ok)
            self.assertIn("openai-codex credentials", response["error"])

            credential_marker = "fixture-secret-must-not-leak"
            valid_auth = json.dumps({
                "providers": {
                    "openai-codex": {"access_token": credential_marker},
                },
            })
            symlink_target = auth_file.with_name("actual-auth.json")
            symlink_target.write_text(valid_auth, encoding="utf-8")
            symlink_target.chmod(0o600)
            auth_file.unlink()
            auth_file.symlink_to(symlink_target)
            ok, response = self.portal.save_soc_ai_settings(settings)
            self.assertFalse(ok)
            self.assertIn("non-symlink", response["error"])

            auth_file.unlink()
            auth_file.write_text(valid_auth, encoding="utf-8")
            auth_file.chmod(0o400)
            ok, response = self.portal.save_soc_ai_settings(settings)
            self.assertFalse(ok)
            self.assertIn("permissions are unsafe", response["error"])

            auth_file.chmod(0o644)
            ok, response = self.portal.save_soc_ai_settings(settings)
            self.assertFalse(ok)
            self.assertIn("permissions are unsafe", response["error"])
            self.assertNotIn(credential_marker, json.dumps(response))

            auth_file.write_text(json.dumps({
                "credential_pool": {
                    "openai-codex": [{
                        "provider": "another-provider",
                        "access_token": credential_marker,
                    }],
                },
            }), encoding="utf-8")
            auth_file.chmod(0o600)
            ok, response = self.portal.save_soc_ai_settings(settings)
            self.assertFalse(ok)
            self.assertIn("credential pool is invalid", response["error"])
            self.assertNotIn(credential_marker, json.dumps(response))

            auth_file.write_text(valid_auth, encoding="utf-8")
            auth_file.chmod(0o600)
            with mock.patch.object(
                self.portal.subprocess,
                "run",
                side_effect=AssertionError("settings readiness must not execute"),
            ):
                ok, response = self.portal.save_soc_ai_settings(settings)

        self.assertTrue(ok, response)
        self.assertNotIn(credential_marker, json.dumps(response))

    def test_read_ai_settings_reports_normalization_failure_without_defaults(self) -> None:
        self.portal.SOC_AI_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.portal.SOC_AI_SETTINGS_FILE.write_text(json.dumps({
            "ollama_url": "file://private-value",
            "enabled_ollama_models": ["local:latest"],
        }), encoding="utf-8")

        response = self.portal.read_soc_ai_settings()

        self.assertFalse(response["ok"])
        self.assertIn("Ollama URL", response["error"])
        self.assertEqual(response["path"], str(self.portal.SOC_AI_SETTINGS_FILE))
        self.assertNotIn("settings", response)
        self.assertNotIn("private-value", json.dumps(response))

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

    def test_ai_analysis_threshold_is_independent_from_pcap(self) -> None:
        legacy = self.portal.default_soc_ai_settings()
        legacy.pop("soc_analyst_analysis_min_severity")
        legacy["soc_analyst_pcap_min_severity"] = "medium"

        ok, migrated = self.portal.normalize_soc_ai_settings(legacy)

        self.assertTrue(ok)
        self.assertEqual(
            migrated["soc_analyst_analysis_min_severity"],
            "informational",
        )
        self.assertEqual(migrated["soc_analyst_pcap_min_severity"], "medium")

        migrated["soc_analyst_analysis_min_severity"] = "high"
        migrated["soc_analyst_pcap_min_severity"] = "low"
        ok, independent = self.portal.normalize_soc_ai_settings(migrated)

        self.assertTrue(ok)
        self.assertEqual(independent["soc_analyst_analysis_min_severity"], "high")
        self.assertEqual(independent["soc_analyst_pcap_min_severity"], "low")

    def test_ai_settings_reject_invalid_analysis_threshold(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings["soc_analyst_analysis_min_severity"] = "everything"

        ok, payload = self.portal.normalize_soc_ai_settings(settings)

        self.assertFalse(ok)
        self.assertIn("automatic AI analysis severity threshold", payload["error"])

    def test_ai_settings_default_and_validate_capture_loss_threshold(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        self.assertEqual(settings["pcap_capture_loss_threshold_percent"], 5.0)

        settings["pcap_capture_loss_threshold_percent"] = "7.25"
        ok, normalized = self.portal.normalize_soc_ai_settings(settings)
        self.assertTrue(ok)
        self.assertEqual(normalized["pcap_capture_loss_threshold_percent"], 7.25)

        for invalid in (0, -1, 100.1, "not-a-number"):
            settings["pcap_capture_loss_threshold_percent"] = invalid
            ok, payload = self.portal.normalize_soc_ai_settings(settings)
            self.assertFalse(ok)
            self.assertIn("capture-loss threshold", payload["error"])

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
        self.assertEqual(
            [entry["model"] for entry in normalized["codex_cli_models"]],
            list(self.portal.CODEX_CLI_MODEL_CATALOG),
        )
        enabled = {
            entry["model"]: entry["reasoning_effort"]
            for entry in normalized["codex_cli_models"]
            if entry["enabled"]
        }
        self.assertEqual(enabled, {"gpt-5.6-sol": "high", "gpt-5.6-terra": "low"})
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
            {"model": "gpt-5.6-terra", "reasoning_effort": "low", "enabled": True},
            {"model": "gpt-5.6-luna", "reasoning_effort": "xhigh", "enabled": False},
        ]
        settings["agent_models"]["soc-analyst"] = "codex-cli:gpt-5.6-sol:high"
        settings["agent_models"]["incident-responder"] = "codex-cli:gpt-5.6-luna:xhigh"

        ok, normalized = self.portal.normalize_soc_ai_settings(settings)

        self.assertTrue(ok)
        self.assertEqual(
            normalized["agent_models"]["soc-analyst"],
            "codex-cli:gpt-5.6-sol:high",
        )
        self.assertNotEqual(
            normalized["agent_models"]["incident-responder"],
            "codex-cli:gpt-5.6-luna:xhigh",
        )
        self.assertTrue(normalized["gpt_cli_enabled"])

    def test_hermes_and_openclaw_toggles_are_authoritative_for_agent_routes(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings.update({
            "hermes_agent_enabled": True,
            "hermes_agent_path": "/usr/local/bin/hermes",
            "hermes_agent_model": "gpt-5.6-sol",
            "hermes_agent_reasoning_effort": "medium",
            "openclaw_enabled": True,
            "openclaw_path": "/opt/homebrew/bin/openclaw",
            "openclaw_model": "ollama/gemma4:26b-mlx",
            "openclaw_reasoning_effort": "xhigh",
        })
        settings["agent_models"]["soc-analyst"] = (
            "hermes-agent:gpt-5.6-sol:medium"
        )
        settings["agent_models"]["incident-responder"] = (
            "openclaw:ollama/gemma4:26b-mlx:xhigh"
        )
        settings["agent_second_opinion_models"]["soc-analyst"] = (
            "openclaw:ollama/gemma4:26b-mlx:xhigh"
        )

        ok, normalized = self.portal.normalize_soc_ai_settings(settings)

        self.assertTrue(ok)
        self.assertTrue(normalized["hermes_agent_enabled"])
        self.assertTrue(normalized["openclaw_enabled"])
        self.assertEqual(
            normalized["agent_models"]["soc-analyst"],
            "hermes-agent:gpt-5.6-sol:medium",
        )
        self.assertEqual(
            normalized["agent_models"]["incident-responder"],
            "openclaw:ollama/gemma4:26b-mlx:xhigh",
        )
        self.assertEqual(
            normalized["agent_second_opinion_models"]["soc-analyst"],
            "openclaw:ollama/gemma4:26b-mlx:xhigh",
        )

        normalized["openclaw_enabled"] = False
        ok, disabled = self.portal.normalize_soc_ai_settings(normalized)

        self.assertTrue(ok)
        self.assertNotEqual(
            disabled["agent_models"]["incident-responder"],
            "openclaw:ollama/gemma4:26b-mlx:xhigh",
        )
        self.assertEqual(
            disabled["agent_second_opinion_models"]["soc-analyst"],
            "",
        )

    def test_second_opinion_routes_require_distinct_underlying_model_identity(self) -> None:
        cases = (
            (
                "codex-cli:gpt-5.6-sol:high",
                "hermes-agent:gpt-5.6-sol:medium",
                {
                    "codex_cli_models": [{
                        "model": "gpt-5.6-sol",
                        "reasoning_effort": "high",
                        "enabled": True,
                    }],
                    "hermes_agent_enabled": True,
                    "hermes_agent_model": "gpt-5.6-sol",
                    "hermes_agent_reasoning_effort": "medium",
                },
            ),
            (
                "ollama:gemma4:31b",
                "openclaw:ollama/gemma4:31b:medium",
                {
                    "enabled_ollama_models": ["gemma4:31b"],
                    "openclaw_enabled": True,
                    "openclaw_model": "ollama/gemma4:31b",
                },
            ),
        )
        for primary, reviewer, overrides in cases:
            with self.subTest(primary=primary, reviewer=reviewer):
                settings = self.portal.default_soc_ai_settings()
                settings.update(overrides)
                settings["agent_models"]["soc-analyst"] = primary
                settings["agent_second_opinion_models"]["soc-analyst"] = reviewer

                ok, normalized = self.portal.normalize_soc_ai_settings(settings)

                self.assertTrue(ok)
                self.assertEqual(
                    normalized["agent_second_opinion_models"]["soc-analyst"],
                    "",
                )

    def test_harness_assignment_migrates_with_its_sole_configured_route(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings.update({
            "hermes_agent_enabled": True,
            "hermes_agent_model": "gpt-5.5",
            "hermes_agent_reasoning_effort": "medium",
            "openclaw_enabled": True,
            "openclaw_model": "ollama/gemma4:26b-mlx",
            "openclaw_reasoning_effort": "low",
        })
        settings["agent_models"]["soc-analyst"] = "hermes-agent:gpt-5.5:medium"
        settings["agent_second_opinion_models"]["incident-responder"] = (
            "openclaw:ollama/gemma4:26b-mlx:low"
        )

        ok, original = self.portal.normalize_soc_ai_settings(settings)
        self.assertTrue(ok)
        original.update({
            "hermes_agent_model": "gpt-5.6-terra",
            "hermes_agent_reasoning_effort": "medium",
            "openclaw_model": "ollama/gemma4:31b",
            "openclaw_reasoning_effort": "high",
        })

        ok, migrated = self.portal.normalize_soc_ai_settings(original)

        self.assertTrue(ok)
        self.assertEqual(
            migrated["agent_models"]["soc-analyst"],
            "hermes-agent:gpt-5.6-terra:medium",
        )
        self.assertEqual(
            migrated["agent_second_opinion_models"]["incident-responder"],
            "openclaw:ollama/gemma4:31b:high",
        )

    def test_openclaw_rejects_non_ollama_provider_routes(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings.update({
            "openclaw_enabled": True,
            "openclaw_model": "openai/gpt-5.6-sol",
        })

        ok, response = self.portal.normalize_soc_ai_settings(settings)

        self.assertFalse(ok)
        self.assertIn("explicit ollama/<model> routes only", response["error"])

    def test_openclaw_rejects_non_loopback_ollama_endpoint(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings.update({
            "openclaw_enabled": True,
            "openclaw_model": "ollama/gemma4:26b-mlx",
            "ollama_url": "http://192.0.2.50:11434",
        })

        ok, response = self.portal.normalize_soc_ai_settings(settings)

        self.assertFalse(ok)
        self.assertIn("loopback Ollama endpoint", response["error"])

    def test_missing_agent_runtime_settings_migrate_disabled(self) -> None:
        legacy = self.portal.default_soc_ai_settings()
        for key in (
            "hermes_agent_enabled",
            "hermes_agent_path",
            "hermes_agent_model",
            "hermes_agent_reasoning_effort",
            "openclaw_enabled",
            "openclaw_path",
            "openclaw_model",
            "openclaw_reasoning_effort",
        ):
            legacy.pop(key)

        ok, normalized = self.portal.normalize_soc_ai_settings(legacy)

        self.assertTrue(ok)
        self.assertFalse(normalized["hermes_agent_enabled"])
        self.assertEqual(normalized["hermes_agent_path"], "hermes")
        self.assertEqual(normalized["hermes_agent_model"], "gpt-5.5")
        self.assertFalse(normalized["openclaw_enabled"])
        self.assertEqual(normalized["openclaw_path"], "openclaw")
        self.assertEqual(normalized["openclaw_model"], "ollama/gemma4:26b-mlx")
        self.assertNotIn("openclaw_agent_id", normalized)

    def test_legacy_openclaw_agent_id_is_ignored_for_stateless_inference(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings["openclaw_agent_id"] = "../legacy-agent"

        ok, normalized = self.portal.normalize_soc_ai_settings(settings)

        self.assertTrue(ok)
        self.assertNotIn("openclaw_agent_id", normalized)

    def test_each_agent_runtime_can_be_the_only_provider_for_every_duty(self) -> None:
        cases = (
            (
                {"hermes_agent_enabled": True},
                "hermes-agent:gpt-5.5:medium",
                "cloud",
            ),
            (
                {"openclaw_enabled": True},
                "openclaw:ollama/gemma4:26b-mlx:medium",
                "ollama",
            ),
        )
        for overrides, expected_route, expected_mode in cases:
            with self.subTest(route=expected_route):
                settings = self.portal.default_soc_ai_settings()
                settings["enabled_ollama_models"] = []
                settings["codex_cli_models"] = []
                settings.update(overrides)

                ok, normalized = self.portal.normalize_soc_ai_settings(settings)

                self.assertTrue(ok)
                self.assertEqual(normalized["mode"], expected_mode)
                self.assertEqual(
                    set(normalized["agent_models"].values()),
                    {expected_route},
                )

    def test_agent_runtime_settings_reject_unsafe_executables_and_fields(self) -> None:
        invalid_settings = (
            ("hermes_agent_path", "hermes --unsafe", "Hermes Agent"),
            ("hermes_agent_path", "/tmp/not-hermes", "Hermes Agent"),
            ("hermes_agent_path", "/tmp/$(id)/hermes", "Hermes Agent"),
            ("hermes_agent_path", "/tmp/@scope/hermes", "Hermes Agent"),
            ("hermes_agent_path", "/tmp/percent%dir/hermes", "Hermes Agent"),
            ("openclaw_path", "openclaw;sh", "OpenClaw"),
            ("openclaw_path", "/tmp/not-openclaw", "OpenClaw"),
            ("openclaw_path", "/tmp/agent tools/openclaw", "OpenClaw"),
            ("openclaw_path", "/tmp/comma,dir/openclaw", "OpenClaw"),
            ("openclaw_path", "/tmp/equal=dir/openclaw", "OpenClaw"),
            ("hermes_agent_model", "bad\nmodel", "Hermes Agent"),
            ("hermes_agent_model", "other-provider/model", "Hermes Agent"),
            ("hermes_agent_reasoning_effort", "high", "Hermes Agent"),
            ("openclaw_model", "bad\x00model", "OpenClaw"),
            ("openclaw_model", "ollama/model;command", "OpenClaw"),
            ("openclaw_model", "openai/gpt-5.6-sol", "OpenClaw"),
        )
        for key, value, expected in invalid_settings:
            with self.subTest(key=key, value=repr(value)):
                settings = self.portal.default_soc_ai_settings()
                settings[key] = value

                ok, response = self.portal.normalize_soc_ai_settings(settings)

                self.assertFalse(ok)
                self.assertIn(expected, response["error"])

    def test_retired_hybrid_policy_is_ignored_and_not_persisted(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings["hybrid_policy"] = "invalid-legacy-value"

        ok, normalized = self.portal.normalize_soc_ai_settings(settings)

        self.assertTrue(ok)
        self.assertNotIn("hybrid_policy", normalized)

    def test_changing_codex_effort_preserves_the_assigned_model(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest"]
        settings["codex_cli_models"] = [
            {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
        ]
        settings["agent_models"]["soc-analyst"] = "codex-cli:gpt-5.6-sol:medium"

        ok, normalized = self.portal.normalize_soc_ai_settings(settings)

        self.assertTrue(ok)
        self.assertEqual(
            normalized["agent_models"]["soc-analyst"],
            "codex-cli:gpt-5.6-sol:high",
        )

    def test_codex_cli_model_roster_rejects_duplicates_and_unknown_models(self) -> None:
        for roster in (
            [
                {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
                {"model": "gpt-5.6-sol", "reasoning_effort": "xhigh", "enabled": False},
            ],
            [{"model": "gpt-9-unknown", "reasoning_effort": "high", "enabled": True}],
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

    def test_agent_model_save_atomically_updates_reviewer_and_adjudicator(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings.update({
            "enabled_ollama_models": [
                "primary:latest",
                "reviewer:latest",
                "adjudicator:latest",
            ],
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
            "adjudicator_model": "ollama:adjudicator:latest",
        })

        self.assertTrue(ok)
        self.assertEqual(response["second_opinion_model_route"], "ollama:reviewer:latest")
        self.assertEqual(
            response["adjudicator_model_route"],
            "ollama:adjudicator:latest",
        )
        persisted = json.loads(self.portal.SOC_AI_SETTINGS_FILE.read_text(encoding="utf-8"))
        self.assertEqual(
            persisted["agent_second_opinion_models"]["soc-analyst"],
            "ollama:reviewer:latest",
        )
        self.assertEqual(
            persisted["agent_adjudicator_models"]["soc-analyst"],
            "ollama:adjudicator:latest",
        )

    def test_agent_model_save_rejects_non_independent_adjudicator(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings.update({
            "enabled_ollama_models": ["primary:latest", "reviewer:latest"],
            "agent_models": {
                role: "ollama:primary:latest"
                for role in self.portal.CYBER_SECURITY_AGENT_ROLES
            },
        })
        saved, _ = self.portal.save_soc_ai_settings(settings)
        self.assertTrue(saved)

        for adjudicator in ("ollama:primary:latest", "ollama:reviewer:latest"):
            with self.subTest(adjudicator=adjudicator):
                ok, response = self.portal.save_soc_agent_model({
                    "role": "soc-analyst",
                    "model": "ollama:primary:latest",
                    "second_opinion_model": "ollama:reviewer:latest",
                    "adjudicator_model": adjudicator,
                })
                self.assertFalse(ok)
                self.assertIn("adjudicator must differ", response["error"])

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

    def test_agent_model_save_rejects_cross_harness_identity_collision(self) -> None:
        settings = self.portal.default_soc_ai_settings()
        settings["codex_cli_models"] = [{
            "model": "gpt-5.6-sol",
            "reasoning_effort": "high",
            "enabled": True,
        }]
        settings.update({
            "hermes_agent_enabled": True,
            "hermes_agent_model": "gpt-5.6-sol",
            "hermes_agent_reasoning_effort": "medium",
        })
        with mock.patch.object(
            self.portal,
            "_enabled_cli_harnesses_ready",
            return_value=(True, ""),
        ):
            saved, _ = self.portal.save_soc_ai_settings(settings)
            self.assertTrue(saved)
            ok, response = self.portal.save_soc_agent_model({
                "role": "soc-analyst",
                "model": "codex-cli:gpt-5.6-sol:high",
                "second_opinion_model": "hermes-agent:gpt-5.6-sol:medium",
            })

        self.assertFalse(ok)
        self.assertIn("provider/model identity", response["error"])

    def test_agent_model_save_rejects_unknown_role_and_disabled_route(self) -> None:
        saved, _ = self.portal.save_soc_ai_settings(self.portal.default_soc_ai_settings())
        self.assertTrue(saved)

        for payload, expected in (
            ({"role": "unknown", "model": "ollama:devstral:latest"}, "role is invalid"),
            ({"role": "soc-analyst", "model": "ollama:disabled:latest"}, "not enabled"),
            ({"role": "soc-analyst", "model": "codex-cli:gpt-5.6-sol:medium"}, "not enabled"),
            ({"role": "soc-analyst", "model": "hermes-agent:gpt-5.5:medium"}, "not enabled"),
            ({"role": "soc-analyst", "model": "openclaw:ollama/gemma4:26b-mlx:medium"}, "not enabled"),
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
