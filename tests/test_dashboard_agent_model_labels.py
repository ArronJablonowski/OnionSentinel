#!/usr/bin/env python3
"""Contract tests for Cyber Security Agent model assignments on Settings."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"


def load_builder():
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location("build_soc_alerts_dashboard", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DashboardAgentModelLabelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = load_builder()

    def test_model_route_label_is_specific_to_each_agent(self) -> None:
        base = {
            "ollama_model": "local-test:latest",
            "enabled_ollama_models": ["local-test:latest"],
            "cloud_provider": "codex-cli",
            "cloud_model": "gpt-5.5",
            "codex_cli_model": "gpt-5.5",
            "codex_cli_reasoning_effort": "medium",
            "gpt_cli_enabled": True,
            "agent_models": {
                "soc-analyst": "ollama:local-test:latest",
                "incident-responder": "gpt-cli",
            },
        }

        self.assertEqual(
            self.builder.agent_model_route_label(base, "soc-analyst"),
            "Ollama: local-test:latest",
        )
        self.assertEqual(
            self.builder.agent_model_route_label(base, "incident-responder"),
            "Codex CLI: gpt-5.5 (medium)",
        )
        self.assertEqual(
            self.builder.agent_model_route_label(base, "threat-hunter"),
            "No analysis model assigned",
        )

    def test_every_collapsed_agent_row_shows_the_resolved_model(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "mode": "ollama",
            "ollama_model": "local-test:latest",
            "enabled_ollama_models": ["local-test:latest"],
            "agent_models": {
                role: "ollama:local-test:latest" for role in self.builder.CYBER_SECURITY_AGENT_ROLES
            },
        }
        with (
            mock.patch.object(self.builder, "load_soc_ai_settings", return_value=settings),
            mock.patch.object(self.builder, "list_ollama_models", return_value=["local-test:latest"]),
        ):
            rendered = self.builder.settings_page_section()

        self.assertEqual(rendered.count('data-agent-model="'), 5)
        self.assertEqual(rendered.count('data-agent-second-opinion-model="'), 5)
        self.assertEqual(rendered.count('data-agent-adjudicator-model="'), 5)
        self.assertEqual(rendered.count("None selected"), 10)
        self.assertEqual(rendered.count("data-agent-model-select"), 5)
        self.assertEqual(rendered.count("data-agent-second-opinion-select"), 5)
        self.assertEqual(rendered.count("data-agent-adjudicator-select"), 5)
        self.assertEqual(rendered.count("data-agent-model-save="), 5)
        self.assertGreaterEqual(rendered.count("Ollama: local-test:latest"), 10)

    def test_collapsed_agent_row_shows_the_resolved_second_opinion_model(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "mode": "ollama",
            "ollama_model": "primary:latest",
            "enabled_ollama_models": ["primary:latest", "reviewer:latest"],
            "agent_models": {
                role: "ollama:primary:latest" for role in self.builder.CYBER_SECURITY_AGENT_ROLES
            },
            "agent_second_opinion_models": {
                role: "ollama:reviewer:latest" for role in self.builder.CYBER_SECURITY_AGENT_ROLES
            },
        }
        with (
            mock.patch.object(self.builder, "load_soc_ai_settings", return_value=settings),
            mock.patch.object(
                self.builder,
                "list_ollama_models",
                return_value=["primary:latest", "reviewer:latest"],
            ),
        ):
            rendered = self.builder.settings_page_section()

        self.assertEqual(rendered.count('data-agent-second-opinion-model="'), 5)
        for role in self.builder.CYBER_SECURITY_AGENT_ROLES:
            self.assertIn(
                f'data-agent-second-opinion-model="{role}">Ollama: reviewer:latest</span>',
                rendered,
            )
        self.assertEqual(rendered.count("None selected"), 5)

    def test_model_selection_uses_collapsed_provider_sections_and_model_toggles(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "enabled_ollama_models": ["primary:latest"],
            "ollama_model": "primary:latest",
        }
        with (
            mock.patch.object(self.builder, "load_soc_ai_settings", return_value=settings),
            mock.patch.object(self.builder, "list_ollama_models", return_value=["primary:latest", "fallback:latest"]),
        ):
            rendered = self.builder.settings_page_section()

        self.assertIn('id="ollama-provider-settings"', rendered)
        self.assertIn('id="gpt-cli-provider-settings"', rendered)
        self.assertIn('id="onion-sentinel-harness-settings"', rendered)
        self.assertIn('id="hermes-harness-settings"', rendered)
        self.assertIn('id="openclaw-harness-settings"', rendered)
        self.assertIn('id="onion-sentinel-harness-title">Onion Sentinel Harness', rendered)
        self.assertIn('id="hermes-harness-title">Hermes Harness', rendered)
        self.assertIn('id="openclaw-harness-title">OpenClaw Harness', rendered)
        onion_start = rendered.index('id="onion-sentinel-harness-settings"')
        hermes_start = rendered.index('id="hermes-harness-settings"')
        openclaw_start = rendered.index('id="openclaw-harness-settings"')
        self.assertLess(onion_start, rendered.index('id="ollama-provider-settings"'))
        self.assertLess(rendered.index('id="gpt-cli-provider-settings"'), hermes_start)
        self.assertLess(hermes_start, rendered.index('id="ai-hermes-agent-enabled"'))
        self.assertLess(rendered.index('id="ai-hermes-agent-reasoning-effort"'), openclaw_start)
        self.assertLess(openclaw_start, rendered.index('id="ai-openclaw-enabled"'))
        self.assertIn("Codex CLI", rendered)
        self.assertIn('id="ai-codex-cli-path"', rendered)
        self.assertIn('id="ai-codex-cli-models"', rendered)
        self.assertNotIn('id="add-codex-cli-model"', rendered)
        self.assertNotIn("data-codex-cli-model-name", rendered)
        self.assertNotIn("data-codex-cli-model-remove", rendered)
        self.assertIn("data-codex-cli-model-effort", rendered)
        self.assertIn("data-codex-cli-model-enabled", rendered)
        self.assertEqual(rendered.count("data-codex-cli-model-row"), 4)
        self.assertEqual(rendered.count("data-codex-cli-model-enabled"), 4)
        catalog_positions = [
            rendered.index(f'data-codex-cli-model="{model}"')
            for model in self.builder.CODEX_CLI_MODEL_CATALOG
        ]
        self.assertEqual(catalog_positions, sorted(catalog_positions))
        for model in self.builder.CODEX_CLI_MODEL_CATALOG:
            self.assertIn(f'aria-label="Enable Codex CLI {model}"', rendered)
            self.assertIn(
                f'aria-label="Reasoning effort for Codex CLI {model}"',
                rendered,
            )
        self.assertNotIn('id="ai-cloud-command"', rendered)
        self.assertNotIn('id="ai-analysis-mode"', rendered)
        self.assertEqual(rendered.count("data-ollama-model-toggle"), 2)
        self.assertNotIn('<details class="settings-provider-details" id="ollama-provider-settings" open', rendered)
        self.assertNotIn('<details class="settings-provider-details" id="gpt-cli-provider-settings" open', rendered)
        script = self.builder.SETTINGS_PAGE_JS
        self.assertIn(
            "const codexCliCatalog = ['gpt-5.5', 'gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-5.6-luna'];",
            script,
        )
        self.assertIn("model: String(row.dataset.codexCliModel || '').trim()", script)
        self.assertNotIn("appendCodexCliModel", script)
        self.assertNotIn("addCodexCliModelButton", script)

    def test_hermes_and_openclaw_have_independent_settings_toggles(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "hermes_agent_enabled": True,
            "hermes_agent_model": "gpt-5.6-sol",
            "hermes_agent_reasoning_effort": "medium",
            "openclaw_enabled": False,
            "openclaw_model": "ollama/gemma4:26b-mlx",
            "openclaw_reasoning_effort": "xhigh",
        }
        with (
            mock.patch.object(self.builder, "load_soc_ai_settings", return_value=settings),
            mock.patch.object(
                self.builder,
                "list_ollama_models",
                return_value=["devstral:latest"],
            ),
        ):
            rendered = self.builder.settings_page_section()

        self.assertIn("Hermes Harness", rendered)
        self.assertIn("OpenClaw Harness", rendered)
        self.assertIn('id="ai-hermes-agent-enabled"', rendered)
        self.assertIn("data-hermes-agent-enabled", rendered)
        self.assertIn('aria-label="Enable Hermes Agent" checked', rendered)
        self.assertIn('id="ai-openclaw-enabled"', rendered)
        self.assertIn("data-openclaw-enabled", rendered)
        self.assertNotIn('aria-label="Enable OpenClaw" checked', rendered)
        self.assertIn("One isolated, explicit Ollama route", rendered)
        for field_id in (
            "ai-hermes-agent-path",
            "ai-hermes-agent-model",
            "ai-hermes-agent-reasoning-effort",
            "ai-openclaw-path",
            "ai-openclaw-model",
            "ai-openclaw-reasoning-effort",
        ):
            self.assertIn(f'id="{field_id}"', rendered)
        self.assertIn(
            'id="ai-hermes-agent-reasoning-effort" disabled',
            rendered,
        )
        self.assertIn(
            '<option value="medium" selected>Medium (required)</option>',
            rendered,
        )
        self.assertNotIn("ai-openclaw-agent-id", rendered)
        self.assertNotIn("openclaw_agent_id", self.builder.SETTINGS_PAGE_JS)
        self.assertIn("hermes_agent_enabled: hermesEnabled", self.builder.SETTINGS_PAGE_JS)
        self.assertIn("openclaw_enabled: openclawIsEnabled", self.builder.SETTINGS_PAGE_JS)
        self.assertNotIn('id="ai-hybrid-policy"', rendered)
        self.assertNotIn("hybrid_policy", self.builder.SETTINGS_PAGE_JS)
        self.assertIn(
            "OpenClaw currently supports explicit ollama/<model> routes only.",
            self.builder.SETTINGS_PAGE_JS,
        )
        self.assertIn(
            "payload.hermes_agent_reasoning_effort !== 'medium'",
            self.builder.SETTINGS_PAGE_JS,
        )
        self.assertIn(
            "OpenClaw requires a loopback Ollama endpoint on port 11434.",
            self.builder.SETTINGS_PAGE_JS,
        )

    def test_dashboard_never_exposes_a_non_ollama_openclaw_assignment(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "openclaw_enabled": True,
            "openclaw_model": "openai/gpt-5.6-sol",
        }

        self.assertEqual(
            self.builder.enabled_agent_model_routes(settings)[-1],
            "openclaw:ollama/gemma4:26b-mlx:medium",
        )

    def test_soc_automation_section_has_independent_analysis_threshold(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "soc_analyst_analysis_min_severity": "medium",
            "soc_analyst_pcap_min_severity": "high",
            "soc_analyst_incident_min_severity": "disabled",
        }
        with (
            mock.patch.object(self.builder, "load_soc_ai_settings", return_value=settings),
            mock.patch.object(self.builder, "list_ollama_models", return_value=["devstral:latest"]),
        ):
            rendered = self.builder.settings_page_section()

        self.assertIn("Lowest severity for automatic AI analysis", rendered)
        self.assertIn('id="soc-analyst-analysis-min-severity"', rendered)
        self.assertIn('id="pcap-capture-loss-threshold-percent"', rendered)
        self.assertIn("PCAP capture-loss safety threshold", rendered)
        self.assertIn('data-soc-policy-label="analysis">Medium and higher</span>', rendered)
        analysis_select = rendered.split(
            'id="soc-analyst-analysis-min-severity"',
            1,
        )[1].split("</select>", 1)[0]
        self.assertIn('<option value="medium" selected>Medium</option>', analysis_select)
        self.assertIn(
            "soc_analyst_analysis_min_severity: socAnalysisMinSeverity?.value",
            self.builder.SETTINGS_PAGE_JS,
        )
        self.assertIn(
            "pcap_capture_loss_threshold_percent: Number",
            self.builder.SETTINGS_PAGE_JS,
        )

    def test_ai_status_applies_threshold_only_to_unanalyzed_automatic_work(self) -> None:
        row = {
            "alert_id": "low-alert",
            "filter_status": "accepted",
            "triage_level": "low",
        }

        status = self.builder.ai_workflow_status_for_row(
            row,
            {},
            {},
            set(),
            "medium",
        )
        self.assertEqual(status[0], "not-queued")
        self.assertEqual(status[1], "Skipped")
        self.assertIn("Medium automatic AI-analysis minimum", status[2])

        historical = self.builder.ai_workflow_status_for_row(
            row,
            {
                "low-alert": {
                    "generated_at": "2026-07-24  12:00:00Z",
                    "response": {"_analysis_model": "historical-model"},
                }
            },
            {},
            set(),
            "medium",
        )
        self.assertEqual(historical[0], "analyzed")
        self.assertEqual(historical[1], "Analyzed")

        manual = self.builder.ai_workflow_status_for_row(
            row,
            {},
            {
                "low-alert": {
                    "generated_at": "2026-07-24  12:01:00Z",
                    "_prompt_mtime": 1.0,
                    "_prompt_filename": "manual-prompt.json",
                }
            },
            set(),
            "medium",
        )
        self.assertEqual(manual[0], "queued")
        self.assertEqual(manual[1], "Queued")

        unknown = self.builder.ai_workflow_status_for_row(
            {
                "alert_id": "unknown-alert",
                "filter_status": "accepted",
                "triage_level": "mystery",
            },
            {},
            {},
            set(),
            "informational",
        )
        self.assertEqual(unknown[0], "not-queued")
        self.assertEqual(unknown[1], "Skipped")
        self.assertIn("Unrecognized severity mystery", unknown[2])

    def test_only_enabled_codex_model_entries_appear_in_agent_selectors(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "enabled_ollama_models": ["primary:latest"],
            "codex_cli_models": [
                {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
                {"model": "gpt-5.6-terra", "reasoning_effort": "low", "enabled": True},
                {"model": "gpt-5.6-luna", "reasoning_effort": "xhigh", "enabled": False},
            ],
            "agent_models": {
                role: "codex-cli:gpt-5.6-sol:high"
                for role in self.builder.CYBER_SECURITY_AGENT_ROLES
            },
        }

        self.assertEqual(
            self.builder.enabled_agent_model_routes(settings),
            [
                "ollama:primary:latest",
                "codex-cli:gpt-5.6-sol:high",
                "codex-cli:gpt-5.6-terra:low",
            ],
        )
        options = self.builder.agent_model_option_rows(settings, "soc-analyst")
        self.assertIn("Codex CLI: gpt-5.6-sol (high)", options)
        self.assertIn("Codex CLI: gpt-5.6-terra (low)", options)
        self.assertNotIn("Codex CLI: gpt-5.6-luna (xhigh)", options)

    def test_only_enabled_agent_runtime_routes_appear_in_agent_selectors(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "enabled_ollama_models": ["primary:latest"],
            "hermes_agent_enabled": True,
            "hermes_agent_model": "gpt-5.6-sol",
            "hermes_agent_reasoning_effort": "medium",
            "openclaw_enabled": False,
            "openclaw_model": "ollama/gemma4:26b-mlx",
            "openclaw_reasoning_effort": "xhigh",
            "agent_models": {
                role: "hermes-agent:gpt-5.6-sol:medium"
                for role in self.builder.CYBER_SECURITY_AGENT_ROLES
            },
        }

        self.assertEqual(
            self.builder.enabled_agent_model_routes(settings),
            [
                "ollama:primary:latest",
                "hermes-agent:gpt-5.6-sol:medium",
            ],
        )
        options = self.builder.agent_model_option_rows(settings, "soc-analyst")
        self.assertIn("Hermes Agent: gpt-5.6-sol (medium)", options)
        self.assertNotIn("OpenClaw:", options)
        self.assertEqual(
            self.builder.agent_model_route_label(settings, "soc-analyst"),
            "Hermes Agent: gpt-5.6-sol (medium)",
        )

        settings["openclaw_enabled"] = True
        settings["agent_second_opinion_models"]["soc-analyst"] = (
            "openclaw:ollama/gemma4:26b-mlx:xhigh"
        )
        options = self.builder.agent_model_option_rows(
            settings,
            "soc-analyst",
            second_opinion=True,
        )
        self.assertIn("OpenClaw: ollama/gemma4:26b-mlx (xhigh)", options)
        self.assertEqual(
            self.builder.agent_second_opinion_model_route_label(
                settings,
                "soc-analyst",
            ),
            "OpenClaw: ollama/gemma4:26b-mlx (xhigh)",
        )

    def test_reviewer_options_exclude_same_underlying_model_identity(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "enabled_ollama_models": ["gemma4:31b"],
            "codex_cli_models": [{
                "model": "gpt-5.6-sol",
                "reasoning_effort": "high",
                "enabled": True,
            }],
            "hermes_agent_enabled": True,
            "hermes_agent_model": "gpt-5.6-sol",
            "hermes_agent_reasoning_effort": "medium",
            "openclaw_enabled": True,
            "openclaw_model": "ollama/gemma4:31b",
            "agent_models": {
                role: "codex-cli:gpt-5.6-sol:high"
                for role in self.builder.CYBER_SECURITY_AGENT_ROLES
            },
        }

        self.assertEqual(
            self.builder.model_route_identity(
                "codex-cli:gpt-5.6-sol:high",
                settings,
            ),
            self.builder.model_route_identity(
                "hermes-agent:gpt-5.6-sol:medium",
                settings,
            ),
        )
        options = self.builder.agent_model_option_rows(
            settings,
            "soc-analyst",
            second_opinion=True,
        )
        self.assertNotIn("Hermes Agent:", options)
        self.assertIn("OpenClaw:", options)

        settings.update({
            "openclaw_model": "ollama/gemma4:31b",
            "agent_models": {
                role: "ollama:gemma4:31b"
                for role in self.builder.CYBER_SECURITY_AGENT_ROLES
            },
        })
        options = self.builder.agent_model_option_rows(
            settings,
            "soc-analyst",
            second_opinion=True,
        )
        self.assertNotIn("OpenClaw:", options)
        self.assertIn("Codex CLI:", options)

    def test_harness_routes_migrate_with_provider_model_and_effort_changes(self) -> None:
        routes = [
            "ollama:local:latest",
            "hermes-agent:gpt-5.6-terra:medium",
            "openclaw:ollama/gemma4:31b:high",
        ]
        primary = self.builder.normalize_agent_models(
            {
                "soc-analyst": "hermes-agent:gpt-5.5:medium",
                "incident-responder": "ollama:local:latest",
            },
            routes,
        )
        reviewers = self.builder.normalize_agent_second_opinion_models(
            {
                "incident-responder": "openclaw:ollama/gemma4:26b-mlx:low",
            },
            routes,
            primary,
        )

        self.assertEqual(
            primary["soc-analyst"],
            "hermes-agent:gpt-5.6-terra:medium",
        )
        self.assertEqual(
            reviewers["incident-responder"],
            "openclaw:ollama/gemma4:31b:high",
        )
        script = self.builder.SETTINGS_PAGE_JS
        self.assertIn("function modelRouteIdentity(route, settings = {})", script)
        self.assertIn(
            "return routes.find(candidate => candidate.startsWith(prefix)) || normalized;",
            script,
        )

    def test_dashboard_executable_path_normalization_matches_runtime_allowlist(self) -> None:
        self.assertEqual(
            self.builder._normalized_cli_path(
                "/opt/onion-sentinel+tools/bin/hermes",
                "hermes",
            ),
            "/opt/onion-sentinel+tools/bin/hermes",
        )
        for unsafe in (
            "/opt/@scope/bin/hermes",
            "/opt/percent%dir/bin/hermes",
            "/opt/comma,dir/bin/hermes",
            "/opt/equal=dir/bin/hermes",
        ):
            with self.subTest(unsafe=unsafe):
                self.assertEqual(
                    self.builder._normalized_cli_path(unsafe, "hermes"),
                    "hermes",
                )

    def test_legacy_codex_roster_expands_to_the_fixed_catalog(self) -> None:
        entries = self.builder._normalized_codex_cli_models(
            [{"model": "gpt-5.5", "reasoning_effort": "high", "enabled": True}],
            legacy_model="gpt-5.5",
            legacy_effort="medium",
            legacy_enabled=False,
        )

        self.assertEqual(
            [entry["model"] for entry in entries],
            list(self.builder.CODEX_CLI_MODEL_CATALOG),
        )
        self.assertEqual(entries[0]["reasoning_effort"], "high")
        self.assertTrue(entries[0]["enabled"])
        self.assertTrue(all(not entry["enabled"] for entry in entries[1:]))

    def test_ai_activity_and_flow_show_the_assigned_codex_model(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "enabled_ollama_models": ["previous-local:latest"],
            "codex_cli_models": [
                {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
            ],
            "agent_models": {
                role: "codex-cli:gpt-5.6-sol:high"
                for role in self.builder.CYBER_SECURITY_AGENT_ROLES
            },
        }
        with mock.patch.object(self.builder, "load_soc_ai_settings", return_value=settings):
            assignment = self.builder.current_soc_analysis_model()
            state = self.builder.ai_activity_state([])

        self.assertEqual(assignment["provider"], "Codex CLI")
        self.assertEqual(assignment["model_detail"], "gpt-5.6-sol (high)")
        self.assertEqual(state["model"], "Codex CLI · gpt-5.6-sol (high)")
        self.assertNotIn("previous-local:latest", state["detail"])

        with (
            mock.patch.object(self.builder, "current_soc_analysis_model", return_value=assignment),
            mock.patch.object(self.builder, "count_ai_analysis_artifacts", return_value=0),
            mock.patch.object(
                self.builder,
                "telegram_sent_counts",
                return_value={"critical": 0, "high": 0},
            ),
        ):
            flow = self.builder.flow_page_section([])

        self.assertIn("Assigned AI triage", flow)
        self.assertIn("<strong>Codex CLI</strong><em>gpt-5.6-sol (high)</em>", flow)
        self.assertNotIn("<strong>Ollama</strong><em>previous-local:latest</em>", flow)
        self.assertIn(
            "requestUrl.pathname.endsWith('/soc-alerts-status.json')",
            self.builder.build_html([]),
        )

    def test_saved_settings_refresh_role_specific_controls(self) -> None:
        script = self.builder.SETTINGS_PAGE_JS

        self.assertIn("const agentModelLabels = [...document.querySelectorAll('[data-agent-model]')]", script)
        self.assertIn(
            "const agentSecondOpinionModelLabels = [...document.querySelectorAll('[data-agent-second-opinion-model]')]",
            script,
        )
        self.assertIn("element.textContent = route ? agentModelRouteLabel(route, settings) : 'None selected';", script)
        self.assertIn("const agentSecondOpinionSelects", script)
        self.assertIn("const agentAdjudicatorSelects", script)
        self.assertIn("settings.agent_second_opinion_models", script)
        self.assertIn("settings.agent_adjudicator_models", script)
        self.assertIn("/api/soc-settings/agent-model", script)
        self.assertIn("second_opinion_model: secondOpinionModel", script)
        self.assertIn("adjudicator_model: adjudicatorModel", script)
        self.assertIn("data-agent-model-status", script)
        self.assertIn("element.classList.toggle('error', kind === 'error');", script)
        self.assertIn("element.classList.toggle('ok', kind === 'ok');", script)
        self.assertNotIn("element.classList.toggle('is-error'", script)
        self.assertNotIn("element.classList.toggle('is-ok'", script)

    def test_model_inventory_renders_workflow_compatibility_warnings(self) -> None:
        script = self.builder.SETTINGS_PAGE_JS
        css = self.builder.SETTINGS_PAGE_CSS

        self.assertIn("workflowCompatibilityReason", script)
        self.assertIn("Workflow compatibility warning:", script)
        self.assertIn("data.compatibility", script)
        self.assertIn("?refresh=1", script)
        self.assertIn(".settings-model-warning", css)

    def test_onion_sentinel_harness_lists_read_only_investigation_skills(self) -> None:
        settings = {
            **self.builder.default_soc_ai_settings(),
            "enabled_ollama_models": ["primary:latest"],
            "ollama_model": "primary:latest",
        }
        registry = {
            "schema": "onion-sentinel-investigation-skills-v1",
            "version": 1,
            "mode": "shadow",
            "registry_sha256": "a" * 64,
            "skills": [{
                "id": "dns-activity-investigation",
                "version": 3,
                "status": "shadow",
                "skill_sha256": "b" * 64,
                "roles": ["soc-analyst", "incident-responder"],
                "match": {"protocols": ["udp"], "destination_ports": [53]},
                "objective": "Distinguish expected DNS from suspicious activity <safely>.",
                "required_evidence": ["alert", "zeek_dns"],
                "pivot_plan": [{
                    "step": "dns-timeline",
                    "backend": "elastic",
                    "pack": "dns_activity",
                    "purpose": "establish_timeline",
                    "discriminator": "Recover exact requests and answers.",
                    "required": True,
                }],
                "alternative_hypotheses": ["Expected resolution."],
                "stop_conditions": ["Stop after the bounded timeline is resolved."],
                "confidence_limiters": ["Reputation alone is not proof."],
                "known_false_positive_patterns": ["Operating-system checks."],
                "verification": ["Cite the query digest."],
            }],
        }
        with (
            mock.patch.object(self.builder, "load_soc_ai_settings", return_value=settings),
            mock.patch.object(self.builder, "list_ollama_models", return_value=["primary:latest"]),
            mock.patch.object(
                self.builder,
                "load_dashboard_investigation_skills",
                return_value=registry,
            ),
        ):
            rendered = self.builder.settings_page_section()

        onion_start = rendered.index('id="onion-sentinel-harness-settings"')
        skills_start = rendered.index('id="onion-sentinel-skills-title"')
        hermes_start = rendered.index('id="hermes-harness-settings"')
        self.assertLess(onion_start, skills_start)
        self.assertLess(skills_start, hermes_start)
        self.assertIn("Harness Skills", rendered)
        self.assertIn('data-investigation-skill="dns-activity-investigation"', rendered)
        self.assertIn("DNS Activity Investigation", rendered)
        self.assertIn("1 shadow", rendered)
        self.assertIn("v3", rendered)
        self.assertIn("Repeatable evidence pivots", rendered)
        self.assertIn("Skill source file", rendered)
        self.assertIn("~/n8n-local/config/investigation_skills.json", rendered)
        self.assertIn("Alternative hypotheses", rendered)
        self.assertIn("Confidence limiters", rendered)
        self.assertIn("Known false-positive patterns", rendered)
        self.assertIn("Verification rules", rendered)
        self.assertIn("b" * 64, rendered)
        self.assertIn("a" * 64, rendered)
        self.assertIn("&lt;safely&gt;", rendered)
        skill_section = rendered[skills_start:hermes_start]
        self.assertNotIn("Activate skill", skill_section)
        self.assertNotIn("Edit skill", skill_section)
        self.assertNotIn("Delete skill", skill_section)
        self.assertIn("This catalog is read-only", skill_section)

    def test_investigation_skill_catalog_fails_closed_when_registry_is_unavailable(self) -> None:
        rendered = self.builder.investigation_skill_catalog({
            "mode": "unavailable",
            "skills": [],
            "error": "invalid registry <blocked>",
        })

        self.assertIn("Harness Skills", rendered)
        self.assertIn("Unavailable", rendered)
        self.assertIn("invalid registry &lt;blocked&gt;", rendered)
        self.assertNotIn("data-investigation-skill=", rendered)


if __name__ == "__main__":
    unittest.main()
