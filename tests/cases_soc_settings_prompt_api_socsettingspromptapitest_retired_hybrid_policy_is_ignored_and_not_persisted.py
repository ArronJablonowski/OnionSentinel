from __future__ import annotations

from soc_settings_prompt_api_fixtures import (
    PORTAL_PATH,
    Path,
    REPO_ROOT,
    SettingsPostRequest,
    importlib,
    io,
    json,
    load_portal,
    mock,
    sys,
    tempfile,
    unittest,
)

class SocSettingsPromptApiTestRetiredHybridPolicyIsIgnoredAndNotPersistedCases:
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
