import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n" / "bin" / "upgrade-runtime-policy.py"
MODEL_SETTINGS = ROOT / "n8n" / "config" / "ai_model_settings.json"
INSTALLER = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
PRIOR_MODEL_SETTINGS_SHA256 = (
    "fd9f93123b22c0664d147fdcd012d1c016329566ffaea97cb4bfa7c5d7daaf2b"
)
PRE_ADJUDICATOR_MODEL_SETTINGS_SHA256 = (
    "bafb138cf8d2c216bf9fe37ea92d5b822b9444a108e9ca5de51a09f587983118"
)
PRIOR_REVIEWER_PROMPT_SHA256 = {
    "cyber_threat_intel_second_opinion_prompt.md": (
        "2c0a5093fc6c79d6bb7f40a278a265e2edba91d69e7fa763508f16eaf5f69e44"
    ),
    "incident_responder_second_opinion_prompt.md": (
        "71400cd9a6826be6b23a2cfa3cdacbada21ff6ef16d0093dac49c13dcf63d646"
    ),
    "siem_engineer_second_opinion_prompt.md": (
        "d2d60b55dd3050d99f42cc62653376c9ed6b1a5e3ad47bd3ea9b2a2f884d0dac"
    ),
    "soc_analyst_second_opinion_prompt.md": (
        "db79fa2ac912b7227e4889626d853eca28a950966b93acd822582b0468dcc5ff"
    ),
    "threat_hunter_second_opinion_prompt.md": (
        "15af4c64dfa8fcd5388286250212c24224aeb06716efb7da1e29bd6dd6469017"
    ),
}
OLDER_INCIDENT_RESPONDER_PROMPT_SHA256 = (
    "c13d5fcd90644db6fcd745fdc5c6ce978ccdd62a3f3e115dfce0aec634f77421"
)
ENDPOINT_ATTRIBUTION_REVIEWER_PROMPT_SHA256 = {
    "incident_responder_second_opinion_prompt.md": (
        "3b84b2972bbe7a447e5a981ac63669b538e944c91d0f089715cdcd04414b156e"
    ),
    "soc_analyst_second_opinion_prompt.md": (
        "42e45f57ab6a802eaa8e383b7eba82780c2ade58d99e06ef041912fa01ce2af9"
    ),
}


def load_module():
    spec = importlib.util.spec_from_file_location("runtime_policy_upgrade", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load runtime policy upgrade helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RuntimePolicyUpgradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_exact_prior_baseline_is_upgraded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.md"
            destination = root / "runtime.md"
            source.write_text("new reviewed policy\n", encoding="utf-8")
            destination.write_text("old reviewed policy\n", encoding="utf-8")
            prior = hashlib.sha256(destination.read_bytes()).hexdigest()

            result = self.module.upgrade_runtime_policy(
                source=source,
                destination=destination,
                accepted_prior_hashes={prior},
            )

            self.assertEqual(result["action"], "upgraded_reviewed_baseline")
            self.assertEqual(destination.read_bytes(), source.read_bytes())

    def test_operator_modified_policy_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.md"
            destination = root / "runtime.md"
            source.write_text("new reviewed policy\n", encoding="utf-8")
            destination.write_text("operator custom policy\n", encoding="utf-8")

            result = self.module.upgrade_runtime_policy(
                source=source,
                destination=destination,
                accepted_prior_hashes={"a" * 64},
            )

            self.assertEqual(result["action"], "preserved_operator_policy")
            self.assertEqual(
                destination.read_text(encoding="utf-8"),
                "operator custom policy\n",
            )

    def test_symlink_destination_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.md"
            actual = root / "actual.md"
            destination = root / "runtime.md"
            source.write_text("new reviewed policy\n", encoding="utf-8")
            actual.write_text("old reviewed policy\n", encoding="utf-8")
            destination.symlink_to(actual)

            with self.assertRaises(self.module.PolicyUpgradeError):
                self.module.upgrade_runtime_policy(
                    source=source,
                    destination=destination,
                    accepted_prior_hashes={
                        hashlib.sha256(actual.read_bytes()).hexdigest()
                    },
                )

    @staticmethod
    def prior_model_settings() -> dict:
        settings = json.loads(MODEL_SETTINGS.read_text(encoding="utf-8"))
        settings.pop("agent_adjudicator_models", None)
        for entry in settings["codex_cli_models"]:
            if entry["model"] == "gpt-5.6-terra":
                entry["enabled"] = False
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
            settings.pop(key, None)
        # The prior template exposed this now-retired, behaviorally inert key
        # immediately before the MaxMind paths. Preserve the old insertion order
        # so the approved byte-for-byte digest still describes that template.
        settings = {
            key: value
            for existing_key, existing_value in settings.items()
            for key, value in (
                (
                    ("hybrid_policy", "cloud_for_critical_high_or_recommended"),
                    (existing_key, existing_value),
                )
                if existing_key == "maxmind_geoip_asn_db_path"
                else ((existing_key, existing_value),)
            )
        }
        settings["agent_second_opinion_models"]["incident-responder"] = (
            "ollama:gemma4:31b"
        )
        for entry in settings["codex_cli_models"]:
            if entry["model"] == "gpt-5.6-sol":
                entry["enabled"] = False
                entry["reasoning_effort"] = "medium"
        return settings

    @staticmethod
    def write_settings(path: Path, settings: dict) -> None:
        path.write_text(
            json.dumps(settings, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_exact_prior_model_settings_template_is_upgraded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "ai_model_settings.json"
            self.write_settings(destination, self.prior_model_settings())
            self.assertEqual(
                hashlib.sha256(destination.read_bytes()).hexdigest(),
                PRIOR_MODEL_SETTINGS_SHA256,
                "approved digest must describe the intended old repository template",
            )

            result = self.module.upgrade_runtime_policy(
                source=MODEL_SETTINGS,
                destination=destination,
                accepted_prior_hashes={PRIOR_MODEL_SETTINGS_SHA256},
            )

            self.assertEqual(result["action"], "upgraded_reviewed_baseline")
            self.assertEqual(destination.read_bytes(), MODEL_SETTINGS.read_bytes())

    def test_custom_sol_model_settings_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "ai_model_settings.json"
            settings = self.prior_model_settings()
            settings["agent_second_opinion_models"]["incident-responder"] = (
                "codex-cli:gpt-5.6-sol:high"
            )
            for entry in settings["codex_cli_models"]:
                if entry["model"] == "gpt-5.6-sol":
                    entry["enabled"] = True
                    entry["reasoning_effort"] = "high"
            self.write_settings(destination, settings)
            original = destination.read_bytes()

            result = self.module.upgrade_runtime_policy(
                source=MODEL_SETTINGS,
                destination=destination,
                accepted_prior_hashes={PRIOR_MODEL_SETTINGS_SHA256},
            )

            self.assertEqual(result["action"], "preserved_operator_policy")
            self.assertEqual(destination.read_bytes(), original)

    def test_installer_seeds_then_exactly_migrates_model_settings(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        seed = (
            'cp "$REPO_DIR/n8n/config/ai_model_settings.json" '
            '"$STACK_DIR/config/ai_model_settings.json"'
        )
        migration = (
            '--source "$REPO_DIR/n8n/config/ai_model_settings.json" \\\n'
            '  --destination "$STACK_DIR/config/ai_model_settings.json" \\\n'
        )

        self.assertIn(seed, installer)
        self.assertIn(migration, installer)
        self.assertIn(
            f'--accepted-prior-sha256 "{PRIOR_MODEL_SETTINGS_SHA256}"',
            installer,
        )
        self.assertIn(
            f'--accepted-prior-sha256 "{PRE_ADJUDICATOR_MODEL_SETTINGS_SHA256}"',
            installer,
        )
        self.assertLess(installer.index(seed), installer.index(migration))

    def test_installer_exactly_migrates_every_shipped_reviewer_prompt(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        seed_loop = installer.index("for reviewer_prompt in")

        for prompt_name, prior_digest in PRIOR_REVIEWER_PROMPT_SHA256.items():
            with self.subTest(prompt=prompt_name):
                source = ROOT / "n8n" / "config" / prompt_name
                self.assertNotEqual(
                    hashlib.sha256(source.read_bytes()).hexdigest(),
                    prior_digest,
                    "the accepted predecessor must not equal the new source",
                )
                migration = (
                    f'--source "$REPO_DIR/n8n/config/{prompt_name}" \\\n'
                    f'  --destination "$STACK_DIR/config/{prompt_name}"'
                )
                migration_index = installer.index(migration)
                self.assertLess(seed_loop, migration_index)
                self.assertIn(
                    f'--accepted-prior-sha256 "{prior_digest}"',
                    installer[migration_index:],
                )

    def test_installer_retains_older_incident_responder_upgrade_path(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        incident_migration = installer.index(
            '--source "$REPO_DIR/n8n/config/'
            'incident_responder_second_opinion_prompt.md"'
        )
        following_migration = installer.index(
            '--source "$REPO_DIR/n8n/config/'
            'siem_engineer_second_opinion_prompt.md"',
            incident_migration,
        )
        incident_block = installer[incident_migration:following_migration]

        self.assertIn(
            f'--accepted-prior-sha256 "{OLDER_INCIDENT_RESPONDER_PROMPT_SHA256}"',
            incident_block,
        )
        self.assertIn(
            '--accepted-prior-sha256 "'
            f'{PRIOR_REVIEWER_PROMPT_SHA256["incident_responder_second_opinion_prompt.md"]}'
            '"',
            incident_block,
        )

    def test_installer_accepts_endpoint_attribution_reviewer_baselines(
        self,
    ) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        for prompt_name, prior_digest in (
            ENDPOINT_ATTRIBUTION_REVIEWER_PROMPT_SHA256.items()
        ):
            with self.subTest(prompt=prompt_name):
                migration_index = installer.index(
                    f'--source "$REPO_DIR/n8n/config/{prompt_name}"'
                )
                self.assertIn(
                    f'--accepted-prior-sha256 "{prior_digest}"',
                    installer[migration_index:],
                )


if __name__ == "__main__":
    unittest.main()
