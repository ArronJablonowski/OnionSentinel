from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))

from onion_sentinel.analysis import entrypoint  # noqa: E402


DEFAULTS = entrypoint.Defaults(
    prompt_dir=Path("/defaults/prompts"),
    out_dir=Path("/defaults/output"),
    ai_settings_file=Path("/defaults/settings.json"),
    harness_policy=Path("/defaults/harness-policy.json"),
    harness_db=Path("/defaults/harness.sqlite3"),
    system_prompt_file=Path("/defaults/system.md"),
    second_opinion_prompt_file=Path("/defaults/reviewer.md"),
    adjudicator_prompt_file=Path("/defaults/adjudicator.md"),
    live_osquery_config=Path("/defaults/osquery.json"),
    incident_evidence_config=Path("/defaults/evidence.json"),
    investigation_pivot_dir=Path("/defaults/pivots"),
    max_response_bytes=1024 * 1024,
    max_prompt_bytes=512 * 1024,
)


class AnalysisEntrypointPackageTests(unittest.TestCase):
    def test_public_option_order_matches_the_legacy_cli(self) -> None:
        parser = entrypoint.build_parser(DEFAULTS, {})
        self.assertEqual(
            [action.dest for action in parser._actions],
            [
                "help",
                "prompt_package",
                "prompt_dir",
                "out_dir",
                "ai_settings_file",
                "investigation_harness_policy",
                "investigation_harness_db",
                "analysis_mode",
                "model",
                "ollama_url",
                "system_prompt_file",
                "second_opinion_prompt_file",
                "disagreement_adjudicator_prompt_file",
                "live_osquery_config",
                "incident_evidence_config",
                "investigation_pivot_dir",
                "timeout",
                "max_response_bytes",
                "max_prompt_bytes",
                "max_predict_tokens",
                "temperature",
                "response_json",
                "generate_prompt",
                "levels",
                "hours",
                "related_limit",
                "correlation_limit",
                "correlation_min_score",
                "alert_store_url",
                "reanalysis_attempt_id",
                "flush_index_only",
                "stdout",
            ],
        )

    def test_defaults_and_environment_are_injected(self) -> None:
        args = entrypoint.parse(
            DEFAULTS,
            {"ALERT_STORE_URL": "http://alert-store.test"},
            [],
        )
        self.assertEqual(args.prompt_dir, Path("/defaults/prompts"))
        self.assertEqual(args.ai_settings_file, Path("/defaults/settings.json"))
        self.assertEqual(args.max_response_bytes, 1024 * 1024)
        self.assertEqual(args.max_prompt_bytes, 512 * 1024)
        self.assertEqual(args.alert_store_url, "http://alert-store.test")
        self.assertIsNone(args.model)
        self.assertIsNone(args.ollama_url)

    def test_explicit_options_preserve_types_and_values(self) -> None:
        attempt_id = "ira-" + "a" * 40
        args = entrypoint.parse(DEFAULTS, {}, [
            "--prompt-package", "/tmp/prompt.json",
            "--analysis-mode", "hybrid",
            "--model", "model:latest",
            "--timeout", "90",
            "--max-prompt-bytes", str(768 * 1024),
            "--correlation-min-score", "42",
            "--reanalysis-attempt-id", attempt_id,
            "--generate-prompt",
            "--stdout",
        ])
        self.assertEqual(args.prompt_package, Path("/tmp/prompt.json"))
        self.assertEqual(args.analysis_mode, "hybrid")
        self.assertEqual(args.model, "model:latest")
        self.assertEqual(args.timeout, 90)
        self.assertEqual(args.correlation_min_score, 42)
        self.assertEqual(args.reanalysis_attempt_id, attempt_id)
        self.assertTrue(args.generate_prompt)
        self.assertTrue(args.stdout)

    def test_rejects_each_bounded_numeric_contract(self) -> None:
        invalid = (
            ["--timeout", "0"],
            ["--max-predict-tokens", "0"],
            ["--max-response-bytes", "0"],
            ["--max-prompt-bytes", "262143"],
            ["--correlation-limit", "0"],
            ["--correlation-min-score", "101"],
        )
        for argv in invalid:
            with self.subTest(argv=argv), self.assertRaises(SystemExit):
                entrypoint.parse(DEFAULTS, {}, argv)

    def test_reanalysis_attempt_identity_is_exact(self) -> None:
        for value in ("ira-short", "IRA-" + "a" * 40, "ira-" + "g" * 40):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                entrypoint.parse(
                    DEFAULTS,
                    {},
                    ["--reanalysis-attempt-id", value],
                )


if __name__ == "__main__":
    unittest.main()
