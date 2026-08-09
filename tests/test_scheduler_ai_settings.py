from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_ai_settings import (  # noqa: E402
    SchedulerSettingsPolicy,
    StrictSettingsSources,
    cli_agent_roles,
    configured_analysis_levels,
    load_untrusted_settings,
    role_uses_codex_cli,
    strict_controlled_ai_settings,
)


class SchedulerAiSettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-scheduler-settings-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.path = self.root / "ai-settings.json"
        self.policy = SchedulerSettingsPolicy(
            max_bytes=4096,
            agent_roles=(
                "soc-analyst",
                "incident-responder",
                "threat-hunter",
            ),
            codex_models=frozenset(
                {"gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra"}
            ),
            codex_efforts=frozenset(
                {"low", "medium", "high", "xhigh"}
            ),
        )

    def write(self, value: object) -> None:
        self.path.write_text(json.dumps(value), encoding="utf-8")

    def test_untrusted_loader_accepts_one_bounded_utf8_object(self) -> None:
        self.write({"agent_models": {}})
        self.assertEqual(
            load_untrusted_settings(self.path, self.policy),
            {"agent_models": {}},
        )

    def test_untrusted_loader_fails_closed_for_bad_inputs(self) -> None:
        self.assertIsNone(load_untrusted_settings(self.path, self.policy))
        cases = (
            b"[]",
            b"{",
            b"\xff\xfe",
            b"x" * 4097,
        )
        for content in cases:
            with self.subTest(size=len(content)):
                self.path.write_bytes(content)
                self.assertIsNone(
                    load_untrusted_settings(self.path, self.policy)
                )

    def test_cli_roles_require_enabled_exact_codex_or_hermes_routes(self) -> None:
        self.write(
            {
                "codex_cli_models": [
                    {
                        "model": "gpt-5.5",
                        "reasoning_effort": "high",
                        "enabled": True,
                    },
                    {
                        "model": "gpt-5.6-terra",
                        "reasoning_effort": "xhigh",
                        "enabled": False,
                    },
                ],
                "hermes_agent_enabled": True,
                "hermes_agent_model": "gpt-5.6-sol",
                "hermes_agent_reasoning_effort": "medium",
                "openclaw_enabled": True,
                "agent_models": {
                    "soc-analyst": "codex-cli:gpt-5.5:high",
                    "incident-responder": (
                        "hermes-agent:gpt-5.6-sol:medium"
                    ),
                    "threat-hunter": (
                        "openclaw:openai/gpt-5.6-terra:high"
                    ),
                },
            }
        )
        self.assertEqual(
            cli_agent_roles(self.path, self.policy),
            {"soc-analyst", "incident-responder"},
        )

    def test_cli_roles_preserve_legacy_aliases_but_reject_bad_rosters(self) -> None:
        self.write(
            {
                "codex_cli_models": "not-a-list",
                "agent_models": {
                    "soc-analyst": "codex-cli",
                    "incident-responder": "codex-cli:gpt-5.5:high",
                },
            }
        )
        self.assertEqual(
            cli_agent_roles(self.path, self.policy), {"soc-analyst"}
        )

    def test_role_codex_detection_covers_all_assignment_lanes(self) -> None:
        for field in (
            "agent_models",
            "agent_second_opinion_models",
            "agent_adjudicator_models",
        ):
            with self.subTest(field=field):
                self.write(
                    {field: {"soc-analyst": "codex-cli:gpt-5.5:high"}}
                )
                self.assertTrue(
                    role_uses_codex_cli(
                        self.path, self.policy, "soc-analyst"
                    )
                )
        self.write(
            {
                "agent_models": {
                    "soc-analyst": "hermes-agent:gpt-5.5:medium"
                }
            }
        )
        self.assertFalse(
            role_uses_codex_cli(self.path, self.policy, "soc-analyst")
        )

    def test_analysis_floor_intersects_launch_allowlist(self) -> None:
        severity = ("critical", "high", "medium", "low", "informational")
        self.write({"soc_analyst_analysis_min_severity": "medium"})
        self.assertEqual(
            configured_analysis_levels(
                self.path,
                self.policy,
                "critical,high,medium,low",
                severity,
            ),
            ["critical", "high", "medium"],
        )
        self.write({"soc_analyst_analysis_min_severity": "disabled"})
        self.assertEqual(
            configured_analysis_levels(
                self.path, self.policy, "critical,high", severity
            ),
            [],
        )

    def test_missing_or_invalid_floor_preserves_historical_all_severity(self) -> None:
        severity = ("critical", "high", "medium", "low", "informational")
        for value in (None, "not-a-severity", "info"):
            with self.subTest(value=value):
                if value is None:
                    self.path.unlink(missing_ok=True)
                else:
                    self.write(
                        {"soc_analyst_analysis_min_severity": value}
                    )
                self.assertEqual(
                    configured_analysis_levels(
                        self.path,
                        self.policy,
                        "critical,high,medium,low,informational",
                        severity,
                    ),
                    list(severity),
                )

    def test_strict_snapshot_preserves_normalized_and_raw_assignments(self) -> None:
        raw = {"agent_models": {"soc-analyst": "codex-cli"}}
        self.write(raw)
        normalized = {
            "agent_models": {"soc-analyst": "codex-cli:gpt-5.5:high"}
        }
        sources = StrictSettingsSources(
            load_ai_settings=mock.Mock(return_value=normalized),
            read_bytes_bounded=mock.Mock(
                return_value=json.dumps(raw).encode()
            ),
            enabled_agent_model_routes=mock.Mock(
                return_value=["codex-cli:gpt-5.5:high"]
            ),
            max_settings_bytes=2048,
        )
        self.assertEqual(
            strict_controlled_ai_settings(self.path, 4096, sources),
            (
                normalized,
                raw,
                {"codex-cli:gpt-5.5:high"},
            ),
        )
        sources.read_bytes_bounded.assert_called_once_with(self.path, 2048)

    def test_strict_snapshot_rejects_missing_oversized_or_nonobject_root(self) -> None:
        sources = StrictSettingsSources(
            load_ai_settings=mock.Mock(return_value={}),
            read_bytes_bounded=mock.Mock(return_value=b"[]"),
            enabled_agent_model_routes=mock.Mock(return_value=[]),
            max_settings_bytes=2048,
        )
        with self.assertRaisesRegex(RuntimeError, "missing or oversized"):
            strict_controlled_ai_settings(self.path, 4096, sources)
        self.path.write_bytes(b"x" * 4097)
        with self.assertRaisesRegex(RuntimeError, "missing or oversized"):
            strict_controlled_ai_settings(self.path, 4096, sources)
        self.write({})
        with self.assertRaisesRegex(RuntimeError, "root must be an object"):
            strict_controlled_ai_settings(self.path, 4096, sources)


if __name__ == "__main__":
    unittest.main()
