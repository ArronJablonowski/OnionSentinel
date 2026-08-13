from __future__ import annotations

import argparse
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))

from scheduler_cli import (  # noqa: E402
    SchedulerCliDefaults,
    SchedulerCliPolicy,
    _add_scheduler_policy,
    _validate_args,
    parse_scheduler_args,
)


class ParserFailure(RuntimeError):
    pass


class RecordingParser:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)
        raise ParserFailure(message)


class RecordingPattern:
    def __init__(self, calls: list[tuple[str, object]], name: str, valid: bool) -> None:
        self.calls = calls
        self.name = name
        self.valid = valid

    def fullmatch(self, value: object) -> bool:
        self.calls.append((self.name, value))
        return self.valid


def build_defaults(root: Path) -> SchedulerCliDefaults:
    return SchedulerCliDefaults(
        db=root / "alerts.db",
        harness_db=root / "harness.db",
        prompt_dir=root / "prompts",
        analysis_dir=root / "analysis",
        pcap_analysis_dir=root / "pcap",
        rollup_dir=root / "rollups",
        agent_memory_dir=root / "memory",
        shared_memory_file=root / "shared.md",
        asset_inventory_file=root / "assets.json",
        incident_evidence_dir=root / "evidence",
        incident_evidence_config=root / "evidence.json",
        investigation_pivot_dir=root / "pivots",
        live_osquery_config=root / "osquery.json",
        disagreement_adjudicator_prompt=root / "adjudicator.md",
        ai_settings=root / "settings.json",
        investigation_harness_policy=root / "harness.json",
        detection_playbooks=root / "playbooks.json",
        investigation_skills=root / "skills.json",
        lock=root / "worker.lock",
        drain=root / "drain",
        wake=root / "wake",
        levels="critical,high",
        model="default-model",
        max_prompt_bytes=524288,
        portal_wake=root / "portal-wake",
        alert_store_url="http://127.0.0.1:8787",
    )


def action_projection(action: argparse.Action) -> tuple[object, ...]:
    choices = tuple(action.choices) if action.choices is not None else None
    value_type = getattr(action.type, "__name__", None)
    return (
        tuple(action.option_strings),
        action.dest,
        type(action).__name__,
        value_type,
        action.default,
        choices,
    )


class SchedulerCliProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.defaults = build_defaults(self.root)
        self.policy = SchedulerCliPolicy(
            controlled_alert_id=re.compile(r"[A-Za-z0-9._:@=-]{1,256}"),
            controlled_dispatch_id=re.compile(r"[a-f0-9]{64}"),
            stable_group_key_valid=lambda value: bool(value) and "\0" not in str(value),
            stable_group_key_max_bytes=2048,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_scheduler_policy_action_surface_is_exact(self) -> None:
        parser = argparse.ArgumentParser(add_help=False)
        _add_scheduler_policy(parser, self.defaults)
        self.assertEqual(
            [action_projection(action) for action in parser._actions],
            [
                (("--provider-lane",), "provider_lane", "_StoreAction", None, "any", ("any", "ollama", "cli")),
                (("--lock-file",), "lock_file", "_StoreAction", "Path", self.defaults.lock, None),
                (("--drain-file",), "drain_file", "_StoreAction", "Path", self.defaults.drain, None),
                (("--wake-file",), "wake_file", "_StoreAction", "Path", self.defaults.wake, None),
                (("--levels",), "levels", "_StoreAction", None, self.defaults.levels, None),
                (("--hours",), "hours", "_StoreAction", "int", 87600, None),
                (("--max-per-run",), "max_per_run", "_StoreAction", "int", 0, None),
                (("--only-group-id",), "only_group_id", "_StoreAction", None, "", None),
                (("--only-alert-id",), "only_alert_id", "_StoreAction", None, "", None),
                (("--only-stable-group-key",), "only_stable_group_key", "_StoreAction", None, "", None),
                (("--only-dispatch-id",), "only_dispatch_id", "_StoreAction", None, "", None),
                (("--related-limit",), "related_limit", "_StoreAction", "int", 8, None),
                (("--correlation-limit",), "correlation_limit", "_StoreAction", "int", 8, None),
                (("--correlation-min-score",), "correlation_min_score", "_StoreAction", "int", 15, None),
                (("--model",), "model", "_StoreAction", None, self.defaults.model, None),
                (("--timeout",), "timeout", "_StoreAction", "int", 600, None),
                (("--max-prompt-bytes",), "max_prompt_bytes", "_StoreAction", "int", self.defaults.max_prompt_bytes, None),
                (("--portal-wake-file",), "portal_wake_file", "_StoreAction", "Path", self.defaults.portal_wake, None),
                (("--no-portal-refresh",), "no_portal_refresh", "_StoreTrueAction", None, False, None),
                (("--alert-store-url",), "alert_store_url", "_StoreAction", None, self.defaults.alert_store_url, None),
                (("--include-tests",), "include_tests", "_StoreTrueAction", None, False, None),
                (("--dry-run",), "dry_run", "_StoreTrueAction", None, False, None),
            ],
        )

    def test_default_namespace_is_exact(self) -> None:
        args = parse_scheduler_args(self.defaults, self.policy, [])
        expected = {
            "db": self.defaults.db,
            "harness_db": self.defaults.harness_db,
            "prompt_dir": self.defaults.prompt_dir,
            "analysis_dir": self.defaults.analysis_dir,
            "prior_analysis_dir": self.defaults.analysis_dir,
            "pcap_analysis_dir": self.defaults.pcap_analysis_dir,
            "rollup_dir": self.defaults.rollup_dir,
            "agent_memory_dir": self.defaults.agent_memory_dir,
            "shared_memory_file": self.defaults.shared_memory_file,
            "asset_inventory_file": self.defaults.asset_inventory_file,
            "incident_evidence_dir": self.defaults.incident_evidence_dir,
            "incident_evidence_config": self.defaults.incident_evidence_config,
            "investigation_pivot_dir": self.defaults.investigation_pivot_dir,
            "live_osquery_config": self.defaults.live_osquery_config,
            "disagreement_adjudicator_prompt_file": self.defaults.disagreement_adjudicator_prompt,
            "ai_settings_file": self.defaults.ai_settings,
            "investigation_harness_policy": self.defaults.investigation_harness_policy,
            "detection_playbooks": self.defaults.detection_playbooks,
            "investigation_skills": self.defaults.investigation_skills,
            "provider_lane": "any",
            "lock_file": self.defaults.lock,
            "drain_file": self.defaults.drain,
            "wake_file": self.defaults.wake,
            "levels": self.defaults.levels,
            "hours": 87600,
            "max_per_run": 0,
            "only_group_id": "",
            "only_alert_id": "",
            "only_stable_group_key": "",
            "only_dispatch_id": "",
            "related_limit": 8,
            "correlation_limit": 8,
            "correlation_min_score": 15,
            "model": self.defaults.model,
            "timeout": 600,
            "max_prompt_bytes": self.defaults.max_prompt_bytes,
            "portal_wake_file": self.defaults.portal_wake,
            "no_portal_refresh": False,
            "alert_store_url": self.defaults.alert_store_url,
            "include_tests": False,
            "dry_run": False,
        }
        self.assertEqual(vars(args), expected)

    def test_every_option_parses_and_controlled_identity_normalizes(self) -> None:
        path_options = [
            "db", "harness-db", "prompt-dir", "analysis-dir", "prior-analysis-dir",
            "pcap-analysis-dir", "rollup-dir", "agent-memory-dir", "shared-memory-file",
            "asset-inventory-file", "incident-evidence-dir", "incident-evidence-config",
            "investigation-pivot-dir", "live-osquery-config",
            "disagreement-adjudicator-prompt-file", "ai-settings-file",
            "investigation-harness-policy", "detection-playbooks", "investigation-skills",
            "lock-file", "drain-file", "wake-file", "portal-wake-file",
        ]
        argv: list[str] = []
        for index, option in enumerate(path_options):
            argv.extend((f"--{option}", f"/synthetic/path-{index}"))
        argv.extend([
            "--provider-lane", "cli", "--levels", "medium,low", "--hours", "72",
            "--max-per-run", "3", "--only-group-id", " ABCDEF0123456789ABCD ",
            "--only-alert-id", " alert:synthetic ",
            "--only-stable-group-key", " stable key with spaces ",
            "--only-dispatch-id", f" {'b' * 64} ", "--related-limit", "4",
            "--correlation-limit", "5", "--correlation-min-score", "25",
            "--model", "override-model", "--timeout", "91",
            "--max-prompt-bytes", "786432", "--alert-store-url", "http://127.0.0.1:9999",
            "--no-portal-refresh", "--include-tests", "--dry-run",
        ])
        args = parse_scheduler_args(self.defaults, self.policy, argv)
        for index, option in enumerate(path_options):
            self.assertEqual(getattr(args, option.replace("-", "_")), Path(f"/synthetic/path-{index}"))
        self.assertEqual(args.provider_lane, "cli")
        self.assertEqual(args.levels, "medium,low")
        self.assertEqual(args.hours, 72)
        self.assertEqual(args.max_per_run, 3)
        self.assertEqual(args.only_group_id, "abcdef0123456789abcd")
        self.assertEqual(args.only_alert_id, "alert:synthetic")
        self.assertEqual(args.only_stable_group_key, " stable key with spaces ")
        self.assertEqual(args.only_dispatch_id, "b" * 64)
        self.assertEqual(args.related_limit, 4)
        self.assertEqual(args.correlation_limit, 5)
        self.assertEqual(args.correlation_min_score, 25)
        self.assertEqual(args.model, "override-model")
        self.assertEqual(args.timeout, 91)
        self.assertEqual(args.max_prompt_bytes, 786432)
        self.assertEqual(args.alert_store_url, "http://127.0.0.1:9999")
        self.assertTrue(args.no_portal_refresh)
        self.assertTrue(args.include_tests)
        self.assertTrue(args.dry_run)

    def _validation_args(self, **changes: object) -> SimpleNamespace:
        values: dict[str, object] = {
            "hours": 1,
            "timeout": 1,
            "max_prompt_bytes": 262144,
            "max_per_run": 0,
            "only_group_id": "a" * 20,
            "only_alert_id": "alert-valid",
            "only_stable_group_key": "stable-valid",
            "only_dispatch_id": "b" * 64,
            "correlation_limit": 1,
            "correlation_min_score": 0,
        }
        values.update(changes)
        return SimpleNamespace(**values)

    def _recording_policy(
        self,
        calls: list[tuple[str, object]],
        *,
        alert_valid: bool = True,
        stable_valid: bool = True,
        dispatch_valid: bool = True,
    ) -> SchedulerCliPolicy:
        def stable(value: object) -> bool:
            calls.append(("stable", value))
            return stable_valid

        return SchedulerCliPolicy(
            controlled_alert_id=RecordingPattern(calls, "alert", alert_valid),  # type: ignore[arg-type]
            controlled_dispatch_id=RecordingPattern(calls, "dispatch", dispatch_valid),  # type: ignore[arg-type]
            stable_group_key_valid=stable,
            stable_group_key_max_bytes=2048,
        )

    def test_controlled_identity_validation_order_and_short_circuit_are_exact(self) -> None:
        cases = [
            (
                {"only_dispatch_id": ""}, {},
                "--only-group-id, --only-alert-id, --only-stable-group-key, and --only-dispatch-id must be supplied together",
                [],
            ),
            (
                {"only_group_id": "z" * 20}, {},
                "--only-group-id must be one exact 20-hex stable group id",
                [],
            ),
            (
                {}, {"alert_valid": False},
                "--only-alert-id must be one bounded Security Onion/Elastic alert ID",
                [("alert", "alert-valid")],
            ),
            (
                {}, {"stable_valid": False},
                "--only-stable-group-key must be non-empty valid UTF-8, contain no NUL, and be no longer than 2048 bytes",
                [("alert", "alert-valid"), ("stable", "stable-valid")],
            ),
            (
                {}, {"dispatch_valid": False},
                "--only-dispatch-id must be one exact 64-character lowercase SHA-256 hex digest",
                [("alert", "alert-valid"), ("stable", "stable-valid"), ("dispatch", "b" * 64)],
            ),
        ]
        for changes, policy_changes, message, expected_calls in cases:
            with self.subTest(message=message):
                calls: list[tuple[str, object]] = []
                parser = RecordingParser()
                with self.assertRaisesRegex(ParserFailure, re.escape(message)):
                    _validate_args(
                        parser,  # type: ignore[arg-type]
                        self._validation_args(**changes),
                        self._recording_policy(calls, **policy_changes),
                    )
                self.assertEqual(parser.errors, [message])
                self.assertEqual(calls, expected_calls)

    def test_validation_precedence_and_normalized_policy_values_are_exact(self) -> None:
        numeric_cases = [
            ({"hours": 0, "timeout": 0}, "--hours must be positive"),
            ({"timeout": 0, "max_prompt_bytes": 1}, "--timeout must be positive"),
            ({"max_prompt_bytes": 1, "max_per_run": -1}, "--max-prompt-bytes must be at least 262144"),
            ({"max_per_run": -1}, "--max-per-run must be zero or positive"),
        ]
        for changes, message in numeric_cases:
            with self.subTest(message=message):
                calls: list[tuple[str, object]] = []
                parser = RecordingParser()
                args = self._validation_args(
                    only_group_id=" ABCDEF0123456789ABCD ",
                    **changes,
                )
                with self.assertRaisesRegex(ParserFailure, re.escape(message)):
                    _validate_args(
                        parser,  # type: ignore[arg-type]
                        args,
                        self._recording_policy(calls),
                    )
                self.assertEqual(args.only_group_id, " ABCDEF0123456789ABCD ")
                self.assertEqual(calls, [])

        calls = []
        parser = RecordingParser()
        args = self._validation_args(
            only_group_id=" ABCDEF0123456789ABCD ",
            only_alert_id=" alert-valid ",
            only_stable_group_key=" stable-valid ",
            only_dispatch_id=f" {'b' * 64} ",
        )
        result = _validate_args(
            parser,  # type: ignore[arg-type]
            args,
            self._recording_policy(calls),
        )
        self.assertIs(result, args)
        self.assertEqual(args.only_group_id, "abcdef0123456789abcd")
        self.assertEqual(args.only_alert_id, "alert-valid")
        self.assertEqual(args.only_stable_group_key, " stable-valid ")
        self.assertEqual(args.only_dispatch_id, "b" * 64)
        self.assertEqual(
            calls,
            [("alert", "alert-valid"), ("stable", " stable-valid "), ("dispatch", "b" * 64)],
        )

    def test_identity_validation_precedes_correlation_errors(self) -> None:
        cases = [
            ({"correlation_limit": 0, "correlation_min_score": 101}, "--correlation-limit must be positive"),
            ({"correlation_min_score": -1}, "--correlation-min-score must be between 0 and 100"),
            ({"correlation_min_score": 101}, "--correlation-min-score must be between 0 and 100"),
        ]
        for changes, message in cases:
            with self.subTest(message=message):
                calls: list[tuple[str, object]] = []
                parser = RecordingParser()
                with self.assertRaisesRegex(ParserFailure, re.escape(message)):
                    _validate_args(
                        parser,  # type: ignore[arg-type]
                        self._validation_args(**changes),
                        self._recording_policy(calls),
                    )
                self.assertEqual(
                    calls,
                    [("alert", "alert-valid"), ("stable", "stable-valid"), ("dispatch", "b" * 64)],
                )


if __name__ == "__main__":
    unittest.main()
