from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_controlled_claim_contract import (  # noqa: E402
    ControlledClaimSources,
    ControlledRoutePolicy,
    ControlledRouteSources,
    controlled_claim_expectations,
    controlled_job_route_contract,
    incident_reanalysis_attempt_id,
)
from scheduler_controlled_release import (  # noqa: E402
    ControlledReleasePolicy,
    current_runtime_release_id,
    require_controlled_release_attestation,
)


class Rejected(RuntimeError):
    pass


class SchedulerControlledReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-release-contract-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.env_path = self.root / ".env"
        self.release = "a" * 40
        self.policy = ControlledReleasePolicy(
            environment_key="ONION_SENTINEL_RELEASE_ID",
            default_env_path=self.env_path,
            max_env_bytes=1024,
            release_pattern=re.compile(r"[a-f0-9]{40}"),
        )

    def load(self, environ: object, path: Path | None = None) -> str:
        return current_runtime_release_id(
            self.policy, environ=environ, env_path=path
        )

    def test_explicit_process_value_is_authoritative(self) -> None:
        self.env_path.write_text(
            f"ONION_SENTINEL_RELEASE_ID={self.release}\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self.load({"ONION_SENTINEL_RELEASE_ID": "b" * 40}),
            "b" * 40,
        )
        self.assertEqual(
            self.load({"ONION_SENTINEL_RELEASE_ID": ""}), ""
        )
        self.assertEqual(
            self.load({"ONION_SENTINEL_RELEASE_ID": 7}), ""
        )

    def test_literal_env_fallback_accepts_one_exact_value(self) -> None:
        self.env_path.write_text(
            "# deployment metadata\n"
            f" ONION_SENTINEL_RELEASE_ID = {self.release} \n",
            encoding="utf-8",
        )
        self.assertEqual(self.load({}), self.release)

    def test_literal_env_rejects_duplicates_quotes_and_shell_syntax(self) -> None:
        documents = (
            (
                f"ONION_SENTINEL_RELEASE_ID={self.release}\n"
                f"ONION_SENTINEL_RELEASE_ID={'b' * 40}\n"
            ),
            f'ONION_SENTINEL_RELEASE_ID="{self.release}"\n',
            "ONION_SENTINEL_RELEASE_ID=$(git rev-parse HEAD)\n",
            "export ONION_SENTINEL_RELEASE_ID=" + self.release + "\n",
        )
        for document in documents:
            with self.subTest(document=document):
                self.env_path.write_text(document, encoding="utf-8")
                self.assertEqual(self.load({}), "")

    def test_env_fallback_rejects_symlink_oversize_and_invalid_utf8(self) -> None:
        target = self.root / "target.env"
        target.write_text(
            f"ONION_SENTINEL_RELEASE_ID={self.release}\n",
            encoding="utf-8",
        )
        alias = self.root / "alias.env"
        alias.symlink_to(target)
        self.assertEqual(self.load({}, alias), "")
        oversized = self.root / "oversized.env"
        oversized.write_bytes(b"x" * 1025)
        self.assertEqual(self.load({}, oversized), "")
        invalid = self.root / "invalid.env"
        invalid.write_bytes(b"\xff\xfe")
        self.assertEqual(self.load({}, invalid), "")

    def test_attestation_requires_exact_nonempty_release(self) -> None:
        self.assertEqual(
            require_controlled_release_attestation(
                self.policy,
                {"release_id": self.release},
                self.release,
                Rejected,
            ),
            self.release,
        )
        for payload_release, runtime_release in (
            ("b" * 40, self.release),
            (self.release, ""),
            (7, self.release),
        ):
            with self.subTest(payload_release=payload_release):
                with self.assertRaisesRegex(Rejected, "deployed runtime"):
                    require_controlled_release_attestation(
                        self.policy,
                        {"release_id": payload_release},
                        runtime_release,
                        Rejected,
                    )


class SchedulerControlledClaimContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assigned = "codex-cli:gpt-5.5:high"
        self.reviewer = "codex-cli:gpt-5.6-sol:xhigh"
        self.payload = {
            "agent_role": "soc-analyst",
            "expected_assigned_route": self.assigned,
            "expected_reviewer_route": self.reviewer,
            "reviewer_required": True,
            "release_id": "a" * 40,
            "alert_id": "alert-1",
            "representative_alert_id": "alert-1",
            "group_id": "group-1",
            "stable_group_id": "group-1",
            "stable_group_key": "v2|group-1",
            "dispatch_id": "d" * 64,
        }
        self.settings = {
            "agent_models": {"soc-analyst": self.assigned},
            "agent_second_opinion_models": {
                "soc-analyst": self.reviewer
            },
        }
        self.raw = {
            "agent_models": {"soc-analyst": self.assigned},
            "agent_second_opinion_models": {
                "soc-analyst": self.reviewer
            },
        }
        self.load_settings = mock.Mock(
            return_value=(
                self.settings,
                self.raw,
                {self.assigned, self.reviewer},
            )
        )
        self.route_policy = ControlledRoutePolicy(
            model_route_pattern=re.compile(
                r"codex-cli:gpt-5\.(?:5|6-sol):(low|medium|high|xhigh)"
            )
        )
        self.route_sources = ControlledRouteSources(
            load_settings=self.load_settings,
            reject=Rejected,
            settings_errors=(OSError, ValueError, RuntimeError),
        )

    def route(self, payload: dict[str, object] | None = None) -> dict[str, object]:
        return controlled_job_route_contract(
            self.route_policy,
            self.route_sources,
            self.payload if payload is None else payload,
        )

    def test_attempt_id_is_deterministic_non_secret_fingerprint(self) -> None:
        attempt = incident_reanalysis_attempt_id(" secret-lease ")
        self.assertRegex(attempt, r"^ira-[a-f0-9]{40}$")
        self.assertNotIn("secret-lease", attempt)
        self.assertEqual(attempt, incident_reanalysis_attempt_id("secret-lease"))
        self.assertEqual(incident_reanalysis_attempt_id(""), "")

    def test_exact_enabled_route_contract_is_returned(self) -> None:
        self.assertEqual(
            self.route(),
            {
                "expected_assigned_route": self.assigned,
                "expected_reviewer_route": self.reviewer,
                "reviewer_required": True,
            },
        )

    def test_invalid_route_identity_rejects_before_settings_load(self) -> None:
        mutations = (
            ("reviewer_required", False),
            ("agent_role", "threat-hunter"),
            ("expected_reviewer_route", self.assigned),
            ("expected_assigned_route", "openclaw:gpt-5.5:high"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                candidate = dict(self.payload)
                candidate[field] = value
                self.load_settings.reset_mock()
                with self.assertRaisesRegex(Rejected, "route contract"):
                    self.route(candidate)
                self.load_settings.assert_not_called()

    def test_settings_failure_and_assignment_drift_fail_closed(self) -> None:
        self.load_settings.side_effect = OSError("secret path detail")
        with self.assertRaisesRegex(Rejected, "settings are unavailable"):
            self.route()
        self.load_settings.side_effect = None
        self.load_settings.return_value = (
            self.settings,
            self.raw,
            {self.assigned},
        )
        with self.assertRaisesRegex(Rejected, "exactly match"):
            self.route()

    def claim_sources(self) -> ControlledClaimSources:
        return ControlledClaimSources(
            stable_group_key_valid=lambda value: (
                isinstance(value, str) and value.startswith("v2|")
            ),
            require_release=mock.Mock(return_value="a" * 40),
            route_contract=mock.Mock(
                return_value={
                    "expected_assigned_route": self.assigned,
                    "expected_reviewer_route": self.reviewer,
                    "reviewer_required": True,
                }
            ),
            reject=Rejected,
        )

    def args(self, **changes: object) -> SimpleNamespace:
        values = {
            "only_group_id": "group-1",
            "only_alert_id": "alert-1",
            "only_stable_group_key": "v2|group-1",
            "only_dispatch_id": "d" * 64,
            **changes,
        }
        return SimpleNamespace(**values)

    def test_uncontrolled_invocation_returns_empty_without_contract_calls(self) -> None:
        sources = self.claim_sources()
        result = controlled_claim_expectations(
            sources, SimpleNamespace(), {"durable_job_id": 7}, self.payload
        )
        self.assertEqual(result, {})
        sources.require_release.assert_not_called()
        sources.route_contract.assert_not_called()

    def test_exact_frozen_candidate_returns_atomic_claim_expectations(self) -> None:
        sources = self.claim_sources()
        result = controlled_claim_expectations(
            sources, self.args(), {"durable_job_id": 7}, self.payload
        )
        self.assertEqual(result["expected_job_id"], 7)
        self.assertEqual(result["expected_representative_alert_id"], "alert-1")
        self.assertEqual(result["expected_dispatch_id"], "d" * 64)
        self.assertEqual(result["expected_stable_group_key"], "v2|group-1")
        sources.require_release.assert_called_once_with(self.payload)
        sources.route_contract.assert_called_once_with(self.payload)

    def test_incomplete_identity_job_or_payload_drift_rejects(self) -> None:
        cases = (
            (self.args(only_alert_id=""), {"durable_job_id": 7}, self.payload, "incomplete"),
            (self.args(), {"durable_job_id": 0}, self.payload, "durable AI job"),
            (
                self.args(),
                {"durable_job_id": 7},
                {**self.payload, "dispatch_id": "e" * 64},
                "frozen dispatch",
            ),
        )
        for args, selected, payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(Rejected, message):
                    controlled_claim_expectations(
                        self.claim_sources(), args, selected, payload
                    )


if __name__ == "__main__":
    unittest.main()
