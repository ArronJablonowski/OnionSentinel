"""Direct contracts for controlled-result identity and route admission."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.evaluation import result_identity  # noqa: E402


ENVIRONMENT_KEYS = {
    "job_id": "JOB_ID",
    "job_type": "JOB_TYPE",
    "lease_token": "LEASE_TOKEN",
    "cohort_id": "COHORT_ID",
    "dispatch_id": "DISPATCH_ID",
    "representative_alert_id": "ALERT_ID",
    "stable_group_id": "GROUP_ID",
    "stable_group_key": "GROUP_KEY",
    "agent_role": "AGENT_ROLE",
    "reanalysis_attempt_id": "ATTEMPT_ID",
    "release_id": "CLAIM_RELEASE_ID",
    "expected_assigned_route": "ASSIGNED_ROUTE",
    "expected_reviewer_route": "REVIEWER_ROUTE",
    "reviewer_required": "REVIEWER_REQUIRED",
}
RELEASE_ID = "a" * 40
ASSIGNED = "codex-cli:gpt-5.5:high"
REVIEWER = "codex-cli:gpt-5.6-sol:xhigh"
POLICY = result_identity.Policy(
    result_environment=ENVIRONMENT_KEYS,
    release_environment_key="RUNTIME_RELEASE_ID",
    model_route_pattern=re.compile(
        r"(?:codex-cli|ollama):[A-Za-z0-9._-]+:(?:low|medium|high|xhigh)"
    ),
    job_roles={
        "ai_analysis": "soc-analyst",
        "incident_response_analysis": "incident-responder",
    },
    maximum_settings_bytes=4096,
)


def environment(*, incident: bool = False) -> dict[str, str]:
    attempt = "ira-" + "b" * 40 if incident else ""
    values = {
        "job_id": "7",
        "job_type": (
            "incident_response_analysis" if incident else "ai_analysis"
        ),
        "lease_token": "77777777-7777-4777-8777-777777777777",
        "cohort_id": "cohort-7",
        "dispatch_id": "7" * 64,
        "representative_alert_id": "alert-7",
        "stable_group_id": "7" * 20,
        "stable_group_key": "v2|controlled|group-7",
        "agent_role": "incident-responder" if incident else "soc-analyst",
        "reanalysis_attempt_id": attempt,
        "release_id": RELEASE_ID,
        "expected_assigned_route": ASSIGNED,
        "expected_reviewer_route": REVIEWER,
        "reviewer_required": "1",
    }
    return {
        **{ENVIRONMENT_KEYS[field]: value for field, value in values.items()},
        "RUNTIME_RELEASE_ID": RELEASE_ID,
    }


def dependencies(env: dict[str, str]) -> result_identity.Dependencies:
    return result_identity.Dependencies(
        environment=env,
        enabled_routes=lambda settings: set(settings.get("enabled", [])),
    )


class ResultIdentityPackageTests(unittest.TestCase):
    def test_valid_identity_consumes_lease_environment(self) -> None:
        env = environment()
        identity = result_identity.identity(
            True,
            reanalysis_attempt_id="",
            policy=POLICY,
            dependencies=dependencies(env),
        )
        self.assertEqual(identity["job_id"], 7)
        self.assertEqual(identity["agent_role"], "soc-analyst")
        self.assertEqual(identity["release_id"], RELEASE_ID)
        self.assertTrue(identity["reviewer_required"])
        for key in ENVIRONMENT_KEYS.values():
            self.assertNotIn(key, env)
        self.assertEqual(env["RUNTIME_RELEASE_ID"], RELEASE_ID)

    def test_incident_identity_requires_exact_reanalysis_attempt(self) -> None:
        attempt = "ira-" + "b" * 40
        valid = result_identity.identity(
            True,
            reanalysis_attempt_id=attempt,
            policy=POLICY,
            dependencies=dependencies(environment(incident=True)),
        )
        self.assertEqual(valid["reanalysis_attempt_id"], attempt)
        with self.assertRaisesRegex(SystemExit, "identity is invalid"):
            result_identity.identity(
                True,
                reanalysis_attempt_id="ira-" + "c" * 40,
                policy=POLICY,
                dependencies=dependencies(environment(incident=True)),
            )

    def test_disabled_mode_rejects_and_consumes_leaked_identity(self) -> None:
        env = environment()
        with self.assertRaisesRegex(SystemExit, "requires controlled evaluation"):
            result_identity.identity(
                False,
                reanalysis_attempt_id="",
                policy=POLICY,
                dependencies=dependencies(env),
            )
        for key in ENVIRONMENT_KEYS.values():
            self.assertNotIn(key, env)

    def test_route_admission_requires_file_runtime_and_enabled_parity(self) -> None:
        identity = {
            "agent_role": "incident-responder",
            "expected_assigned_route": ASSIGNED,
            "expected_reviewer_route": REVIEWER,
            "reviewer_required": True,
        }
        settings = {
            "agent_models": {"incident-responder": ASSIGNED},
            "agent_second_opinion_models": {
                "incident-responder": REVIEWER,
            },
            "enabled": [ASSIGNED, REVIEWER],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "settings.json"
            path.write_text(json.dumps(settings), encoding="utf-8")
            result_identity.require_routes(
                identity, path, settings, "incident-responder",
                policy=POLICY, dependencies=dependencies({}),
            )
            tampered = dict(settings)
            tampered["agent_models"] = {
                "incident-responder": "ollama:local:high"
            }
            with self.assertRaisesRegex(SystemExit, "exactly match"):
                result_identity.require_routes(
                    identity, path, tampered, "incident-responder",
                    policy=POLICY, dependencies=dependencies({}),
                )

    def test_route_identity_rejects_same_underlying_model(self) -> None:
        identity = {
            "agent_role": "soc-analyst",
            "expected_assigned_route": ASSIGNED,
            "expected_reviewer_route": "codex-cli:gpt-5.5:xhigh",
            "reviewer_required": True,
        }
        with self.assertRaisesRegex(SystemExit, "route identity is invalid"):
            result_identity.require_routes(
                identity, Path("/does/not/matter"), {}, "soc-analyst",
                policy=POLICY, dependencies=dependencies({}),
            )


if __name__ == "__main__":
    unittest.main()
