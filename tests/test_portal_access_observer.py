from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_access_observer as observer  # noqa: E402
from portal_request_routes import classify_post_route  # noqa: E402
from portal_session_principal import HumanPrincipal  # noqa: E402


KEY = b"observe-audit-key-material-32-bytes-minimum"


def route(path: str):
    return classify_post_route(
        path,
        cti_program_path="/api/cyber-threat-intel/program",
        prompt_paths={"/api/soc-settings/analyst-prompt"},
    )


class PortalAccessObserverTests(unittest.TestCase):
    def test_legacy_mode_is_an_exact_no_observation_boundary(self) -> None:
        self.assertIsNone(
            observer.begin_observation(
                route("/api/soc-settings/ai-model"),
                mode="legacy",
                principal=None,
                same_origin_authorized=False,
                csrf_authorized=False,
                request_id="request-1",
                signing_key=KEY,
            )
        )

    def test_observe_projection_is_metadata_only_and_records_would_deny(self) -> None:
        target = "sensitive target value"
        observation = observer.begin_observation(
            route("/api/soc-alerts/" + target + "/escalate"),
            mode="observe",
            principal=None,
            same_origin_authorized=True,
            csrf_authorized=False,
            request_id="request-2",
            signing_key=KEY,
        )
        self.assertIsNotNone(observation)
        fields = observer.finalize_observation(
            observation,
            http_status=202,
            occurred_at="2026-08-15T05:00:00Z",
        )
        encoded = json.dumps(fields, sort_keys=True)
        self.assertNotIn(target, encoded)
        self.assertEqual(fields["role"], "unauthenticated")
        self.assertEqual(fields["permission"], "alert.escalate")
        self.assertEqual(fields["action"], "soc_alert_escalate")
        self.assertEqual(fields["outcome"], "allowed")
        self.assertEqual(
            fields["reason_code"], "observe_would_deny_unauthenticated"
        )
        self.assertEqual(
            fields["target_digest"], hashlib.sha256(target.encode()).hexdigest()
        )

    def test_principal_fingerprint_is_keyed_stable_and_not_reversible_text(self) -> None:
        principal = HumanPrincipal("human_session", "operator-7", "analyst")
        first = observer.begin_observation(
            route("/api/soc-alerts/group/ack"),
            mode="observe",
            principal=principal,
            same_origin_authorized=True,
            csrf_authorized=True,
            request_id="request-3",
            signing_key=KEY,
        )
        second = observer.begin_observation(
            route("/api/soc-alerts/other/ack"),
            mode="observe",
            principal=principal,
            same_origin_authorized=True,
            csrf_authorized=True,
            request_id="request-4",
            signing_key=KEY,
        )
        self.assertEqual(
            first.principal_fingerprint, second.principal_fingerprint
        )
        self.assertNotIn("operator-7", first.principal_fingerprint)
        fields = observer.finalize_observation(
            first,
            http_status=403,
            occurred_at="2026-08-15T05:00:01Z",
        )
        self.assertEqual(fields["role"], "analyst")
        self.assertEqual(fields["outcome"], "denied")
        self.assertEqual(fields["reason_code"], "observe_would_allow")

    def test_login_boundary_uses_explicit_authentication_permission(self) -> None:
        observation = observer.begin_observation(
            route("/admin/login"),
            mode="observe",
            principal=None,
            same_origin_authorized=False,
            csrf_authorized=False,
            request_id="request-5",
            signing_key=KEY,
        )
        fields = observer.finalize_observation(
            observation,
            http_status=302,
            occurred_at="2026-08-15T05:00:02Z",
        )
        self.assertEqual(fields["permission"], "authentication.login")
        self.assertEqual(fields["reason_code"], "observe_authentication_boundary")

    def test_enforcement_projection_distinguishes_precommit_and_final_outcome(self):
        principal = HumanPrincipal(
            "human_session", "local-administrator", "administrator"
        )
        observation = observer.begin_observation(
            route("/api/soc-settings/ai-model"),
            mode="admin-enforce",
            principal=principal,
            same_origin_authorized=True,
            csrf_authorized=True,
            request_id="request-enforced-1",
            signing_key=KEY,
        )
        precommit = observer.precommit_observation(
            observation,
            occurred_at="2026-08-15T06:50:00Z",
        )
        final = observer.finalize_observation(
            observation,
            http_status=204,
            occurred_at="2026-08-15T06:50:01Z",
        )
        self.assertEqual(
            (precommit["http_status"], precommit["reason_code"]),
            (100, "enforce_authorized_precommit"),
        )
        self.assertEqual(
            (final["outcome"], final["reason_code"]),
            ("allowed", "enforce_authorized"),
        )

    def test_enforcement_denial_cannot_be_projected_as_a_precommit(self):
        observation = observer.begin_observation(
            route("/api/soc-settings/ai-model"),
            mode="admin-enforce",
            principal=None,
            same_origin_authorized=False,
            csrf_authorized=False,
            request_id="request-enforced-2",
            signing_key=KEY,
        )
        final = observer.finalize_observation(
            observation,
            http_status=401,
            occurred_at="2026-08-15T06:51:00Z",
        )
        self.assertEqual(final["reason_code"], "enforce_denied_unauthenticated")
        with self.assertRaises(observer.AccessObservationError):
            observer.precommit_observation(
                observation,
                occurred_at="2026-08-15T06:51:00Z",
            )


if __name__ == "__main__":
    unittest.main()
