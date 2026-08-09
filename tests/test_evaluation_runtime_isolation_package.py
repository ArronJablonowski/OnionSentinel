from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from n8n.onion_sentinel.evaluation import runtime_isolation


class IsolationError(ValueError):
    pass


class EvaluationRuntimeIsolationPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "home"
        self.parent = self.home / "n8n-local" / "harness-evaluations"
        self.runtime = self.parent / "run-1"
        self.runtime.mkdir(parents=True, mode=0o700)
        self.parent.chmod(0o700)
        self.runtime.chmod(0o700)
        self.tmpdir = self.runtime / "tmp"
        self.tmpdir.mkdir(mode=0o700)
        self.token = "a" * 64
        self.environment = {
            "EVALUATION_MODE": "1",
            "EVALUATION_RUNTIME": str(self.runtime),
            "EVALUATION_TOKEN": self.token,
        }
        self.incident_routes = []
        self.policy = runtime_isolation.Policy(
            home=self.home,
            mode_environment_key="EVALUATION_MODE",
            runtime_environment_key="EVALUATION_RUNTIME",
            token_environment_key="EVALUATION_TOKEN",
            token_pattern=re.compile(r"[a-f0-9]{64}"),
        )
        self.dependencies = runtime_isolation.Dependencies(
            environment=self.environment,
            owner_id=os.getuid,
            pin_tmpdir=lambda _root: self.tmpdir,
            validate_incident_route=lambda *args, **kwargs: (
                self.incident_routes.append((args, kwargs))
            ),
            isolation_error=IsolationError,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_disabled_mode_has_no_runtime_or_tmpdir(self) -> None:
        self.environment["EVALUATION_MODE"] = "0"

        result = runtime_isolation.resolve(
            "unsafe and intentionally unparsed",
            policy=self.policy,
            dependencies=self.dependencies,
        )

        self.assertEqual(
            result,
            runtime_isolation.Result(enabled=False, root=None, tmpdir=None),
        )

    def test_mode_token_and_origin_are_fail_closed(self) -> None:
        cases = (
            ("EVALUATION_MODE", "yes", "must be unset"),
            ("EVALUATION_TOKEN", "short", "ephemeral authorization token"),
        )
        for key, value, error in cases:
            original = self.environment[key]
            self.environment[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(SystemExit, error):
                runtime_isolation.resolve(
                    "http://127.0.0.1:18787",
                    policy=self.policy,
                    dependencies=self.dependencies,
                )
            self.environment[key] = original
        for origin in (
            "https://127.0.0.1:18787",
            "http://example.test:18787",
            "http://127.0.0.1:8787",
            "http://127.0.0.1:18787/path",
        ):
            with self.subTest(origin=origin), self.assertRaisesRegex(
                SystemExit, "alternate loopback"
            ):
                runtime_isolation.resolve(
                    origin, policy=self.policy, dependencies=self.dependencies
                )

    def test_valid_string_runtime_is_canonical_owner_private_and_pinned(self) -> None:
        result = runtime_isolation.resolve(
            "http://127.0.0.1:18787",
            policy=self.policy,
            dependencies=self.dependencies,
        )

        self.assertEqual(
            result,
            runtime_isolation.Result(
                enabled=True, root=self.runtime, tmpdir=self.tmpdir
            ),
        )
        self.runtime.chmod(0o750)
        with self.assertRaisesRegex(SystemExit, "must be owner-only"):
            runtime_isolation.resolve(
                "http://127.0.0.1:18787",
                policy=self.policy,
                dependencies=self.dependencies,
            )

    def _runtime_args(self) -> SimpleNamespace:
        directories = {
            name: self.runtime / name
            for name in ("prompts", "analysis", "pivots")
        }
        for path in directories.values():
            path.mkdir(mode=0o700)
        files = {
            name: self.runtime / name
            for name in (
                "prompt.json", "settings.json", "policy.json", "primary.md",
                "reviewer.md", "disagreement.md", "live-osquery.json",
                "incident.json",
            )
        }
        for path in files.values():
            path.write_text("{}\n", encoding="utf-8")
            path.chmod(0o600)
        files["live-osquery.json"].write_text(
            '{"enabled":false}\n', encoding="utf-8"
        )
        return SimpleNamespace(
            model="",
            generate_prompt=False,
            alert_store_url="http://127.0.0.1:18787",
            prompt_dir=directories["prompts"],
            out_dir=directories["analysis"],
            investigation_pivot_dir=directories["pivots"],
            prompt_package=files["prompt.json"],
            ai_settings_file=files["settings.json"],
            investigation_harness_policy=files["policy.json"],
            system_prompt_file=files["primary.md"],
            second_opinion_prompt_file=files["reviewer.md"],
            disagreement_adjudicator_prompt_file=files["disagreement.md"],
            live_osquery_config=files["live-osquery.json"],
            incident_evidence_config=files["incident.json"],
            response_json=None,
        )

    def test_namespace_requires_every_frozen_path_and_disabled_live_osquery(self) -> None:
        args = self._runtime_args()

        result = runtime_isolation.resolve(
            args, policy=self.policy, dependencies=self.dependencies
        )

        self.assertTrue(result.enabled)
        self.assertEqual(self.incident_routes[0][0][1], self.runtime)
        self.assertEqual(self.incident_routes[0][1]["expected_home"], self.home)
        args.live_osquery_config.write_text(
            '{"enabled":true}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(SystemExit, "explicitly disabled"):
            runtime_isolation.resolve(
                args, policy=self.policy, dependencies=self.dependencies
            )

    def test_namespace_rejects_override_and_path_escape(self) -> None:
        args = self._runtime_args()
        args.model = "override"
        with self.assertRaisesRegex(SystemExit, "forbids --model"):
            runtime_isolation.resolve(
                args, policy=self.policy, dependencies=self.dependencies
            )
        args.model = ""
        outside = self.root / "outside.json"
        outside.write_text("{}\n", encoding="utf-8")
        outside.chmod(0o600)
        args.ai_settings_file = outside
        with self.assertRaisesRegex(SystemExit, "AI settings"):
            runtime_isolation.resolve(
                args, policy=self.policy, dependencies=self.dependencies
            )


if __name__ == "__main__":
    unittest.main()
