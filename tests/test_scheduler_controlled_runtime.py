from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_controlled_runtime import (  # noqa: E402
    ControlledRuntimePolicy,
    ControlledRuntimeSources,
    _safe_loopback_origin,
    validate_controlled_evaluation_runtime,
)


class IsolationError(RuntimeError):
    pass


class SchedulerControlledRuntimeTests(unittest.TestCase):
    def policy(self) -> ControlledRuntimePolicy:
        return ControlledRuntimePolicy(
            home=Path("/synthetic/home"),
            release_environment_key="ONION_SENTINEL_RELEASE_ID",
            token_environment_key="ONION_SENTINEL_EVALUATION_TOKEN",
            release_pattern=re.compile(r"[a-f0-9]{40}"),
            token_pattern=re.compile(r"[A-Za-z0-9_-]{43}"),
        )

    def sources(self, environment: dict[str, str]) -> ControlledRuntimeSources:
        return ControlledRuntimeSources(
            environment=environment,
            effective_uid=lambda: 501,
            pin_tmpdir=mock.Mock(),
            validate_incident_evidence_route=mock.Mock(),
            role_prompt_file=mock.Mock(),
            role_second_opinion_prompt_file=mock.Mock(),
            role_memory_file=mock.Mock(),
            isolation_error=IsolationError,
        )

    def test_disabled_mode_returns_before_reading_runtime_arguments(self) -> None:
        result = validate_controlled_evaluation_runtime(
            SimpleNamespace(),
            self.policy(),
            self.sources({"ONION_SENTINEL_EVALUATION_MODE": "0"}),
        )

        self.assertIsNone(result)

    def test_unrecognized_mode_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "must be unset, 0, or 1"):
            validate_controlled_evaluation_runtime(
                SimpleNamespace(),
                self.policy(),
                self.sources({"ONION_SENTINEL_EVALUATION_MODE": "true"}),
            )

    def test_model_override_fails_before_runtime_filesystem_access(self) -> None:
        sources = self.sources({"ONION_SENTINEL_EVALUATION_MODE": "1"})

        with self.assertRaisesRegex(SystemExit, "forbids --model"):
            validate_controlled_evaluation_runtime(
                SimpleNamespace(model="override"),
                self.policy(),
                sources,
            )

        sources.pin_tmpdir.assert_not_called()

    def test_only_ephemeral_loopback_origins_are_accepted(self) -> None:
        self.assertTrue(
            _safe_loopback_origin(
                SimpleNamespace(alert_store_url="http://127.0.0.1:18787")
            )
        )
        for origin in (
            "http://127.0.0.1:8787",
            "https://127.0.0.1:18787",
            "http://10.77.7.225:18787",
            "http://user@127.0.0.1:18787",
            "http://127.0.0.1:18787/path",
            "http://127.0.0.1:18787?query=1",
        ):
            with self.subTest(origin=origin):
                self.assertFalse(
                    _safe_loopback_origin(
                        SimpleNamespace(alert_store_url=origin)
                    )
                )


if __name__ == "__main__":
    unittest.main()
