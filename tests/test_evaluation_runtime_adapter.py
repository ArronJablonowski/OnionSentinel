#!/usr/bin/env python3
"""Characterization tests for controlled-evaluation runtime binding."""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.evaluation import runtime_adapter


class GateError(RuntimeError):
    pass


class EvaluationRuntimeAdapterTests(unittest.TestCase):
    def test_runtime_resolution_uses_live_policy_ports_and_publishes_tmpdir(
        self,
    ) -> None:
        environment = {"MODE": "1", "ROOT": "/evaluation", "TOKEN": "ok"}
        pinned = Path("/evaluation/tmp")
        bindings = {
            "HOME": Path("/operator"),
            "CONTROLLED_EVALUATION_MODE_ENV": "MODE",
            "CONTROLLED_EVALUATION_RUNTIME_DIR_ENV": "ROOT",
            "CONTROLLED_EVALUATION_TOKEN_ENV": "TOKEN",
            "CONTROLLED_EVALUATION_TOKEN_RE": re.compile(r"ok"),
            "os": SimpleNamespace(environ=environment, getuid=lambda: 501),
            "pin_controlled_tmpdir": mock.Mock(name="pin_tmpdir"),
            "validate_controlled_incident_evidence_route": mock.Mock(
                name="validate_route"
            ),
            "ControlledEvaluationIsolationError": ValueError,
            "_CONTROLLED_EVALUATION_TMPDIR": Path("/stale/tmp"),
        }
        observed: dict[str, object] = {}

        def resolve(runtime, *, policy, dependencies):
            observed.update(
                runtime=runtime, policy=policy, dependencies=dependencies
            )
            self.assertIsNone(bindings["_CONTROLLED_EVALUATION_TMPDIR"])
            return SimpleNamespace(
                enabled=True, root=Path("/evaluation"), tmpdir=pinned
            )

        module = SimpleNamespace(
            Policy=lambda **values: SimpleNamespace(**values),
            Dependencies=lambda **values: SimpleNamespace(**values),
            resolve=resolve,
        )
        self.assertEqual(
            runtime_adapter.resolve_runtime(bindings, module, "loopback-origin"),
            (True, Path("/evaluation")),
        )
        self.assertEqual(bindings["_CONTROLLED_EVALUATION_TMPDIR"], pinned)
        self.assertEqual(observed["runtime"], "loopback-origin")
        self.assertEqual(observed["policy"].home, Path("/operator"))
        self.assertIs(observed["dependencies"].environment, environment)
        self.assertIs(
            observed["dependencies"].pin_tmpdir,
            bindings["pin_controlled_tmpdir"],
        )

    def test_token_is_consumed_and_never_left_in_environment(self) -> None:
        token = "a" * 64
        environment = {"TOKEN": token}
        bindings = {
            "os": SimpleNamespace(environ=environment),
            "CONTROLLED_EVALUATION_TOKEN_ENV": "TOKEN",
            "CONTROLLED_EVALUATION_TOKEN_RE": re.compile(r"[a-f0-9]{64}"),
            "_CONTROLLED_EVALUATION_TOKEN": "stale",
        }
        self.assertEqual(runtime_adapter.consume_token(bindings, True), token)
        self.assertNotIn("TOKEN", environment)
        self.assertEqual(bindings["_CONTROLLED_EVALUATION_TOKEN"], token)

        environment["TOKEN"] = "not-valid"
        with self.assertRaisesRegex(SystemExit, "exact ephemeral"):
            runtime_adapter.consume_token(bindings, True)
        self.assertNotIn("TOKEN", environment)

    def test_direct_output_remains_inside_canonical_runtime_root(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            inside = root / "analysis"
            outside = root.parent / "outside-analysis"
            self.assertEqual(
                runtime_adapter.output_directory(inside, root), inside
            )
            with self.assertRaisesRegex(SystemExit, "out_dir must stay inside"):
                runtime_adapter.output_directory(outside, root)

    def test_result_requires_both_frozen_routes_and_memory_freeze_is_scoped(
        self,
    ) -> None:
        primary = "codex-cli:gpt-5.5:high"
        reviewer = "codex-cli:gpt-5.6-sol:xhigh"
        identity = {
            "expected_assigned_route": primary,
            "expected_reviewer_route": reviewer,
        }
        complete = {
            "_analysis_model_route": primary,
            "_second_opinion": {
                "status": "completed",
                "model_route": reviewer,
                "response": {"_analysis_model_route": reviewer},
            },
        }
        runtime_adapter.require_result_routes(
            identity, complete, gate_error=GateError
        )
        tampered = dict(complete)
        tampered["_analysis_model_route"] = reviewer
        with self.assertRaisesRegex(GateError, "both frozen routes"):
            runtime_adapter.require_result_routes(
                identity, tampered, gate_error=GateError
            )
        self.assertEqual(
            runtime_adapter.apply_memory_freeze(
                True, "eligible", freeze_enabled=True
            ),
            (False, "controlled harness evaluation froze memory writeback"),
        )
        self.assertEqual(
            runtime_adapter.apply_memory_freeze(
                True, "eligible", freeze_enabled=False
            ),
            (True, "eligible"),
        )


if __name__ == "__main__":
    unittest.main()
