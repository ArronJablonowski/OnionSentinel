"""Direct contracts for assigned-route primary model execution."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis import primary_execution  # noqa: E402


class RouteError(RuntimeError):
    pass


class Harness:
    def __init__(self, mode="shadow"):
        self.policy = mock.Mock(mode=mode)
        self.preflight_model_call = mock.Mock()
        self.model_call = mock.Mock()


def policy(*, evaluation=False) -> primary_execution.Policy:
    return primary_execution.Policy(
        agent_roles=frozenset({"soc-analyst", "incident-responder"}),
        evaluation_harness_run=evaluation,
    )


def dependencies(**overrides) -> primary_execution.Dependencies:
    clock = iter((10.0, 12.5, 15.0))
    values = {
        "attach_evidence_contract": mock.Mock(),
        "canonical_route": lambda value: str(value or "").strip().lower(),
        "notify_phase": mock.Mock(),
        "analyze_route": mock.Mock(return_value={"summary": "complete"}),
        "monotonic": lambda: next(clock),
        "warning": mock.Mock(),
        "route_error": RouteError,
    }
    values.update(overrides)
    return primary_execution.Dependencies(**values)


class PrimaryExecutionPackageTests(unittest.TestCase):
    def execute(self, package: dict, *, deps=None, runtime=None, evaluation=False,
                role="soc-analyst", settings=None):
        return primary_execution.execute(
            package, object(), (
                settings if settings is not None
                else {"agent_models": {"soc-analyst": "MODEL"}}
            ),
            role, phase_callback=mock.sentinel.phase, harness_runtime=runtime,
            policy=policy(evaluation=evaluation), dependencies=deps or dependencies(),
        )

    def test_success_attaches_contract_notifies_and_records_route(self) -> None:
        package = {"alert": {"id": "a"}}
        runtime = Harness()
        deps = dependencies(analyze_route=mock.Mock(return_value={"summary": "ok"}))
        result = self.execute(package, deps=deps, runtime=runtime)
        self.assertEqual(result["summary"], "ok")
        deps.attach_evidence_contract.assert_called_once_with(package)
        deps.notify_phase.assert_called_once_with(
            mock.sentinel.phase, "primary_analysis", "model",
        )
        runtime.preflight_model_call.assert_called_once()
        self.assertEqual(runtime.model_call.call_args.kwargs["requested_route"], "model")
        self.assertNotIn("status", runtime.model_call.call_args.kwargs)

    def test_non_evidence_package_does_not_attach_contract(self) -> None:
        deps = dependencies()
        self.execute({"metadata": {}}, deps=deps)
        deps.attach_evidence_contract.assert_not_called()

    def test_unknown_role_or_missing_assignment_fails_before_model_call(self) -> None:
        analyze = mock.Mock()
        deps = dependencies(analyze_route=analyze)
        with self.assertRaisesRegex(SystemExit, "Unknown cyber-security agent role"):
            self.execute({}, deps=deps, role="foreign")
        with self.assertRaisesRegex(SystemExit, "no enabled analysis model"):
            self.execute({}, deps=deps, settings={"agent_models": {}})
        analyze.assert_not_called()

    def test_model_failure_is_recorded_and_reraised(self) -> None:
        runtime = Harness()
        deps = dependencies(analyze_route=mock.Mock(side_effect=ValueError("failed")))
        with self.assertRaisesRegex(ValueError, "failed"):
            self.execute({}, deps=deps, runtime=runtime)
        self.assertEqual(runtime.model_call.call_args.kwargs["response"], {})
        self.assertEqual(runtime.model_call.call_args.kwargs["status"], "failed:ValueError")

    def test_shadow_observation_failure_warns_but_enforce_and_evaluation_fail(self) -> None:
        shadow = Harness("shadow")
        shadow.preflight_model_call.side_effect = RuntimeError("trace unavailable")
        shadow_deps = dependencies()
        self.execute({}, deps=shadow_deps, runtime=shadow)
        shadow_deps.warning.assert_called_once()

        for mode, evaluation in (("enforce", False), ("shadow", True)):
            runtime = Harness(mode)
            runtime.preflight_model_call.side_effect = RuntimeError("trace unavailable")
            with self.subTest(mode=mode, evaluation=evaluation), self.assertRaisesRegex(
                RuntimeError, "trace unavailable",
            ):
                self.execute({}, runtime=runtime, evaluation=evaluation)

    def test_controlled_evaluation_requires_observed_assigned_route(self) -> None:
        deps = dependencies(analyze_route=mock.Mock(return_value={
            "_analysis_model_route": "other",
        }))
        with self.assertRaisesRegex(RouteError, "did not preserve"):
            self.execute({}, deps=deps, evaluation=True)

    def test_package_has_no_io_primitives(self) -> None:
        source = (ROOT / "n8n/onion_sentinel/analysis/primary_execution.py").read_text()
        for primitive in ("subprocess", "urlopen(", "import requests", "open("):
            self.assertNotIn(primitive, source)


if __name__ == "__main__":
    unittest.main()
