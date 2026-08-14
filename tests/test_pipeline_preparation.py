from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import unittest

from onion_sentinel import preparation
from onion_sentinel.pipeline import RuntimeContext, Stage


class FakeHarness:
    def __init__(self, mode: str = "shadow") -> None:
        self.policy = SimpleNamespace(mode=mode)
        self.phases: list[tuple[str, str, str]] = []

    def phase(self, phase: str, route: str, reason: str) -> None:
        self.phases.append((phase, route, reason))


class PipelinePreparationTests(unittest.TestCase):
    def inputs(self, *, frozen: bool = False) -> preparation.PreparationInputs:
        return preparation.PreparationInputs(
            run_id="run-1",
            source_revision="1" * 40,
            prompt_package={"alert": "a"},
            settings={
                "agent_models": {"soc-analyst": "codex:gpt-5.5"},
                "agent_second_opinion_models": {"soc-analyst": "codex:gpt-5.6"},
            },
            agent_role="soc-analyst",
            memory_frozen=frozen,
            reanalysis_attempt_id="attempt-1",
            policy_path=Path("policy.json"),
            database_path=Path("harness.sqlite3"),
            query_contract={"schema": "v1"},
            max_query_rounds=4,
            max_queries_total=20,
            max_queries_per_round=5,
            max_prompt_bytes=1000,
            max_response_bytes=2000,
        )

    def ports(
        self,
        *,
        enabled: bool = True,
        mode: str = "shadow",
        allowed: bool = True,
        start_error: Exception | None = None,
    ) -> tuple[preparation.PreparationPorts, dict[str, object]]:
        state: dict[str, object] = {"warnings": [], "written": [], "monitor": 0}
        harness = FakeHarness(mode)

        def start(request: preparation.HarnessStartRequest, policy: object) -> object:
            state["request"] = request
            state["policy"] = policy
            if start_error:
                raise start_error
            return harness

        def write(record: dict[str, object]) -> None:
            state["written"].append(dict(record))  # type: ignore[union-attr]

        def monitor() -> None:
            state["monitor"] = int(state["monitor"]) + 1

        return preparation.PreparationPorts(
            enabled_routes=lambda settings: ["codex:gpt-5.5", "codex:gpt-5.6"],
            canonical_route=lambda route, admitted: str(route),
            load_harness_policy=lambda path: SimpleNamespace(enabled=enabled, mode=mode),
            harness_activation=lambda policy_enabled, assigned, reviewer: (
                allowed, "eligible" if allowed else "external provider"
            ),
            start_harness=start,
            build_running_record=lambda: {"status": "running"},
            write_running_record=write,
            publish_phase=lambda record, phase, route, reason: {
                **record, "active_phase": phase, "active_route": route
            },
            start_monitor=monitor,
            process_id=lambda: 42,
            warn=lambda message: state["warnings"].append(message),  # type: ignore[union-attr]
        ), state

    def context(self) -> RuntimeContext:
        context = RuntimeContext("run-1", arguments=SimpleNamespace())
        context.advance(Stage.LOAD, "loaded")
        context.advance(Stage.ATTEST, "attested")
        return context

    def test_prepares_routes_harness_telemetry_and_monitor(self) -> None:
        ports, state = self.ports()
        result = preparation.prepare(self.context(), self.inputs(), ports)
        request = state["request"]
        self.assertEqual(request.assigned_route, "codex:gpt-5.5")
        self.assertEqual(request.configuration["reviewer_route"], "codex:gpt-5.6")
        self.assertEqual(result.running_record["runner_pid"], 42)
        self.assertEqual(state["monitor"], 1)
        result.update_phase("primary", "codex:gpt-5.5", "new alert")
        self.assertEqual(result.running_record["active_phase"], "primary")
        self.assertEqual(result.harness.phases[-1], ("primary", "codex:gpt-5.5", "new alert"))

    def test_harness_request_preserves_complete_configuration_contract(self) -> None:
        ports, state = self.ports()
        inputs = self.inputs()

        preparation.prepare(self.context(), inputs, ports)

        request = state["request"]
        self.assertEqual(request.run_id, "run-1")
        self.assertEqual(request.source_revision, "1" * 40)
        self.assertIs(request.prompt_package, inputs.prompt_package)
        self.assertEqual(request.role, "soc-analyst")
        self.assertEqual(request.assigned_route, "codex:gpt-5.5")
        self.assertEqual(request.reanalysis_attempt_id, "attempt-1")
        self.assertEqual(request.policy_path, Path("policy.json"))
        self.assertEqual(request.database_path, Path("harness.sqlite3"))
        self.assertEqual(
            request.configuration,
            {
                "query_contract": {"schema": "v1"},
                "agent_role": "soc-analyst",
                "assigned_route": "codex:gpt-5.5",
                "reviewer_route": "codex:gpt-5.6",
                "evaluation_memory_frozen": False,
                "limits": {
                    "max_query_rounds": 4,
                    "max_queries_total": 20,
                    "max_queries_per_round": 5,
                    "max_prompt_bytes": 1000,
                    "max_response_bytes": 2000,
                },
            },
        )

    def test_disabled_policy_bypasses_without_warning_and_still_starts_telemetry(self) -> None:
        ports, state = self.ports(enabled=False, allowed=False)
        context = self.context()

        result = preparation.prepare(context, self.inputs(), ports)

        self.assertIsNone(result.harness)
        self.assertEqual(state["warnings"], [])
        self.assertEqual(state["written"], [{"status": "running", "runner_pid": 42}])
        self.assertEqual(state["monitor"], 1)
        self.assertTrue(result.monitor_started)
        self.assertEqual(context.stage, Stage.PREPARE)

    def test_monitor_failure_stops_before_flag_and_context_transition(self) -> None:
        ports, state = self.ports()
        ports = preparation.PreparationPorts(
            **{
                **ports.__dict__,
                "start_monitor": lambda: (_ for _ in ()).throw(
                    RuntimeError("monitor failed")
                ),
            }
        )
        context = self.context()

        with self.assertRaisesRegex(RuntimeError, "monitor failed"):
            preparation.prepare(context, self.inputs(), ports)

        self.assertEqual(state["written"], [{"status": "running", "runner_pid": 42}])
        self.assertEqual(context.stage, Stage.ATTEST)

    def test_shadow_initialization_failure_warns_and_continues(self) -> None:
        ports, state = self.ports(start_error=RuntimeError("db busy"))
        result = preparation.prepare(self.context(), self.inputs(), ports)
        self.assertIsNone(result.harness)
        self.assertIn("shadow initialization failed", state["warnings"][0])

    def test_enforce_initialization_failure_is_fatal(self) -> None:
        ports, _ = self.ports(mode="enforce", start_error=RuntimeError("db busy"))
        with self.assertRaisesRegex(RuntimeError, "db busy"):
            preparation.prepare(self.context(), self.inputs(), ports)

    def test_controlled_run_cannot_bypass_harness(self) -> None:
        ports, _ = self.ports(allowed=False)
        with self.assertRaisesRegex(RuntimeError, "cannot bypass"):
            preparation.prepare(self.context(), self.inputs(frozen=True), ports)

    def test_shadow_observation_failure_is_nonfatal(self) -> None:
        ports, state = self.ports()
        result = preparation.prepare(self.context(), self.inputs(), ports)
        self.assertIsNone(result.observe(lambda: (_ for _ in ()).throw(ValueError("bad"))))
        self.assertIn("shadow observation failed", state["warnings"][0])


if __name__ == "__main__":
    unittest.main()
