"""Characterize legacy AI-pipeline adapter construction and invocation."""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n/bin"
MODULE_PATH = BIN / "local_ai_pipeline_adapters.py"
SPEC = importlib.util.spec_from_file_location(
    "local_ai_pipeline_adapters_projection", MODULE_PATH
)
adapters = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(adapters)


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )

    class Complexity(ast.NodeVisitor):
        def __init__(self):
            self.value = 1

        def visit_FunctionDef(self, node):
            return

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_If(self, node):
            self.value += 1
            self.generic_visit(node)

        visit_For = visit_If
        visit_While = visit_If

        def visit_Try(self, node):
            self.value += len(node.handlers)
            self.generic_visit(node)

        def visit_BoolOp(self, node):
            self.value += max(0, len(node.values) - 1)
            self.generic_visit(node)

        def visit_IfExp(self, node):
            self.value += 1
            self.generic_visit(node)

        def visit_ListComp(self, node):
            self.value += sum(
                1 + len(generator.ifs) for generator in node.generators
            )
            self.generic_visit(node)

        visit_SetComp = visit_ListComp
        visit_GeneratorExp = visit_ListComp

    visitor = Complexity()
    for child in target.body:
        visitor.visit(child)
    return target.end_lineno - target.lineno + 1, visitor.value


class Capture:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeModule:
    PublicationPorts = Capture
    FinalizationInputs = Capture
    FinalizationPorts = Capture
    PreparationInputs = Capture
    PreparationPorts = Capture
    AnalysisReviewPorts = Capture

    def __init__(self):
        self.finalized = None
        self.prepared = None

    def finalize(self, inputs, ports):
        self.finalized = (inputs, ports)

    def prepare(self, context, inputs, ports):
        self.prepared = (context, inputs, ports)
        return "prepared-result"


class TrackingBindings(dict):
    def __init__(self, values):
        super().__init__(values)
        self.trace: list[str] = []

    def __getitem__(self, key):
        self.trace.append(key)
        return super().__getitem__(key)


class Recorder:
    def __init__(self):
        self.events: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def function(self, name: str, result: Any = None):
        def invoke(*args, **kwargs):
            self.events.append((name, args, kwargs))
            return result if result is not None else f"{name}-result"

        return invoke


class Harness:
    def __init__(self, recorder: Recorder):
        self.recorder = recorder

    def preflight_completion(self, **kwargs):
        return self.recorder.function("preflight")(**kwargs)

    def fail(self, reason):
        return self.recorder.function("harness.fail")(reason)

    def record_response(self, *args, **kwargs):
        return self.recorder.function("record_response")(*args, **kwargs)


class ResourceMonitor:
    def __init__(self, recorder: Recorder):
        self.recorder = recorder

    def start(self):
        return self.recorder.function("monitor.start")()

    def stop(self):
        return self.recorder.function("monitor.stop")()


class ActivePath:
    def __init__(self, recorder: Recorder):
        self.recorder = recorder

    def unlink(self, **kwargs):
        return self.recorder.function("active.unlink")(**kwargs)


def observed(recorder: Recorder):
    def observe(invoke):
        recorder.events.append(("observe", (), {}))
        return invoke()

    return observe


class LocalAiPipelineAdaptersProjectionTests(unittest.TestCase):
    def test_changed_phases_meet_architecture_contract(self):
        names = (
            "_queue_analysis_index",
            "_submit_analysis_index",
            "publication_ports",
            "_build_telemetry_record",
            "finalize_pipeline_telemetry",
            "_preparation_inputs",
            "prepare_runtime",
            "_analysis_evidence_paths",
            "_run_primary_analysis",
            "_run_configured_review",
            "analysis_review_ports",
        )
        for name in names:
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_publication_ports_preserve_lazy_bindings_and_controlled_routes(self):
        recorder = Recorder()
        bindings = TrackingBindings(
            {
                "analysis_index_payload": recorder.function("payload"),
                "queue_analysis_index": recorder.function("queue"),
                "post_controlled_analysis_index": recorder.function("submit.controlled"),
                "post_analysis_index": recorder.function("submit.normal"),
                "quarantine_analysis_index": recorder.function("quarantine"),
                "discard_pending_memory_writeback": recorder.function("discard"),
            }
        )
        module = FakeModule()
        args = SimpleNamespace(
            reanalysis_attempt_id="attempt-267",
            alert_store_url="http://127.0.0.1:9",
        )
        paths = SimpleNamespace(
            index_queue_dir="controlled-queue",
            index_quarantine_dir="quarantine-dir",
            memory_pending_dir="pending-dir",
        )
        harness = Harness(recorder)
        with mock.patch.object(
            adapters,
            "write_outputs",
            side_effect=recorder.function("write_outputs", ("j", "m", "g")),
        ):
            ports = adapters.publication_ports(
                bindings,
                module,
                args=args,
                run_id="run-267",
                prompt_path="prompt.json",
                prompt_package={"case": 267},
                response={"verdict": "true_positive"},
                started_at="start",
                runtime_paths=paths,
                harness=harness,
                observe=observed(recorder),
            )
            self.assertEqual(bindings.trace, [])
            self.assertEqual(
                list(ports.kwargs),
                [
                    "write_outputs",
                    "build_payload",
                    "preflight",
                    "queue",
                    "submit",
                    "quarantine",
                    "discard_memory",
                ],
            )
            self.assertEqual(ports.write_outputs(), ("j", "m", "g"))
            ports.build_payload("generated", "artifact")
            ports.preflight()
            ports.queue("payload", True)
            ports.queue("payload", False)
            ports.submit("payload", True)
            ports.submit("payload", False)
            ports.quarantine("path", "payload", ValueError("bad"))
            ports.discard_memory()

        self.assertEqual(
            bindings.trace,
            [
                "analysis_index_payload",
                "queue_analysis_index",
                "queue_analysis_index",
                "post_controlled_analysis_index",
                "post_analysis_index",
                "quarantine_analysis_index",
                "discard_pending_memory_writeback",
            ],
        )
        self.assertIn(
            (
                "payload",
                (
                    "run-267",
                    {"case": 267},
                    {"verdict": "true_positive"},
                    "attempt-267",
                    "start",
                    "generated",
                    "artifact",
                ),
                {},
            ),
            recorder.events,
        )
        self.assertIn(
            ("queue", ("payload",), {"queue_dir": "controlled-queue"}),
            recorder.events,
        )
        self.assertIn(("queue", ("payload",), {}), recorder.events)
        self.assertIn(
            (
                "quarantine",
                ("path", "payload", mock.ANY),
                {"quarantine_dir": "quarantine-dir"},
            ),
            recorder.events,
        )

    def test_telemetry_finalization_preserves_inputs_ports_and_lazy_record(self):
        recorder = Recorder()
        bindings = TrackingBindings(
            {
                "best_effort_warning": recorder.function("warn"),
                "build_llm_log_record": recorder.function("build_record", {"record": 1}),
                "project_now": recorder.function("now", "finished"),
                "effective_ai_settings": recorder.function("settings", {"fallback": True}),
                "append_jsonl": recorder.function("append"),
                "atomic_write_json": recorder.function("write_current"),
            }
        )
        module = FakeModule()
        harness = Harness(recorder)
        monitor = ResourceMonitor(recorder)
        active = ActivePath(recorder)
        paths = SimpleNamespace(log_file="log.jsonl", current_file="current.json")
        args = SimpleNamespace(name="args")

        with mock.patch.object(adapters.time, "monotonic", return_value=125.5):
            adapters.finalize_pipeline_telemetry(
                bindings,
                module,
                status="failure",
                error="synthetic",
                monitor_started=True,
                harness=harness,
                resource_monitor=monitor,
                started_at="started",
                started_monotonic=100.0,
                run_id="run-267",
                prompt_path=None,
                prompt_package={"case": 267},
                settings={},
                args=args,
                response=None,
                json_path=None,
                md_path=None,
                runtime_paths=paths,
                running_record={"status": "running"},
                active_record_path=active,
            )

        inputs, ports = module.finalized
        self.assertEqual(
            inputs.args,
            ("failure", "synthetic", True, True, harness),
        )
        self.assertEqual(
            list(ports.kwargs),
            [
                "fail_harness",
                "stop_monitor",
                "build_record",
                "append_record",
                "write_current",
                "cleanup_active",
                "warn",
            ],
        )
        self.assertEqual(bindings.trace, ["best_effort_warning"])
        ports.fail_harness("reason")
        ports.stop_monitor()
        with mock.patch.object(adapters.time, "monotonic", return_value=125.5):
            self.assertEqual(ports.build_record(), {"record": 1})
        ports.append_record({"record": 1})
        ports.write_current({"record": 1})
        ports.cleanup_active()
        ports.warn("warning")
        self.assertEqual(
            bindings.trace,
            [
                "best_effort_warning",
                "build_llm_log_record",
                "project_now",
                "effective_ai_settings",
                "append_jsonl",
                "atomic_write_json",
            ],
        )
        build = next(event for event in recorder.events if event[0] == "build_record")
        self.assertEqual(build[2]["runtime_seconds"], 25.5)
        self.assertEqual(build[2]["settings"], {"fallback": True})
        self.assertIn(
            ("active.unlink", (), {"missing_ok": True}),
            recorder.events,
        )

    def test_runtime_preparation_preserves_constructor_and_port_call_shapes(self):
        recorder = Recorder()
        bindings = TrackingBindings(
            {
                "INVESTIGATION_QUERY_CONTRACT": "query-contract",
                "MAX_INVESTIGATION_QUERY_ROUNDS": 2,
                "MAX_INVESTIGATION_QUERIES_TOTAL": 6,
                "MAX_INVESTIGATION_QUERIES_PER_ROUND": 3,
                "enabled_agent_model_routes": recorder.function("enabled_routes"),
                "canonical_model_route": recorder.function("canonical_route"),
                "load_investigation_harness_policy": recorder.function("load_policy"),
                "should_start_onion_sentinel_harness": recorder.function("activate", True),
                "start_harness_run": recorder.function("start_harness", "harness"),
                "build_llm_log_record": recorder.function("build_running", {"running": 1}),
                "atomic_write_json": recorder.function("write_running"),
                "publish_current_analysis_phase": recorder.function("publish_phase"),
            }
        )
        module = FakeModule()
        args = SimpleNamespace(
            reanalysis_attempt_id="attempt-267",
            investigation_harness_policy="policy.json",
            investigation_harness_db="harness.sqlite3",
            max_prompt_bytes=1000,
            max_response_bytes=2000,
        )
        monitor = ResourceMonitor(recorder)
        with (
            mock.patch.object(adapters.os, "getpid", return_value=267),
            mock.patch.dict(
                adapters.os.environ,
                {"ONION_SENTINEL_RELEASE_ID": "1" * 40},
            ),
        ):
            result = adapters.prepare_runtime(
                bindings,
                module,
                "context",
                args=args,
                run_id="run-267",
                prompt_path="prompt.json",
                prompt_package={"case": 267},
                settings={"route": "primary"},
                agent_role="soc-analyst",
                memory_frozen=True,
                started_at="started",
                active_record_path="active.json",
                resource_monitor=monitor,
            )
        self.assertEqual(result, "prepared-result")
        context, inputs, ports = module.prepared
        self.assertEqual(context, "context")
        self.assertEqual(
            inputs.args,
            (
                "run-267",
                "1" * 40,
                {"case": 267},
                {"route": "primary"},
                "soc-analyst",
                True,
                "attempt-267",
                "policy.json",
                "harness.sqlite3",
                "query-contract",
                2,
                6,
                3,
                1000,
                2000,
            ),
        )
        self.assertEqual(
            list(ports.kwargs),
            [
                "enabled_routes",
                "canonical_route",
                "load_harness_policy",
                "harness_activation",
                "start_harness",
                "build_running_record",
                "write_running_record",
                "publish_phase",
                "start_monitor",
                "process_id",
                "warn",
            ],
        )
        self.assertEqual(
            bindings.trace,
            [
                "INVESTIGATION_QUERY_CONTRACT",
                "MAX_INVESTIGATION_QUERY_ROUNDS",
                "MAX_INVESTIGATION_QUERIES_TOTAL",
                "MAX_INVESTIGATION_QUERIES_PER_ROUND",
                "enabled_agent_model_routes",
                "canonical_model_route",
                "load_investigation_harness_policy",
            ],
        )
        ports.harness_activation(True, "primary", "reviewer")
        request = SimpleNamespace(
            run_id="run-267",
            source_revision="1" * 40,
            prompt_package={"case": 267},
            role="soc-analyst",
            assigned_route="primary",
            configuration={"mode": "shadow"},
            reanalysis_attempt_id="attempt-267",
            policy_path="policy.json",
            database_path="harness.sqlite3",
        )
        ports.start_harness(request, "policy")
        ports.build_running_record()
        ports.write_running_record({"running": 1})
        ports.publish_phase({"running": 1}, "analysis", "primary", "reason")
        ports.start_monitor()
        self.assertEqual(ports.process_id(), 267)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            ports.warn("synthetic")
        self.assertEqual(stderr.getvalue(), "warning: synthetic\n")
        self.assertIn(
            (
                "activate",
                (),
                {
                    "policy_enabled": True,
                    "assigned_route": "primary",
                    "reviewer_route": "reviewer",
                },
            ),
            recorder.events,
        )

    def test_analysis_review_ports_preserve_paths_laziness_and_identities(self):
        recorder = Recorder()
        bindings = TrackingBindings(
            {
                "DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE": "default-evidence",
                "DEFAULT_INVESTIGATION_PIVOT_DIR": "default-pivots",
                "sanitize_saved_response_input": recorder.function("sanitize"),
                "load_json": recorder.function("load", {"saved": 1}),
                "analyze_with_config": recorder.function("analyze", {"primary": 1}),
                "validate_response": recorder.function("validate"),
                "second_opinion_trigger": recorder.function("trigger"),
                "apply_configured_second_opinion": recorder.function("review"),
                "apply_saved_response_review_gate": recorder.function("saved_gate"),
                "notify_analysis_phase": recorder.function("notify"),
                "precommit_controlled_evaluation_reviewer_gate": recorder.function("controlled_gate"),
                "require_controlled_evaluation_result_routes": recorder.function("require_routes"),
            }
        )
        module = FakeModule()
        args = SimpleNamespace(
            incident_evidence_config="evidence.json",
            investigation_pivot_dir="pivots",
            response_json="response.json",
            max_response_bytes=2048,
        )
        harness = Harness(recorder)
        ports = adapters.analysis_review_ports(
            bindings,
            module,
            args=args,
            prompt_package={"case": 267},
            settings={"route": "primary"},
            agent_role="incident-responder",
            live_osquery_config={"enabled": False},
            enrichment_config={"public": True},
            controlled_identity={"release": "synthetic"},
            harness_runtime=harness,
            observe_harness=observed(recorder),
            update_phase=recorder.function("phase"),
        )
        self.assertEqual(
            bindings.trace,
            [
                "DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE",
                "DEFAULT_INVESTIGATION_PIVOT_DIR",
            ],
        )
        self.assertEqual(
            list(ports.kwargs),
            [
                "load_saved_response",
                "run_primary_analysis",
                "validate_primary",
                "observe_primary",
                "review_trigger",
                "run_configured_review",
                "apply_saved_review_gate",
                "notify_saved_post_processing",
                "controlled_reviewer_gate",
                "require_result_routes",
                "observe_reviewer",
            ],
        )
        ports.load_saved_response()
        ports.run_primary_analysis()
        ports.validate_primary({"primary": 1})
        ports.observe_primary({"primary": 1})
        ports.review_trigger({"primary": 1})
        ports.run_configured_review({"primary": 1}, "forced")
        ports.apply_saved_review_gate({"primary": 1})
        ports.notify_saved_post_processing()
        ports.controlled_reviewer_gate({"primary": 1}, "trigger", True)
        ports.require_result_routes({"primary": 1})
        ports.observe_reviewer({"reviewer": 1})
        self.assertEqual(
            bindings.trace,
            [
                "DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE",
                "DEFAULT_INVESTIGATION_PIVOT_DIR",
                "sanitize_saved_response_input",
                "load_json",
                "analyze_with_config",
                "validate_response",
                "second_opinion_trigger",
                "apply_configured_second_opinion",
                "apply_saved_response_review_gate",
                "notify_analysis_phase",
                "precommit_controlled_evaluation_reviewer_gate",
                "require_controlled_evaluation_result_routes",
            ],
        )
        analyze = next(event for event in recorder.events if event[0] == "analyze")
        self.assertEqual(analyze[2]["security_onion_config_path"], "evidence.json")
        self.assertEqual(analyze[2]["investigation_pivot_dir"], "pivots")
        self.assertEqual(analyze[2]["live_osquery_config"], {"enabled": False})
        review = next(event for event in recorder.events if event[0] == "review")
        self.assertEqual(review[2]["force_review_reason"], "forced")
        responses = [event for event in recorder.events if event[0] == "record_response"]
        self.assertEqual(
            [event[2]["decision_id"] for event in responses],
            ["primary", "independent-review"],
        )


if __name__ == "__main__":
    unittest.main()
