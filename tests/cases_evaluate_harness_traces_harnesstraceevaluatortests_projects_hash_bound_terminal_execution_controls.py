from __future__ import annotations

from installer_source_fixture import read_installer_source

from evaluate_harness_traces_fixtures import (
    EVALUATOR_PATH,
    HARNESS_PATH,
    HARNESS_SPEC,
    INSTALLER_PATH,
    Path,
    ROOT,
    SPEC,
    canonical_json,
    collections,
    contextlib,
    create_terminal_harness_database,
    create_trace_database,
    digest_json,
    evaluator,
    harness,
    hashlib,
    importlib,
    io,
    json,
    os,
    replace_terminal_manifest,
    sqlite3,
    sys,
    tempfile,
    trace_evaluation_api,
    trace_evaluation_contract,
    trace_evaluation_events,
    trace_evaluation_integrity,
    trace_evaluation_model_completion,
    trace_evaluation_model_contract,
    trace_evaluation_model_routes,
    trace_evaluation_output,
    trace_evaluation_reviewer,
    trace_evaluation_run,
    trace_evaluation_skills,
    trace_evaluation_storage,
    trace_evaluation_summary,
    unittest,
    v2_skill_selection,
)

class HarnessTraceEvaluatorTestsProjectsHashBoundTerminalExecutionControlsCases:
    def test_projects_hash_bound_terminal_execution_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            policy = harness.HarnessPolicy.from_dict(
                {
                    "schema": harness.POLICY_SCHEMA,
                    "version": "terminal-execution-controls",
                    "enabled": True,
                    "mode": "shadow",
                    "budgets": dict(harness.DEFAULT_BUDGETS),
                    "role_capabilities": {
                        role: sorted(capabilities)
                        for role, capabilities
                        in harness.DEFAULT_ROLE_CAPABILITIES.items()
                    },
                    "approval_required": [],
                    "memory": {
                        "require_independent_agreement": True,
                        "shared_requires_human_approval": True,
                    },
                }
            )
            route = "codex-cli:gpt-5.6-sol:high"
            envelope = harness.JobEnvelope.from_prompt(
                run_id="terminal-control-run",
                prompt_package={
                    "group_id": "1" * 20,
                    "alert": {"alert_id": "alert-terminal-control"},
                    "evidence_reference_contract": {"references": []},
                },
                role=harness.AgentRole.SOC_ANALYST.value,
                assigned_route=route,
                configuration={
                    "reviewer_route": "codex-cli:gpt-5.6-sol:xhigh",
                    "evaluation_memory_frozen": True,
                },
                source_revision="1" * 40,
                policy_version="terminal-execution-controls",
            )
            run = harness.HarnessRun(
                harness.HarnessStore(database),
                envelope,
                policy,
            )
            run.preflight_model_call(
                call_id="primary",
                input_value={"case": "terminal-control"},
                requested_route=route,
                purpose="primary analysis",
            )
            run.model_call(
                call_id="primary",
                purpose="primary analysis",
                requested_route=route,
                response={
                    "_analysis_model": "gpt-5.6-sol",
                    "_analysis_model_path": "frontier-codex-cli",
                    "_analysis_provider": "codex-cli",
                    "_analysis_model_route": route,
                },
                input_value={"case": "terminal-control"},
                duration_seconds=0.1,
            )
            run.complete(
                {
                    "analysis_id": run.run_id,
                    "submitted_response_sha256": "a" * 64,
                    "stored_response_sha256": "b" * 64,
                    "evaluation_memory_frozen": True,
                },
                check_budget=False,
            )

            report = evaluator.evaluate_database(database, run.run_id)
            result = report["runs"][0]
            self.assertEqual(result["assigned_route"], route)
            self.assertEqual(
                result["assigned_reviewer_route"],
                "codex-cli:gpt-5.6-sol:xhigh",
            )
            self.assertEqual(
                result["terminal_execution_summary"],
                {
                    "analysis_id": run.run_id,
                    "submitted_response_sha256": "a" * 64,
                    "stored_response_sha256": "b" * 64,
                    "evaluation_memory_frozen": True,
                },
            )
            self.assertEqual(
                result["models"]["successful_primary_call_count"],
                1,
            )
            self.assertTrue(result["integrity"]["valid"])


    def test_installer_preserves_policy_and_installs_harness_assets(self):
        source = read_installer_source(INSTALLER_PATH)
        policy = '$STACK_DIR/config/investigation_harness_policy.json'
        policy_guard = f'if [[ ! -f "{policy}" ]]'
        policy_copy = (
            'cp "$REPO_DIR/n8n/config/investigation_harness_policy.json" \\\n'
            f'    "{policy}"'
        )
        self.assertIn(policy_guard, source)
        self.assertIn(policy_copy, source)
        self.assertLess(source.index(policy_guard), source.index(policy_copy))
        self.assertIn(f'chmod 0600 "{policy}"', source)
        self.assertIn(
            "policy must be a regular file",
            source,
        )
        self.assertIn(
            "policy schema must be a regular file",
            source,
        )
        self.assertIn(
            'cp "$REPO_DIR/n8n/config/investigation_harness_policy.schema.json"',
            source,
        )
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/onion_sentinel_harness.py"',
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/evaluate-harness-traces.py" '
                '"$STACK_DIR/bin/evaluate-harness-traces.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_skills.py" '
                '"$STACK_DIR/bin/trace_evaluation_skills.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_storage.py" '
                '"$STACK_DIR/bin/trace_evaluation_storage.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_integrity.py" '
                '"$STACK_DIR/bin/trace_evaluation_integrity.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_reviewer.py" '
                '"$STACK_DIR/bin/trace_evaluation_reviewer.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_model_contract.py" '
                '"$STACK_DIR/bin/trace_evaluation_model_contract.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_model_completion.py" '
                '"$STACK_DIR/bin/trace_evaluation_model_completion.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_model_routes.py" '
                '"$STACK_DIR/bin/trace_evaluation_model_routes.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_run.py" '
                '"$STACK_DIR/bin/trace_evaluation_run.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_output.py" '
                '"$STACK_DIR/bin/trace_evaluation_output.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_summary.py" '
                '"$STACK_DIR/bin/trace_evaluation_summary.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_events.py" '
                '"$STACK_DIR/bin/trace_evaluation_events.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_contract.py" '
                '"$STACK_DIR/bin/trace_evaluation_contract.py"'
            ),
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/trace_evaluation_api.py" '
                '"$STACK_DIR/bin/trace_evaluation_api.py"'
            ),
            source,
        )
