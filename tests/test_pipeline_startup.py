from __future__ import annotations

from pathlib import Path
import unittest

from n8n.onion_sentinel.pipeline import RuntimeContext, Stage
from n8n.onion_sentinel.pipeline import RuntimePathDefaults
from n8n.onion_sentinel.startup import (
    BootstrapPolicy,
    BootstrapPorts,
    PromptAttestationPolicy,
    PromptAttestationPorts,
    bootstrap,
    load_and_attest,
    reconcile_deferred_results,
)


class Args:
    generate_prompt = False
    prompt_dir = Path("prompts")
    max_prompt_bytes = 1024
    ai_settings_file = Path("config/settings.json")
    live_osquery_config = Path("config/live.json")
    alert_store_url = "http://alert-store"


class BootstrapArgs:
    out_dir = Path("output")
    reanalysis_attempt_id = "attempt-1"
    investigation_harness_db = Path("production.sqlite3")
    flush_index_only = False
    alert_store_url = "http://alert-store"


class PipelineStartupTests(unittest.TestCase):
    def policy(self) -> PromptAttestationPolicy:
        return PromptAttestationPolicy(
            package_type="soc-ai-investigation-prompt",
            allowed_roles=frozenset({"soc-analyst", "incident-responder"}),
            default_settings_file=Path("default/settings.json"),
            default_live_osquery_file=Path("default/live.json"),
            controlled_identity={"job_id": "job-1"},
        )

    def ports(self, package: dict, events: list[str]) -> PromptAttestationPorts:
        return PromptAttestationPorts(
            generate_prompt=lambda _args: Path("generated.json"),
            latest_prompt=lambda _directory: Path("latest.json"),
            load_json=lambda path, _limit: events.append(f"load:{path}") or package,
            role_prompt_file=lambda directory, role: directory / f"{role}.md",
            role_review_file=lambda directory, role: directory / f"{role}-review.md",
            validate_incident_evidence=lambda _value: events.append("incident-evidence"),
            effective_settings=lambda _args: {"route": "fake"},
            require_controlled_routes=lambda identity, _args, _settings, role: events.append(
                f"routes:{identity['job_id']}:{role}"
            ),
            prepare_live_osquery=lambda _package, role, path: f"live:{role}:{path}",
            prepare_enrichment=lambda _package, role, url: f"enrich:{role}:{url}",
            attach_evidence_contract=lambda _package: events.append("evidence-contract"),
        )

    def test_incident_prompt_is_loaded_attested_and_prepared(self) -> None:
        events: list[str] = []
        package = {
            "package_type": "soc-ai-investigation-prompt",
            "agent_role": "incident-responder",
            "system_prompt_file": "config/incident-responder.md",
            "second_opinion_system_prompt_file": "config/incident-responder-review.md",
            "incident_response_evidence": {"schema": "v2"},
        }
        context = RuntimeContext("startup", arguments=Args())
        result = load_and_attest(
            context, Args(), policy=self.policy(), ports=self.ports(package, events)
        )
        self.assertEqual(context.stage, Stage.ATTEST)
        self.assertEqual(result.agent_role, "incident-responder")
        self.assertEqual(result.settings, {"route": "fake"})
        self.assertIn("incident-evidence", events)
        self.assertIn("routes:job-1:incident-responder", events)
        self.assertIn("evidence-contract", events)

    def test_invalid_package_type_fails_after_load_transition(self) -> None:
        context = RuntimeContext("invalid", arguments=Args())
        with self.assertRaisesRegex(SystemExit, "unexpected prompt package type"):
            load_and_attest(
                context, Args(), policy=self.policy(),
                ports=self.ports({"package_type": "wrong"}, []),
            )
        self.assertEqual(context.stage, Stage.LOAD)

    def test_noncanonical_prompt_path_fails_closed(self) -> None:
        package = {
            "package_type": "soc-ai-investigation-prompt",
            "agent_role": "soc-analyst",
            "system_prompt_file": "/tmp/untrusted.md",
        }
        with self.assertRaisesRegex(SystemExit, "canonical soc-analyst"):
            load_and_attest(
                RuntimeContext("path", arguments=Args()), Args(),
                policy=self.policy(), ports=self.ports(package, []),
            )


class PipelineBootstrapTests(unittest.TestCase):
    def policy(self) -> BootstrapPolicy:
        return BootstrapPolicy(
            freeze_memory_env="FREEZE_MEMORY",
            path_defaults=RuntimePathDefaults(
                log_dir=Path("logs"),
                index_queue_dir=Path("queue"),
                index_quarantine_dir=Path("quarantine"),
                memory_receipt_dir=Path("receipts"),
                memory_pending_dir=Path("pending"),
                memory_committed_dir=Path("committed"),
            ),
        )

    def ports(
        self,
        events: list,
        *,
        controlled: bool = False,
        runtime_dir: Path | None = None,
        flush_result: tuple[int, int, int] = (0, 0, 0),
    ) -> BootstrapPorts:
        return BootstrapPorts(
            controlled_runtime=lambda _args: (controlled, runtime_dir),
            controlled_output_dir=lambda output, root: root / output,
            consume_token=lambda value: events.append(("token", value)),
            result_identity=lambda value, attempt: (
                {"attempt": attempt} if value else None
            ),
            boolean_setting=lambda value: str(value or "") == "1",
            flush_queue=lambda url, enabled: (
                events.append(("flush", url, enabled)) or flush_result
            ),
            emit=lambda value: events.append(("emit", value)),
        )

    def test_controlled_bootstrap_confines_paths_and_harness_database(self) -> None:
        args = BootstrapArgs()
        result = bootstrap(
            args,
            environment={"FREEZE_MEMORY": "1"},
            policy=self.policy(),
            ports=self.ports([], controlled=True, runtime_dir=Path("evaluation")),
        )
        self.assertTrue(result.controlled)
        self.assertTrue(result.memory_frozen)
        self.assertEqual(args.investigation_harness_db, Path("evaluation/investigation-harness.sqlite3"))
        self.assertTrue(result.runtime_paths.log_dir.is_relative_to(Path("evaluation")))

    def test_controlled_bootstrap_requires_exact_memory_freeze(self) -> None:
        with self.assertRaisesRegex(SystemExit, "FREEZE_MEMORY=1"):
            bootstrap(
                BootstrapArgs(), environment={}, policy=self.policy(),
                ports=self.ports([], controlled=True, runtime_dir=Path("evaluation")),
            )

    def test_flush_only_returns_bounded_exit_without_pipeline_start(self) -> None:
        args = BootstrapArgs()
        args.flush_index_only = True
        events: list = []
        result = bootstrap(
            args, environment={}, policy=self.policy(),
            ports=self.ports(events, flush_result=(3, 1, 2)),
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn(("flush", "http://alert-store", True), events)
        self.assertEqual(events[-1][1]["quarantined"], 2)

    def test_deferred_failure_blocks_a_new_model_call(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "could not be reconciled"):
            reconcile_deferred_results(
                controlled=False,
                memory_frozen=False,
                alert_store_url="http://alert-store",
                flush_queue=lambda _url, _enabled: (0, 1, 0),
            )

    def test_controlled_run_does_not_touch_global_deferred_spool(self) -> None:
        calls: list = []
        reconcile_deferred_results(
            controlled=True,
            memory_frozen=True,
            alert_store_url="http://alert-store",
            flush_queue=lambda url, enabled: calls.append((url, enabled)) or (0, 0, 0),
        )
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
