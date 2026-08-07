from __future__ import annotations

from pathlib import Path
import unittest

from n8n.onion_sentinel.pipeline import RuntimeContext, Stage
from n8n.onion_sentinel.startup import (
    PromptAttestationPolicy,
    PromptAttestationPorts,
    load_and_attest,
)


class Args:
    generate_prompt = False
    prompt_dir = Path("prompts")
    max_prompt_bytes = 1024
    ai_settings_file = Path("config/settings.json")
    live_osquery_config = Path("config/live.json")
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


if __name__ == "__main__":
    unittest.main()
