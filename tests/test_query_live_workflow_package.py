"""Direct contracts for the bounded live endpoint follow-up workflow."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query import live_workflow  # noqa: E402


class ClientError(ValueError):
    pass


POLICY = live_workflow.Policy(
    schema="live-v1",
    supported_roles=frozenset({"soc-analyst", "incident-responder"}),
)


class Recorder:
    def __init__(self, *, fail_collection: bool = False) -> None:
        self.fail_collection = fail_collection
        self.collections: list[tuple] = []
        self.analyses: list[tuple] = []

    def descriptor(self, config: dict) -> dict:
        return {
            "enabled": config.get("enabled"),
            "target_aliases": config.get("allowed_target_aliases", []),
            "allowed_tables": ["processes"],
            "target_platform": "darwin",
            "osquery_version": "5.17.0",
            "table_schemas": {"processes": ["pid"]},
            "max_queries": 2,
            "max_rows_per_query": 25,
            "restrictions": ["read only"],
        }

    def collect(self, case_id: str, requests: list, config: dict) -> dict:
        self.collections.append((case_id, requests, config))
        if self.fail_collection:
            raise ClientError("collector unavailable")
        return {
            "schema": "live-v1",
            "case_id": case_id,
            "generated_at": "now",
            "complete": True,
            "read_only": True,
            "results": [{"status": "ok"}],
        }

    def analyze(self, route: str, prompt: dict, args: object, settings: dict) -> dict:
        self.analyses.append((route, prompt, args, settings))
        return {"summary": "final", "live_osquery_requests": [{"ignored": True}]}

    def dependencies(self) -> live_workflow.Dependencies:
        return live_workflow.Dependencies(
            capability_descriptor=self.descriptor,
            collect=self.collect,
            now=lambda: "failure-time",
            canonical_model_route=lambda value: f"route:{value}",
            analyze_model_route=self.analyze,
            collection_errors=(ClientError, OSError),
            client_error=ClientError,
        )


class LiveWorkflowPackageTests(unittest.TestCase):
    def test_capability_is_role_scoped_and_model_safe(self) -> None:
        recorder = Recorder()
        prompt = {
            "investigation_query_capability": {
                "enabled": False,
                "backends": {},
            },
        }
        config = {
            "enabled": True,
            "allowed_agent_roles": ["incident-responder"],
            "allowed_target_aliases": ["endpoint-a"],
            "transport_secret": "not projected",
        }
        scoped = live_workflow.prepare_capability(
            prompt,
            "soc-analyst",
            config,
            policy=POLICY,
            dependencies=recorder.dependencies(),
        )
        self.assertFalse(scoped["enabled"])
        self.assertEqual(scoped["allowed_target_aliases"], [])
        backend = prompt["investigation_query_capability"]["backends"]["osquery"]
        self.assertFalse(backend["enabled"])
        self.assertNotIn("transport_secret", repr(prompt))
        self.assertIsNone(live_workflow.prepare_capability(
            {}, "threat-hunter", config, policy=POLICY,
            dependencies=recorder.dependencies(),
        ))

    def test_case_identity_prefers_group_then_alert(self) -> None:
        grouped = live_workflow.case_id({
            "analyst_state": {"group_id": "group-1"},
            "alert": {"alert_id": "alert-1"},
        })
        alerted = live_workflow.case_id({"alert": {"alert_id": "alert-1"}})
        self.assertEqual(
            grouped,
            "ir-" + hashlib.sha256(b"group-1").hexdigest()[:32],
        )
        self.assertEqual(
            alerted,
            "ir-" + hashlib.sha256(b"alert-1").hexdigest()[:32],
        )

    def test_follow_up_collects_once_and_ignores_repeated_requests(self) -> None:
        recorder = Recorder()
        prompt = {"analyst_state": {"group_id": "group-1"}}
        primary = {"live_osquery_requests": [{"query": "SELECT 1;"}]}
        settings = {"agent_models": {"incident-responder": "codex:gpt"}}
        result = live_workflow.follow_up(
            prompt, primary, object(), settings, {"enabled": True},
            policy=POLICY, dependencies=recorder.dependencies(),
        )
        self.assertEqual(len(recorder.collections), 1)
        self.assertEqual(len(recorder.analyses), 1)
        self.assertEqual(recorder.analyses[0][0], "route:codex:gpt")
        self.assertTrue(prompt["live_osquery_follow_up"]["final_pass"])
        self.assertEqual(result["summary"], "final")
        self.assertNotIn("live_osquery_requests", result)
        self.assertEqual(result["_live_osquery_follow_up"], {
            "requested": 1,
            "collected": 1,
            "complete": True,
            "collection_error": "",
            "repeated_requests_ignored": 1,
        })

    def test_collection_failure_becomes_explicit_final_pass_evidence(self) -> None:
        recorder = Recorder(fail_collection=True)
        prompt = {"alert": {"alert_id": "alert-1"}}
        result = live_workflow.follow_up(
            prompt,
            {"live_osquery_requests": [{"query": "SELECT 1;"}]},
            object(),
            {"agent_models": {"incident-responder": "model"}},
            {"enabled": True},
            policy=POLICY,
            dependencies=recorder.dependencies(),
        )
        evidence = prompt["live_osquery_evidence"]
        self.assertFalse(evidence["complete"])
        self.assertTrue(evidence["read_only"])
        self.assertEqual(evidence["collection_error"], "collector unavailable")
        self.assertEqual(result["_live_osquery_follow_up"]["collected"], 0)
        self.assertEqual(
            result["_live_osquery_follow_up"]["collection_error"],
            "collector unavailable",
        )

    def test_no_requests_returns_same_response_without_side_effects(self) -> None:
        recorder = Recorder()
        prompt: dict = {}
        primary = {"summary": "unchanged"}
        result = live_workflow.follow_up(
            prompt, primary, object(), {}, None,
            policy=POLICY, dependencies=recorder.dependencies(),
        )
        self.assertIs(result, primary)
        self.assertEqual(prompt, {})
        self.assertEqual(recorder.collections, [])
        self.assertEqual(recorder.analyses, [])


if __name__ == "__main__":
    unittest.main()
