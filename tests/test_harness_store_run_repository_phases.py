#!/usr/bin/env python3
"""Characterize harness run and evidence repository phases."""
from __future__ import annotations

import ast
import copy
import importlib.util
import inspect
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_repository():
    path = BIN / "harness_store_run_repository.py"
    spec = importlib.util.spec_from_file_location(
        "harness_store_run_repository_phases_characterization",
        path,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REPOSITORY = load_repository()


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(
        (BIN / "harness_store_run_repository.py").read_text(encoding="utf-8")
    )
    if "." in name:
        class_name, function_name = name.split(".", 1)
        owner = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        )
        candidates = owner.body
    else:
        function_name = name
        candidates = tree.body
    target = next(
        node
        for node in candidates
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    )
    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.Assert)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class TracedRow(dict):
    def __init__(self, values: dict[str, Any]) -> None:
        super().__init__(values)
        self.accesses: list[str] = []

    def __getitem__(self, key: str) -> Any:
        self.accesses.append(key)
        return super().__getitem__(key)


class FakeCursor:
    def __init__(self, row: Any = None) -> None:
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, rows: list[Any] | None = None) -> None:
        self.rows = list(rows or [])
        self.events: list[Any] = []

    def execute(self, query: str, parameters: Any = None):
        normalized = " ".join(query.split())
        self.events.append(("execute", normalized, parameters))
        row = self.rows.pop(0) if "SELECT" in normalized else None
        return FakeCursor(row)

    def commit(self) -> None:
        self.events.append(("commit",))


class FakeConnect:
    def __init__(self, connection: FakeConnection, events: list[Any]) -> None:
        self.connection = connection
        self.events = events

    def __enter__(self):
        self.events.append(("connect.enter",))
        return self.connection

    def __exit__(self, exc_type, exc, traceback):
        self.events.append(
            ("connect.exit", None if exc_type is None else exc_type.__name__)
        )
        return False


class FakeRepository:
    def __init__(self) -> None:
        self.path = Path("/synthetic/harness.sqlite3")
        self.events: list[Any] = []

    def _require_mutable_run_tx(self, connection: Any, run_id: str) -> None:
        self.events.append(("require_mutable", connection, run_id))

    def _append_event_tx(self, connection: Any, **kwargs: Any) -> dict[str, Any]:
        self.events.append(("append_event", connection, copy.deepcopy(kwargs)))
        return {
            "event_id": "event-1",
            "created_at": "event-time",
            "run_id": kwargs["run_id"],
        }

    def _update_run_stage_tx(self, connection: Any, **kwargs: Any) -> None:
        self.events.append(("update_stage", connection, copy.deepcopy(kwargs)))

    def _audit_event(self, event: Any) -> None:
        self.events.append(("audit", copy.deepcopy(event)))

    def snapshot(self, run_id: str) -> dict[str, Any]:
        self.events.append(("snapshot", run_id))
        return {"run_id": run_id, "status": "running"}

    def register_evidence(self, run_id: str, **kwargs: Any) -> None:
        self.events.append(("register_evidence", run_id, copy.deepcopy(kwargs)))

    def append_event(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.events.append(("append_public", copy.deepcopy(args), copy.deepcopy(kwargs)))
        return {"event_id": "catalogued"}


class HarnessStoreRunRepositoryPhasesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = FakeRepository()
        self.connection = FakeConnection()
        self.connect_events: list[Any] = []
        self.connect_patch = mock.patch.object(
            REPOSITORY,
            "_connect",
            side_effect=lambda path: FakeConnect(
                self.connection,
                self.connect_events,
            ),
        )
        self.now_patch = mock.patch.object(
            REPOSITORY,
            "utc_now",
            return_value="fixed-now",
        )
        self.connect_patch.start()
        self.now_patch.start()
        self.addCleanup(self.connect_patch.stop)
        self.addCleanup(self.now_patch.stop)

    def test_changed_run_and_evidence_phases_stay_within_budget(self) -> None:
        functions = (
            "_validate_existing_run",
            "_run_insert_values",
            "_run_started_payload",
            "_append_run_started",
            "_validated_stage",
            "_require_transitionable_run",
            "_append_transition_event",
            "_update_transition_stage",
            "_evidence_identity",
            "_validate_evidence_replay",
            "_evidence_insert_values",
            "_contract_references",
            "_contract_trust_tier",
            "_register_contract_reference",
            "_append_evidence_catalogue",
            "HarnessStoreRunRepository.start_run",
            "HarnessStoreRunRepository.transition",
            "HarnessStoreRunRepository.register_evidence",
            "HarnessStoreRunRepository.register_evidence_contract",
        )
        for name in functions:
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def invoke(self, name: str, *args: Any, **kwargs: Any):
        method = getattr(REPOSITORY.HarnessStoreRunRepository, name)
        return method(self.repo, *args, **kwargs)

    def envelope(self) -> SimpleNamespace:
        return SimpleNamespace(
            run_id="run-1",
            trace_id="trace-1",
            correlation_id="correlation-1",
            case_id="case-1",
            alert_id="alert-1",
            role="soc-analyst",
            task_kind="analysis",
            assigned_route="route-primary",
            assigned_reviewer_route="route-reviewer",
            prompt_digest="1" * 64,
            evidence_manifest_digest="2" * 64,
            configuration_digest="3" * 64,
            parent_run_id="parent-1",
            job_digest="4" * 64,
            created_at="created-time",
            skill_selection_attestation={"schema": "skills-v1"},
        )

    def policy(self) -> SimpleNamespace:
        return SimpleNamespace(
            version=7,
            digest="5" * 64,
            mode="shadow",
        )

    def test_public_signatures_are_stable(self) -> None:
        expected = {
            "start_run": "(self, envelope: 'JobEnvelope', policy: 'HarnessPolicy') -> 'dict[str, Any]'",
            "transition": "(self, run_id: 'str', stage: 'str', *, route: 'str' = '', reason: 'str' = '', ordinal: 'int' = 0) -> 'dict[str, Any]'",
            "register_evidence": "(self, run_id: 'str', *, evidence_ref: 'str', source: 'str', source_class: 'str', trust_tier: 'str', corroborating: 'bool', status: 'str' = '', evidence_digest: 'str' = '', metadata: 'Mapping[str, Any] | None' = None) -> 'None'",
            "register_evidence_contract": "(self, run_id: 'str', contract: 'Mapping[str, Any] | None') -> 'int'",
        }
        for name, signature in expected.items():
            with self.subTest(name=name):
                self.assertEqual(
                    str(inspect.signature(getattr(REPOSITORY.HarnessStoreRunRepository, name))),
                    signature,
                )

    def test_existing_run_replay_returns_row_and_commits(self) -> None:
        row = TracedRow(
            {
                "run_id": "run-1",
                "job_digest": "4" * 64,
                "policy_digest": "5" * 64,
                "status": "running",
            }
        )
        self.connection.rows = [row]
        result = self.invoke("start_run", self.envelope(), self.policy())
        self.assertEqual(result, dict(row))
        self.assertEqual(row.accesses, ["job_digest", "policy_digest"])
        self.assertEqual(self.connection.events[-1], ("commit",))
        self.assertEqual(self.repo.events, [])

    def test_existing_run_collision_fails_without_commit(self) -> None:
        row = TracedRow(
            {"job_digest": "different", "policy_digest": "5" * 64}
        )
        self.connection.rows = [row]
        with self.assertRaisesRegex(
            REPOSITORY.HarnessIntegrityError,
            "^run_id collides with a different job or policy$",
        ):
            self.invoke("start_run", self.envelope(), self.policy())
        self.assertEqual(row.accesses, ["job_digest"])
        self.assertNotIn(("commit",), self.connection.events)

    def test_new_run_preserves_insert_event_commit_audit_and_snapshot_order(self) -> None:
        self.connection.rows = [None]
        envelope = self.envelope()
        policy = self.policy()
        self.assertEqual(
            self.invoke("start_run", envelope, policy),
            {"run_id": "run-1", "status": "running"},
        )
        insert = next(
            event
            for event in self.connection.events
            if event[0] == "execute" and event[1].startswith("INSERT INTO")
        )
        self.assertEqual(
            insert[2],
            (
                "run-1", "trace-1", "correlation-1", "case-1", "alert-1",
                "soc-analyst", "analysis", REPOSITORY.RunStatus.RUNNING.value,
                REPOSITORY.Stage.INTAKE.value, "route-primary", "route-reviewer",
                "1" * 64, "2" * 64, "3" * 64, 7, "5" * 64, "shadow",
                "parent-1", "4" * 64, "created-time", "created-time",
            ),
        )
        append = self.repo.events[0]
        self.assertEqual(append[0], "append_event")
        self.assertEqual(append[2]["event_type"], "run.started")
        self.assertEqual(append[2]["idempotency_key"], "run.started")
        self.assertEqual(append[2]["created_at"], "created-time")
        self.assertEqual(append[2]["payload"]["skill_selection_attestation"], {"schema": "skills-v1"})
        self.assertEqual(
            [event[0] for event in self.repo.events],
            ["append_event", "audit", "snapshot"],
        )
        self.assertEqual(self.connection.events[-1], ("commit",))
        self.assertEqual(self.connect_events[-1], ("connect.exit", None))

    def test_transition_rejects_unknown_stage_before_connection(self) -> None:
        with self.assertRaisesRegex(
            REPOSITORY.HarnessPolicyError,
            "^unknown harness stage: invalid$",
        ):
            self.invoke("transition", "run-1", "invalid")
        self.assertEqual(self.connect_events, [])

    def test_transition_unknown_and_terminal_runs_fail_before_event(self) -> None:
        self.connection.rows = [None]
        with self.assertRaisesRegex(REPOSITORY.HarnessIntegrityError, "^unknown harness run$"):
            self.invoke("transition", "run-1", REPOSITORY.Stage.CONTEXT_ASSEMBLY.value)
        self.assertEqual(self.repo.events, [])

        terminal = TracedRow({"status": "succeeded", "active_route": "old"})
        self.connection = FakeConnection([terminal])
        self.connect_events.clear()
        with self.assertRaisesRegex(
            REPOSITORY.HarnessIntegrityError,
            "^cannot transition a terminal harness run$",
        ):
            self.invoke("transition", "run-1", REPOSITORY.Stage.CONTEXT_ASSEMBLY.value)
        self.assertEqual(terminal.accesses, ["status"])

    def test_transition_preserves_route_fallback_payload_and_event_order(self) -> None:
        row = TracedRow({"status": "running", "active_route": "prior-route"})
        self.connection.rows = [row]
        event = self.invoke(
            "transition",
            "run-1",
            REPOSITORY.Stage.CONTEXT_ASSEMBLY.value,
            route="",
            reason="r" * 600,
            ordinal=3,
        )
        self.assertEqual(event["event_id"], "event-1")
        self.assertEqual(row.accesses, ["status", "active_route"])
        append = self.repo.events[0][2]
        self.assertEqual(append["payload"], {"active_route": "", "reason": "r" * 500})
        self.assertEqual(append["idempotency_key"], f"stage:{REPOSITORY.Stage.CONTEXT_ASSEMBLY.value}:3")
        self.assertEqual(self.repo.events[1][2]["active_route"], "prior-route")
        self.assertEqual([item[0] for item in self.repo.events], ["append_event", "update_stage", "audit"])

    def evidence_kwargs(self) -> dict[str, Any]:
        return {
            "evidence_ref": " evidence:1 ",
            "source": "elastic",
            "source_class": "security_onion_event",
            "trust_tier": REPOSITORY.TrustTier.TRUSTED_COLLECTOR.value,
            "corroborating": True,
            "status": "ok",
            "evidence_digest": "6" * 64,
            "metadata": {"returned": 1},
        }

    def test_evidence_validation_precedes_connection(self) -> None:
        kwargs = self.evidence_kwargs()
        kwargs["evidence_ref"] = "  "
        with self.assertRaisesRegex(REPOSITORY.HarnessIntegrityError, "^evidence reference is required$"):
            self.invoke("register_evidence", "run-1", **kwargs)
        kwargs["evidence_ref"] = "ref"
        kwargs["trust_tier"] = "invalid"
        with self.assertRaisesRegex(REPOSITORY.HarnessIntegrityError, "^unknown evidence trust tier$"):
            self.invoke("register_evidence", "run-1", **kwargs)
        self.assertEqual(self.connect_events, [])

    def test_existing_evidence_replay_commits_and_collision_fails(self) -> None:
        row = TracedRow({"evidence_digest": "6" * 64})
        self.connection.rows = [row]
        kwargs = self.evidence_kwargs()
        self.invoke("register_evidence", "run-1", **kwargs)
        self.assertEqual(row.accesses, ["evidence_digest"])
        self.assertEqual(self.connection.events[-1], ("commit",))

        collision = TracedRow({"evidence_digest": "different"})
        self.connection = FakeConnection([collision])
        self.connect_events.clear()
        with self.assertRaisesRegex(
            REPOSITORY.HarnessIntegrityError,
            "^immutable evidence reference collides with different content$",
        ):
            self.invoke("register_evidence", "run-1", **kwargs)
        self.assertNotIn(("commit",), self.connection.events)

    def test_new_evidence_preserves_normalization_insert_and_inputs(self) -> None:
        self.connection.rows = [None]
        kwargs = self.evidence_kwargs()
        original = copy.deepcopy(kwargs)
        self.invoke("register_evidence", "run-1", **kwargs)
        self.assertEqual(kwargs, original)
        insert = next(
            event for event in self.connection.events
            if event[0] == "execute" and event[1].startswith("INSERT INTO")
        )
        self.assertEqual(
            insert[2],
            (
                "run-1", "evidence:1", "elastic", "security_onion_event",
                REPOSITORY.TrustTier.TRUSTED_COLLECTOR.value, 1, "ok", "6" * 64,
                "fixed-now", '{"returned":1}',
            ),
        )
        self.assertEqual([item[0] for item in self.repo.events], ["require_mutable"])
        self.assertEqual(self.connection.events[-1], ("commit",))

    def test_contract_without_reference_list_is_noop(self) -> None:
        for contract in (None, {}, {"references": {}}, {"references": "bad"}):
            with self.subTest(contract=contract):
                self.repo.events.clear()
                self.assertEqual(self.invoke("register_evidence_contract", "run-1", contract), 0)
                self.assertEqual(self.repo.events, [])

    def test_contract_preserves_filter_bound_trust_mapping_and_catalogue_event(self) -> None:
        references: list[Any] = [
            None,
            {},
            {"ref": "memory-1", "source": "memory", "source_class": "agent_memory", "returned": 2},
            {"ref": "public-1", "source": "vt", "source_class": "public_enrichment", "corroborating": True},
            {"ref": "collector-1", "source": "elastic", "status": "ok", "evidence_digest": "7" * 64},
        ]
        references.extend(
            {"ref": f"bounded-{index}", "source": "extra"}
            for index in range(REPOSITORY.MAX_EVIDENCE_REFS)
        )
        contract = {"schema": "evidence-v1", "references": references}
        original = copy.deepcopy(contract)
        expected_digest = REPOSITORY.digest_json(contract)
        count = self.invoke("register_evidence_contract", "run-1", contract)
        expected_count = REPOSITORY.MAX_EVIDENCE_REFS - 2
        self.assertEqual(count, expected_count)
        self.assertEqual(contract, original)
        registrations = [event for event in self.repo.events if event[0] == "register_evidence"]
        self.assertEqual(len(registrations), expected_count)
        self.assertEqual(registrations[0][2]["trust_tier"], REPOSITORY.TrustTier.MEMORY_LEAD.value)
        self.assertEqual(registrations[1][2]["trust_tier"], REPOSITORY.TrustTier.EXTERNAL_INTELLIGENCE.value)
        self.assertEqual(registrations[2][2]["trust_tier"], REPOSITORY.TrustTier.TRUSTED_COLLECTOR.value)
        self.assertEqual(registrations[0][2]["metadata"], {"returned": 2})
        catalogue = self.repo.events[-1]
        self.assertEqual(catalogue[0], "append_public")
        self.assertEqual(
            catalogue[1],
            (
                "run-1", "evidence.catalogued",
                REPOSITORY.Stage.CONTEXT_ASSEMBLY.value,
                {
                    "contract_schema": "evidence-v1",
                    "references_registered": expected_count,
                    "manifest_digest": expected_digest,
                },
            ),
        )
        self.assertEqual(
            catalogue[2]["idempotency_key"],
            f"evidence.catalogued:{expected_digest[:24]}",
        )


if __name__ == "__main__":
    unittest.main()
