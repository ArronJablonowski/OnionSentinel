#!/usr/bin/env python3
"""Direct contracts for ordered prompt-package orchestration."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import prompt_package_orchestrator as orchestrator  # noqa: E402


def callback(name: str):
    return mock.Mock(name=name)


def sources(**changes) -> orchestrator.PromptPackageWorkflowSources:
    values = {
        field: callback(field)
        for field in orchestrator.PromptPackageWorkflowSources.__dataclass_fields__
    }
    values.update(
        {
            "detection_context_sources": mock.Mock(
                name="detection_context_sources",
                return_value="detection-sources",
            ),
            "load_system_prompt": mock.Mock(return_value="role prompt"),
            "agent_task": mock.Mock(return_value="role task"),
            "execution_lineage": mock.Mock(return_value={"group_id": "group-1"}),
            "project_now": mock.Mock(return_value="2026-08-08  12:00:00-06:00"),
            "model_policy": mock.Mock(return_value={"review": True}),
        }
    )
    values.update(changes)
    return orchestrator.PromptPackageWorkflowSources(**values)


def policy() -> orchestrator.PromptPackageWorkflowPolicy:
    return orchestrator.PromptPackageWorkflowPolicy(
        default_investigation_skills_path=Path("/defaults/skills.json"),
        default_detection_playbooks_path=Path("/defaults/playbooks.json"),
        default_asset_inventory_path=Path("/defaults/assets.json"),
        maximum_detection_group_rows=5000,
        maximum_incident_evidence_bytes=8192,
        query_packs=("alert_context", "network_flow"),
        query_v2=True,
    )


def args() -> SimpleNamespace:
    return SimpleNamespace(
        rollup_dir=Path("/runtime/rollups"),
        rollup_bytes=1024,
        related_limit=7,
        include_tests=False,
        pcap_analysis_dir=Path("/runtime/pcap"),
        pcap_analysis_limit=4,
        correlation_limit=5,
        correlation_min_score=0.75,
        agent_role="incident-responder",
        agent_memory_file=Path("/runtime/role-memory.md"),
        shared_memory_file=Path("/runtime/shared-memory.md"),
        memory_bytes=2048,
        blind_reanalysis=True,
        incident_evidence_file=Path("/runtime/evidence.json"),
        system_prompt_file=Path("/runtime/system.md"),
        second_opinion_prompt_file=Path("/runtime/review.md"),
        analysis_dir=Path("/runtime/analysis"),
    )


class PromptPackageOrchestratorTests(unittest.TestCase):
    def test_workflow_maps_policy_and_runtime_inputs_into_each_phase(self):
        dependencies = sources()
        runtime_args = args()
        selected = {"triage_level": "high", "alert_id": "alert-1"}
        snapshot = SimpleNamespace(
            analyst_state={"group_id": "group-1"},
            pcap_evidence={"pcap": 1},
            public_enrichment={"enrichment": 1},
            ac_hunter_evidence={"available": True, "evidence_ref": "ac-hunter:" + "a" * 64},
            alert={"alert_id": "alert-1"},
            grouped_alert_context={"count": 2},
            authorization_evidence={"authorized": False},
            correlated_alert_context={"candidates": []},
        )
        detection = SimpleNamespace(
            exact_validation_rows=[{"event": 1}],
            detection_validation={"matched": True},
            asset_context={"assets": []},
        )
        phases: list[str] = []

        with (
            mock.patch.object(
                orchestrator,
                "collect_core_evidence_snapshot",
                side_effect=lambda *_: (phases.append("core"), snapshot)[1],
            ) as collect_core,
            mock.patch.object(
                orchestrator,
                "prepare_detection_context",
                side_effect=lambda *_: (phases.append("detection"), detection)[1],
            ) as prepare_detection,
            mock.patch.object(
                orchestrator,
                "prepare_prompt_evidence_admission",
                side_effect=lambda *_: (phases.append("admission"), "admitted")[1],
            ) as admit,
            mock.patch.object(
                orchestrator,
                "build_prompt_contract",
                side_effect=lambda *_: (phases.append("contract"), {"schema": 1})[1],
            ) as contract,
            mock.patch.object(
                orchestrator,
                "collect_historical_evidence_snapshot",
                side_effect=lambda *_: (phases.append("history"), "history")[1],
            ) as collect_history,
            mock.patch.object(
                orchestrator,
                "assemble_prepared_prompt_package",
                side_effect=lambda *_: (phases.append("assembly"), {"ok": True})[1],
            ) as assemble,
        ):
            result = orchestrator.build_prepared_prompt_package(
                dependencies,
                policy(),
                "connection",
                selected,
                runtime_args,
            )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(
            phases,
            ["core", "detection", "admission", "contract", "history", "assembly"],
        )
        core_request = collect_core.call_args.args[1]
        self.assertEqual(core_request.connection, "connection")
        self.assertEqual(core_request.rollup_bytes, 1024)
        detection_request = prepare_detection.call_args.args[1]
        self.assertEqual(
            detection_request.investigation_skills_path,
            Path("/defaults/skills.json"),
        )
        self.assertEqual(detection_request.maximum_group_rows, 5000)
        self.assertEqual(
            detection_request.available_evidence_sources,
            ("ac_hunter_behavioral_context",),
        )
        admission_request = admit.call_args.args[1]
        self.assertEqual(admission_request.group_id, "group-1")
        self.assertIs(
            admission_request.ac_hunter_context,
            snapshot.ac_hunter_evidence,
        )
        self.assertEqual(admission_request.maximum_incident_evidence_bytes, 8192)
        contract_request = contract.call_args.args[0]
        self.assertEqual(contract_request.query_packs, ("alert_context", "network_flow"))
        self.assertTrue(contract_request.query_v2)
        history_request = collect_history.call_args.args[1]
        self.assertTrue(history_request.blind_reanalysis)
        view = assemble.call_args.args[0]
        self.assertEqual(view.lineage, {"group_id": "group-1"})
        self.assertEqual(view.generated_at, "2026-08-08  12:00:00-06:00")
        self.assertEqual(view.analysis_policy, {"review": True})

    def test_phase_failure_stops_all_later_work(self):
        with (
            mock.patch.object(
                orchestrator,
                "collect_core_evidence_snapshot",
                side_effect=RuntimeError("collector failed"),
            ),
            mock.patch.object(orchestrator, "prepare_detection_context") as detection,
            mock.patch.object(
                orchestrator,
                "prepare_prompt_evidence_admission",
            ) as admission,
            mock.patch.object(orchestrator, "build_prompt_contract") as contract,
            mock.patch.object(
                orchestrator,
                "collect_historical_evidence_snapshot",
            ) as history,
            mock.patch.object(
                orchestrator,
                "assemble_prepared_prompt_package",
            ) as assembly,
        ):
            with self.assertRaisesRegex(RuntimeError, "collector failed"):
                orchestrator.build_prepared_prompt_package(
                    sources(),
                    policy(),
                    "connection",
                    {"triage_level": "high"},
                    args(),
                )

        detection.assert_not_called()
        admission.assert_not_called()
        contract.assert_not_called()
        history.assert_not_called()
        assembly.assert_not_called()


if __name__ == "__main__":
    unittest.main()
