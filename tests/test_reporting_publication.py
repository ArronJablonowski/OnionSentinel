#!/usr/bin/env python3
"""Failure-boundary contracts for analysis artifact publication."""
from __future__ import annotations

import json
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))
BIN_ROOT = N8N_ROOT / "bin"
if str(BIN_ROOT) not in sys.path:
    sys.path.insert(0, str(BIN_ROOT))

from onion_sentinel.analysis.reporting import publication
import local_ai_pipeline_adapters as PIPELINE_ADAPTERS


RUNNER_PATH = ROOT / "n8n" / "bin" / "run-local-ai-analysis.py"
SPEC = importlib.util.spec_from_file_location("publication_compat_runner", RUNNER_PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RUNNER)


class ReportingPublicationTests(unittest.TestCase):
    def plan(self, root: Path) -> publication.OutputPublicationPlan:
        return publication.build_plan(
            Path("/synthetic/prompt.json"),
            {
                "alert": {
                    "alert_id": "alert/1",
                    "rule_name": "Synthetic",
                    "triage_level": "high",
                },
                "agent_memory_file": "/memory/agent.md",
                "shared_memory_file": "/memory/shared.md",
            },
            {
                "_analysis_model_path": "codex-cli",
                "_analysis_input_mode": "model_execution",
                "summary": "bounded",
            },
            SimpleNamespace(
                out_dir=root,
                system_prompt_file=Path("/config/system.md"),
                second_opinion_prompt_file=Path("/config/review.md"),
            ),
            "analysis-1",
            generated_at="2026-08-06  12:34:56-06:00",
            safe_filename=lambda value: str(value).replace("/", "-"),
            filename_timestamp=lambda _value: "20260806-123456",
            render_markdown=lambda *_args: "# bounded report\n",
            saved_response_input_mode="saved_response",
            default_second_opinion_prompt_file=Path("/default/review.md"),
        )

    def test_plan_preserves_names_and_structured_payload_contract(self) -> None:
        plan = self.plan(Path("/synthetic/output"))
        self.assertEqual(
            plan.json_path.name,
            "20260806-123456-alert-1-local-ai-analysis.json",
        )
        self.assertEqual(
            plan.markdown_path.name,
            "20260806-123456-alert-1-local-ai-analysis.md",
        )
        self.assertEqual(plan.enriched["analysis_id"], "analysis-1")
        self.assertEqual(plan.enriched["analysis_type"], "codex-cli")
        self.assertEqual(plan.enriched["alert_id"], "alert/1")
        self.assertEqual(plan.enriched["response"]["summary"], "bounded")
        self.assertTrue(plan.json_text.endswith("\n"))

    def test_pair_is_private_atomic_and_has_no_temporary_debris(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "output"
            plan = self.plan(root)
            json_path, markdown_path, generated_at = publication.publish(plan)
            self.assertEqual(generated_at, plan.generated_at)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(json_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(markdown_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                json.loads(json_path.read_text(encoding="utf-8"))["analysis_id"],
                "analysis-1",
            )
            self.assertEqual(
                markdown_path.read_text(encoding="utf-8"),
                "# bounded report\n",
            )
            self.assertFalse(any(root.glob(".*.tmp")))

    def test_second_write_failure_removes_only_this_attempts_first_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "output"
            plan = self.plan(root)
            calls = 0

            def fail_second(path, content, *, root):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("synthetic markdown failure")
                publication.atomic_private_text(path, content, root=root)

            with self.assertRaisesRegex(OSError, "synthetic markdown failure"):
                publication.publish(plan, writer=fail_second)
            self.assertFalse(plan.json_path.exists())
            self.assertFalse(plan.markdown_path.exists())
            self.assertFalse(any(root.glob(".*.tmp")))

    def test_existing_destination_fails_closed_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "output"
            root.mkdir(mode=0o700)
            plan = self.plan(root)
            plan.json_path.write_text("existing\n", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "already exists"):
                publication.publish(plan)
            self.assertEqual(
                plan.json_path.read_text(encoding="utf-8"),
                "existing\n",
            )
            self.assertFalse(plan.markdown_path.exists())

    def test_symlink_output_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name)
            real = parent / "real"
            real.mkdir()
            linked = parent / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "must not be a symlink"):
                publication.publish(self.plan(linked))

    def test_pipeline_adapter_delegates_to_private_publication(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "output"
            args = SimpleNamespace(
                out_dir=root,
                system_prompt_file=Path("/config/system.md"),
                second_opinion_prompt_file=Path("/config/review.md"),
            )
            response = RUNNER.validate_response(
                {
                    "detection_outcome": "inconclusive",
                    "bluf": "Inconclusive: synthetic output test.",
                    "summary": "Synthetic summary.",
                    "likely_meaning": "Unknown.",
                    "severity_reasoning": "Bounded.",
                    "alert_frequency_assessment": "One alert.",
                    "public_enrichment_findings": [],
                    "pcap_analysis_findings": [],
                    "false_positive_possibilities": [],
                    "recommended_next_steps": ["Review."],
                    "evidence_used": ["Synthetic."],
                    "evidence_gaps": ["Live host evidence."],
                    "confidence": "low",
                    "escalation_needed": True,
                    "hosted_second_opinion_recommended": True,
                    "tuning_recommendation": "none",
                    "tuning_reason": "Insufficient evidence.",
                    "recommended_tuning_actions": [],
                }
            )
            bindings = vars(RUNNER).copy()
            bindings["project_now"] = lambda: "2026-08-06  12:34:56-06:00"
            json_path, markdown_path, generated_at = (
                PIPELINE_ADAPTERS.write_outputs(
                    bindings,
                    Path("/synthetic/prompt.json"),
                    {
                        "alert": {
                            "alert_id": "alert-1",
                            "rule_name": "Synthetic",
                            "triage_level": "low",
                        },
                        "analysis_policy": {},
                    },
                    response,
                    args,
                    "analysis-1",
                )
            )
            self.assertEqual(generated_at, "2026-08-06  12:34:56-06:00")
            self.assertEqual(json_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(markdown_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                json.loads(json_path.read_text(encoding="utf-8"))["analysis_id"],
                "analysis-1",
            )
            self.assertIn(
                "# Local AI Analysis - Synthetic",
                markdown_path.read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
