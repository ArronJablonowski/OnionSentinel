import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "export-adjudicated-analysis-replays.py"
SPEC = importlib.util.spec_from_file_location("adjudicated_replay_export", MODULE_PATH)
exporter = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(exporter)


class FakeRunner:
    @staticmethod
    def normalized_detection_outcome(value):
        return str(value)

    @staticmethod
    def legacy_verdict_factors(outcome, escalation_needed=False):
        mapping = {
            "false_positive_logic_rule": {
                "event_status": "observed",
                "detection_validity": "logic_error",
                "activity_disposition": "unknown",
                "handling": "monitor",
                "duplicate_of": None,
            }
        }
        return mapping[outcome]

    @staticmethod
    def derive_legacy_detection_outcome(factors):
        if factors.get("duplicate_of"):
            return "duplicate"
        if factors.get("detection_validity") == "logic_error":
            return "false_positive_logic_rule"
        return "inconclusive"


class AdjudicatedReplayExportTests(unittest.TestCase):
    def test_exports_latest_adjudication_with_confined_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analysis_dir = root / "analysis"
            prompt_dir = root / "prompts"
            analysis_dir.mkdir()
            prompt_dir.mkdir()
            prompt_path = prompt_dir / "prompt.json"
            prompt_path.write_text(
                json.dumps(
                    {
                        "package_type": "soc-ai-investigation-prompt",
                        "alert": {"alert_id": "fixture"},
                    }
                ),
                encoding="utf-8",
            )
            artifact_path = analysis_dir / "analysis.json"
            artifact_path.write_text(
                json.dumps({"prompt_package": str(prompt_path)}),
                encoding="utf-8",
            )
            database = root / "alerts.sqlite3"
            connection = sqlite3.connect(database)
            connection.executescript(
                """
                CREATE TABLE ai_analysis_runs (
                  analysis_id TEXT PRIMARY KEY,
                  response_json TEXT,
                  artifact_path TEXT,
                  alert_id TEXT,
                  agent_role TEXT
                );
                CREATE TABLE analyst_adjudications (
                  adjudication_id TEXT PRIMARY KEY,
                  analysis_id TEXT,
                  outcome_override TEXT,
                  confidence TEXT,
                  rationale TEXT,
                  evidence_gap TEXT,
                  next_action TEXT,
                  event_status TEXT,
                  detection_validity TEXT,
                  activity_disposition TEXT,
                  handling TEXT,
                  duplicate_of TEXT,
                  created_at TEXT
                );
                """
            )
            connection.execute(
                "INSERT INTO ai_analysis_runs VALUES (?, ?, ?, ?, ?)",
                (
                    "analysis-1",
                    json.dumps(
                        {
                            "detection_outcome": "true_positive_malicious",
                            "_second_opinion": {
                                "status": "completed",
                                "response": {
                                    "detection_outcome": "false_positive_logic_rule",
                                    "event_status": "observed",
                                    "detection_validity": "logic_error",
                                },
                            },
                        }
                    ),
                    str(artifact_path),
                    "fixture",
                    "soc-analyst",
                ),
            )
            connection.execute(
                "INSERT INTO analyst_adjudications VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "adj-old",
                    "analysis-1",
                    "inconclusive",
                    "low",
                    "old rationale",
                    "",
                    "",
                    None,
                    None,
                    None,
                    None,
                    None,
                    "2026-07-23T00:00:00Z",
                ),
            )
            connection.execute(
                "INSERT INTO analyst_adjudications VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "adj-new",
                    "analysis-1",
                    "false_positive_logic_rule",
                    "high",
                    "Packet evidence contradicts signature intent.",
                    "Endpoint telemetry is unavailable.",
                    "Collect endpoint process telemetry.",
                    "observed",
                    "logic_error",
                    "unknown",
                    "investigate",
                    None,
                    "2026-07-24T00:00:00Z",
                ),
            )
            connection.commit()
            connection.row_factory = sqlite3.Row
            item = exporter.latest_adjudications(connection, None, 10)[0]
            case = exporter.replay_case(
                FakeRunner,
                item,
                analysis_root=analysis_dir,
                prompt_root=prompt_dir,
            )

            self.assertEqual(case["case_id"], "adjudication-adj-new")
            self.assertEqual(
                case["expected"]["detection_outcome"],
                "false_positive_logic_rule",
            )
            self.assertEqual(case["expected"]["detection_validity"], "logic_error")
            self.assertEqual(case["expected"]["handling"], "investigate")
            self.assertEqual(
                case["label_provenance"]["rationale"],
                "Packet evidence contradicts signature intent.",
            )
            self.assertEqual(
                case["reviewer_response"]["detection_outcome"],
                "false_positive_logic_rule",
            )
            self.assertEqual(
                case["allowed_evidence_refs"],
                ["alert", "alert:fixture"],
            )
            self.assertNotIn("reviewer", case["label_provenance"])

            connection.execute(
                """
                UPDATE analyst_adjudications
                SET activity_disposition = 'malicious', handling = 'contain'
                WHERE adjudication_id = 'adj-new'
                """
            )
            connection.commit()
            contradictory = exporter.latest_adjudications(connection, None, 10)[0]
            with self.assertRaisesRegex(
                ValueError,
                "contradictory authoritative labels",
            ):
                exporter.replay_case(
                    FakeRunner,
                    contradictory,
                    analysis_root=analysis_dir,
                    prompt_root=prompt_dir,
                )
            connection.execute(
                """
                UPDATE analyst_adjudications
                SET activity_disposition = 'unknown', handling = 'investigate'
                WHERE adjudication_id = 'adj-new'
                """
            )
            connection.execute(
                "DELETE FROM analyst_adjudications WHERE adjudication_id = ?",
                ("adj-new",),
            )
            legacy_item = exporter.latest_adjudications(connection, None, 10)[0]
            legacy_case = exporter.replay_case(
                FakeRunner,
                legacy_item,
                analysis_root=analysis_dir,
                prompt_root=prompt_dir,
            )
            self.assertEqual(
                legacy_case["expected"],
                {"detection_outcome": "inconclusive"},
            )
            connection.close()

            out = root / "private" / "replays.json"
            exporter.atomic_private_json(
                out,
                {
                    "schema": exporter.REPLAY_SCHEMA,
                    "cases": [case],
                },
            )
            self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)

    def test_rejects_artifact_outside_allowed_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            allowed.mkdir()
            outside = root / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "outside"):
                exporter.confined_path(outside, allowed)


if __name__ == "__main__":
    unittest.main()
