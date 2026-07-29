#!/usr/bin/env python3
"""Regression checks for Mac Studio PCAP evidence parsing and AI ingestion."""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PCAP_WORKER_PATH = REPO_ROOT / "n8n" / "bin" / "process-pcap-evidence.py"
PROMPT_BUILDER_PATH = REPO_ROOT / "n8n" / "bin" / "build-ai-investigation-prompt.py"
AI_RUNNER_PATH = REPO_ROOT / "n8n" / "bin" / "run-local-ai-analysis.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PcapAnalysisWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.worker = load_module("process_pcap_evidence", PCAP_WORKER_PATH)
        self.prompt_builder = load_module("build_ai_investigation_prompt", PROMPT_BUILDER_PATH)
        self.ai_runner = load_module("run_local_ai_analysis", AI_RUNNER_PATH)
        # Archive safety tests should be deterministic even when the host that
        # runs pytest is above the production new-work disk threshold.
        self.capacity_patch = mock.patch.object(
            self.worker,
            "require_runtime_capacity",
            return_value={"used_percent": 10.0, "projected_used_percent": 10.0},
        )
        self.capacity_patch.start()

    def tearDown(self) -> None:
        self.capacity_patch.stop()
        self.tmp.cleanup()

    def test_ai_runner_extracts_first_complete_json_object(self) -> None:
        result = self.ai_runner.extract_json_object(
            'Preface {"summary":"usable"}\n{"extra":"trailing object"}'
        )

        self.assertEqual(result, {"summary": "usable"})

    def test_ai_runner_rejects_malformed_json_without_guessing(self) -> None:
        with self.assertRaisesRegex(SystemExit, "valid JSON object"):
            self.ai_runner.extract_json_object('analysis: {"summary": invalid}')

    def test_worker_records_missing_local_artifact_without_failing(self) -> None:
        args = type(
            "Args",
            (),
            {
                "artifact_dir": self.root / "artifacts",
                "out_dir": self.root / "pcap-analysis",
            },
        )()
        request = {
            "request_id": "pcap-unit-test",
            "alert_id": "alert-1",
            "group_id": "group-1",
            "artifact_path": "/nsm/pcapout/onion-sentinel/pcap-unit-test.tar",
            "status": "fulfilled",
        }

        analysis = self.worker.process_one(request, args)

        self.assertEqual(analysis["artifact_state"], "artifact-not-copied-to-mac")
        self.assertFalse(analysis["zeek"]["available"])
        self.assertFalse(analysis["tshark"]["available"])
        self.assertTrue((self.root / "pcap-analysis" / "pcap-unit-test-pcap-analysis.json").exists())
        self.assertTrue((self.root / "pcap-analysis" / "pcap-unit-test-pcap-analysis.md").exists())

    def test_worker_ignores_pending_request_id(self) -> None:
        db_path = self.root / "alerts.sqlite3"
        conn = sqlite3.connect(db_path)
        conn.executescript(
            """
            CREATE TABLE pcap_requests (
              request_id TEXT,
              status TEXT,
              created_at TEXT,
              updated_at TEXT,
              artifact_path TEXT
            );
            INSERT INTO pcap_requests VALUES (
              'pending-unit-test', 'pending',
              '2026-07-07  10:00:00-06:00',
              '2026-07-07  10:00:00-06:00',
              NULL
            );
            """
        )
        conn.close()

        found = self.worker.pending_requests(
            db_path,
            "pending-unit-test",
            1,
            self.root / "pcap-analysis",
            False,
        )

        self.assertEqual(found, [])

    def test_worker_does_not_starve_older_unprocessed_fulfilled_request(self) -> None:
        db_path = self.root / "alerts.sqlite3"
        out_dir = self.root / "analysis"
        out_dir.mkdir()
        conn = sqlite3.connect(db_path)
        conn.executescript(
            """
            CREATE TABLE pcap_requests (
              request_id TEXT, status TEXT, created_at TEXT, updated_at TEXT,
              completed_at TEXT, artifact_path TEXT
            );
            INSERT INTO pcap_requests VALUES
              ('older-unprocessed', 'fulfilled', '2026-07-12  10:00:00-06:00', '2026-07-12  10:01:00-06:00', '2026-07-12  10:01:00-06:00', 'older.tar'),
              ('newer-processed', 'fulfilled', '2026-07-12  11:00:00-06:00', '2026-07-12  11:01:00-06:00', '2026-07-12  11:01:00-06:00', 'newer.tar');
            """
        )
        conn.close()
        self.worker.analysis_json_path(out_dir, "newer-processed").write_text("{}", encoding="utf-8")

        found = self.worker.pending_requests(db_path, None, 1, out_dir, False)

        self.assertEqual([item["request_id"] for item in found], ["older-unprocessed"])

    def test_worker_positive_path_uses_generated_runtime_pcap_fixture(self) -> None:
        pcap_path = self.root / "benign-dns.pcap"
        pcap_path.write_bytes(
            b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xff\xff\x00\x00\x01\x00\x00\x00"
        )
        args = type(
            "Args",
            (),
            {
                "artifact_dir": self.root / "artifacts",
                "out_dir": self.root / "pcap-analysis",
            },
        )()
        request = {
            "request_id": "benign-dns",
            "alert_id": "alert-1",
            "group_id": "group-1",
            "artifact_path": str(pcap_path),
            "status": "manual",
        }

        with (
            mock.patch.object(
                self.worker,
                "run_zeek",
                return_value={
                    "available": True,
                    "record_counts": {"conn": 1, "dns": 1},
                    "top_connections": [{"count": 1, "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.10"}],
                    "dns_queries": [{"count": 1, "query": "example.test"}],
                },
            ),
            mock.patch.object(
                self.worker,
                "run_tshark",
                return_value={
                    "available": True,
                    "samples": [{"pcap": str(pcap_path), "protocol_hierarchy": "frame\nip\nudp\ndns", "conversations": "UDP Conversations"}],
                },
            ),
        ):
            analysis = self.worker.process_one(request, args, pcap_path)

        self.assertEqual(analysis["artifact_state"], "direct")
        self.assertEqual(analysis["pcap_files"][0]["name"], "benign-dns.pcap")
        self.assertEqual(analysis["zeek"]["record_counts"]["dns"], 1)
        self.assertIn("UDP Conversations", (self.root / "pcap-analysis" / "benign-dns-pcap-analysis.md").read_text(encoding="utf-8"))

    def test_successful_broker_analysis_deletes_raw_request_directory(self) -> None:
        artifact_dir = self.root / "artifacts"
        request_dir = artifact_dir / "broker-cleanup-test"
        request_dir.mkdir(parents=True)
        (request_dir / "capture.pcap").write_bytes(b"synthetic-pcap")
        args = type("Args", (), {"artifact_dir": artifact_dir, "out_dir": self.root / "analysis", "retain_artifact": False})()
        request = {"request_id": "broker-cleanup-test", "artifact_path": "capture.pcap", "status": "fulfilled"}
        with (
            mock.patch.object(self.worker, "run_zeek", return_value={"available": True, "commands": [{"ok": True}]}),
            mock.patch.object(self.worker, "run_tshark", return_value={"available": True, "commands": [{"ok": True}], "samples": []}),
        ):
            analysis = self.worker.process_one(request, args)
        self.assertFalse(request_dir.exists())
        self.assertTrue(analysis["raw_artifact_cleanup"]["deleted"])
        persisted = json.loads((args.out_dir / "broker-cleanup-test-pcap-analysis.json").read_text(encoding="utf-8"))
        self.assertTrue(persisted["raw_artifact_cleanup"]["deleted"])

    def test_partial_broker_analysis_preserves_raw_artifact(self) -> None:
        artifact_dir = self.root / "artifacts"
        request_dir = artifact_dir / "broker-retry-test"
        request_dir.mkdir(parents=True)
        (request_dir / "capture.pcap").write_bytes(b"synthetic-pcap")
        args = type("Args", (), {"artifact_dir": artifact_dir, "out_dir": self.root / "analysis", "retain_artifact": False})()
        request = {"request_id": "broker-retry-test", "artifact_path": "capture.pcap", "status": "fulfilled"}
        with (
            mock.patch.object(self.worker, "run_zeek", return_value={"available": True, "commands": [{"ok": True}]}),
            mock.patch.object(self.worker, "run_tshark", return_value={"available": True, "commands": [{"ok": False}], "samples": []}),
        ):
            analysis = self.worker.process_one(request, args)
        self.assertTrue(request_dir.exists())
        self.assertFalse(analysis["raw_artifact_cleanup"]["deleted"])

    def test_safe_extract_rejects_archive_links(self) -> None:
        archive_path = self.root / "linked.tar"
        with tarfile.open(archive_path, "w") as archive:
            member = tarfile.TarInfo("capture.pcap")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            archive.addfile(member)

        with self.assertRaisesRegex(ValueError, "unsupported archive member type"):
            self.worker.safe_extract_tar(archive_path, self.root / "extract")

    def test_safe_extract_enforces_member_budget(self) -> None:
        archive_path = self.root / "many.tar"
        with tarfile.open(archive_path, "w") as archive:
            for index in range(3):
                archive.addfile(tarfile.TarInfo(f"empty-{index}.pcap"))

        with mock.patch.object(self.worker, "MAX_ARCHIVE_MEMBERS", 2):
            with self.assertRaisesRegex(ValueError, "too many members"):
                self.worker.safe_extract_tar(archive_path, self.root / "extract")

    def test_prompt_package_includes_compact_pcap_evidence(self) -> None:
        analysis_dir = self.root / "pcap-analysis"
        analysis_dir.mkdir()
        (analysis_dir / "pcap-unit-test-pcap-analysis.json").write_text(
            json.dumps(
                {
                    "generated_at": "2026-07-07  10:00:00-06:00",
                    "artifact_state": "copied-artifact",
                    "request": {"request_id": "pcap-unit-test", "alert_id": "alert-1", "group_id": "group-1"},
                    "pcap_files": [{"name": "capture.pcap", "size_bytes": 12, "sha256": "a" * 64, "path": "/tmp/capture.pcap"}],
                    "tool_paths": {"zeek": "/usr/local/bin/zeek", "tshark": "/usr/local/bin/tshark"},
                    "zeek": {
                        "available": True,
                        "record_counts": {"conn": 1, "dns": 1},
                        "top_connections": [{"count": 1, "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.10"}],
                        "dns_queries": [{"count": 1, "query": "example.test"}],
                    },
                    "tshark": {"available": True, "samples": [{"pcap": "/tmp/capture.pcap", "conversations": "TCP Conversations"}]},
                }
            ),
            encoding="utf-8",
        )
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE pcap_requests (
              request_id TEXT,
              alert_id TEXT,
              group_id TEXT,
              status TEXT,
              created_at TEXT,
              claimed_at TEXT,
              completed_at TEXT,
              artifact_path TEXT,
              artifact_sha256 TEXT,
              artifact_size_bytes INTEGER,
              error TEXT
            );
            CREATE TABLE alert_group_alias (
              legacy_group_id TEXT PRIMARY KEY,
              stable_group_id TEXT NOT NULL,
              stable_group_key TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            INSERT INTO pcap_requests VALUES (
              'pcap-unit-test', 'alert-1', 'group-1', 'fulfilled',
              '2026-07-07  09:59:00-06:00', NULL, '2026-07-07  10:00:00-06:00',
              '/nsm/pcapout/onion-sentinel/pcap-unit-test.tar', 'bbbb', 99, NULL
            );
            """
        )
        selected = {"alert_id": "alert-1", "stable_group_id": "stable-group-1"}

        context = self.prompt_builder.pcap_evidence_context(conn, selected, analysis_dir, 3)
        conn.close()

        self.assertEqual(len(context["pcap_requests"]), 1)
        self.assertEqual(len(context["parsed_evidence"]), 1)
        self.assertEqual(context["exact_alert_evidence_count"], 1)
        self.assertEqual(context["stable_group_related_evidence_count"], 0)
        evidence = context["parsed_evidence"][0]
        self.assertEqual(evidence["evidence_relationship"], "exact_alert")
        self.assertEqual(evidence["zeek"]["record_counts"]["conn"], 1)
        self.assertEqual(evidence["tshark"]["samples"][0]["conversations"], "TCP Conversations")

    def test_prompt_package_includes_stable_group_pcap_as_historical_context(self) -> None:
        analysis_dir = self.root / "pcap-analysis-related"
        analysis_dir.mkdir()
        (analysis_dir / "pcap-related-pcap-analysis.json").write_text(
            json.dumps(
                {
                    "generated_at": "2026-07-07  10:00:00-06:00",
                    "artifact_state": "copied-artifact",
                    "request": {
                        "request_id": "pcap-related",
                        "alert_id": "older-alert",
                        "group_id": "legacy-group",
                    },
                    "pcap_files": [
                        {
                            "name": "capture.pcap",
                            "size_bytes": 12,
                            "sha256": "a" * 64,
                        }
                    ],
                    "zeek": {"available": True, "record_counts": {"conn": 1}},
                    "tshark": {"available": True},
                }
            ),
            encoding="utf-8",
        )
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE pcap_requests (
              request_id TEXT,
              alert_id TEXT,
              group_id TEXT,
              status TEXT,
              created_at TEXT,
              claimed_at TEXT,
              completed_at TEXT,
              artifact_path TEXT,
              artifact_sha256 TEXT,
              artifact_size_bytes INTEGER,
              error TEXT
            );
            CREATE TABLE alert_group_alias (
              legacy_group_id TEXT PRIMARY KEY,
              stable_group_id TEXT NOT NULL,
              stable_group_key TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            INSERT INTO alert_group_alias VALUES (
              'legacy-group', 'stable-group-1', 'stable-key',
              '2026-07-07  10:00:00-06:00'
            );
            INSERT INTO pcap_requests VALUES (
              'pcap-related', 'older-alert', 'legacy-group', 'fulfilled',
              '2026-07-07  09:59:00-06:00', NULL,
              '2026-07-07  10:00:00-06:00',
              '/nsm/pcapout/pcap-related.tar', 'bbbb', 99, NULL
            );
            """
        )

        context = self.prompt_builder.pcap_evidence_context(
            conn,
            {"alert_id": "selected-alert", "stable_group_id": "stable-group-1"},
            analysis_dir,
            3,
        )
        conn.close()

        self.assertEqual(len(context["pcap_requests"]), 1)
        self.assertEqual(len(context["parsed_evidence"]), 1)
        self.assertEqual(context["exact_alert_evidence_count"], 0)
        self.assertEqual(context["stable_group_related_evidence_count"], 1)
        self.assertEqual(
            context["parsed_evidence"][0]["evidence_relationship"],
            "stable_group_related",
        )

    def test_prompt_package_includes_compact_public_enrichment(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            CREATE TABLE alerts (
              alert_id TEXT PRIMARY KEY,
              first_seen TEXT,
              last_seen TEXT,
              seen_count INTEGER,
              rule_name TEXT,
              source_ip TEXT,
              destination_ip TEXT,
              destination_port TEXT,
              triage_level TEXT,
              triage_score INTEGER,
              filter_status TEXT,
              suppression_key TEXT,
              enrichment_json TEXT
            )
            """
        )
        conn.execute(
            """
            INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "alert-1",
                "2026-07-08  10:00:00-06:00",
                "2026-07-08  10:00:00-06:00",
                1,
                "ET TEST public enrichment",
                "192.0.2.10",
                "198.51.100.10",
                "443",
                "medium",
                50,
                "accepted",
                "medium|ET TEST public enrichment|192.0.2.10|198.51.100.10|accepted",
                json.dumps(
                    {
                        "external_intel": {
                            "records": [
                                {
                                    "source": "otx",
                                    "indicator": "198.51.100.10",
                                    "indicator_type": "ip",
                                    "verdict": "suspicious",
                                    "confidence": 55,
                                    "tags": ["pulses:2"],
                                    "raw_response": {"omitted": "from prompt"},
                                }
                            ],
                            "skipped": [{"source": "virustotal", "reason": "rate_limited"}],
                            "errors": [],
                            "indicators": {"ips": ["198.51.100.10"]},
                        }
                    }
                ),
            ),
        )
        selected = conn.execute("SELECT * FROM alerts WHERE alert_id = 'alert-1'").fetchone()

        context = self.prompt_builder.public_enrichment_context(conn, selected, 5, include_tests=True)
        conn.close()

        self.assertEqual(context["verdict_counts"], {"suspicious": 1})
        self.assertEqual(context["records"][0]["source"], "otx")
        self.assertEqual(context["records"][0]["indicator"], "198.51.100.10")
        self.assertNotIn("raw_response", context["records"][0])
        self.assertEqual(context["skipped"][0]["source"], "virustotal")

    def test_ai_runner_renders_pcap_analysis_findings(self) -> None:
        response = {
            "detection_outcome": "true_positive_suspicious",
            "bluf": "True Positive - Suspicious: The synthetic DNS evidence is real but not confirmed malicious.",
            "summary": "Synthetic alert summary.",
            "likely_meaning": "Synthetic meaning.",
            "severity_reasoning": "Synthetic severity.",
            "alert_frequency_assessment": "Synthetic frequency.",
            "public_enrichment_findings": ["OTX marked 198.51.100.10 suspicious with medium confidence."],
            "pcap_analysis_findings": ["Zeek saw one DNS query for example.test."],
            "false_positive_possibilities": [],
            "recommended_next_steps": ["Pivot in Security Onion."],
            "evidence_used": ["Synthetic evidence."],
            "evidence_gaps": [],
            "confidence": "medium",
            "escalation_needed": False,
            "hosted_second_opinion_recommended": False,
            "tuning_recommendation": "none",
            "tuning_reason": "No tuning needed.",
            "recommended_tuning_actions": [],
        }
        normalized = self.ai_runner.validate_response(response)
        markdown = self.ai_runner.render_markdown(
            {"alert": {"alert_id": "alert-1", "rule_name": "Unit Test", "triage_level": "low"}, "analysis_policy": {}},
            normalized,
            "2026-07-07  10:00:00-06:00",
            self.root / "analysis.json",
        )

        self.assertIn("## BLUF", markdown)
        self.assertIn("**Detection outcome:** true_positive_suspicious", markdown)
        self.assertIn("True Positive - Suspicious:", markdown)
        self.assertIn("## PCAP Analysis Findings", markdown)
        self.assertIn("## Public Enrichment Findings", markdown)
        self.assertIn("OTX marked 198.51.100.10 suspicious", markdown)
        self.assertIn("Zeek saw one DNS query for example.test.", markdown)


if __name__ == "__main__":
    unittest.main()
