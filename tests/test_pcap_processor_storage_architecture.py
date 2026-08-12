"""Characterize PCAP request storage and artifact admission before extraction."""

from __future__ import annotations

import hashlib
import inspect
import io
import json
import sqlite3
import stat
import sys
import tarfile
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))
import pcap_processor_storage as STORAGE  # noqa: E402


class PcapProcessorStorageCharacterizationTests(unittest.TestCase):
    def test_legacy_namespace_and_signatures_are_frozen(self):
        self.assertEqual(
            sorted(name for name in vars(STORAGE) if not name.startswith("__")),
            [
                "Any", "BIN_DIR", "BoundedHttpError", "BoundedProcessError",
                "BoundedTopCounter", "Counter", "CoverageTracker", "DEFAULT_AI_SETTINGS",
                "DEFAULT_ARTIFACT_DIR", "DEFAULT_DB", "DEFAULT_DETECTION_PLAYBOOKS",
                "DEFAULT_MAXMIND_DB", "DEFAULT_MAXMIND_DBS", "DEFAULT_OUT_DIR",
                "DEFAULT_WAKE", "DeterministicReservoir", "HEAVY_HITTER_CAPACITY", "HOME",
                "ICMP_ABNORMAL_MIN_FRAME_BYTES", "ICMP_PAIR_STATE_LIMIT", "Iterable",
                "LOG_LIMIT", "MAXMIND_GEOIP_MAX_LOOKUPS", "MAX_ARCHIVE_MEMBERS",
                "MAX_CONTROL_RESPONSE_BYTES", "MAX_EXTRACTED_BYTES", "MAX_PCAP_FILES",
                "MAX_REMOTE_ARTIFACT_BYTES", "MAX_SELECTION_WINDOW_SECONDS",
                "MAX_TOOL_STDERR_BYTES", "MAX_TOOL_STDOUT_BYTES", "PARSER_TIMEOUT_SECONDS",
                "PCAP_SUFFIXES", "Path", "QUERY_INDEX_LIMIT", "REMOTE_FETCH_TIMEOUT_SECONDS",
                "RUNTIME_PYTHON_DIR", "SUMMARY_LIMIT", "TLS_VERSION_NAMES",
                "TSHARK_OCCURRENCE_SEPARATOR", "TSHARK_SAMPLE_LIMIT", "_icmp_scope_match",
                "_timestamp_epoch", "analysis_completed", "analysis_json_path", "annotations",
                "argparse", "candidate_artifact_paths", "compact_maxmind_record",
                "configured_maxmind_db_path", "configured_maxmind_db_paths",
                "consume_wake_marker", "csv", "delete_request_artifacts",
                "detection_marker_specs", "dt", "extract_rule_context",
                "fetch_remote_artifact", "hashlib", "icmp_evidence_scope", "ipaddress",
                "json", "load_detection_playbooks", "load_json_lines", "local_artifact_path",
                "materialize_pcap_files", "maxmind_geoip_summary", "os", "parse_args",
                "pending_requests", "project_now", "public_ip", "re", "read_bounded_json",
                "request_from_row", "require_runtime_capacity", "resolve_detection_playbook",
                "rows", "run_bounded_command", "run_bounded_command_to_file", "run_command",
                "run_isolated_command", "safe_extract_tar", "safe_filename",
                "sanitize_evidence_text", "scan_json_lines", "sha256_file", "shutil",
                "signal_follow_up", "signature_context_for_request", "sqlite3",
                "stream_isolated_lines", "sys", "table_columns", "tarfile", "tempfile",
                "tls_version_name", "tool_path", "top_values", "tshark_occurrences", "urllib",
            ],
        )
        expected = {
            "request_from_row": "(row: 'sqlite3.Row') -> 'dict[str, Any]'",
            "table_columns": "(conn: 'sqlite3.Connection', table: 'str') -> 'set[str]'",
            "pending_requests": "(db_path: 'Path', request_id: 'str | None', limit: 'int', out_dir: 'Path', overwrite: 'bool') -> 'list[dict[str, Any]]'",
            "signature_context_for_request": (
                "(db_path: 'Path', request: 'dict[str, Any]', playbook_path: 'Path' = "
                f"{STORAGE.DEFAULT_DETECTION_PLAYBOOKS!r}) -> "
                "'tuple[dict[str, Any], dict[str, Any] | None]'"
            ),
            "_timestamp_epoch": "(value: 'object') -> 'float | None'",
            "icmp_evidence_scope": "(request: 'dict[str, Any]') -> 'dict[str, Any]'",
            "_icmp_scope_match": "(source: 'str', destination: 'str', timestamp: 'float | None', scope: 'dict[str, Any]') -> 'tuple[bool, str]'",
            "analysis_json_path": "(out_dir: 'Path', request_id: 'str') -> 'Path'",
            "candidate_artifact_paths": "(request: 'dict[str, Any]', artifact_dir: 'Path') -> 'list[Path]'",
            "local_artifact_path": "(request: 'dict[str, Any]', artifact_dir: 'Path') -> 'Path'",
            "fetch_remote_artifact": "(request: 'dict[str, Any]', artifact_dir: 'Path', ssh_target: 'str', ssh_bin: 'str' = 'ssh') -> 'dict[str, Any]'",
            "safe_extract_tar": "(path: 'Path', destination: 'Path') -> 'None'",
            "materialize_pcap_files": "(request: 'dict[str, Any]', args: 'argparse.Namespace', work_dir: 'Path', direct_pcap: 'Path | None' = None) -> 'tuple[list[Path], str]'",
            "scan_json_lines": "(path: 'Path', limit: 'int' = 2000) -> 'dict[str, Any]'",
            "load_json_lines": "(path: 'Path', limit: 'int' = 2000) -> 'list[dict[str, Any]]'",
            "top_values": "(records: 'list[dict[str, Any]]', *fields: 'str') -> 'list[dict[str, Any]]'",
        }
        self.assertEqual(
            {name: str(inspect.signature(getattr(STORAGE, name))) for name in expected},
            expected,
        )

    def test_pending_selection_skips_completed_artifacts_before_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "alerts.db"
            output = root / "out"
            output.mkdir()
            connection = sqlite3.connect(database)
            connection.execute(
                """
                CREATE TABLE pcap_requests (
                  request_id TEXT, status TEXT, created_at TEXT, updated_at TEXT,
                  completed_at TEXT, analysis_status TEXT
                )
                """
            )
            connection.executemany(
                "INSERT INTO pcap_requests VALUES (?, 'fulfilled', ?, ?, ?, 'completed')",
                [
                    ("older", "2026-01-01", "2026-01-01", "2026-01-01"),
                    ("newest", "2026-01-02", "2026-01-02", "2026-01-02"),
                ],
            )
            connection.commit()
            connection.close()
            STORAGE.analysis_json_path(output, "newest").write_text("{}", encoding="utf-8")

            selected = STORAGE.pending_requests(database, None, 1, output, False)

        self.assertEqual([item["request_id"] for item in selected], ["older"])

    def test_exact_playbook_policy_and_fail_closed_boundaries_are_frozen(self):
        no_id, no_playbook = STORAGE.signature_context_for_request(Path("missing"), {})
        self.assertIsNone(no_playbook)
        self.assertEqual(no_id["playbook_policy"]["status"], "not_evaluated")
        missing, missing_playbook = STORAGE.signature_context_for_request(
            Path("missing"), {"alert_id": "a"}
        )
        self.assertIsNone(missing_playbook)
        self.assertEqual(missing["playbook_policy"]["status"], "alert_database_missing")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "alerts.db"
            registry_path = root / "playbooks.json"
            registry_path.write_text("{}", encoding="utf-8")
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE alerts (alert_id TEXT, alert_json TEXT, raw_event_json TEXT, rule_id TEXT)"
            )
            connection.execute(
                "INSERT INTO alerts VALUES ('a', '{}', '{}', '7')"
            )
            connection.commit()
            connection.close()
            with (
                mock.patch.object(STORAGE, "extract_rule_context", return_value={"sid": "7"}),
                mock.patch.object(
                    STORAGE,
                    "load_detection_playbooks",
                    return_value={"version": 3},
                ),
                mock.patch.object(
                    STORAGE,
                    "resolve_detection_playbook",
                    return_value={"id": "exact"},
                ),
            ):
                context, playbook = STORAGE.signature_context_for_request(
                    database, {"alert_id": "a"}, registry_path
                )

        self.assertEqual(playbook, {"id": "exact"})
        self.assertEqual(
            context["playbook_policy"],
            {
                "status": "exact_playbook_matched",
                "fail_closed": False,
                "registry_version": 3,
                "evidence_gap": "",
            },
        )

    def test_icmp_scope_window_and_exclusion_precedence_are_frozen(self):
        scope = STORAGE.icmp_evidence_scope(
            {
                "alert_id": "alert",
                "source_ip": "192.0.2.1",
                "destination_ip": "198.51.100.2",
                "first_seen": "2026-01-01T00:00:00Z",
                "last_seen": "2026-01-01T00:00:10Z",
                "max_window_seconds": 30,
            }
        )
        self.assertEqual(scope["window_end_epoch"] - scope["window_start_epoch"], 30)
        self.assertEqual(scope["window_basis"], "bounded-pcap-request-window")
        self.assertEqual(
            STORAGE._icmp_scope_match("203.0.113.1", "203.0.113.2", None, scope),
            (False, "endpoint"),
        )
        self.assertEqual(
            STORAGE._icmp_scope_match("192.0.2.1", "198.51.100.2", None, scope),
            (False, "missing_timestamp"),
        )
        self.assertEqual(
            STORAGE._icmp_scope_match(
                "198.51.100.2",
                "192.0.2.1",
                (scope["window_start_epoch"] + scope["window_end_epoch"]) / 2,
                scope,
            ),
            (True, ""),
        )

    def test_remote_path_metadata_and_success_contract_are_frozen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = {
                "request_id": "request",
                "artifact_path": "/nsm/pcapout/onion-sentinel/request/capture.pcap",
            }
            self.assertEqual(
                STORAGE.fetch_remote_artifact({}, root, ""),
                {"ok": False, "reason": "remote fetch not configured"},
            )
            traversal = {**base, "artifact_path": "/nsm/pcapout/onion-sentinel/../secret"}
            self.assertEqual(
                STORAGE.fetch_remote_artifact(traversal, root, "relay")["reason"],
                "remote artifact path contains traversal components",
            )
            payload = b"pcap-unit"
            request = {
                **base,
                "artifact_size_bytes": len(payload),
                "artifact_sha256": hashlib.sha256(payload).hexdigest(),
            }

            def transfer(command, destination, **kwargs):
                destination.write_bytes(payload)
                return SimpleNamespace(returncode=0, stderr="")

            with (
                mock.patch.object(STORAGE, "require_runtime_capacity"),
                mock.patch.object(
                    STORAGE, "run_bounded_command_to_file", side_effect=transfer
                ),
            ):
                result = STORAGE.fetch_remote_artifact(request, root, "relay", "ssh-unit")
            destination = Path(result["path"])
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertFalse(destination.with_suffix(".pcap.tmp").exists())

    def test_archive_type_path_and_materialization_contracts_are_frozen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "capture.tar"
            with tarfile.open(archive_path, "w") as archive:
                info = tarfile.TarInfo("nested/unit.pcap")
                payload = b"pcap"
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            destination = root / "extract"
            destination.mkdir()
            with mock.patch.object(STORAGE, "require_runtime_capacity"):
                STORAGE.safe_extract_tar(archive_path, destination)
            self.assertEqual((destination / "nested/unit.pcap").read_bytes(), b"pcap")

            artifact_dir = root / "artifacts"
            request_dir = artifact_dir / "request"
            request_dir.mkdir(parents=True)
            copied_archive = request_dir / "capture.tar"
            copied_archive.write_bytes(archive_path.read_bytes())
            args = Namespace(
                fetch_remote=False,
                artifact_dir=artifact_dir,
                ssh_target="",
                ssh_bin="ssh",
            )
            work = root / "work"
            work.mkdir()
            with mock.patch.object(STORAGE, "require_runtime_capacity"):
                pcaps, state = STORAGE.materialize_pcap_files(
                    {"request_id": "request", "artifact_path": "capture.tar"},
                    args,
                    work,
                )
            self.assertEqual(state, "extracted-artifact")
            self.assertEqual([path.name for path in pcaps], ["unit.pcap"])

    def test_bounded_jsonl_and_summary_order_are_frozen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            path.write_text(
                '\n'.join(['{"kind":"dns","value":"a"}', "bad", "[]", '{"kind":"dns","value":"a"}', '{"kind":"tls","value":"b"}']) + "\n",
                encoding="utf-8",
            )
            result = STORAGE.scan_json_lines(path, 2)
        self.assertEqual(
            result,
            {
                "records": [
                    {"kind": "dns", "value": "a"},
                    {"kind": "dns", "value": "a"},
                ],
                "valid_records": 3,
                "invalid_lines": 2,
                "truncated": True,
            },
        )
        self.assertEqual(
            STORAGE.top_values(
                [
                    {"kind": "dns", "value": "a"},
                    {"kind": "tls", "value": "b"},
                    {"kind": "dns", "value": "a"},
                ],
                "kind",
                "value",
            ),
            [
                {"count": 2, "kind": "dns", "value": "a"},
                {"count": 1, "kind": "tls", "value": "b"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
