import importlib.util
import io
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError


REPO_ROOT = Path(__file__).resolve().parents[1]
PROMPT_BUILDER = REPO_ROOT / "n8n" / "bin" / "build-ai-investigation-prompt.py"
AI_RUNNER = REPO_ROOT / "n8n" / "bin" / "run-local-ai-analysis.py"
ALERT_STORE = REPO_ROOT / "n8n" / "alert_store" / "alert_store.js"
CORRELATION_MODULE = REPO_ROOT / "n8n" / "alert_store" / "lib" / "correlation_context.js"
ANALYSIS_RESULT_ROUTES = REPO_ROOT / "n8n" / "alert_store" / "routes" / "analysis_result_routes.js"
ANALYSIS_RESULT_SERVICE = REPO_ROOT / "n8n" / "alert_store" / "services" / "analysis_result_service.js"
SCHEMA_FOUNDATION = REPO_ROOT / "n8n" / "alert_store" / "services" / "alert_store_schema_foundation.js"
INCIDENT_ANALYSIS_SCHEMA = REPO_ROOT / "n8n" / "alert_store" / "services" / "incident_analysis_schema.js"
AI_REVIEW_SCHEMA = REPO_ROOT / "n8n" / "alert_store" / "services" / "ai_review_schema.js"
AUTHORIZED_CAMPAIGN_PERSISTENCE = REPO_ROOT / "n8n" / "alert_store" / "services" / "authorized_campaign_persistence.js"
CORRELATION_BACKFILL = REPO_ROOT / "n8n" / "bin" / "backfill-ai-correlation-context.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AiCorrelationContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = load_module("onion_sentinel_prompt_builder", PROMPT_BUILDER)
        cls.runner = load_module("onion_sentinel_ai_runner", AI_RUNNER)
        cls.backfill = load_module("onion_sentinel_correlation_backfill", CORRELATION_BACKFILL)

    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE alerts (
              alert_id TEXT PRIMARY KEY, stable_group_id TEXT, first_seen TEXT,
              last_seen TEXT, timestamp TEXT, rule_name TEXT, source_ip TEXT,
              destination_ip TEXT, destination_port INTEGER,
              transport_protocol TEXT, triage_level TEXT, triage_score INTEGER,
              filter_status TEXT, seen_count INTEGER
            );
            CREATE TABLE alert_observables (
              group_id TEXT, observable_type TEXT, observable_value TEXT,
              role TEXT, source TEXT
            );
            CREATE TABLE ai_analysis_runs (
              analysis_id TEXT, group_id TEXT, generated_at TEXT, model TEXT,
              detection_outcome TEXT, bluf TEXT, summary TEXT, confidence TEXT
            );
            CREATE TABLE alert_correlations (
              source_group_id TEXT, related_group_id TEXT, correlation_score REAL,
              reasons_json TEXT, shared_observables_json TEXT, model_status TEXT,
              model_confidence TEXT, model_hypothesis TEXT, updated_at TEXT
            );
            """
        )
        alerts = [
            ("selected", "a" * 20, "2026-07-15  08:00:00-06:00", "2026-07-15  10:00:00-06:00", "Rule A", "10.0.0.10", "198.51.100.20", 443, "tcp", "high", 75, "accepted", 1),
            ("related", "b" * 20, "2026-07-15  08:30:00-06:00", "2026-07-15  09:30:00-06:00", "Rule B", "10.0.0.10", "203.0.113.30", 443, "tcp", "medium", 55, "accepted", 2),
            ("weak", "c" * 20, "2026-07-01  08:00:00-06:00", "2026-07-01  09:00:00-06:00", "Rule C", "10.0.0.30", "203.0.113.40", 443, "tcp", "low", 25, "accepted", 1),
        ]
        self.conn.executemany(
            "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(a, g, first, last, last, rule, src, dst, port, proto, level, score, status, seen) for a, g, first, last, rule, src, dst, port, proto, level, score, status, seen in alerts],
        )
        observables = [
            ("a" * 20, "ip", "10.0.0.10", "source", "alert"),
            ("a" * 20, "domain", "example.test", "indicator", "alert-indicator"),
            ("a" * 20, "port", "443", "destination", "alert"),
            ("a" * 20, "protocol", "tcp", "network", "alert"),
            ("b" * 20, "ip", "10.0.0.10", "source", "alert"),
            ("b" * 20, "domain", "example.test", "indicator", "alert-indicator"),
            ("b" * 20, "port", "443", "destination", "alert"),
            ("b" * 20, "protocol", "tcp", "network", "alert"),
            ("c" * 20, "port", "443", "destination", "alert"),
            ("c" * 20, "protocol", "tcp", "network", "alert"),
        ]
        self.conn.executemany("INSERT INTO alert_observables VALUES (?, ?, ?, ?, ?)", observables)
        self.conn.execute(
            "INSERT INTO ai_analysis_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("prior-run", "b" * 20, "2026-07-15  09:45:00-06:00", "devstral:latest", "inconclusive", "Prior hypothesis", "Earlier assessment", "medium"),
        )
        self.conn.commit()

    def tearDown(self) -> None:
        self.conn.close()

    def test_correlation_context_prefers_strong_shared_evidence(self) -> None:
        selected = self.conn.execute("SELECT * FROM alerts WHERE alert_id = 'selected'").fetchone()
        context = self.builder.correlated_alert_context(self.conn, selected, limit=8, min_score=15)

        self.assertEqual(context["selected_group_id"], "a" * 20)
        self.assertEqual([item["group_id"] for item in context["candidates"]], ["b" * 20])
        candidate = context["candidates"][0]
        self.assertGreaterEqual(candidate["score"], 90)
        self.assertEqual(candidate["prior_analysis"]["bluf"], "Prior hypothesis")
        self.assertTrue(any("shared domain" in reason for reason in candidate["correlation_reasons"]))

    def test_correlation_context_promotes_same_community_and_reversed_flow(self) -> None:
        self.conn.executescript(
            """
            ALTER TABLE alerts ADD COLUMN source_port INTEGER;
            ALTER TABLE alerts ADD COLUMN network_protocol TEXT;
            ALTER TABLE alerts ADD COLUMN alert_json TEXT;
            ALTER TABLE alerts ADD COLUMN raw_event_json TEXT;
            """
        )
        community_id = "1:gVOca2cr2eIKwoIKZ8QnLwW2gqU="
        self.conn.execute(
            """
            UPDATE alerts
            SET source_port = 51000,
                network_protocol = 'tls',
                alert_json = ?
            WHERE alert_id = 'selected'
            """,
            [json.dumps({"network": {"community_id": community_id}})],
        )
        self.conn.execute(
            """
            UPDATE alerts
            SET source_ip = '198.51.100.20',
                destination_ip = '10.0.0.10',
                source_port = 443,
                destination_port = 51000,
                network_protocol = 'tls',
                last_seen = '2026-07-15  09:59:59-06:00',
                alert_json = ?
            WHERE alert_id = 'related'
            """,
            [json.dumps({"network": {"community_id": community_id}})],
        )
        self.conn.commit()

        selected = self.conn.execute(
            "SELECT * FROM alerts WHERE alert_id = 'selected'"
        ).fetchone()
        context = self.builder.correlated_alert_context(
            self.conn,
            selected,
            limit=8,
            min_score=15,
        )

        relationships = context["candidates"][0][
            "deterministic_relationships"
        ]
        self.assertEqual(
            {item["kind"] for item in relationships},
            {"same_community_id", "reversed_five_tuple"},
        )
        self.assertGreaterEqual(context["candidates"][0]["score"], 85)
        self.assertNotIn("alert_json", context["candidates"][0]["alert"])
        self.assertNotIn("raw_event_json", context["candidates"][0]["alert"])
        self.assertTrue(
            all(
                "correlation lead" in item["interpretation_limit"]
                for item in relationships
            )
        )

    def test_correlation_context_promotes_bounded_dns_to_tls_link(self) -> None:
        self.conn.executescript(
            """
            ALTER TABLE alerts ADD COLUMN source_port INTEGER;
            ALTER TABLE alerts ADD COLUMN network_protocol TEXT;
            ALTER TABLE alerts ADD COLUMN alert_json TEXT;
            ALTER TABLE alerts ADD COLUMN raw_event_json TEXT;
            """
        )
        self.conn.execute(
            """
            UPDATE alerts
            SET last_seen = '2026-07-15  09:29:58-06:00',
                network_protocol = 'dns',
                alert_json = ?
            WHERE alert_id = 'selected'
            """,
            [json.dumps({
                "dns": {
                    "answers": [{"data": "203.0.113.30"}],
                    "question": {"name": "example.test"},
                }
            })],
        )
        self.conn.execute(
            """
            UPDATE alerts
            SET source_ip = '10.0.0.10',
                destination_ip = '203.0.113.30',
                destination_port = 443,
                source_port = 52000,
                network_protocol = 'tls',
                last_seen = '2026-07-15  09:30:00-06:00',
                alert_json = ?
            WHERE alert_id = 'related'
            """,
            [json.dumps({"tls": {"server": {"name": "example.test"}}})],
        )
        self.conn.commit()

        selected = self.conn.execute(
            "SELECT * FROM alerts WHERE alert_id = 'selected'"
        ).fetchone()
        context = self.builder.correlated_alert_context(
            self.conn,
            selected,
            limit=8,
            min_score=15,
        )

        relationship = next(
            item
            for item in context["candidates"][0][
                "deterministic_relationships"
            ]
            if item["kind"] == "dns_answer_to_destination"
        )
        self.assertEqual(relationship["facts"]["resolved_ip"], "203.0.113.30")
        self.assertEqual(relationship["facts"]["elapsed_seconds"], 2.0)
        self.assertEqual(
            relationship["direction"],
            "selected_dns_to_related_network",
        )

    def test_correlation_rejects_placeholder_and_stale_flow_joins(self) -> None:
        self.conn.executescript(
            """
            ALTER TABLE alerts ADD COLUMN source_port INTEGER;
            ALTER TABLE alerts ADD COLUMN network_protocol TEXT;
            ALTER TABLE alerts ADD COLUMN alert_json TEXT;
            ALTER TABLE alerts ADD COLUMN raw_event_json TEXT;
            """
        )
        self.conn.execute(
            """
            UPDATE alerts
            SET source_port = 51000,
                network_protocol = 'tls',
                last_seen = '2026-01-01  10:00:00-06:00',
                alert_json = ?
            WHERE alert_id = 'selected'
            """,
            [json.dumps({"network": {"community_id": "-"}})],
        )
        self.conn.execute(
            """
            UPDATE alerts
            SET source_ip = '198.51.100.20',
                destination_ip = '10.0.0.10',
                source_port = 443,
                destination_port = 51000,
                network_protocol = 'tls',
                last_seen = '2026-07-01  10:00:00-06:00',
                alert_json = ?
            WHERE alert_id = 'related'
            """,
            [json.dumps({"network": {"community_id": "-"}})],
        )
        self.conn.commit()

        selected = self.conn.execute(
            "SELECT * FROM alerts WHERE alert_id = 'selected'"
        ).fetchone()
        context = self.builder.correlated_alert_context(
            self.conn,
            selected,
            limit=8,
            min_score=15,
        )

        self.assertEqual(
            context["candidates"][0]["deterministic_relationships"],
            [],
        )

    def test_representative_selection_orders_offsets_chronologically(self) -> None:
        self.conn.execute(
            """
            INSERT INTO alerts
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "related-newer-utc",
                "b" * 20,
                "2026-11-01  00:00:00-07:00",
                "2026-11-01  01:10:00-07:00",
                "2026-11-01  01:10:00-07:00",
                "Rule B",
                "10.0.0.10",
                "203.0.113.31",
                443,
                "tcp",
                "medium",
                55,
                "accepted",
                1,
            ),
        )
        self.conn.execute(
            """
            UPDATE alerts
            SET last_seen = '2026-11-01  01:50:00-06:00',
                timestamp = '2026-11-01  01:50:00-06:00'
            WHERE alert_id = 'related'
            """
        )
        self.conn.commit()

        selected = self.conn.execute(
            "SELECT * FROM alerts WHERE alert_id = 'selected'"
        ).fetchone()
        context = self.builder.correlated_alert_context(
            self.conn,
            selected,
            limit=8,
            min_score=15,
        )

        self.assertEqual(
            context["candidates"][0]["alert"]["alert_id"],
            "related-newer-utc",
        )

    def test_runner_repairs_missing_correlation_output(self) -> None:
        response = {
            key: value for key, value in self.runner.DEFAULT_RESPONSE_VALUES.items()
        }
        response.update({
            "summary": "summary",
            "likely_meaning": "meaning",
            "severity_reasoning": "reason",
        })
        normalized = self.runner.validate_response(response)

        self.assertFalse(normalized["correlation_assessment"]["correlation_found"])
        self.assertEqual(normalized["correlation_assessment"]["related_groups"], [])
        self.assertEqual(normalized["correlation_assessment"]["episode_id"], "")
        self.assertEqual(normalized["correlation_assessment"]["episode_basis"], [])

    def test_runner_derives_stable_episode_id_from_related_groups(self) -> None:
        first = self.runner.normalize_correlation_assessment(
            {
                "correlation_found": True,
                "related_groups": [
                    {"group_id": "group-b", "reason": "same process"},
                    {"group_id": "group-a", "reason": "same process"},
                ],
            }
        )
        second = self.runner.normalize_correlation_assessment(
            {
                "correlation_found": True,
                "episode_id": "model-controlled-value-is-ignored",
                "related_groups": [
                    {"group_id": "group-a", "reason": "same process"},
                    {"group_id": "group-b", "reason": "same process"},
                ],
            }
        )

        self.assertEqual(first["episode_id"], second["episode_id"])
        self.assertRegex(first["episode_id"], r"^episode-[a-f0-9]{20}$")
        self.assertEqual(
            first["episode_basis"],
            ["related_group:group-a", "related_group:group-b"],
        )

    def test_alert_store_owns_correlation_writes(self) -> None:
        composition = (
            REPO_ROOT
            / "n8n"
            / "alert_store"
            / "composition"
            / "application_graph_runtime.js"
        ).read_text(encoding="utf-8")
        application_composition = (
            REPO_ROOT
            / "n8n"
            / "alert_store"
            / "composition"
            / "application_composition.js"
        ).read_text(encoding="utf-8")
        foundation = SCHEMA_FOUNDATION.read_text(encoding="utf-8")
        incident_schema = INCIDENT_ANALYSIS_SCHEMA.read_text(encoding="utf-8")
        review_schema = AI_REVIEW_SCHEMA.read_text(encoding="utf-8")
        result_service = ANALYSIS_RESULT_SERVICE.read_text(encoding="utf-8")
        campaign_persistence = AUTHORIZED_CAMPAIGN_PERSISTENCE.read_text(encoding="utf-8")
        result_routes = ANALYSIS_RESULT_ROUTES.read_text(encoding="utf-8")
        runner = AI_RUNNER.read_text(encoding="utf-8")

        self.assertIn("createApplicationComposition", composition)
        self.assertIn("createAlertStoreSchemaFoundation", application_composition)
        self.assertIn("createIncidentAnalysisSchema", application_composition)
        self.assertIn("createAiReviewSchema", application_composition)
        self.assertIn("CREATE TABLE IF NOT EXISTS alert_observables", foundation)
        self.assertIn("CREATE TABLE IF NOT EXISTS ai_analysis_runs", incident_schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS alert_correlations", review_schema)
        self.assertIn("path: '/analysis/result'", result_routes)
        self.assertIn("withWriteGate,", composition)
        self.assertIn("withTransaction,", composition)
        self.assertIn("await withWriteGate(async () =>", result_service)
        self.assertIn("await withTransaction(async () =>", result_service)
        self.assertIn("observable.observable_type = 'community_id'", campaign_persistence)
        self.assertNotIn("sqlite3.connect", runner)

    def test_observable_module_normalizes_alert_facts(self) -> None:
        script = f"""
          const m = require({json.dumps(str(CORRELATION_MODULE))});
          const rows = m.buildAlertObservables(
            {{
              source: {{ip: '10.0.0.10'}},
              destination: {{ip: '198.51.100.2', port: 443}},
              network: {{community_id: '1:gVOca2cr2eIKwoIKZ8QnLwW2gqU='}},
              rule_name: 'Rule A'
            }},
            {{alert_id: 'a', source_ip: '10.0.0.10', destination_ip: '198.51.100.2', destination_port: 443, rule_name: 'Rule A'}},
            () => ({{domains: ['Example.COM'], public_ips: ['198.51.100.2'], urls: [], hashes: [], cves: []}})
          );
          process.stdout.write(JSON.stringify(rows));
        """
        completed = subprocess.run(["node", "-e", script], text=True, capture_output=True, check=True)
        values = {(item["observable_type"], item["observable_value"]) for item in json.loads(completed.stdout)}

        self.assertIn(("domain", "example.com"), values)
        self.assertIn(("port", "443"), values)
        self.assertIn(("rule", "rule a"), values)
        self.assertIn(
            ("community_id", "1:gVOca2cr2eIKwoIKZ8QnLwW2gqU="),
            values,
        )

    def test_community_id_observable_can_create_a_candidate(self) -> None:
        self.conn.execute(
            "DELETE FROM alert_observables WHERE group_id IN (?, ?)",
            ("a" * 20, "b" * 20),
        )
        community_id = "1:gVOca2cr2eIKwoIKZ8QnLwW2gqU="
        self.conn.executemany(
            "INSERT INTO alert_observables VALUES (?, ?, ?, ?, ?)",
            [
                (
                    "a" * 20,
                    "community_id",
                    community_id,
                    "flow",
                    "alert",
                ),
                (
                    "b" * 20,
                    "community_id",
                    community_id,
                    "flow",
                    "alert",
                ),
            ],
        )
        self.conn.commit()

        selected = self.conn.execute(
            "SELECT * FROM alerts WHERE alert_id = 'selected'"
        ).fetchone()
        context = self.builder.correlated_alert_context(
            self.conn,
            selected,
            limit=8,
            min_score=15,
        )

        self.assertEqual(
            [item["group_id"] for item in context["candidates"]],
            ["b" * 20],
        )
        self.assertEqual(
            context["candidates"][0]["shared_observables"][0]["type"],
            "community_id",
        )

    def test_observable_module_rejects_placeholder_community_id(self) -> None:
        self.assertIsNone(
            self.builder.COMMUNITY_ID_V1_RE.fullmatch(
                "1:gVOca2cr2eIKwoIKZ8QnLwW2gqV="
            )
        )
        script = f"""
          const m = require({json.dumps(str(CORRELATION_MODULE))});
          process.stdout.write(JSON.stringify({{
            placeholder: m.normalizedObservableValue('community_id', '-'),
            malformed: m.normalizedObservableValue('community_id', '1:not-base64'),
            noncanonical: m.normalizedObservableValue(
              'community_id',
              '1:gVOca2cr2eIKwoIKZ8QnLwW2gqV='
            ),
            canonical: m.normalizedObservableValue(
              'community_id',
              '1:gVOca2cr2eIKwoIKZ8QnLwW2gqU='
            )
          }}));
        """
        completed = subprocess.run(
            ["node", "-e", script],
            text=True,
            capture_output=True,
            check=True,
        )
        values = json.loads(completed.stdout)
        self.assertEqual(values["placeholder"], "")
        self.assertEqual(values["malformed"], "")
        self.assertEqual(values["noncanonical"], "")
        self.assertEqual(
            values["canonical"],
            "1:gVOca2cr2eIKwoIKZ8QnLwW2gqU=",
        )

    def test_historical_artifact_payload_is_bounded_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            prompt = root / "prompt.json"
            prompt.write_text(json.dumps({
                "correlated_alert_context": {
                    "candidates": [{
                        "group_id": "b" * 20,
                        "score": 80,
                        "correlation_reasons": ["shared domain"],
                    }]
                },
                "pcap_evidence": {"summary": "bounded text only"},
            }), encoding="utf-8")
            artifact = root / "example-local-ai-analysis.json"
            artifact.write_text(json.dumps({
                "alert_id": "example-alert",
                "generated_at": "2026-07-15  10:00:00-06:00",
                "prompt_package": str(prompt),
                "response": {
                    "summary": "Historical assessment",
                    "correlation_assessment": {"correlation_found": False},
                },
            }), encoding="utf-8")

            first = self.backfill.artifact_payload(artifact)
            second = self.backfill.artifact_payload(artifact)

        self.assertIsNotNone(first)
        self.assertEqual(first["analysis_id"], second["analysis_id"])
        self.assertEqual(first["correlation_candidates"][0]["group_id"], "b" * 20)
        self.assertEqual(len(first["evidence_hash"]), 64)
        self.assertNotIn("pcap_evidence", first)

    def test_backfill_skips_artifacts_for_expired_alert_rows(self) -> None:
        error = HTTPError(
            url="http://127.0.0.1:8787/analysis/result",
            code=400,
            msg="Bad Request",
            hdrs=None,
            fp=io.BytesIO(b'{"ok":false,"reason":"analysis alert_id not found"}'),
        )
        try:
            with mock.patch.object(self.backfill.urllib.request, "urlopen", side_effect=error):
                with self.assertRaises(self.backfill.HistoricalAlertMissing):
                    self.backfill.post_payload("http://127.0.0.1:8787", {"alert_id": "expired"})
        finally:
            error.close()


if __name__ == "__main__":
    unittest.main()
