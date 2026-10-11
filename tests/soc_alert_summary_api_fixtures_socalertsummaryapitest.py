from __future__ import annotations

from soc_alert_summary_api_fixtures import (
    PORTAL_PATH,
    Path,
    REPO_ROOT,
    ThreadPoolExecutor,
    dt,
    importlib,
    json,
    load_portal,
    mock,
    sqlite3,
    sys,
    tempfile,
    time,
    unittest,
)

class SocAlertSummaryApiTestFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "alerts.sqlite3"
        self.portal = load_portal()
        self.portal.HOME = Path(self.tmp.name)
        self.portal.SOC_ALERT_STORE_DB = self.db_path
        self.portal.SOC_ALERT_STORE_API_URL = ""
        self.portal.SOC_ALERT_STORE_DIRECT_WRITE_ALLOWED = True
        self.portal.SOC_ALERT_STATUS_FILE = Path(self.tmp.name) / ".soc_alert_status.json"
        self.portal.SOC_ALERT_STATIC_STATUS_FILE = Path(self.tmp.name) / "soc-alerts-status.json"
        self.portal.ASSET_INVENTORY_FILE = Path(self.tmp.name) / "asset-inventory.json"
        self.portal.DHCP_ASSET_DISCOVERY_STATE_FILE = (
            Path(self.tmp.name) / "dhcp-observations.json"
        )
        self.portal.ASSET_INVENTORY_CACHE = {"signature": None, "inventory": None}
        self.portal.SOC_AI_SETTINGS_FILE = Path(self.tmp.name) / "ai-model-settings.json"
        self.portal.SOC_AI_SETTINGS_FILE.write_text(
            json.dumps(self.portal.default_soc_ai_settings()),
            encoding="utf-8",
        )
        self.portal.SOC_ALERT_LLM_ANALYSIS_CURRENT_FILE = (
            Path(self.tmp.name) / "current-analysis.json"
        )
        self.portal.SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR = (
            Path(self.tmp.name) / "active-analyses"
        )
        self.portal.SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR.mkdir()
        self.portal.SOC_ALERT_PCAP_WORKFLOW_STATE_FILE = Path(self.tmp.name) / "pcap-workflow-state.json"
        self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR = Path(self.tmp.name) / "pcap-analysis"
        self.portal.SOC_ALERT_PCAP_ARTIFACT_DIR = Path(self.tmp.name) / "pcap-artifacts"
        self.portal.SOC_ALERT_AI_ANALYSIS_DIR = Path(self.tmp.name) / "ai-analysis"
        self.portal.SOC_ALERT_AI_ANALYSIS_DIR.mkdir()
        self.portal.SOC_ALERT_DETAIL_DIR = Path(self.tmp.name) / "details"
        self.portal.SOC_ALERT_DETAIL_DIR.mkdir()
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE alerts (
              alert_id TEXT PRIMARY KEY,
              first_seen TEXT,
              last_seen TEXT,
              seen_count INTEGER,
              timestamp TEXT,
              rule_name TEXT,
              event_dataset TEXT,
              severity INTEGER,
              severity_label TEXT,
              source_ip TEXT,
              source_port INTEGER,
              destination_ip TEXT,
              destination_port INTEGER,
              network_protocol TEXT,
              transport_protocol TEXT,
              triage_level TEXT,
              filter_status TEXT,
              suppression_key TEXT,
              enrichment_json TEXT,
              alert_json TEXT,
              raw_event_json TEXT
            );
            CREATE TABLE alert_group_summary (
              group_id TEXT PRIMARY KEY,
              group_key TEXT NOT NULL UNIQUE,
              representative_alert_id TEXT,
              first_seen TEXT,
              last_seen TEXT,
              raw_alert_count INTEGER NOT NULL DEFAULT 0,
              total_seen_count INTEGER NOT NULL DEFAULT 0,
              timestamp TEXT,
              rule_name TEXT,
              event_dataset TEXT,
              severity INTEGER,
              severity_label TEXT,
              source_ip TEXT,
              source_port INTEGER,
              destination_ip TEXT,
              destination_port INTEGER,
              network_protocol TEXT,
              transport_protocol TEXT,
              traffic_direction TEXT,
              triage_score INTEGER,
              triage_level TEXT,
              routing TEXT,
              filter_status TEXT,
              alert_json TEXT,
              filter_reason TEXT,
              suppression_key TEXT,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE suppression_log (
              suppression_key TEXT PRIMARY KEY,
              rule_name TEXT NOT NULL,
              reason TEXT,
              window_start TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              seen_count INTEGER NOT NULL DEFAULT 1,
              suppressed_count INTEGER NOT NULL DEFAULT 0,
              escalated_count INTEGER NOT NULL DEFAULT 0,
              ttl_seconds INTEGER NOT NULL,
              escalation_threshold INTEGER NOT NULL
            );
            CREATE TABLE pcap_requests (
              request_id TEXT PRIMARY KEY,
              status TEXT NOT NULL,
              alert_id TEXT,
              group_id TEXT,
              group_key TEXT,
              first_seen TEXT,
              last_seen TEXT,
              source_ip TEXT,
              source_port INTEGER,
              destination_ip TEXT,
              destination_port INTEGER,
              network_protocol TEXT,
              transport_protocol TEXT,
              community_id TEXT,
              requested_by TEXT,
              reason TEXT NOT NULL,
              max_window_seconds INTEGER NOT NULL,
              relay_host TEXT,
              artifact_path TEXT,
              artifact_sha256 TEXT,
              artifact_size_bytes INTEGER,
              error TEXT,
              request_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              claimed_at TEXT,
              completed_at TEXT,
              transfer_stage TEXT,
              transfer_bytes INTEGER NOT NULL DEFAULT 0,
              transfer_total_bytes INTEGER NOT NULL DEFAULT 0,
              transfer_progress_at TEXT,
              transfer_duration_seconds INTEGER,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE ai_analysis_runs (
              analysis_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL,
              alert_id TEXT NOT NULL,
              generated_at TEXT NOT NULL,
              model TEXT,
              model_path TEXT,
              detection_outcome TEXT,
              bluf TEXT,
              summary TEXT,
              confidence TEXT,
              artifact_path TEXT,
              evidence_hash TEXT,
              response_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            """
        )
        self.insert_summary(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted",
            "newest-alert",
            "Newest detection",
            "critical",
            "2026-07-03  12:00:00Z",
            2,
            5,
        )
        self.insert_summary(
            "high|Older detection|192.0.2.20|198.51.100.20|accepted",
            "older-alert",
            "Older detection",
            "high",
            "2026-07-03  11:00:00Z",
            1,
            1,
        )
        self.insert_summary(
            "critical|Suppressed backend detection|192.0.2.30|198.51.100.30|suppressed",
            "backend-suppressed-alert",
            "Suppressed backend detection",
            "critical",
            "2026-07-03  12:30:00Z",
            7,
            7,
            filter_status="suppressed",
        )
        self.conn.commit()


    def tearDown(self) -> None:
        self.conn.close()
        self.tmp.cleanup()


    def insert_summary(
        self,
        group_key: str,
        alert_id: str,
        rule_name: str,
        level: str,
        last_seen: str,
        raw_count: int,
        total_count: int,
        filter_status: str = "accepted",
        source_ip: str = "192.0.2.10",
        destination_ip: str = "198.51.100.10",
        destination_port: int = 443,
    ) -> str:
        group_id = self.portal.soc_alert_group_id(group_key)
        self.conn.execute(
            """
            INSERT INTO alert_group_summary (
              group_id, group_key, representative_alert_id, first_seen, last_seen,
              raw_alert_count, total_seen_count, timestamp, rule_name, event_dataset,
              severity, severity_label, source_ip, source_port, destination_ip,
              destination_port, transport_protocol, traffic_direction, triage_score,
              triage_level, routing, filter_status, alert_json, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'suricata.alert', 4, ?, ?,
                    4444, ?, ?, 'tcp', 'outbound', 90, ?,
              'analyst-review-immediate', ?, '{}', ?)
            """,
            (
                group_id,
                group_key,
                alert_id,
                last_seen,
                last_seen,
                raw_count,
                total_count,
                last_seen,
                rule_name,
                level,
                source_ip,
                destination_ip,
                destination_port,
                level,
                filter_status,
                last_seen,
            ),
        )
        return group_id


