#!/usr/bin/env python3
"""Architecture regressions for the alert-store critical path."""
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_STORE = REPO_ROOT / "n8n" / "alert_store" / "alert_store.js"


class AlertStoreResilienceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.code = ALERT_STORE.read_text(encoding="utf-8")

    def test_enrichment_uses_a_separate_gate(self) -> None:
        self.assertIn("let enrichmentGate = Promise.resolve();", self.code)
        self.assertIn("withEnrichmentGate(() => enrichAlert(alert))", self.code)

    def test_sqlite_gate_only_wraps_storage(self) -> None:
        self.assertIn(
            "withSqliteWriteGate(() => storeAlertUnlocked(alert))",
            self.code,
        )
        store_unlocked = self.code.split("async function storeAlertUnlocked(alert)", 1)[1].split(
            "async function applySuppressionPolicy", 1
        )[0]
        self.assertNotIn("enrichAlert(", store_unlocked)
        self.assertNotIn("maybeNotifyTelegram(", store_unlocked)

    def test_notification_failure_does_not_reject_persisted_alert(self) -> None:
        self.assertIn("status: 'failed'", self.code)
        self.assertIn("Persistence succeeded", self.code)

    def test_analyst_state_is_owned_by_alert_store(self) -> None:
        self.assertIn("CREATE TABLE IF NOT EXISTS analyst_alert_group_state", self.code)
        self.assertIn("parsedUrl.pathname === '/analyst-status'", self.code)
        self.assertIn("withSqliteWriteGate(async () =>", self.code)

    def test_pcap_mutations_use_the_sqlite_gate(self) -> None:
        self.assertIn("withSqliteWriteGate(() => createPcapRequest(payload))", self.code)
        self.assertIn("withSqliteWriteGate(() => claimPcapRequest(payload))", self.code)
        self.assertIn("withSqliteWriteGate(() => completePcapRequest(payload))", self.code)

    def test_summary_rebuild_uses_one_windowed_scan(self) -> None:
        rebuild = self.code.split("async function rebuildAlertGroupSummariesUnlocked()", 1)[1].split(
            "async function rebuildAlertGroupSummaries()", 1
        )[0]
        self.assertIn("ROW_NUMBER() OVER", rebuild)
        self.assertNotIn("refreshAlertGroupSummary(", rebuild)

    def test_oversized_payload_returns_413_without_socket_destroy(self) -> None:
        parser = self.code.split("function readJsonBody(request)", 1)[1].split(
            "function sendJson", 1
        )[0]
        self.assertIn("error.statusCode = 413", parser)
        self.assertNotIn("request.destroy", parser)


if __name__ == "__main__":
    unittest.main()
