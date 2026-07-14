#!/usr/bin/env python3
"""Architecture regressions for the alert-store critical path."""
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_STORE = REPO_ROOT / "n8n" / "alert_store" / "alert_store.js"
PROVIDER_SCHEDULER = REPO_ROOT / "n8n" / "alert_store" / "lib" / "provider_scheduler.js"


class AlertStoreResilienceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.code = ALERT_STORE.read_text(encoding="utf-8")
        cls.provider_scheduler = PROVIDER_SCHEDULER.read_text(encoding="utf-8")

    def test_enrichment_uses_a_separate_gate(self) -> None:
        self.assertIn("require('./lib/provider_scheduler')", self.code)
        self.assertIn("enrichmentScheduler.run(", self.code)
        self.assertIn("await Promise.all(jobs);", self.code)
        self.assertNotIn("withEnrichmentGate", self.code)

    def test_enrichment_is_durable_and_outside_ingest_latency(self) -> None:
        self.assertIn("require('./lib/durable_job_queue')", self.code)
        self.assertIn("durableJobs.enqueue('public_enrichment'", self.code)
        self.assertIn("async function drainEnrichmentJobs()", self.code)
        store = self.code.split("async function storeAlert(rawAlert)", 1)[1].split(
            "async function drainEnrichmentJobs", 1
        )[0]
        self.assertNotIn("await enrichAlert(", store)

    def test_enrichment_provider_circuits_are_bounded(self) -> None:
        self.assertIn("ENRICHMENT_CIRCUIT_FAILURE_THRESHOLD", self.code)
        self.assertIn("ENRICHMENT_CIRCUIT_RESET_MS", self.code)
        self.assertIn("provider circuit open until", self.provider_scheduler)

    def test_enrichment_requests_identify_the_service_and_keep_safe_provider_errors(self) -> None:
        self.assertIn("'User-Agent': 'Onion-Sentinel/1.0'", self.code)
        self.assertIn("function providerErrorDetail(body)", self.code)
        self.assertIn("Censys Platform API returned HTTP", self.code)

    def test_sqlite_gate_only_wraps_storage(self) -> None:
        self.assertIn(
            "withSqliteWriteGate(() => withImmediateTransaction(async () =>",
            self.code,
        )
        store_unlocked = self.code.split("async function storeAlertUnlocked(alert)", 1)[1].split(
            "async function applySuppressionPolicy", 1
        )[0]
        self.assertNotIn("enrichAlert(", store_unlocked)
        self.assertNotIn("maybeNotifyTelegram(", store_unlocked)

    def test_notification_failure_does_not_reject_persisted_alert(self) -> None:
        self.assertIn("CREATE TABLE IF NOT EXISTS notification_outbox", self.code)
        self.assertIn("withImmediateTransaction(async () =>", self.code)
        self.assertIn("void drainTelegramOutbox();", self.code)
        store = self.code.split("async function storeAlert(rawAlert)", 1)[1].split(
            "async function storeAlertUnlocked(alert)", 1
        )[0]
        self.assertNotIn("postTelegramMessage(", store)

    def test_notification_outbox_has_bounded_retry(self) -> None:
        self.assertIn("TELEGRAM_OUTBOX_MAX_ATTEMPTS", self.code)
        self.assertIn("outboxRetryTimestamp", self.code)
        self.assertIn("terminal ? 'failed' : 'pending'", self.code)

    def test_analyst_state_is_owned_by_alert_store(self) -> None:
        self.assertIn("CREATE TABLE IF NOT EXISTS analyst_alert_group_state", self.code)
        self.assertIn("parsedUrl.pathname === '/analyst-status'", self.code)
        self.assertIn("withSqliteWriteGate(async () =>", self.code)

    def test_pcap_mutations_use_the_sqlite_gate(self) -> None:
        self.assertIn("withSqliteWriteGate(() => createPcapRequest(payload))", self.code)
        self.assertIn("withSqliteWriteGate(() => claimPcapRequest(payload))", self.code)
        self.assertIn("withSqliteWriteGate(() => completePcapRequest(payload))", self.code)

    def test_ai_job_reconciliation_is_bounded_and_transactional(self) -> None:
        self.assertIn("parsedUrl.pathname === '/jobs/reconcile-completed'", self.code)
        self.assertIn(".slice(0, 2000)", self.code)
        self.assertIn("durableJobs.completePendingByDedupeKeys", self.code)

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
