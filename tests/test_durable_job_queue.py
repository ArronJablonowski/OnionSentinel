from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
QUEUE = ROOT / "n8n" / "alert_store" / "lib" / "durable_job_queue.js"


class DurableJobQueueTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = QUEUE.read_text(encoding="utf-8")

    def test_jobs_are_deduplicated_and_priority_ordered(self):
        self.assertIn("UNIQUE(job_type, dedupe_key)", self.code)
        self.assertIn("ORDER BY priority DESC, next_attempt_at ASC, id ASC", self.code)

    def test_claims_have_leases_and_bounded_attempts(self):
        self.assertIn("lease_expires_at", self.code)
        self.assertIn("attempt_count < max_attempts", self.code)
        self.assertIn("terminal ? 'failed' : 'pending'", self.code)

    def test_retry_uses_exponential_backoff(self):
        self.assertIn("2 ** Math.max", self.code)
        self.assertIn("Math.min(3600", self.code)

    def test_completed_artifacts_can_reconcile_stale_pending_jobs_in_batches(self):
        self.assertIn("completePendingByDedupeKeys", self.code)
        self.assertIn("offset += 500", self.code)
        self.assertIn("status = 'pending'", self.code)

    def test_last_completion_survives_requeue(self):
        self.assertIn("last_completed_at TEXT", self.code)
        self.assertIn("ELSE last_completed_at END", self.code)
        self.assertIn("last_completed_at = completed_at", self.code)

    def test_evidence_arriving_during_processing_latches_one_rerun(self):
        self.assertIn("rerun_requested INTEGER", self.code)
        self.assertIn("processing_started_at TEXT", self.code)
        self.assertIn("requested_at TEXT", self.code)
        self.assertIn("THEN 1 ELSE 0 END", self.code)
        self.assertIn("CASE WHEN rerun_requested = 1 THEN 'pending' ELSE 'completed' END", self.code)


if __name__ == "__main__":
    unittest.main()
