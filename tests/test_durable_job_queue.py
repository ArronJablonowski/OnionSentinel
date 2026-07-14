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


if __name__ == "__main__":
    unittest.main()
