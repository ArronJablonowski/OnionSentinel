from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PostgresShadowReconcilerTest(unittest.TestCase):
    def test_reconciler_compares_identity_revision_and_queue_state(self):
        source = (
            ROOT / "operations/reconcile-postgres-shadow.js"
        ).read_text(encoding="utf-8")
        self.assertIn("?mode=ro", source)
        self.assertIn("outbox.revision", source)
        self.assertIn("source_revision", source)
        self.assertIn("missing_count", source)
        self.assertIn("mismatch_count", source)
        self.assertIn("statement_timeout: 15000", source)
        self.assertIn("query_timeout: 20000", source)
        self.assertNotIn("console.log(env", source)

    def test_five_minute_monitor_runs_exact_shadow_reconciliation(self):
        monitor = (
            ROOT / "n8n/bin/monitor-n8n-stack.zsh"
        ).read_text(encoding="utf-8")
        installer = (
            ROOT / "n8n/bin/install-macstudio-stack.zsh"
        ).read_text(encoding="utf-8")
        self.assertIn("check_postgres_shadow_reconciliation", monitor)
        self.assertIn("--sqlite", monitor)
        self.assertIn("postgres-shadow-reconciliation.json", monitor)
        self.assertIn("chmod 0600", monitor)
        self.assertIn(
            "operations/reconcile-postgres-shadow.js",
            installer,
        )


if __name__ == "__main__":
    unittest.main()
