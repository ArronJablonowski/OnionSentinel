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
        self.assertNotIn("console.log(env", source)


if __name__ == "__main__":
    unittest.main()
