from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PostgresQueueMigrationTest(unittest.TestCase):
    def test_schema_has_concurrent_idempotent_queue_primitives(self):
        schema = (ROOT / "n8n/postgres/alert-store-queue-schema.sql").read_text(encoding="utf-8")
        self.assertIn("UNIQUE (job_type, dedupe_key)", schema)
        self.assertIn("JSONB", schema)
        self.assertIn("FOR UPDATE SKIP LOCKED", schema)
        self.assertIn("rerun_requested", schema)
        self.assertIn("release_expired_leases", schema)
        self.assertIn("ON CONFLICT (job_type, dedupe_key)", schema)
        self.assertIn("shadow_durable_jobs", schema)
        self.assertIn("apply_shadow_durable_job", schema)
        self.assertIn("current.source_revision < EXCLUDED.source_revision", schema)
        self.assertIn("shadow_reconciliation_counts", schema)

    def test_verifier_is_network_isolated_and_uses_pinned_image(self):
        verifier = (ROOT / "operations/verify-postgres-queue-schema.zsh").read_text(encoding="utf-8")
        self.assertIn("--network none", verifier)
        self.assertIn("postgres@sha256:", verifier)
        self.assertIn("trap cleanup", verifier)
        self.assertIn("processing:true", verifier)
        self.assertIn("stale shadow revision overwrote newer state", verifier)
        self.assertNotIn("10.77.7.225", verifier)

    def test_plan_forbids_unsafe_queue_only_dual_write(self):
        plan = (ROOT / "docs/postgresql-alert-store-queue-migration.md").read_text(encoding="utf-8")
        self.assertIn("dual-write window", plan)
        self.assertIn("transactional outbox", plan)
        self.assertIn("least-privilege role", plan)
        self.assertIn("127.0.0.1", plan)

    def test_sqlite_shadow_outbox_is_transactional_and_revision_bound(self):
        module = (
            ROOT / "n8n/alert_store/lib/postgres_shadow_outbox.js"
        ).read_text(encoding="utf-8")
        self.assertIn("AFTER INSERT ON durable_jobs", module)
        self.assertIn("AFTER UPDATE ON durable_jobs", module)
        self.assertIn("projected_revision < revision", module)
        self.assertIn("revision = ?", module)
        self.assertNotIn("postgres://", module)


if __name__ == "__main__":
    unittest.main()
