from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "n8n" / "postgres" / "asset-inventory-schema.sql"
STORE = ROOT / "n8n" / "alert_store" / "lib" / "postgres_asset_store.js"
SERVICE = ROOT / "n8n" / "alert_store" / "alert_store.js"
COLLECTOR = ROOT / "n8n" / "bin" / "collect-dhcp-asset-discovery.py"
PLIST = ROOT / "n8n" / "launchd" / "com.arron.soc.dhcp-asset-discovery.plist"
PORTAL = ROOT / "onion-sentinel-dashboard" / "report_portal.py"
BUILDER = (
    ROOT
    / "onion-sentinel-dashboard"
    / "scripts"
    / "build_soc_alerts_dashboard.py"
)


class PostgresAssetInventoryTests(unittest.TestCase):
    def test_schema_is_normalized_indexed_and_audited(self) -> None:
        sql = SCHEMA.read_text(encoding="utf-8").lower()
        for table in (
            "inventory_records",
            "identifiers",
            "dhcp_observations",
            "review_decisions",
            "audit_events",
        ):
            self.assertIn(
                f"create table if not exists onion_sentinel_assets.{table}",
                sql,
            )
        self.assertIn("idx_osa_identifiers_lookup", sql)
        self.assertIn("idx_osa_dhcp_ip", sql)
        self.assertIn("reject_audit_mutation", sql)
        self.assertIn("before update or delete", sql)
        self.assertNotIn("drop schema", sql)

    def test_service_has_paged_reads_and_token_gated_writes(self) -> None:
        source = SERVICE.read_text(encoding="utf-8")
        self.assertIn("GET' && parsedUrl.pathname === '/assets/inventory'", source)
        self.assertIn("parsedUrl.searchParams.get('limit')", source)
        self.assertIn("requireAssetStoreWriteAuthorization(request)", source)
        self.assertIn("crypto.timingSafeEqual", source)
        self.assertIn("ASSET_STORE_WRITE_TOKEN", source)
        self.assertIn("store.putDhcpState", source)

    def test_runtime_collector_is_database_fail_closed(self) -> None:
        collector = COLLECTOR.read_text(encoding="utf-8")
        plist = PLIST.read_text(encoding="utf-8")
        self.assertIn("--require-database", collector)
        self.assertIn("--require-database", plist)
        self.assertLess(
            collector.rindex("database_result = persist_database_state("),
            collector.index("atomic_write_json(args.state, updated)"),
        )

    def test_dashboard_uses_server_side_paging(self) -> None:
        portal = PORTAL.read_text(encoding="utf-8")
        builder = BUILDER.read_text(encoding="utf-8")
        self.assertIn('"/assets/inventory?', portal)
        self.assertIn("ASSET_DATABASE_READ_ENABLED", portal)
        self.assertIn("asset-page-previous", builder)
        self.assertIn("asset-page-next", builder)
        self.assertIn("limit:pageSize.value", builder)
        self.assertIn("offset:String(pageOffset)", builder)

    def test_node_record_validation_rejects_bad_identity(self) -> None:
        script = f"""
          const store = require({json.dumps(str(STORE))});
          let rejected = 0;
          for (const record of [
            {{asset_id:'a',valid_from:'2026-01-01T00:00:00Z',identifiers:{{}}}},
            {{asset_id:'a',valid_from:'not-a-time',identifiers:{{ip_addresses:['192.0.2.1']}}}},
            {{asset_id:'a',valid_from:'2026-01-01T00:00:00Z',identifiers:{{ip_addresses:['not-ip']}}}},
          ]) {{
            try {{ store.normalizeInventoryRecord(record); }} catch (_) {{ rejected += 1; }}
          }}
          if (rejected !== 3) process.exit(2);
        """
        result = subprocess.run(
            ["node", "-e", script],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
