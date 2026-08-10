from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "n8n" / "postgres" / "asset-inventory-schema.sql"
STORE = ROOT / "n8n" / "alert_store" / "lib" / "postgres_asset_store.js"
READ_PROJECTION = (
    ROOT
    / "n8n"
    / "alert_store"
    / "lib"
    / "postgres_asset_read_projection.js"
)
INVENTORY_REPOSITORY = (
    ROOT
    / "n8n"
    / "alert_store"
    / "lib"
    / "postgres_asset_inventory_repository.js"
)
DHCP_REPOSITORY = (
    ROOT
    / "n8n"
    / "alert_store"
    / "lib"
    / "postgres_asset_dhcp_repository.js"
)
RUNTIME = ROOT / "n8n" / "alert_store" / "services" / "postgres_auxiliary_store_runtime.js"
REQUEST_AUTHORIZATION = (
    ROOT / "n8n" / "alert_store" / "lib" / "request_authorization.js"
)
ROUTE_COMPOSITION = (
    ROOT / "n8n" / "alert_store" / "composition" / "route_composition.js"
)
RUNTIME_FOUNDATION_COMPOSITION = (
    ROOT
    / "n8n"
    / "alert_store"
    / "composition"
    / "runtime_foundation_composition.js"
)
ENTRYPOINT = ROOT / "n8n" / "alert_store" / "alert_store.js"
RUNTIME_CONFIGURATION = (
    ROOT / "n8n" / "alert_store" / "lib" / "runtime_configuration.js"
)
ROUTES = ROOT / "n8n" / "alert_store" / "routes" / "inventory_routes.js"
SERVICE = ROOT / "n8n" / "alert_store" / "services" / "inventory_service.js"
COLLECTOR = ROOT / "n8n" / "bin" / "collect-dhcp-asset-discovery.py"
PLIST = ROOT / "n8n" / "launchd" / "com.arron.soc.dhcp-asset-discovery.plist"
PORTAL = ROOT / "onion-sentinel-dashboard" / "report_portal.py"
PORTAL_ASSET_RUNTIME = (
    ROOT / "onion-sentinel-dashboard" / "portal_asset_runtime.py"
)
BUILDER = (
    ROOT
    / "onion-sentinel-dashboard"
    / "scripts"
    / "build_soc_alerts_dashboard.py"
)
ASSET_PAGE = (
    ROOT
    / "onion-sentinel-dashboard"
    / "scripts"
    / "dashboard_asset_inventory_page.py"
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
        entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
        routes = ROUTES.read_text(encoding="utf-8")
        service = SERVICE.read_text(encoding="utf-8")
        store = STORE.read_text(encoding="utf-8")
        read_projection = READ_PROJECTION.read_text(encoding="utf-8")
        write_sources = (
            INVENTORY_REPOSITORY.read_text(encoding="utf-8")
            + DHCP_REPOSITORY.read_text(encoding="utf-8")
        )
        runtime = RUNTIME.read_text(encoding="utf-8")
        request_authorization = REQUEST_AUTHORIZATION.read_text(encoding="utf-8")
        route_composition = ROUTE_COMPOSITION.read_text(encoding="utf-8")
        runtime_foundation = RUNTIME_FOUNDATION_COMPOSITION.read_text(encoding="utf-8")
        runtime_configuration = RUNTIME_CONFIGURATION.read_text(encoding="utf-8")
        self.assertIn("path: '/assets/inventory'", routes)
        self.assertIn("parsedUrl.searchParams.get('limit')", routes)
        self.assertIn("authorizeWrite(request)", routes)
        self.assertIn("function requireAssetWrite(request)", request_authorization)
        self.assertIn("function requireAssetStore()", runtime)
        self.assertIn(
            "authorizeWrite: inventory.authorizeWrite",
            route_composition,
        )
        self.assertIn("createInventoryService", route_composition)
        self.assertNotIn("createInventoryService", entrypoint)
        for forwarding_function in (
            "initializePostgresAssetStore",
            "initializePostgresAcHunterStore",
            "initializePostgresSoftwareStore",
            "requirePostgresAssetStore",
            "requirePostgresSoftwareStore",
            "requirePostgresAcHunterStore",
            "assetStoreWriteAuthorized",
            "requireAssetStoreWriteAuthorization",
        ):
            self.assertNotIn(f"function {forwarding_function}", entrypoint)
        self.assertIn("crypto.timingSafeEqual", runtime_foundation)
        self.assertIn("ASSET_STORE_WRITE_TOKEN", runtime_configuration)
        self.assertIn("createPostgresAuxiliaryStoreRuntime", runtime_foundation)
        self.assertIn("PostgreSQL asset inventory is unavailable", runtime)
        self.assertIn("asset_store.postgres_idle_error", runtime)
        self.assertNotIn("ASSET_STORE_WRITE_TOKEN", runtime)
        self.assertIn("assetStore().putDhcpState", service)
        self.assertIn("assetStore().promoteDhcp", service)
        self.assertIn("assetStore().approveDhcpIpChange", service)
        self.assertIn("assetStore().updateAsset", service)
        self.assertIn("assetStore().demoteAsset", service)
        self.assertIn("/assets/approve-dhcp-ip-change", routes)
        self.assertIn("/assets/update", routes)
        self.assertIn("/assets/demote", routes)
        self.assertIn(
            "conditions.push('$1::timestamptz IS NOT NULL')",
            read_projection,
        )
        self.assertIn("asset.ip_address_changed_from_dhcp", write_sources)
        self.assertIn("ip_change_approved", write_sources)
        self.assertIn("explicit DHCP IP-change confirmation is required", write_sources)
        self.assertIn("lower(asset_id) = lower($1)", write_sources)
        self.assertIn("asset name already belongs to authoritative asset", write_sources)
        self.assertIn("asset.edited", write_sources)
        self.assertIn("asset.demoted_to_dhcp", write_sources)
        self.assertIn(
            "asset has no preserved DHCP observation to return to review",
            write_sources,
        )
        self.assertEqual(write_sources.count("$7::jsonb, $8::jsonb"), 2)
        self.assertIn("JSON.stringify(current.expected_services)", write_sources)
        self.assertIn("JSON.stringify(current.expected_behaviors)", write_sources)
        self.assertIn("JSON.stringify(desired.expected_services)", write_sources)
        self.assertIn("JSON.stringify(desired.expected_behaviors)", write_sources)

    def test_schema_allows_distinct_ip_change_review_decision(self) -> None:
        sql = SCHEMA.read_text(encoding="utf-8")
        self.assertIn("'ip_change_approved'", sql)
        self.assertIn("review_decisions_decision_check", sql)

    def test_store_rejects_unsafe_promotion_before_database_access(self) -> None:
        script = f"""
          const {{createPostgresAssetStore}} = require({json.dumps(str(STORE))});
          const pool = {{
            query: async () => {{ throw new Error('database must not be reached'); }},
            connect: async () => {{ throw new Error('database must not be reached'); }},
          }};
          const store = createPostgresAssetStore({{
            pool,
            schemaPath: {json.dumps(str(SCHEMA))},
          }});
          (async () => {{
            let localRejected = false;
            try {{
              await store.promoteDhcp({{
                discovery_id: '0123456789abcdef0123',
                expected_ip: '192.0.2.10',
                expected_mac: '02:00:00:00:00:01',
                expected_hostname: 'candidate.lan',
                asset_id: 'candidate',
                role: 'workstation',
                reason: 'reviewed',
                confirm: 'PROMOTE:0123456789abcdef0123',
              }});
            }} catch (error) {{
              localRejected = /explicit operator acceptance/.test(error.message);
            }}
            let confirmationRejected = false;
            try {{
              await store.approveDhcpIpChange({{
                discovery_id: '0123456789abcdef0123',
                expected_ip: '192.0.2.11',
                expected_mac: '',
                expected_hostname: 'known.lan',
                asset_id: 'known',
                reason: 'reviewed',
                confirm: 'wrong',
              }});
            }} catch (error) {{
              confirmationRejected = /explicit DHCP IP-change confirmation/.test(
                error.message,
              );
            }}
            let editRejected = false;
            try {{
              await store.updateAsset({{
                asset_id: 'known',
                expected_valid_from: '2026-07-30T20:00:00Z',
                reason: 'reviewed',
                confirm: 'wrong',
              }});
            }} catch (error) {{
              editRejected = /explicit asset edit confirmation/.test(error.message);
            }}
            let demotionRejected = false;
            try {{
              await store.demoteAsset({{
                asset_id: 'known',
                expected_valid_from: '2026-07-30T20:00:00Z',
                reason: 'reviewed',
                confirm: 'wrong',
              }});
            }} catch (error) {{
              demotionRejected = /explicit asset demotion confirmation/.test(
                error.message,
              );
            }}
            if (!localRejected || !confirmationRejected || !editRejected || !demotionRejected) process.exit(2);
          }})().catch(() => process.exit(3));
        """
        result = subprocess.run(
            ["node", "-e", script],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_runtime_collector_is_database_fail_closed(self) -> None:
        collector = COLLECTOR.read_text(encoding="utf-8")
        plist = PLIST.read_text(encoding="utf-8")
        self.assertIn("--require-database", collector)
        self.assertIn("--require-database", plist)
        self.assertLess(
            collector.rindex("database_result = persist_database_state("),
            collector.index("atomic_write_json(args.state, updated)"),
        )

    def test_edit_and_demote_transactions_preserve_history_and_dhcp(self) -> None:
        script = f"""
          const {{createPostgresAssetStore}} = require({json.dumps(str(STORE))});
          function currentRecord() {{
            return {{
              record_id: 41,
              asset_id: 'known',
              valid_from: new Date('2026-07-30T20:00:00Z'),
              valid_until: null,
              role: 'workstation',
              platform: 'macOS',
              owner_ref: 'operator-reviewed',
              criticality: 'medium',
              expected_services: [],
              expected_behaviors: [],
              source_type: 'operator-approved-dhcp',
              source_ref: 'DHCP discovery',
              confidence: 'medium',
              share_with_hosted_models: false,
            }};
          }}
          function fakePool(mode) {{
            const statements = [];
            const calls = [];
            const client = {{
              query: async (sql, params=[]) => {{
                statements.push(String(sql));
                calls.push({{sql:String(sql),params}});
                if (String(sql).includes('SELECT record.*')) return {{rows:[currentRecord()]}};
                if (String(sql).includes('SELECT DISTINCT record.asset_id')) return {{rows:[]}};
                if (String(sql).includes('SELECT identifier_type, normalized_value')) return {{rows:[
                  {{identifier_type:'ip',normalized_value:'192.0.2.40'}},
                  {{identifier_type:'mac',normalized_value:'00:11:22:33:44:66'}},
                  {{identifier_type:'hostname',normalized_value:'known.lan'}},
                ]}};
                if (String(sql).includes('FROM onion_sentinel_assets.dhcp_observations')) return {{rows:[
                  {{discovery_id:'0123456789abcdef0123',last_seen:new Date()}},
                ]}};
                if (String(sql).includes('clock_timestamp() AS changed_at')) return {{rows:[
                  {{changed_at:new Date('2026-07-30T21:00:00Z')}},
                ]}};
                if (String(sql).includes('RETURNING record_id, valid_from')) return {{rows:[
                  {{record_id:42,valid_from:new Date('2026-07-30T21:00:00Z')}},
                ]}};
                return {{rows:[],rowCount:1}};
              }},
              release: () => undefined,
            }};
            return {{
              query: async () => {{ throw new Error('unexpected pool query'); }},
              connect: async () => client,
              statements,
              calls,
            }};
          }}
          (async () => {{
            const editPool = fakePool('edit');
            const editStore = createPostgresAssetStore({{
              pool:editPool,
              schemaPath:{json.dumps(str(SCHEMA))},
            }});
            const edited = await editStore.updateAsset({{
              asset_id:'known',
              expected_valid_from:'2026-07-30T20:00:00Z',
              ip_addresses:['192.0.2.40'],
              mac_addresses:['00:11:22:33:44:66'],
              hostnames:['known.lan'],
              role:'workstation',
              platform:'macOS',
              criticality:'medium',
              confidence:'high',
              reason:'reviewed edit',
              confirm:'EDIT:known',
            }}, {{actor:'change-1'}});
            if (edited.status !== 'edited') process.exit(2);
            if (!editPool.statements.some(sql => sql.includes(\"VALUES ('asset.edited'\"))) process.exit(3);
            if (!editPool.statements.some(sql => sql.trim() === 'COMMIT')) process.exit(4);
            const versionInsert = editPool.calls.find(call =>
              call.sql.includes('INSERT INTO onion_sentinel_assets.inventory_records')
            );
            if (!versionInsert.sql.includes('$7::jsonb, $8::jsonb')) process.exit(10);
            if (versionInsert.params[6] !== '[]' || versionInsert.params[7] !== '[]') process.exit(11);

            const demotePool = fakePool('demote');
            const demoteStore = createPostgresAssetStore({{
              pool:demotePool,
              schemaPath:{json.dumps(str(SCHEMA))},
            }});
            const demoted = await demoteStore.demoteAsset({{
              asset_id:'known',
              expected_valid_from:'2026-07-30T20:00:00Z',
              reason:'return to DHCP review',
              confirm:'DEMOTE:known',
            }}, {{actor:'change-2'}});
            if (demoted.status !== 'demoted') process.exit(5);
            if (demoted.discovery_ids[0] !== '0123456789abcdef0123') process.exit(6);
            if (!demotePool.statements.some(sql => sql.includes(\"VALUES ('asset.demoted_to_dhcp'\"))) process.exit(7);
            if (!demotePool.statements.some(sql => sql.trim() === 'COMMIT')) process.exit(8);
          }})().catch(error => {{
            console.error(error);
            process.exit(9);
          }});
        """
        result = subprocess.run(
            ["node", "-e", script],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dashboard_uses_server_side_paging(self) -> None:
        portal_config = (
            ROOT / "onion-sentinel-dashboard/portal_runtime_config.py"
        ).read_text(encoding="utf-8")
        asset_runtime = PORTAL_ASSET_RUNTIME.read_text(encoding="utf-8")
        asset_page = ASSET_PAGE.read_text(encoding="utf-8")
        self.assertIn('"/assets/inventory?', asset_runtime)
        self.assertIn("ASSET_DATABASE_READ_ENABLED", portal_config)
        self.assertIn("asset-page-previous", asset_page)
        self.assertIn("asset-page-next", asset_page)
        self.assertIn("limit:pageSize.value", asset_page)
        self.assertIn("offset:String(pageOffset)", asset_page)

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
