"""Regression coverage for live ingestion starving or blocking alert pages."""
import sqlite3
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'onion-sentinel-dashboard'))
from portal_soc_query_runtime import soc_alert_enriched_page_rows


class AlertPageLoadingTests(unittest.TestCase):
    def test_representative_enrichment_uses_primary_key_not_group_scan(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.row_factory = sqlite3.Row
        db.execute('CREATE TABLE alerts(alert_id TEXT PRIMARY KEY, enrichment_json TEXT)')
        db.execute('INSERT INTO alerts VALUES (?,?)', ('representative', '{"current":true}'))
        trace = []
        db.set_trace_callback(trace.append)
        runtime = SimpleNamespace(
            soc_alert_db_connect=lambda: db,
            merge_page_enrichment=lambda rows, enrichments: enrichments,
            soc_alert_group_enrichment_json_map=lambda *_: self.fail('historical group scan'),
        )
        result = soc_alert_enriched_page_rows(runtime, [
            {'alert_id': 'representative', 'group_key': 'visible'},
        ])
        self.assertEqual(result, {'visible': '{"current":true}'})
        self.assertTrue(any('WHERE alert_id IN' in query for query in trace))

    def test_live_events_do_not_discard_same_query_response(self):
        shell = (ROOT / 'onion-sentinel-dashboard/scripts/dashboard_shell_page.py').read_text()
        self.assertIn('requestVersion!==apiAlertRequestVersion&&requestUrl!==apiBuildUrl()', shell)
        self.assertIn('AbortSignal.timeout(15000)', shell)


if __name__ == '__main__':
    unittest.main()
