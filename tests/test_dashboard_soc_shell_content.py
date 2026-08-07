import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import dashboard_soc_shell_content as content  # noqa: E402


class DashboardSocShellContentTests(unittest.TestCase):
    def test_alert_table_has_api_pagination_and_evidence_columns(self) -> None:
        rendered = content.render_alert_table_shell()
        self.assertIn('id="api-page-size"', rendered)
        self.assertIn('id="api-alert-page-status"', rendered)
        self.assertIn('class="outcome-header"', rendered)
        self.assertIn('class="pcap-size-header"', rendered)
        self.assertEqual(rendered.count('id="soc-alert-evidence-column-styles"'), 1)

    def test_alert_table_preserves_mobile_triage_and_sort_contracts(self) -> None:
        rendered = content.render_alert_table_shell()
        self.assertIn('class="mobile-triage-bar"', rendered)
        for key in ("count", "severity", "last_seen", "alert", "risk"):
            self.assertIn(f'data-sort-key="{key}"', rendered)
        for severity in ("critical", "high", "medium", "low", "informational"):
            self.assertIn(f'data-severity-filter="{severity}"', rendered)

    def test_overview_includes_read_only_flow_and_escaped_display_addresses(self) -> None:
        rendered = content.render_soc_overview(42)
        self.assertIn("42 grouped detections", rendered)
        self.assertIn("restricted SSH poll", rendered)
        self.assertIn('data-ip="192.168.1.7">xxx.xxx.xxx.xxx', rendered)
        self.assertIn('data-ip="10.88.8.8">xxx.xxx.xxx.xxx', rendered)
        self.assertIn('data-ip="10.77.7.225">xxx.xxx.xxx.xxx', rendered)


if __name__ == "__main__":
    unittest.main()
