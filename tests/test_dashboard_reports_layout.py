import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_BUILDER = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"


class DashboardReportsLayoutTests(unittest.TestCase):
    def test_alert_column_has_stable_desktop_width_and_two_line_title(self) -> None:
        source = DASHBOARD_BUILDER.read_text()

        self.assertIn(".llm-log-alerts{width:400px}", source)
        self.assertIn(".llm-log-table{width:100%;border-collapse:collapse;min-width:1880px", source)
        self.assertIn("-webkit-line-clamp:2", source)
        self.assertIn("text-overflow:ellipsis;white-space:nowrap", source)

    def test_mobile_alert_text_is_not_clamped(self) -> None:
        source = DASHBOARD_BUILDER.read_text()

        self.assertIn(".llm-log-table td:nth-child(3) strong{display:block;overflow:visible;-webkit-line-clamp:unset", source)
        self.assertIn(".llm-log-table td:nth-child(3) code{overflow:visible;text-overflow:clip;white-space:normal}", source)


if __name__ == "__main__":
    unittest.main()
