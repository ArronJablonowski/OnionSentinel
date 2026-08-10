import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_BUILDER = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"
DASHBOARD_BUILDER_RUNTIME = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_builder_runtime.py"
REPORTS_ASSETS = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_reports_assets.py"
REPORTS_PAGE = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_reports_page.py"


def reports_source() -> str:
    return DASHBOARD_BUILDER_RUNTIME.read_text() + REPORTS_ASSETS.read_text() + REPORTS_PAGE.read_text()


class DashboardReportsLayoutTests(unittest.TestCase):
    def test_alert_column_has_stable_desktop_width_and_two_line_title(self) -> None:
        source = reports_source()

        self.assertIn(".llm-log-alerts{width:400px}", source)
        self.assertIn(".llm-log-table{width:100%;border-collapse:collapse;min-width:2320px", source)
        self.assertIn("-webkit-line-clamp:2", source)
        self.assertIn("text-overflow:ellipsis;white-space:nowrap", source)

    def test_mobile_alert_text_is_not_clamped(self) -> None:
        source = reports_source()

        self.assertIn(".llm-log-table td:nth-child(3) strong{display:block;overflow:visible;-webkit-line-clamp:unset", source)
        self.assertIn(".llm-log-table td:nth-child(3) code{overflow:visible;text-overflow:clip;white-space:normal}", source)

    def test_reports_show_observed_model_agent_and_job_provenance(self) -> None:
        source = reports_source()

        self.assertIn("Agent Analysis Activity Log", source)
        self.assertIn('id="llm-log-agent-totals"', source)
        self.assertIn("'siem-engineer':'SIEM Engineer'", source)
        self.assertIn("'threat-hunter':'Threat Hunter'", source)
        self.assertIn('id="llm-current-agent"', source)
        self.assertIn('id="llm-current-job"', source)
        self.assertIn("<th>Status</th><th>Agent</th><th>Job</th>", source)
        self.assertIn("executedModel(current, true)", source)
        self.assertIn("'No model running'", source)
        self.assertIn("const rows = [...activeRuns, ...historical]", source)
        self.assertIn('colspan="18"', source)
        self.assertIn('.llm-log-agent{width:150px}', source)
        self.assertIn('.llm-log-job{width:220px}', source)


if __name__ == "__main__":
    unittest.main()
