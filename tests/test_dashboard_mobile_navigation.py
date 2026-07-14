import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_BUILDER = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"


class DashboardMobileNavigationTest(unittest.TestCase):
    def test_mobile_navigation_is_top_collapsed_drawer(self):
        source = DASHBOARD_BUILDER.read_text()

        self.assertIn("@media(max-width:1180px)", source)
        self.assertIn(".sidebar{{position:fixed;left:0;right:0;top:0;bottom:auto", source)
        self.assertIn(".sidebar .nav{{display:none", source)
        self.assertIn(".app-shell.mobile-nav-open .sidebar .nav{{display:grid", source)
        self.assertIn("Open navigation menu", source)

        self.assertNotIn(".sidebar{{position:fixed;left:0;right:0;bottom:0;top:auto", source)
        self.assertNotIn(".content{{padding:14px 10px 92px}}", source)

    def test_mobile_expansion_survives_api_refresh_without_persisting(self):
        source = DASHBOARD_BUILDER.read_text()

        self.assertIn("expandedMobileId=document.querySelector('.mobile-alert-card.mobile-expanded')", source)
        self.assertIn("restoreExpandedApiMobileCard(expandedMobileId)", source)
        self.assertNotIn("localStorage.setItem('expandedMobile", source)


if __name__ == "__main__":
    unittest.main()
