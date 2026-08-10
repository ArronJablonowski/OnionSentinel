import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_BUILDER = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"
DASHBOARD_BUILDER_RUNTIME = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_builder_runtime.py"
SHELL_PAGE = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_shell_page.py"


def dashboard_contract_source() -> str:
    shell = SHELL_PAGE.read_text(encoding="utf-8")
    return DASHBOARD_BUILDER_RUNTIME.read_text(encoding="utf-8") + shell.replace("{", "{{").replace("}", "}}")


class DashboardMobileNavigationTest(unittest.TestCase):
    def test_mobile_navigation_is_top_collapsed_drawer(self):
        source = dashboard_contract_source()

        self.assertIn("@media(max-width:1180px)", source)
        self.assertIn(".sidebar{{position:fixed;left:0;right:0;top:0;bottom:auto", source)
        self.assertIn(".sidebar .nav{{display:none", source)
        self.assertIn(".app-shell.mobile-nav-open .sidebar .nav{{display:grid", source)
        self.assertIn("Open navigation menu", source)

        self.assertNotIn(".sidebar{{position:fixed;left:0;right:0;bottom:0;top:auto", source)
        self.assertNotIn(".content{{padding:14px 10px 92px}}", source)

    def test_open_mobile_navigation_owns_vertical_scrolling(self):
        source = dashboard_contract_source()

        self.assertIn(
            ".app-shell.mobile-nav-open .sidebar{{height:100vh;height:100dvh;"
            "max-height:100vh;max-height:100dvh;overflow:hidden",
            source,
        )
        self.assertIn(
            ".app-shell.mobile-nav-open .sidebar .nav{{display:grid;"
            "grid-auto-rows:max-content;align-content:start;flex:1 1 auto;"
            "min-height:0;width:100%;overflow-x:hidden;overflow-y:auto",
            source,
        )
        self.assertIn("touch-action:pan-y", source)
        self.assertIn("calc(20px + env(safe-area-inset-bottom))", source)
        self.assertIn(
            ".app-shell.mobile-nav-open .sidebar .nav-item{{width:100%;"
            "height:auto;min-height:48px",
            source,
        )

    def test_mobile_expansion_survives_api_refresh_without_persisting(self):
        source = dashboard_contract_source()

        self.assertIn("expandedMobileId=document.querySelector('.mobile-alert-card.mobile-expanded')", source)
        self.assertIn("restoreExpandedApiMobileCard(expandedMobileId)", source)
        self.assertNotIn("localStorage.setItem('expandedMobile", source)

    def test_pinned_alert_row_is_desktop_only(self):
        source = dashboard_contract_source()

        self.assertIn(
            "@media(max-width:1180px),(max-height:599px)"
            "{{.pinned-alert-viewport,.pinned-alert-viewport.visible"
            "{{display:none!important}}}}",
            source,
        )

    def test_phone_landscape_uses_mobile_alert_cards(self):
        source = dashboard_contract_source()

        self.assertIn("@media(max-width:960px) and (max-height:560px)", source)
        self.assertIn(
            ".mobile-alert-list{{display:grid;gap:10px;width:100%;"
            "max-width:100%;overflow:hidden}}.table-card{{display:none}}",
            source,
        )

    def test_phone_landscape_compacts_controls_and_metrics(self):
        source = dashboard_contract_source()

        self.assertIn(
            "@media(max-width:960px) and (max-height:560px)"
            "{{.topbar{{grid-template-columns:minmax(0,1fr);grid-template-areas:'title'",
            source,
        )
        self.assertIn(
            ".search-wrap.alerts-only,.toggle-refresh-group.alerts-only{{display:none!important}}",
            source,
        )
        self.assertIn(
            ".metrics,.metrics.verbose-metrics{{display:flex!important;gap:8px!important;"
            "max-width:100%;margin-bottom:8px;overflow-x:auto",
            source,
        )
        self.assertIn(
            ".mobile-triage-bar{{display:grid;grid-template-columns:minmax(0,1fr) auto;",
            source,
        )

    def test_mobile_alert_controls_meet_touch_target_minimum(self):
        source = dashboard_contract_source()

        self.assertIn(
            ".mobile-controls-toggle,.alerts-refresh"
            "{{width:44px!important;height:44px!important;"
            "min-width:44px!important;min-height:44px!important",
            source,
        )
        self.assertIn(
            ".mobile-sort-label select,.mobile-card-actions .ack-button"
            "{{min-height:44px!important}}",
            source,
        )
        self.assertIn(
            "@media(max-width:1180px){{.search,.sort-header,.api-page-button,"
            ".api-page-size select,.api-page-controls select,.ack-button"
            "{{min-height:44px!important}}",
            source,
        )


if __name__ == "__main__":
    unittest.main()
