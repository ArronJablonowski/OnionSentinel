import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_BUILDER = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"
DASHBOARD_BUILDER_RUNTIME = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_builder_runtime.py"
SHELL_PAGE = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_shell_page.py"
NAV_STYLE = REPO_ROOT / "onion-sentinel-dashboard" / "assets" / "dashboard-navigation.css"


def dashboard_contract_source() -> str:
    shell = SHELL_PAGE.read_text(encoding="utf-8")
    return DASHBOARD_BUILDER_RUNTIME.read_text(encoding="utf-8") + shell.replace("{", "{{").replace("}", "}}")


class DashboardMobileNavigationTest(unittest.TestCase):
    def test_mobile_navigation_is_always_a_pinned_left_rail(self):
        source = dashboard_contract_source()
        css = NAV_STYLE.read_text()
        self.assertIn('assets/dashboard-navigation.css?v=20261011-pinned', source)
        self.assertIn('position: fixed !important', css)
        self.assertIn('inset: 0 auto 0 0 !important', css)
        self.assertIn('grid-column: 2', css)
        self.assertIn('height: 100dvh !important', css)

    def test_open_mobile_navigation_owns_vertical_scrolling(self):
        css = NAV_STYLE.read_text()
        self.assertIn('flex: 1 1 auto', css)
        self.assertIn('min-height: 0', css)
        self.assertIn('overflow-y: auto', css)
        self.assertIn('overscroll-behavior-y: contain', css)
        self.assertIn('touch-action: pan-y', css)
        self.assertIn('env(safe-area-inset-bottom)', css)
        self.assertIn('min-height: 48px', css)
        self.assertIn('.nav-item:focus-visible', css)

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
