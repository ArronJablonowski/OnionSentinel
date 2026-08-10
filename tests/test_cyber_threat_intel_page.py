from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = REPO_ROOT / "onion-sentinel-dashboard"
BUILDER_PATH = DASHBOARD_DIR / "scripts" / "build_soc_alerts_dashboard.py"
BUILDER_RUNTIME_PATH = DASHBOARD_DIR / "scripts" / "dashboard_builder_runtime.py"
MODULE_PATH = DASHBOARD_DIR / "scripts" / "dashboard_cyber_threat_intel_page.py"
PORTAL_PATH = DASHBOARD_DIR / "report_portal.py"
INSTALLER_PATH = REPO_ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class CyberThreatIntelPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.page = load_module("dashboard_cyber_threat_intel_page", MODULE_PATH)
        cls.builder = load_module("cti_page_test_builder", BUILDER_PATH)
        cls.portal = load_module("cti_page_test_portal", PORTAL_PATH)

    def test_cti_page_is_a_full_lifecycle_workspace_not_a_placeholder(self):
        page = self.builder.cyber_threat_intel_page_section([])
        required = (
            'id="cti-workspace"',
            "Intelligence that changes a decision",
            "Intelligence operating loop",
            "Priority intelligence requirement templates",
            "Defensive action contract",
            "CTI source portfolio",
            "Technology intelligence watchlist",
            "Publication quality gates",
            "Measure what intelligence changed",
        )
        for marker in required:
            self.assertIn(marker, page)
        self.assertNotIn("Data-backed widgets can be added here", page)
        self.assertIn("Templates · not active PIRs", page)
        self.assertIn("Drafting and summarization only", page)

    def test_source_and_technology_lists_have_accessible_crud_controls(self):
        page = self.builder.cyber_threat_intel_page_section([])
        self.assertGreaterEqual(page.count('data-cti-add="source"'), 2)
        self.assertGreaterEqual(page.count('data-cti-add="technology"'), 2)
        self.assertIn('id="cti-source-search" type="search"', page)
        self.assertIn('id="cti-technology-search" type="search"', page)
        self.assertIn('role="dialog" aria-modal="true"', page)
        self.assertIn('aria-labelledby="cti-editor-title"', page)
        self.assertIn('id="cti-delete-entry"', page)
        self.assertIn('data-cti-close aria-label="Close editor"', page)

    def test_client_uses_safe_dom_and_secure_revisioned_api_contract(self):
        script = self.builder.CYBER_THREAT_INTEL_JS
        self.assertIn("/api/cyber-threat-intel/program", script)
        self.assertIn("credentials: 'same-origin'", script)
        self.assertIn("'X-Onion-Sentinel-Request': 'dashboard'", script)
        self.assertIn("expected_revision: state.program.revision", script)
        self.assertIn("textContent", script)
        self.assertNotIn("innerHTML", script)
        self.assertIn("response.status === 409", script)
        self.assertIn("response.status === 403", script)
        self.assertIn("/api/admin/session-status", script)

    def test_page_styles_preserve_professional_tables_and_mobile_layout(self):
        styles = self.builder.CYBER_THREAT_INTEL_CSS
        self.assertIn(".cti-table-wrap{overflow:auto", styles)
        self.assertIn("min-width:1260px", styles)
        self.assertIn("@media(max-width:720px)", styles)
        self.assertIn(".cti-modal[hidden]{display:none}", styles)
        self.assertIn(".cti-lifecycle{display:grid", styles)

    def test_assigned_model_label_is_html_escaped(self):
        with mock.patch.object(self.builder, "load_soc_ai_settings", return_value={}), mock.patch.object(
            self.builder,
            "agent_model_route_label",
            return_value='<script>alert("x")</script>',
        ):
            page = self.builder.cyber_threat_intel_page_section([])
        self.assertNotIn('<script>alert("x")</script>', page)
        self.assertIn('&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;', page)

    def test_cti_writes_require_an_admin_session_in_shared_handler(self):
        class Session:
            def __init__(self, authenticated: bool):
                self.authenticated = authenticated

            def _admin_authenticated(self):
                return self.authenticated

        authorize = self.portal.PortalHandler._cti_program_write_authorized
        self.assertFalse(authorize(Session(False)))
        self.assertTrue(authorize(Session(True)))

    def test_render_dispatch_uses_the_cti_specific_page_and_assets(self):
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(BUILDER_PATH.parent.glob("dashboard_builder_*.py"))
        )
        self.assertIn("if page_key == 'cyber_threat_intel':", source)
        self.assertIn("cyber_threat_intel_page_section(reports)", source)
        self.assertIn("inject_cyber_threat_intel_assets", source)

    def test_builder_reexports_bounded_cti_module_assets(self):
        self.assertIs(
            self.builder.render_cyber_threat_intel_page,
            self.page.render_cyber_threat_intel_page,
        )
        self.assertIs(
            self.builder.inject_cyber_threat_intel_assets,
            self.page.inject_cyber_threat_intel_assets,
        )
        self.assertIs(self.builder.CYBER_THREAT_INTEL_CSS, self.page.CYBER_THREAT_INTEL_CSS)
        self.assertIs(self.builder.CYBER_THREAT_INTEL_JS, self.page.CYBER_THREAT_INTEL_JS)
        self.assertLessEqual(len(MODULE_PATH.read_text(encoding="utf-8").splitlines()), 600)

    def test_cti_view_model_escapes_assigned_model(self):
        rendered = self.page.render_cyber_threat_intel_page(
            self.page.CyberThreatIntelPageViewModel(
                urgent_local_signals=2,
                repeated_local_signals=3,
                model_label='<script>alert("unsafe")</script>',
            )
        )
        self.assertIn('<strong>2</strong><em>Open critical/high alert groups</em>', rendered)
        self.assertIn('<strong>3</strong><em>Open groups repeated 5+ times</em>', rendered)
        self.assertIn('&lt;script&gt;alert(&quot;unsafe&quot;)&lt;/script&gt;', rendered)

    def test_installer_copies_cti_module_once(self):
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_cyber_threat_intel_page.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_cyber_threat_intel_page.py"'
        )
        self.assertEqual(installer.count(command), 1)


if __name__ == "__main__":
    unittest.main()
