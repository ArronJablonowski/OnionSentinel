from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
COMPONENT_PATH = SCRIPT_DIR / "dashboard_shell_components.py"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load(path: Path, name: str):
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class DashboardShellComponentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.shell = load(COMPONENT_PATH, "dashboard_shell_components")
        cls.builder = load(BUILDER_PATH, "dashboard_shell_builder_test")

    def test_page_registry_is_complete_unique_and_icon_bound(self) -> None:
        keys = [page.key for page in self.shell.PAGES]
        filenames = [page.filename for page in self.shell.PAGES]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(len(filenames), len(set(filenames)))
        self.assertEqual(set(keys), set(self.shell.NAV_ICONS))
        self.assertEqual(keys, [row[0] for row in self.builder.PAGE_DEFS])
        self.assertEqual(self.builder.PAGE_BY_KEY, self.shell.PAGE_BY_KEY)

    def test_navigation_is_accessible_escaped_and_deterministic(self) -> None:
        first = self.shell.build_nav_html("alerts", 17, 'High"><script>')
        second = self.shell.build_nav_html("alerts", 17, 'High"><script>')
        self.assertEqual(first, second)
        self.assertEqual(first.count('class="nav-item active"'), 1)
        self.assertIn('href="index.html"', first)
        self.assertIn('aria-label="SOC Alerts"', first)
        self.assertIn('aria-hidden="true"', first)
        self.assertIn('id="soc-alerts-nav-count"', first)
        self.assertIn('>17</span>', first)
        self.assertNotIn("<script>", first)
        self.assertIn("nav-count-sev-high-script", first)

    def test_unknown_page_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown dashboard page"):
            self.shell.build_nav_html("missing", 0)
        with self.assertRaisesRegex(ValueError, "unknown dashboard page"):
            self.shell.placeholder_page_section("missing")

    def test_builder_uses_component_renderers(self) -> None:
        self.assertIs(self.builder.build_nav_html, self.shell.build_nav_html)
        self.assertIs(
            self.builder.placeholder_page_section,
            self.shell.placeholder_page_section,
        )
        page = self.builder.render_static_page(self.builder.build_html([]), "playbooks", [])
        self.assertIn('<h2>Playbooks</h2>', page)
        self.assertIn('class="nav-item active" href="playbooks.html"', page)

    def test_installer_copies_shell_component(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_shell_components.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_shell_components.py"',
            installer,
        )


if __name__ == "__main__":
    unittest.main()
