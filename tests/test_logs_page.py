#!/usr/bin/env python3
"""Frontend and deployment contracts for the Onion Sentinel Logs page."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
BUILDER_PATH = DASHBOARD_DIR / "scripts" / "build_soc_alerts_dashboard.py"
BUILDER_RUNTIME_PATH = DASHBOARD_DIR / "scripts" / "dashboard_builder_runtime.py"
SHELL_COMPONENT_PATH = DASHBOARD_DIR / "scripts" / "dashboard_shell_components.py"
LOGS_PAGE_PATH = DASHBOARD_DIR / "scripts" / "dashboard_logs_page.py"
SERVER_PATH = DASHBOARD_DIR / "onion_sentinel_server.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "logs_page_builder",
        BUILDER_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LogsPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = load_builder()
        cls.section = cls.builder.logs_page_section()
        cls.page = cls.builder.render_static_page(
            cls.builder.build_html([]),
            "logs",
            [],
        )
        cls.builder_source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(BUILDER_PATH.parent.glob("dashboard_builder_*.py"))
        )
        cls.shell_source = SHELL_COMPONENT_PATH.read_text(encoding="utf-8")
        cls.logs_page_source = LOGS_PAGE_PATH.read_text(encoding="utf-8")
        cls.server_source = SERVER_PATH.read_text(encoding="utf-8")
        cls.installer_source = INSTALLER_PATH.read_text(encoding="utf-8")

    def test_navigation_and_page_identity_are_generated(self) -> None:
        keys = [definition[0] for definition in self.builder.PAGE_DEFS]

        self.assertEqual(keys[keys.index("reports") + 1], "logs")
        self.assertEqual(keys[keys.index("logs") + 1], "playbooks")
        self.assertIn(
            '<a class="nav-item active" href="logs.html"',
            self.page,
        )
        self.assertIn(
            '<h1 id="page-title">Onion Sentinel Logs</h1>',
            self.page,
        )
        self.assertIn('id="application-logs-view"', self.page)
        self.assertIn('id="application-log-list"', self.page)
        self.assertIn("Application and service runtime logs", self.page)
        self.assertIn("'logs': '<svg", self.shell_source)

    def test_log_sections_are_collapsed_and_contents_load_only_on_expand(self) -> None:
        self.assertIn("const details=node('details','log-card');", self.section)
        self.assertNotIn("details.open=true", self.section)
        self.assertNotIn("details.setAttribute('open'", self.section)
        self.assertIn(
            "Expand this section to load the newest 200 lines.",
            self.section,
        )
        self.assertIn(
            "Log output loads only when this section is expanded.",
            self.section,
        )
        self.assertIn(
            "details.addEventListener('toggle',()=>{if(details.open&&!view.loaded)void loadLog(view)})",
            self.section,
        )
        self.assertIn(
            "memberSelect.addEventListener('change',()=>{view.loaded=false;updateMemberPath(view);if(details.open)void loadLog(view)})",
            self.section,
        )
        self.assertIn(
            "linesSelect.addEventListener('change',()=>{view.loaded=false;if(details.open)void loadLog(view)})",
            self.section,
        )

    def test_server_supplied_log_data_uses_text_nodes_not_html_sinks(self) -> None:
        self.assertIn("element.textContent=String(text)", self.section)
        self.assertIn(
            "const code=node('code','',content||'The selected log file is empty.');",
            self.section,
        )
        self.assertIn(
            "copy.appendChild(node('code','log-file-path',String(item.path??'Path unavailable')))",
            self.section,
        )
        self.assertIn(
            "if(item.description)copy.appendChild(node('span','log-description',item.description))",
            self.section,
        )
        self.assertIn("list.replaceChildren(fragment)", self.section)
        for unsafe_sink in (
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
        ):
            self.assertNotIn(unsafe_sink, self.section)

    def test_page_uses_bounded_same_origin_application_log_api(self) -> None:
        self.assertIn("const CATALOG_ENDPOINT='/api/application-logs';", self.section)
        self.assertIn(
            "fetch(CATALOG_ENDPOINT,{cache:'no-store',credentials:'same-origin'})",
            self.section,
        )
        self.assertIn(
            "fetch(`${CATALOG_ENDPOINT}/${encodeURIComponent(String(view.item.id??''))}?${query.toString()}`,{cache:'no-store',credentials:'same-origin'})",
            self.section,
        )
        self.assertIn("const query=new URLSearchParams({member,lines:String(selectedLines)})", self.section)
        self.assertIn("[100,200,500].forEach", self.section)
        self.assertIn("response.status===403", self.section)
        self.assertIn("Administration sign-in is required", self.section)

        self.assertIn('APPLICATION_LOG_API_PATH = "/api/application-logs"', self.server_source)
        self.assertIn("def application_log_route_identifier(path: str)", self.server_source)
        self.assertIn("application_logs.is_application_log_id(identifier)", self.server_source)
        self.assertIn("if not self._admin_authenticated():", self.server_source)
        self.assertIn("application_logs.catalog_response()", self.server_source)
        self.assertIn("application_logs.content_response(", self.server_source)
        self.assertIn("min(application_logs.MAX_TAIL_LINES, lines)", self.server_source)

    def test_render_dispatch_builds_the_logs_specific_page(self) -> None:
        self.assertIn(
            "from dashboard_logs_page import logs_page_section",
            self.builder_source,
        )
        self.assertIn("def logs_page_section()", self.logs_page_source)
        self.assertIn("if page_key == 'logs':", self.builder_source)
        self.assertIn(
            "return logs_page_section(), None",
            self.builder_source,
        )
        self.assertIn(
            "('logs', 'logs.html', 'Onion Sentinel Logs', 'Application and service runtime logs')",
            self.shell_source,
        )
        self.assertNotIn('id="overview-view"', self.page)
        self.assertNotIn('id="alerts-view"', self.page)

    def test_mac_studio_installer_packages_the_log_api_module(self) -> None:
        page_copy_command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_logs_page.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_logs_page.py"'
        )
        self.assertEqual(self.installer_source.count(page_copy_command), 1)
        copy_command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/application_logs.py" '
            '"$DASHBOARD_RUNTIME_DIR/application_logs.py"'
        )
        self.assertEqual(self.installer_source.count(copy_command), 1)
        self.assertLess(
            self.installer_source.index(copy_command),
            self.installer_source.index(
                'cp "$REPO_DIR/onion-sentinel-dashboard/http_runtime.py"'
            ),
        )


if __name__ == "__main__":
    unittest.main()
