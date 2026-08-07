import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_BUILDER = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"
SETTINGS_MODULES = (
    REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_settings_assets.py",
    REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_settings_agent_card.py",
    REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_settings_page.py",
    REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_settings_client_shell.py",
    REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_settings_client_model.py",
    REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_settings_client_actions.py",
)
PORTAL_ROUTES = REPO_ROOT / "onion-sentinel-dashboard" / "portal_request_routes.py"


def settings_source() -> str:
    """Return the complete Settings implementation across its owned modules."""
    paths = (DASHBOARD_BUILDER, *SETTINGS_MODULES)
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def load_dashboard_builder():
    script_dir = DASHBOARD_BUILDER.parent
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))
    spec = importlib.util.spec_from_file_location("settings_memory_dashboard_builder", DASHBOARD_BUILDER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_portal_routes():
    spec = importlib.util.spec_from_file_location(
        "settings_memory_portal_routes", PORTAL_ROUTES
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DashboardSettingsMemoryViewerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = load_dashboard_builder()
        cls.routes = load_portal_routes()

    def test_each_primary_and_reviewer_prompt_path_opens_its_collapsed_editor(self) -> None:
        source = settings_source()
        rendered = self.builder.settings_page_section()

        for prompt_target in (
            "soc-analyst-prompt",
            "soc-analyst-second-opinion-prompt",
            "incident-responder-prompt",
            "incident-responder-second-opinion-prompt",
            "siem-engineer-prompt",
            "siem-engineer-second-opinion-prompt",
            "cyber-threat-intel-prompt",
            "cyber-threat-intel-second-opinion-prompt",
            "threat-hunter-prompt",
            "threat-hunter-second-opinion-prompt",
        ):
            self.assertIn(f'data-prompt-target="{prompt_target}"', rendered)
        self.assertEqual(rendered.count('class="settings-path-row settings-file-link settings-prompt-link"'), 10)
        helper = source[source.index("def agent_prompt_editors("):source.index("def list_ollama_models(")]
        self.assertEqual(helper.count('<details class="settings-provider-details settings-agent-prompt-details"'), 2)
        self.assertNotIn("<details open", helper)
        self.assertLess(
            helper.index("Main system prompt"),
            helper.index("Second-opinion system prompt"),
        )
        for endpoint in (
            "/api/soc-settings/analyst-second-opinion-prompt",
            "/api/soc-settings/incident-responder-second-opinion-prompt",
            "/api/soc-settings/siem-engineer-second-opinion-prompt",
            "/api/soc-settings/cyber-threat-intel-second-opinion-prompt",
            "/api/soc-settings/threat-hunter-second-opinion-prompt",
        ):
            self.assertIn(endpoint, rendered)
        self.assertIn("const promptConfigurations = [...document.querySelectorAll('[data-prompt-save]')]", source)
        self.assertIn("panel.open = true;", source)
        self.assertIn("promptEditor.focus({preventScroll: true});", source)

    def test_each_agent_exposes_read_only_memory_and_shared_memory_buttons(self) -> None:
        rendered = self.builder.settings_page_section()

        for memory_key in (
            "soc-analyst",
            "incident-responder",
            "siem-engineer",
            "cyber-threat-intel",
            "threat-hunter",
        ):
            self.assertIn(f'data-memory-key="{memory_key}"', rendered)
        self.assertEqual(rendered.count('data-memory-key="shared"'), 5)
        self.assertIn('id="settings-memory-content" class="settings-memory-content"', rendered)
        self.assertNotIn('contenteditable="true"', rendered)

    def test_viewer_uses_text_content_and_has_no_memory_write_route(self) -> None:
        dashboard_source = settings_source()

        self.assertIn("memoryContent.textContent = data.content || '';", dashboard_source)
        self.assertIn("/api/soc-settings/agent-memory?key=", dashboard_source)
        self.assertIn("'shared': 'Shared Agent Memory'", dashboard_source)
        self.assertIn("memoryLabels[memoryKey] || 'Agent Memory'", dashboard_source)
        path = "/api/soc-settings/agent-memory"
        get_route = self.routes.classify_get_route(
            path,
            cti_program_path="/api/cyber-threat-intel/program",
            prompt_paths=frozenset(),
        )
        post_route = self.routes.classify_post_route(
            path,
            cti_program_path="/api/cyber-threat-intel/program",
            prompt_paths=frozenset(),
        )
        self.assertEqual(get_route.operation, "soc_agent_memory")
        self.assertFalse(post_route.accepted)

    def test_maxmind_databases_are_a_standalone_three_database_section(self) -> None:
        source = settings_source()
        rendered = self.builder.settings_page_section()

        agent_end = rendered.index('</section>\n      <section class="settings-maxmind-section"')
        maxmind_start = rendered.index('<section class="settings-maxmind-section"')
        self.assertLess(agent_end, maxmind_start)
        for database_type in ("asn", "city", "country"):
            self.assertIn(f'id="maxmind-geoip-{database_type}-db-path"', rendered)
            self.assertIn(f'id="maxmind-geoip-{database_type}-db-state"', rendered)
            self.assertIn(f'maxmind_geoip_{database_type}_db_path:', source)
        self.assertIn('id="save-maxmind-geoip-settings"', rendered)
        self.assertIn("applyGeoIpDatabaseStatuses(data.geoip_databases, data.geoip_database);", source)


if __name__ == "__main__":
    unittest.main()
