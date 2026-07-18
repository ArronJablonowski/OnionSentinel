import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_BUILDER = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"
PORTAL = REPO_ROOT / "onion-sentinel-dashboard" / "report_portal.py"


class DashboardSettingsMemoryViewerTest(unittest.TestCase):
    def test_each_prompt_path_opens_its_existing_editor(self) -> None:
        source = DASHBOARD_BUILDER.read_text(encoding="utf-8")

        for prompt_target in (
            "soc-analyst-prompt",
            "incident-responder-prompt",
            "siem-engineer-prompt",
            "cyber-threat-intel-prompt",
            "threat-hunter-prompt",
        ):
            self.assertIn(f'data-prompt-target="{prompt_target}"', source)
        self.assertEqual(source.count('class="settings-path-row settings-file-link settings-prompt-link"'), 5)
        self.assertIn("panel.open = true;", source)
        self.assertIn("promptEditor.focus({preventScroll: true});", source)

    def test_each_agent_exposes_read_only_memory_and_shared_memory_buttons(self) -> None:
        source = DASHBOARD_BUILDER.read_text(encoding="utf-8")

        for memory_key in (
            "soc-analyst",
            "incident-responder",
            "siem-engineer",
            "cyber-threat-intel",
            "threat-hunter",
        ):
            self.assertIn(f'data-memory-key="{memory_key}"', source)
        self.assertEqual(source.count('data-memory-key="shared"'), 5)
        self.assertIn('id="settings-memory-content" class="settings-memory-content"', source)
        self.assertNotIn('contenteditable="true"', source)

    def test_viewer_uses_text_content_and_has_no_memory_write_route(self) -> None:
        dashboard_source = DASHBOARD_BUILDER.read_text(encoding="utf-8")
        portal_source = PORTAL.read_text(encoding="utf-8")

        self.assertIn("memoryContent.textContent = data.content || '';", dashboard_source)
        self.assertIn("/api/soc-settings/agent-memory?key=", dashboard_source)
        self.assertIn("'shared': 'Shared Agent Memory'", dashboard_source)
        self.assertIn("memoryLabels[memoryKey] || 'Agent Memory'", dashboard_source)
        self.assertIn('if path == "/api/soc-settings/agent-memory":', portal_source)
        self.assertNotIn('if parsed.path == "/api/soc-settings/agent-memory":', portal_source)


if __name__ == "__main__":
    unittest.main()
