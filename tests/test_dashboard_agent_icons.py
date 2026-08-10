import struct
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_ROOT = REPO_ROOT / "onion-sentinel-dashboard"
DASHBOARD_BUILDER = DASHBOARD_ROOT / "scripts" / "build_soc_alerts_dashboard.py"
DASHBOARD_BUILDER_RUNTIME = DASHBOARD_ROOT / "scripts" / "dashboard_builder_runtime.py"
BUILDER_LAYER_PATHS = tuple(sorted((DASHBOARD_ROOT / "scripts").glob("dashboard_builder_*.py")))
SETTINGS_AGENT_CARD = DASHBOARD_ROOT / "scripts" / "dashboard_settings_agent_card.py"
ASSET_ROOT = DASHBOARD_ROOT / "assets"


class DashboardAgentIconTest(unittest.TestCase):
    def test_agent_icons_are_consistent_transparent_png_assets(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (*BUILDER_LAYER_PATHS, SETTINGS_AGENT_CARD)
        )
        icon_names = (
            "settings-soc-analyst-prompt.png",
            "settings-incident-responder-prompt.png",
            "settings-siem-engineer-prompt.png",
            "settings-cyber-threat-intel-prompt.png",
            "settings-threat-hunter-prompt.png",
        )

        for icon_name in icon_names:
            self.assertIn(f'assets/{icon_name}', source)
            icon_data = (ASSET_ROOT / icon_name).read_bytes()
            self.assertEqual(icon_data[:8], b"\x89PNG\r\n\x1a\n")
            width, height = struct.unpack(">II", icon_data[16:24])
            self.assertEqual((width, height), (512, 512))
            self.assertIn(icon_data[25], (4, 6), f"{icon_name} must retain an alpha channel")

        self.assertNotIn("settings-cyber-threat-intel-prompt.svg", source)


if __name__ == "__main__":
    unittest.main()
