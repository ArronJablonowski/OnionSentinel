import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPT_DIR / "dashboard_timeline_components.py"


def load_timeline_module():
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location("dashboard_timeline_components", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DashboardTimelineComponentsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.timeline = load_timeline_module()

    def test_single_observation_still_renders_standard_timeline(self) -> None:
        rendered = self.timeline.alert_seen_timeline_html({
            "member_timeline": [{
                "alert_id": "synthetic-alert-1",
                "timestamp": "2026-07-15T12:00:00-06:00",
                "first_seen": "2026-07-15T12:00:00-06:00",
                "last_seen": "2026-07-15T12:00:00-06:00",
                "seen_count": 1,
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "destination_port": "443",
            }]
        })

        self.assertIn("Duplicate Alert Timeline", rendered)
        self.assertIn("1 alert row(s), 1 observation(s)", rendered)
        self.assertIn("Only", rendered)
        self.assertIn("192.0.2.10", rendered)
        self.assertIn("0 seconds", rendered)


if __name__ == "__main__":
    unittest.main()
