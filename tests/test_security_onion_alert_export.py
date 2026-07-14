"""Static safety checks for burst-aware Security Onion alert export."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SecurityOnionAlertExportTest(unittest.TestCase):
    def test_export_uses_stable_search_after_pagination(self) -> None:
        code = (ROOT / "security-onion" / "bin" / "export-recent-alerts").read_text()
        self.assertIn('SEARCH_AFTER_FIELD=', code)
        self.assertIn('"search_after": $SEARCH_AFTER', code.replace('\\"', '"'))
        self.assertIn(".hits.hits[-1].sort // empty", code)
        self.assertIn('{"_id": {"order": "desc"}}', code)
        self.assertIn('SO_ALERT_MAX_TOTAL', code)
        self.assertIn('saturated: $saturated', code)

    def test_export_caps_server_side_work(self) -> None:
        code = (ROOT / "security-onion" / "bin" / "export-recent-alerts").read_text()
        self.assertIn('MAX_SIZE=500', code)
        self.assertIn('MAX_TOTAL > 20000', code)


if __name__ == "__main__":
    unittest.main()
