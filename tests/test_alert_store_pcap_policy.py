"""Static regression checks for alert-store PCAP auto-request policy."""
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_STORE = REPO_ROOT / "n8n" / "alert_store" / "alert_store.js"
COMPOSE = REPO_ROOT / "n8n" / "docker-compose.yml"
ENV_EXAMPLE = REPO_ROOT / "n8n" / ".env.example"


class AlertStorePcapPolicyTest(unittest.TestCase):
    def test_alert_store_auto_queues_pcap_for_configured_levels(self) -> None:
        code = ALERT_STORE.read_text()

        self.assertIn("PCAP_AUTO_REQUEST_LEVELS", code)
        self.assertIn("critical,high", code)
        self.assertIn("async function maybeQueueAutomaticPcapRequest", code)
        self.assertIn("const pcap = await maybeQueueAutomaticPcapRequest(alert, row, inserted, suppression);", code)
        self.assertIn("pcap,", code)
        self.assertIn("Automatic PCAP request for ${level} alert", code)

    def test_runtime_templates_expose_auto_pcap_policy(self) -> None:
        compose = COMPOSE.read_text()
        env_example = ENV_EXAMPLE.read_text()

        self.assertIn("PCAP_AUTO_REQUEST_LEVELS=${PCAP_AUTO_REQUEST_LEVELS:-critical,high}", compose)
        self.assertIn("PCAP_AUTO_REQUEST_LEVELS=critical,high", env_example)


if __name__ == "__main__":
    unittest.main()
