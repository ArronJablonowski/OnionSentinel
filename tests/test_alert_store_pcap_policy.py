"""Static regression checks for alert-store PCAP auto-request policy."""
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_STORE = REPO_ROOT / "n8n" / "alert_store" / "alert_store.js"
COMPOSE = REPO_ROOT / "n8n" / "docker-compose.yml"
ENV_EXAMPLE = REPO_ROOT / "n8n" / ".env.example"
PCAP_WORKFLOW = REPO_ROOT / "n8n" / "workflows" / "onion-sentinel-pcap-broker.workflow.json"


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

    def test_chunked_pcap_artifact_upload_contract_is_wired(self) -> None:
        code = ALERT_STORE.read_text()
        compose = COMPOSE.read_text()
        env_example = ENV_EXAMPLE.read_text()
        workflow = PCAP_WORKFLOW.read_text()

        self.assertIn("PCAP_ARTIFACT_CHUNK_MAX_BYTES", code)
        self.assertIn("CREATE TABLE IF NOT EXISTS pcap_artifact_chunks", code)
        self.assertIn("async function ingestPcapArtifactChunk", code)
        self.assertIn("parsedUrl.pathname === '/pcap/artifact-chunk'", code)
        self.assertIn("PCAP_ARTIFACT_CHUNK_MAX_BYTES=${PCAP_ARTIFACT_CHUNK_MAX_BYTES:-524288}", compose)
        self.assertIn("PCAP_ARTIFACT_CHUNK_MAX_BYTES=524288", env_example)
        self.assertIn("body.chunk_base64 ? '/pcap/artifact-chunk' : '/pcap/artifact'", workflow)


if __name__ == "__main__":
    unittest.main()
