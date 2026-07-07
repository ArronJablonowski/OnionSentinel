import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPT_DIR / "dashboard_pcap_components.py"


def load_module():
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location("dashboard_pcap_components", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DashboardPcapComponentsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.components = load_module()

    def test_renders_empty_pcap_state_without_raw_capture_links(self) -> None:
        html = self.components.render_pcap_evidence_markdown(
            ("none", "None", "No parsed PCAP analysis is available"),
            None,
        )

        self.assertIn("## Parsed PCAP Evidence", html)
        self.assertIn("| Status | None |", html)
        self.assertNotIn(".pcap", html.lower())
        self.assertNotIn(".pcapng", html.lower())

    def test_renders_bounded_zeek_and_tshark_summary(self) -> None:
        record = {
            "_analysis_path": "/runtime/pcap-analysis/unit-pcap-analysis.json",
            "generated_at": "2026-07-07T12:00:00Z",
            "artifact_state": "extracted-artifact",
            "request": {"request_id": "unit-request", "alert_id": "unit-alert", "group_id": "unit-group"},
            "pcap_files": [{"name": "capture.pcap", "size_bytes": 12, "sha256": "a" * 64}],
            "zeek": {
                "available": True,
                "record_counts": {"conn.log": 1},
                "dns_queries": [{"query": "example.test", "count": 1}],
            },
            "tshark": {
                "available": True,
                "samples": [{"pcap": "/tmp/capture.pcap", "protocol_hierarchy": "frame\\nip", "conversations": "tcp"}],
            },
        }

        html = self.components.render_pcap_evidence_markdown(
            ("analyzed", "Analyzed", "Parsed Zeek/TShark PCAP analysis is available"),
            record,
            "2026-07-07  12:00:00Z",
        )

        self.assertIn("### Zeek Summary", html)
        self.assertIn("### TShark Corroboration", html)
        self.assertIn("example.test", html)
        self.assertIn("unit-pcap-analysis.json", html)
        self.assertIn("Raw packet payloads are not displayed", html)

    def test_large_parser_output_is_bounded_before_rendering(self) -> None:
        record = {
            "request": {"request_id": "large-output"},
            "pcap_files": [],
            "zeek": {
                "available": True,
                "record_counts": {"dns.log": 100},
                "dns_queries": [{"query": f"long-{index}.example.test", "detail": "x" * 500} for index in range(30)],
            },
            "tshark": {
                "available": True,
                "samples": [{"pcap": "capture.pcap", "protocol_hierarchy": "frame\n" + ("x" * 6000)}],
            },
        }

        html = self.components.render_pcap_evidence_markdown(
            ("analyzed", "Analyzed", "Parsed Zeek/TShark PCAP analysis is available"),
            record,
        )

        self.assertIn("... truncated ...", html)
        self.assertLess(len(html), 14000)

    def test_index_ignores_empty_no_packet_parser_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "empty-pcap-analysis.json").write_text(
                '{"request":{"group_id":"empty"},"pcap_files":[],"zeek":{"available":false}}',
                encoding="utf-8",
            )
            (root / "valid-pcap-analysis.json").write_text(
                '{"request":{"group_id":"valid"},"pcap_files":[{"name":"unit.pcap"}],"zeek":{"available":true}}',
                encoding="utf-8",
            )

            index = self.components.build_pcap_analysis_index(root)

        self.assertNotIn("empty", index["group_ids"])
        self.assertIn("valid", index["group_ids"])


if __name__ == "__main__":
    unittest.main()
