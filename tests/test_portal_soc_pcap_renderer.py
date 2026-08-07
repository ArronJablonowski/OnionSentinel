"""Direct contracts for bounded escaped PCAP evidence rendering."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_pcap_renderer import render_pcap_summary  # noqa: E402


class PcapRendererTests(unittest.TestCase):
    def test_available_summaries_are_escaped_bounded_and_payload_free(self) -> None:
        record = {
            "request": {"request_id": "<script>request</script>"},
            "generated_at": "2026-08-07T12:00:00Z",
            "_analysis_path": "/private/evidence/analysis.json",
            "pcap_files": [{"name": "one"}, {"name": "two"}],
            "zeek": {
                "available": True,
                "record_counts": {"conn": 12},
                "dns_queries": [{"query": f"dns-{index}"} for index in range(15)],
                "notices": ["<img src=x onerror=alert(1)>"],
            },
            "tshark": {
                "available": True,
                "samples": [
                    {"protocol_hierarchy": f"sample-{index}", "conversations": "x" * 1900}
                    for index in range(4)
                ],
            },
        }

        rendered = render_pcap_summary(record)

        self.assertIn("<h3>Parsed PCAP Evidence</h3>", rendered)
        self.assertIn("analysis.json", rendered)
        self.assertNotIn("/private/evidence", rendered)
        self.assertIn("&lt;script&gt;request&lt;/script&gt;", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertIn("dns-9", rendered)
        self.assertNotIn("dns-10", rendered)
        self.assertEqual(rendered.count("<h5>Protocol hierarchy</h5>"), 2)
        self.assertIn("... truncated ...", rendered)
        self.assertIn("raw packet payloads are not displayed", rendered)

    def test_unavailable_parsers_expose_escaped_reasons(self) -> None:
        rendered = render_pcap_summary({
            "request": {}, "pcap_files": [],
            "zeek": {"available": False, "reason": "<offline>"},
            "tshark": {"available": False, "reason": "not installed"},
        })

        self.assertIn("Zeek unavailable: &lt;offline&gt;", rendered)
        self.assertIn("TShark unavailable: not installed", rendered)
        self.assertIn("PCAP files parsed</th><td>0", rendered)

    def test_available_tshark_without_samples_is_explicit(self) -> None:
        rendered = render_pcap_summary({
            "zeek": {"available": True},
            "tshark": {"available": True, "samples": []},
            "pcap_files": [{}],
        })
        self.assertIn("No bounded TShark samples were produced", rendered)


if __name__ == "__main__":
    unittest.main()
