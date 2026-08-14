import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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

    def test_empty_renderer_unpacks_status_before_analysis_and_cells(self) -> None:
        trace: list[tuple[object, ...]] = []

        class StatusProbe:
            def __iter__(self):
                trace.append(("status_iter",))
                return iter(("none", "None", "No evidence"))

        class AnalysisProbe(dict[str, object]):
            def __len__(self) -> int:
                trace.append(("analysis_len",))
                return super().__len__()

        def cell(value: object, max_len: int = 420) -> str:
            trace.append(("cell", value, max_len))
            return f"C[{value}]"

        with mock.patch.object(self.components, "_cell", side_effect=cell):
            rendered = self.components.render_pcap_evidence_markdown(
                StatusProbe(),
                AnalysisProbe(),
            )

        self.assertEqual(
            trace,
            [
                ("status_iter",),
                ("analysis_len",),
                ("cell", "None", 420),
                ("cell", "No evidence", 420),
            ],
        )
        self.assertEqual(
            rendered,
            "\n".join(
                [
                    "## Parsed PCAP Evidence",
                    "",
                    "| Field | Value |",
                    "| --- | --- |",
                    "| Status | C[None] |",
                    "| Detail | C[No evidence] |",
                    "",
                    "No parsed Zeek/TShark PCAP summary is available for this alert group yet.",
                ]
            ),
        )

    def test_unavailable_parsers_preserve_header_lookup_and_path_order(self) -> None:
        trace: list[tuple[object, ...]] = []

        class MappingProbe(dict[str, object]):
            def __init__(self, label: str, **values: object) -> None:
                super().__init__(values)
                self.label = label

            def get(self, key: str, default: object = None) -> object:
                trace.append(("get", self.label, key, default))
                return super().get(key, default)

        class AnalysisProbe(MappingProbe):
            def __len__(self) -> int:
                trace.append(("analysis_len",))
                return super().__len__()

        class FilesProbe(list[object]):
            def __len__(self) -> int:
                trace.append(("files_len",))
                return super().__len__()

        class NameProbe:
            @property
            def name(self) -> str:
                trace.append(("path_name",))
                return "unit-analysis.json"

        request = MappingProbe("request", request_id="request-7")
        zeek = MappingProbe("zeek", available=False, reason="zeek-offline")
        tshark = MappingProbe("tshark", available=False, reason="tshark-offline")
        files = FilesProbe([{"name": "one"}, {"name": "two"}])
        analysis = AnalysisProbe(
            "analysis",
            request=request,
            zeek=zeek,
            tshark=tshark,
            pcap_files=files,
            generated_at="stored-time",
            artifact_state="parsed",
            _analysis_path="/private/unit-analysis.json",
        )

        def cell(value: object, max_len: int = 420) -> str:
            trace.append(("cell", value, max_len))
            return f"C[{value}]"

        def path(value: str) -> NameProbe:
            trace.append(("path", value))
            return NameProbe()

        with (
            mock.patch.object(self.components, "_cell", side_effect=cell),
            mock.patch.object(self.components, "Path", side_effect=path),
        ):
            rendered = self.components.render_pcap_evidence_markdown(
                ("failed", "Failed", "Parser unavailable"),
                analysis,
            )

        self.assertIn("| Request ID | C[request-7] |", rendered)
        self.assertIn("| Generated at | C[stored-time] |", rendered)
        self.assertIn("| PCAP files parsed | 2 |", rendered)
        self.assertIn("Zeek unavailable: C[zeek-offline]", rendered)
        self.assertIn("TShark unavailable: C[tshark-offline]", rendered)
        self.assertEqual(
            trace,
            [
                ("analysis_len",),
                ("get", "analysis", "request", None),
                ("get", "analysis", "request", None),
                ("get", "analysis", "zeek", None),
                ("get", "analysis", "zeek", None),
                ("get", "analysis", "tshark", None),
                ("get", "analysis", "tshark", None),
                ("get", "analysis", "pcap_files", None),
                ("get", "analysis", "pcap_files", None),
                ("get", "analysis", "generated_at", None),
                ("cell", "Failed", 420),
                ("cell", "Parser unavailable", 420),
                ("get", "request", "request_id", None),
                ("cell", "request-7", 420),
                ("cell", "stored-time", 420),
                ("get", "analysis", "artifact_state", None),
                ("cell", "parsed", 420),
                ("files_len",),
                ("get", "analysis", "_analysis_path", None),
                ("path", "/private/unit-analysis.json"),
                ("path_name",),
                ("cell", "unit-analysis.json", 420),
                ("get", "zeek", "available", None),
                ("get", "zeek", "reason", None),
                ("cell", "zeek-offline", 420),
                ("get", "tshark", "available", None),
                ("get", "tshark", "reason", None),
                ("cell", "tshark-offline", 420),
            ],
        )

    def test_available_parser_sections_preserve_bounds_and_sample_admission(self) -> None:
        trace: list[tuple[object, ...]] = []

        class MappingProbe(dict[str, object]):
            def __init__(self, label: str, **values: object) -> None:
                super().__init__(values)
                self.label = label

            def get(self, key: str, default: object = None) -> object:
                trace.append(("get", self.label, key, default))
                return super().get(key, default)

        class SliceProbe(list[object]):
            def __init__(self, label: str, values: list[object]) -> None:
                super().__init__(values)
                self.label = label

            def __getitem__(self, item: object) -> object:
                trace.append(("slice", self.label, item))
                return super().__getitem__(item)

        category_keys = (
            "top_connections",
            "dns_queries",
            "tls_sni",
            "http_hosts",
            "notices",
            "weird",
        )
        zeek_values = {
            key: SliceProbe(key, list(range(12)))
            for key in category_keys
        }
        zeek = MappingProbe(
            "zeek",
            available=True,
            record_counts={"conn.log": 2},
            **zeek_values,
        )
        admitted_sample = MappingProbe(
            "sample",
            pcap="/private/admitted.pcap",
            protocol_hierarchy="frame/ip",
            conversations="tcp conversation",
        )
        excluded_sample = MappingProbe(
            "excluded",
            pcap="/private/excluded.pcap",
            protocol_hierarchy="excluded",
            conversations="excluded",
        )
        samples = SliceProbe("samples", ["skip", admitted_sample, excluded_sample])
        tshark = MappingProbe("tshark", available=True, samples=samples)
        analysis = {
            "request": {},
            "zeek": zeek,
            "tshark": tshark,
            "pcap_files": [{}],
        }

        def bounded(value: object, language: str = "json", max_len: int = 1800) -> str:
            trace.append(("bounded", value, language, max_len))
            return f"B[{language}]"

        with mock.patch.object(
            self.components,
            "_bounded_block",
            side_effect=bounded,
        ):
            rendered = self.components.render_pcap_evidence_markdown(
                ("analyzed", "Analyzed", "Available"),
                analysis,
            )

        self.assertIn("#### admitted.pcap", rendered)
        self.assertNotIn("excluded.pcap", rendered)
        bounded_calls = [event for event in trace if event[0] == "bounded"]
        self.assertEqual(len(bounded_calls), 8)
        for key in category_keys:
            self.assertIn(("slice", key, slice(None, 10, None)), trace)
        self.assertIn(("slice", "samples", slice(None, 2, None)), trace)
        self.assertEqual(
            bounded_calls[-2:],
            [
                ("bounded", "frame/ip", "text", 1800),
                ("bounded", "tcp conversation", "text", 1800),
            ],
        )

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
