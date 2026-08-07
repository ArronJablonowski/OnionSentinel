"""Direct contracts for parsed PCAP artifact indexing and selection."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_pcap_artifacts import (  # noqa: E402
    PcapArtifactSources,
    build_pcap_analysis_index,
    has_parsed_pcap,
    newest_pcap_analysis_record,
)


class PcapArtifactTests(unittest.TestCase):
    def sources(self, records: dict[str, object], mtimes: dict[str, float] | None = None) -> PcapArtifactSources:
        paths = [Path(name) for name in records]

        def read(path: Path) -> object:
            value = records[str(path)]
            if isinstance(value, Exception):
                raise value
            return value

        return PcapArtifactSources(
            paths=lambda: paths,
            read_record=read,
            modified_time=lambda path: (mtimes or {}).get(str(path), 0.0),
        )

    def parsed(self, request_id: str, *, group: str = "group", alert: str = "alert",
               files: list | None = None, zeek: bool = True, tshark: bool = False) -> dict:
        return {
            "request": {"request_id": request_id, "group_id": group, "alert_id": alert},
            "pcap_files": files if files is not None else [{"sha256": request_id, "size_bytes": 10}],
            "zeek": {"available": zeek},
            "tshark": {"available": tshark},
        }

    def test_admission_requires_capture_and_available_parser(self) -> None:
        self.assertTrue(has_parsed_pcap(self.parsed("ok")))
        self.assertTrue(has_parsed_pcap(self.parsed("tshark", zeek=False, tshark=True)))
        self.assertFalse(has_parsed_pcap(self.parsed("none", files=[])))
        self.assertFalse(has_parsed_pcap(self.parsed("unparsed", zeek=False, tshark=False)))

    def test_index_deduplicates_capture_identity_and_ignores_malformed_records(self) -> None:
        records = {
            "one.json": self.parsed("one", files=[
                {"sha256": "same", "size_bytes": 100},
                {"sha256": "unique", "size_bytes": 25},
                {"sha256": "bad", "size_bytes": "invalid"},
            ]),
            "two.json": self.parsed("two", files=[{"sha256": "same", "size_bytes": 100}]),
            "invalid.json": {"pcap_files": []},
            "broken.json": ValueError("broken"),
        }

        index = build_pcap_analysis_index(self.sources(records))

        self.assertEqual(index["request_ids"], {"one", "two"})
        self.assertEqual(index["group_ids"], {"group"})
        self.assertEqual(index["alert_ids"], {"alert"})
        self.assertEqual(index["size_by_group_id"]["group"], 125)
        self.assertEqual(index["size_by_alert_id"]["alert"], 125)

    def test_newest_record_is_group_scoped_and_path_annotated(self) -> None:
        records = {
            "old.json": self.parsed("old"),
            "other.json": self.parsed("other", group="other-group"),
            "new.json": self.parsed("new"),
            "invalid.json": self.parsed("invalid", files=[]),
        }
        result = newest_pcap_analysis_record(
            "group", self.sources(records, {"old.json": 1, "other.json": 5, "new.json": 3}),
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["request"]["request_id"], "new")
        self.assertEqual(result["_analysis_path"], "new.json")
        self.assertIsNone(newest_pcap_analysis_record("missing", self.sources(records)))
        self.assertIsNone(newest_pcap_analysis_record("", self.sources(records)))


if __name__ == "__main__":
    unittest.main()
