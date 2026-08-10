import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"


def load_portal():
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    spec = importlib.util.spec_from_file_location(
        "report_portal_resource_library_contract",
        DASHBOARD / "report_portal.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PortalResourceLibraryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.portal = load_portal()

    def test_filename_sanitization_preserves_original_extension(self):
        sanitize = self.portal.sanitize_resource_filename
        self.assertEqual(sanitize("  Incident / Runbook.txt  ", ".pdf"), "Incident - Runbook.pdf")
        self.assertEqual(sanitize("Threat\\Intel", "pdf"), "Threat-Intel.pdf")
        with self.assertRaisesRegex(ValueError, "empty"):
            sanitize("...", ".pdf")

    def test_tag_normalization_is_bounded_ordered_and_case_insensitive(self):
        tags = self.portal.clean_resource_tags(
            ["  Incident   Response ", "incident response", "Forensics"]
            + [f"tag-{index}" for index in range(20)]
        )
        self.assertEqual(tags[:2], ["Incident Response", "Forensics"])
        self.assertEqual(len(tags), 12)

    def test_exact_source_lookup_is_confined_to_configured_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "library"
            root.mkdir()
            source = root / "guide.pdf"
            source.write_bytes(b"pdf")
            outside = Path(tmp) / "outside.pdf"
            outside.write_bytes(b"pdf")
            with mock.patch.object(self.portal, "RESOURCE_LIBRARY_SOURCES", [("Docs", root)]):
                resource_id = self.portal.resource_library_id_for(source.resolve())
                self.assertEqual(
                    self.portal.find_resource_library_pdf(resource_id, str(source)),
                    (source.resolve(), "Docs", Path("guide.pdf")),
                )
                outside_id = self.portal.resource_library_id_for(outside.resolve())
                self.assertIsNone(
                    self.portal.find_resource_library_pdf(outside_id, str(outside))
                )

    def test_favorite_and_tags_persist_exact_metadata_and_queue_refresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            metadata = Path(tmp) / "metadata.json"
            queue = Path(tmp) / "queue" / "requests.jsonl"
            resource_id = "0123456789ab"
            with (
                mock.patch.object(self.portal, "RESOURCE_LIBRARY_METADATA_FILE", metadata),
                mock.patch.object(self.portal, "RESOURCE_LIBRARY_REMOVAL_QUEUE", queue),
                mock.patch.object(self.portal, "trigger_resource_library_worker"),
                mock.patch.object(self.portal, "now_iso_local", return_value="2026-08-10T00:00:00-06:00"),
            ):
                ok, favorite = self.portal.set_resource_favorite(resource_id, True)
                self.assertTrue(ok)
                self.assertEqual(favorite["favorites"], [resource_id])
                ok, tagged = self.portal.set_resource_tags(
                    resource_id, "Incident Response; incident response; Forensics"
                )
                self.assertTrue(ok)
                self.assertEqual(tagged["tags"], ["Incident Response", "Forensics"])
                saved = self.portal.load_resource_library_metadata()
                self.assertEqual(saved["_favorites"], [resource_id])
                self.assertEqual(
                    saved[resource_id]["custom_tags"],
                    ["Incident Response", "Forensics"],
                )
                queued = queue.read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(queued), 2)
                self.assertIn('"action": "refresh"', queued[0])
                self.assertIn('"reason": "tags"', queued[1])


if __name__ == "__main__":
    unittest.main()
