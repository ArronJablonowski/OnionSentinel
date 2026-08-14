import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
if str(DASHBOARD) not in sys.path:
    sys.path.insert(0, str(DASHBOARD))

import portal_resource_library_store as store  # noqa: E402


class FakeRoot:
    def __init__(self, label, events, *, exists=True, sources=(), failure=None):
        self.label = label
        self.events = events
        self.exists_value = exists
        self.sources = list(sources)
        self.failure = failure

    def exists(self):
        self.events.append(("root.exists", self.label))
        if self.failure == "exists":
            raise RuntimeError(f"{self.label} exists failed")
        return self.exists_value

    def rglob(self, pattern):
        self.events.append(("root.rglob", self.label, pattern))
        if self.failure == "rglob":
            raise RuntimeError(f"{self.label} rglob failed")
        return iter(self.sources)


class FakeSource:
    def __init__(
        self,
        label,
        events,
        *,
        parts,
        name,
        is_file=True,
        rel=None,
        identity="miss",
    ):
        self.label = label
        self.events = events
        self.parts_value = tuple(parts)
        self.name_value = name
        self.is_file_value = is_file
        self.rel = Path(rel or name)
        self.identity = identity

    @property
    def parts(self):
        self.events.append(("source.parts", self.label))
        return self.parts_value

    @property
    def name(self):
        self.events.append(("source.name", self.label))
        return self.name_value

    def is_file(self):
        self.events.append(("source.is_file", self.label))
        return self.is_file_value

    def relative_to(self, root):
        self.events.append(("source.relative_to", self.label, root.label))
        return self.rel


class RecursivePdfLookupTests(unittest.TestCase):
    def test_recursive_lookup_preserves_filter_and_selection_order(self):
        events = []
        macos = FakeSource(
            "macos", events,
            parts=("root", "__MACOSX", "hidden.pdf"),
            name="hidden.pdf",
        )
        dot_file = FakeSource(
            "dot", events,
            parts=("root", "._hidden.pdf"),
            name="._hidden.pdf",
        )
        non_file = FakeSource(
            "non-file", events,
            parts=("root", "folder.pdf"),
            name="folder.pdf",
            is_file=False,
        )
        poster = FakeSource(
            "poster", events,
            parts=("root", "SANS_Posters", "poster.pdf"),
            name="poster.pdf",
            rel="SANS_Posters/poster.pdf",
            identity="target",
        )
        mismatch = FakeSource(
            "mismatch", events,
            parts=("root", "mismatch.pdf"),
            name="mismatch.pdf",
            identity="other",
        )
        target = FakeSource(
            "target", events,
            parts=("root", "target.pdf"),
            name="target.pdf",
            rel="nested/target.pdf",
            identity="target",
        )
        missing = FakeRoot("missing", events, exists=False)
        cheats = FakeRoot(
            "cheats", events,
            sources=(macos, dot_file, non_file, poster),
        )
        docs = FakeRoot("docs", events, sources=(mismatch, target))
        untouched = FakeRoot("untouched", events, failure="exists")

        def identity(source):
            events.append(("resource_id", source.label))
            return source.identity

        with mock.patch.object(store, "resource_library_id_for", side_effect=identity):
            result = store._recursive_source_pdf(
                "target",
                [
                    ("Missing", missing),
                    ("CheatSheets", cheats),
                    ("Docs", docs),
                    ("Untouched", untouched),
                ],
            )

        self.assertEqual(result, (target, "Docs", Path("nested/target.pdf")))
        self.assertEqual(
            events,
            [
                ("root.exists", "missing"),
                ("root.exists", "cheats"),
                ("root.rglob", "cheats", "*.pdf"),
                ("source.parts", "macos"),
                ("source.parts", "dot"),
                ("source.name", "dot"),
                ("source.parts", "non-file"),
                ("source.name", "non-file"),
                ("source.is_file", "non-file"),
                ("source.parts", "poster"),
                ("source.name", "poster"),
                ("source.is_file", "poster"),
                ("source.relative_to", "poster", "cheats"),
                ("root.exists", "docs"),
                ("root.rglob", "docs", "*.pdf"),
                ("source.parts", "mismatch"),
                ("source.name", "mismatch"),
                ("source.is_file", "mismatch"),
                ("source.relative_to", "mismatch", "docs"),
                ("resource_id", "mismatch"),
                ("source.parts", "target"),
                ("source.name", "target"),
                ("source.is_file", "target"),
                ("source.relative_to", "target", "docs"),
                ("resource_id", "target"),
            ],
        )

    def test_recursive_lookup_preserves_root_exception_boundaries(self):
        events = []
        with self.assertRaisesRegex(RuntimeError, "exists failed"):
            store._recursive_source_pdf(
                "target",
                [("Docs", FakeRoot("broken", events, failure="exists"))],
            )
        with self.assertRaisesRegex(RuntimeError, "rglob failed"):
            store._recursive_source_pdf(
                "target",
                [("Docs", FakeRoot("broken", events, failure="rglob"))],
            )


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
