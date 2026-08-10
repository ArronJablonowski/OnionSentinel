import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_portal_admin_session_store import load_portal


class PortalReportCatalogContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.portal = load_portal()

    def test_title_prefers_title_then_h1_then_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            titled = root / "one.html"
            titled.write_text("<h1>Fallback</h1><title>  Primary &amp; Safe </title>")
            heading = root / "two.html"
            heading.write_text("<h1><span>Heading</span> Name</h1>")
            empty = root / "fallback_name.html"
            empty.write_text("<p>none</p>")
            self.assertEqual(self.portal.title_from_html(titled), "Primary & Safe")
            self.assertEqual(self.portal.title_from_html(heading), "Heading Name")
            self.assertEqual(self.portal.title_from_html(empty), "fallback name")

    def test_category_and_daily_brief_contracts_are_exact(self):
        self.assertEqual(
            self.portal.category_for(Path("/x/Daily Threat Intel Briefs/a.html")),
            "Threat Intel",
        )
        self.assertEqual(
            self.portal.category_for(Path("/x/forest_room_dashboard.html")),
            "Prototype: Web app",
        )
        report = self.portal.Report(
            "id", "Daily", Path("2026-08-10 - Daily Threat Intel Brief.html"),
            "rel", "Threat Intel", 1, 1.0, False,
        )
        self.assertTrue(self.portal.is_daily_threat_brief_file(report))

    def test_scan_is_deduplicated_filtered_and_newest_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "library"
            root.mkdir()
            older = root / "older.html"
            older.write_text("<title>Older</title>")
            newer = root / "newer.htm"
            newer.write_text("<title>Newer</title>")
            hidden = root / ".hidden"
            hidden.mkdir()
            (hidden / "secret.html").write_text("<title>Hidden</title>")
            ignored = root / "node_modules"
            ignored.mkdir()
            (ignored / "dependency.html").write_text("<title>Dependency</title>")
            os.utime(older, (100, 100))
            os.utime(newer, (200, 200))
            with (
                mock.patch.object(self.portal, "HOME", Path(tmp).resolve()),
                mock.patch.object(self.portal, "SCAN_ROOTS", [root]),
                mock.patch.object(self.portal, "STANDALONE_HTML", [older]),
            ):
                reports = self.portal.scan_reports()
            self.assertEqual([report.title for report in reports], ["Newer", "Older"])
            self.assertEqual(len({report.rid for report in reports}), 2)
            self.assertEqual(reports[1].rel, "library/older.html")

    def test_soc_default_and_human_size_projection_are_stable(self):
        report = self.portal.Report(
            "soc", "SOC Alerts", Path("index.html"),
            "Cybersecurity/SOC Alerts/index.html", "Cybersecurity", 0, 0.0, True,
        )
        self.assertEqual(self.portal.soc_alerts_default_path([report]), "/view/soc/")
        self.assertEqual(self.portal.human_size(1024), "1.0 KB")
        self.assertEqual(self.portal.human_size(1023), "1023 B")


if __name__ == "__main__":
    unittest.main()
