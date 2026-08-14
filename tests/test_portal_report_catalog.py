#!/usr/bin/env python3
"""Contracts for read-only report catalog discovery."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

import portal_report_catalog as catalog  # noqa: E402
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


class Root:
    def __init__(
        self,
        label: str,
        *,
        exists: bool = True,
        is_file: bool = False,
        suffix: str = "",
        failure: Exception | None = None,
    ) -> None:
        self.label = label
        self.exists_value = exists
        self.is_file_value = is_file
        self.suffix = suffix
        self.failure = failure
        self.calls: list[str] = []

    def exists(self) -> bool:
        self.calls.append("exists")
        if self.failure is not None:
            raise self.failure
        return self.exists_value

    def is_file(self) -> bool:
        self.calls.append("is_file")
        return self.is_file_value

    def __repr__(self) -> str:
        return f"Root({self.label!r})"


class PortalReportCatalogTests(unittest.TestCase):
    def test_candidate_traversal_preserves_order_pruning_and_standalones(self) -> None:
        html_file = Root("file", is_file=True, suffix=".HTML")
        missing = Root("missing", exists=False)
        directory = Root("directory")
        non_html_file = Root("text-file", is_file=True, suffix=".txt")
        standalone = Root("standalone")
        standalone_missing = Root("standalone-missing", exists=False)
        top_dirnames = ["keep", ".hidden", "node_modules", "excluded"]
        walk_calls: list[Root] = []

        def walk(root):
            walk_calls.append(root)
            if root is directory:
                return iter((
                    (
                        "/reports",
                        top_dirnames,
                        ["first.HTML", "skip.txt", "second.htm"],
                    ),
                    ("/reports/keep", [], ["third.HtM"]),
                ))
            return iter(())

        with (
            mock.patch.object(catalog.os, "walk", side_effect=walk),
            mock.patch.object(
                catalog,
                "should_skip_dir",
                wraps=catalog.should_skip_dir,
            ) as skip_dir,
        ):
            result = catalog._candidate_paths(
                [html_file, missing, directory, non_html_file],
                [standalone, standalone_missing, html_file],
                {"node_modules", "excluded"},
            )

        self.assertEqual(
            result,
            [
                html_file,
                Path("/reports/first.HTML"),
                Path("/reports/second.htm"),
                Path("/reports/keep/third.HtM"),
                standalone,
                html_file,
            ],
        )
        self.assertEqual(walk_calls, [directory, non_html_file])
        self.assertEqual(top_dirnames, ["keep"])
        self.assertEqual(
            skip_dir.call_args_list,
            [
                mock.call(Path("/reports/keep"), {"node_modules", "excluded"}),
                mock.call(Path("/reports/.hidden"), {"node_modules", "excluded"}),
                mock.call(Path("/reports/node_modules"), {"node_modules", "excluded"}),
                mock.call(Path("/reports/excluded"), {"node_modules", "excluded"}),
            ],
        )
        self.assertEqual(html_file.calls, ["exists", "is_file", "exists"])
        self.assertEqual(missing.calls, ["exists"])
        self.assertEqual(directory.calls, ["exists", "is_file"])
        self.assertEqual(non_html_file.calls, ["exists", "is_file"])
        self.assertEqual(standalone.calls, ["exists"])
        self.assertEqual(standalone_missing.calls, ["exists"])

    def test_candidate_discovery_prunes_real_hidden_and_excluded_trees(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            reports = root / "reports"
            keep = reports / "keep"
            hidden = reports / ".hidden"
            excluded = reports / "node_modules"
            keep.mkdir(parents=True)
            hidden.mkdir()
            excluded.mkdir()
            (reports / "index.HTML").write_text("index")
            (reports / "notes.txt").write_text("notes")
            (keep / "nested.htm").write_text("nested")
            (hidden / "hidden.html").write_text("hidden")
            (excluded / "dependency.html").write_text("dependency")
            standalone = root / "standalone.txt"
            standalone.write_text("standalone")

            result = catalog._candidate_paths(
                [reports], [standalone], {"node_modules"}
            )

        self.assertEqual(
            result,
            [reports / "index.HTML", keep / "nested.htm", standalone],
        )

    def test_candidate_discovery_preserves_exception_boundaries(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "exists failed"):
            catalog._candidate_paths(
                [Root("broken", failure=RuntimeError("exists failed"))],
                [],
                set(),
            )

        directory = Root("directory")
        with mock.patch.object(
            catalog.os,
            "walk",
            side_effect=RuntimeError("walk failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "walk failed"):
                catalog._candidate_paths([directory], [], set())

        with self.assertRaisesRegex(RuntimeError, "standalone failed"):
            catalog._candidate_paths(
                [],
                [Root("broken", failure=RuntimeError("standalone failed"))],
                set(),
            )


if __name__ == "__main__":
    unittest.main()
