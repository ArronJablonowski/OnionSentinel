from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_detail_runtime import (  # noqa: E402
    soc_alert_validate_detail_layout_html,
)


class PortalSocDetailRuntimeTests(unittest.TestCase):
    def runtime(self, markers=None):
        return SimpleNamespace(
            re=re,
            SOC_ALERT_DETAIL_LAYOUT_VERSION="layout-v1",
            SOC_ALERT_DETAIL_LAYOUT_MARKERS=markers or (
                ("Alpha", '<section id="alpha">'),
                ("Beta", '<section id="beta">'),
            ),
        )

    def test_layout_validation_accepts_exact_version_markers_and_order(self) -> None:
        detail_html = (
            '<article data-layout-version="layout-v1">'
            '<section id="alpha">A</section>'
            '<section id="beta">B</section>'
            "</article>"
        )

        self.assertEqual(
            soc_alert_validate_detail_layout_html(self.runtime(), detail_html),
            [],
        )

    def test_layout_validation_preserves_exact_version_and_count_diagnostics(self) -> None:
        detail_html = (
            '<section id="alpha"></section>'
            '<section id="alpha"></section>'
        )

        self.assertEqual(
            soc_alert_validate_detail_layout_html(self.runtime(), detail_html),
            [
                "Report layout version is missing; expected layout-v1. "
                "The dashboard must be rebuilt from the current report template.",
                'Required section "Alpha" appeared 2 time(s); exactly one is required.',
                'Required section "Beta" appeared 0 time(s); exactly one is required.',
            ],
        )

    def test_layout_validation_reports_only_canonical_order_for_reversed_markers(self) -> None:
        detail_html = (
            '<article data-layout-version="layout-v1">'
            '<section id="beta"></section>'
            '<section id="alpha"></section>'
            "</article>"
        )

        self.assertEqual(
            soc_alert_validate_detail_layout_html(self.runtime(), detail_html),
            ["Required report sections are not in the canonical order."],
        )

    def test_layout_validation_deduplicates_repeated_diagnostics_stably(self) -> None:
        runtime = self.runtime((
            ("Repeated", "missing-marker"),
            ("Repeated", "missing-marker"),
        ))

        self.assertEqual(
            soc_alert_validate_detail_layout_html(
                runtime,
                '<div data-layout-version="layout-v1"></div>',
            ),
            [
                'Required section "Repeated" appeared 0 time(s); exactly one is required.'
            ],
        )


if __name__ == "__main__":
    unittest.main()
