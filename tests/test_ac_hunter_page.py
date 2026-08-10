#!/usr/bin/env python3
"""Frontend contracts for the AC Hunter behavioral-triage workspace."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
BUILDER_PATH = DASHBOARD_DIR / "scripts" / "build_soc_alerts_dashboard.py"
BUILDER_RUNTIME_PATH = DASHBOARD_DIR / "scripts" / "dashboard_builder_runtime.py"
AC_HUNTER_PAGE_PATH = DASHBOARD_DIR / "scripts" / "dashboard_ac_hunter_page.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "ac_hunter_page_builder",
        BUILDER_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AcHunterPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = load_builder()
        cls.section = cls.builder.ac_hunter_page_section()
        cls.page = cls.builder.render_static_page(
            cls.builder.build_html([]),
            "ac_hunter",
            [],
        )
        cls.builder_source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(BUILDER_PATH.parent.glob("dashboard_builder_*.py"))
        )
        cls.page_source = AC_HUNTER_PAGE_PATH.read_text(encoding="utf-8")
        cls.installer_source = INSTALLER_PATH.read_text(encoding="utf-8")

    def test_renderer_is_owned_by_a_deployed_page_module(self) -> None:
        self.assertIn(
            "from dashboard_ac_hunter_page import ac_hunter_page_section",
            self.builder_source,
        )
        self.assertIn("def ac_hunter_page_section()", self.page_source)
        copy_command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_ac_hunter_page.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_ac_hunter_page.py"'
        )
        self.assertEqual(self.installer_source.count(copy_command), 1)

    def test_navigation_and_page_identity_are_generated(self) -> None:
        keys = [definition[0] for definition in self.builder.PAGE_DEFS]

        self.assertEqual(
            keys[keys.index("system_health") + 1],
            "ac_hunter",
        )
        self.assertIn(
            '<a class="nav-item active" href="ac-hunter.html"',
            self.page,
        )
        self.assertIn(
            '<h1 id="page-title">AC Hunter Deep Review</h1>',
            self.page,
        )
        self.assertIn('id="ac-hunter-deep-review-view"', self.page)
        self.assertIn(
            "Behavioral network findings correlated for analyst triage",
            self.page,
        )

    def test_page_preserves_the_behavioral_triage_guardrail(self) -> None:
        self.assertIn(
            "AC Hunter is a behavioral triage source.",
            self.section,
        )
        self.assertIn(
            "Scores and heuristics do not establish malware or compromise.",
            self.section,
        )
        self.assertIn(
            "Validate findings with primary network and endpoint evidence",
            self.section,
        )
        self.assertIn(
            "No conclusion can be drawn from missing data.",
            self.section,
        )

    def test_snapshot_metadata_and_verdict_summary_are_visible(self) -> None:
        for identifier in (
            "ac-hunter-cache-state",
            "ac-hunter-dataset",
            "ac-hunter-range-start",
            "ac-hunter-range-end",
            "ac-hunter-last-pulled",
            "ac-hunter-loading",
            "ac-hunter-stale",
            "ac-hunter-error",
        ):
            self.assertIn(f'id="{identifier}"', self.section)

        for verdict in (
            "high_concern",
            "needs_review",
            "likely_benign",
            "informational",
        ):
            self.assertIn(
                f'data-ac-hunter-verdict-count="{verdict}"',
                self.section,
            )

    def test_all_required_triage_modules_have_explicit_empty_states(self) -> None:
        required = {
            "beacons": "Beaconing detections",
            "sni": "SNI beacon detections",
            "proxy": "Proxy beacon detections",
            "long": "Long connections over 5 hours",
            "dns": "DNS anomalies",
            "unexpected": "Unexpected protocol / port findings",
            "blacklist": "Blacklist results",
            "strobe": "Strobe / scanning results",
        }
        for key, title in required.items():
            self.assertIn(title, self.section)
            self.assertIn(f'id="ac-hunter-{key}-body"', self.section)
            self.assertIn(f'id="ac-hunter-{key}-count"', self.section)

        self.assertIn(
            "No blacklist matches",
            self.section,
        )
        self.assertIn(
            "No strobe or scanning findings",
            self.section,
        )
        self.assertIn(
            "Data unavailable for this module. No conclusion can be drawn.",
            self.section,
        )

    def test_host_correlation_and_analyst_notes_are_first_class_sections(
        self,
    ) -> None:
        self.assertIn("Top risky internal hosts", self.section)
        self.assertIn("Correlated host summary", self.section)
        self.assertIn('id="ac-hunter-risky-hosts"', self.section)
        self.assertIn('id="ac-hunter-correlated-hosts"', self.section)
        self.assertIn('id="ac-hunter-notes-title">Findings that need', self.section)
        self.assertIn('id="ac-hunter-notes"', self.section)
        self.assertIn(
            "Security Onion, Zeek, PCAP, or endpoint pivots",
            self.section,
        )

    def test_api_calls_use_database_read_without_web_triggered_collection(self) -> None:
        self.assertIn(
            "const GET_ENDPOINT='/api/ac-hunter/deep-review'",
            self.section,
        )
        self.assertNotIn("const REFRESH_ENDPOINT=", self.section)
        self.assertNotIn("fetchJson(REFRESH_ENDPOINT", self.section)
        self.assertIn("Reloading the latest AC Hunter snapshot from PostgreSQL", self.section)
        self.assertIn("once an hour at 35 minutes after the hour", self.section)
        self.assertIn("stores a new snapshot only when the dataset changes", self.section)
        self.assertIn(
            "credentials:'same-origin'",
            self.section,
        )
        self.assertIn(
            "window.OnionSentinelReactiveTables.register('ac-hunter-deep-review'",
            self.section,
        )

    def test_api_values_are_inserted_as_text_not_html(self) -> None:
        self.assertIn(
            "const element=document.createElement(tag)",
            self.section,
        )
        self.assertIn(
            "element.textContent=String(text)",
            self.section,
        )
        self.assertIn(
            "body.replaceChildren(fragment)",
            self.section,
        )
        self.assertNotIn(".innerHTML", self.section)
        self.assertNotIn("insertAdjacentHTML", self.section)
        self.assertNotIn("document.write", self.section)

    def test_tables_render_only_normalized_and_module_specific_fields(
        self,
    ) -> None:
        for field in (
            "source_ip",
            "destination_ip",
            "fqdn",
            "score",
            "count",
            "duration",
            "port",
            "protocol",
            "evidence",
            "verdict",
            "reason",
            "timing_mode",
            "data_size_mode",
            "responding_ips",
        ):
            self.assertIn(f".{field}", self.section)

        self.assertNotIn("raw_response", self.section)
        self.assertNotIn("session_cookie", self.section)
        self.assertNotIn("Authorization", self.section)

    def test_beacon_rows_match_review_cards_and_verdicts_have_room(self) -> None:
        self.assertIn(
            '<table class="ac-hunter-beacons-table">',
            self.section,
        )
        self.assertIn(
            "row.dataset.verdict=token(finding?.verdict)",
            self.section,
        )
        self.assertIn(
            ".ac-hunter-table-wrap td:last-child{width:280px}",
            self.section,
        )
        self.assertIn(
            "grid-template-columns:minmax(max-content,1.05fr)",
            self.section,
        )
        self.assertIn("minmax(120px,.9fr) minmax(120px,.9fr)", self.section)
        self.assertIn(".ac-hunter-beacons-table td{width:auto!important", self.section)
        self.assertIn("white-space:nowrap;", self.section)
        self.assertIn("overflow-wrap:normal;", self.section)
        self.assertIn(".ac-hunter-verdict{white-space:nowrap}", self.section)

    def test_page_is_responsive_and_accessible(self) -> None:
        self.assertIn("@media(max-width:820px)", self.section)
        self.assertIn("@media(max-width:560px)", self.section)
        self.assertIn("content:attr(data-label)", self.section)
        self.assertIn('aria-live="polite"', self.section)
        self.assertIn('role="alert"', self.section)
        self.assertIn(
            'aria-label="Reload stored AC Hunter snapshot"',
            self.section,
        )


if __name__ == "__main__":
    unittest.main()
