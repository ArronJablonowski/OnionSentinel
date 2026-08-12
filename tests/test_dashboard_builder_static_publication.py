"""Characterization for dashboard static-page dispatch and publication."""
from __future__ import annotations

from contextlib import ExitStack
import dataclasses
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


CONTENT_CASES = (
    ("home", "executive_home_section", True, "inject_executive_home_assets"),
    ("flow", "flow_page_section", True, "inject_flow_assets"),
    ("system_health", "system_health_page_section", False, "inject_system_health_assets"),
    ("investigations", "incident_response_page_section", False, None),
    ("asset_inventory", "asset_inventory_page_section", False, None),
    ("software_inventory", "software_inventory_page_section", False, None),
    ("ac_hunter", "ac_hunter_page_section", False, None),
    ("settings", "settings_page_section", False, "inject_settings_assets"),
    ("siem_engineering", "siem_engineering_page_section", True, "inject_siem_engineering_assets"),
    ("cyber_threat_intel", "cyber_threat_intel_page_section", True, "inject_cyber_threat_intel_assets"),
    ("threat_hunter", "threat_hunter_page_section", True, "inject_threat_hunter_assets"),
    ("reports", "reports_page_section", True, "inject_reports_assets"),
    ("logs", "logs_page_section", False, None),
)


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "dashboard_builder_static_publication_test",
        BUILDER_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256_json(value: object) -> str:
    encoded = json.dumps(
        value,
        default=str,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class DashboardBuilderStaticPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = load_builder()

    def test_namespace_signatures_and_page_definition_order_are_exact(self) -> None:
        names = sorted(
            name for name in dir(self.builder) if not name.startswith("__")
        )
        self.assertEqual(
            (len(names), sha256_json(names)),
            (480, "75c4d9372093624308e6a2e89b821fd7ba7a4d7bee1e3bd5a355ebb8d54324bd"),
        )
        signatures = {
            name: str(inspect.signature(getattr(self.builder, name)))
            for name in (
                "_static_page_content",
                "render_static_page",
                "write_site_pages",
            )
        }
        self.assertEqual(
            sha256_json(signatures),
            "aef5a70082dc808e8334bcfc73a54c939b9711c3bff8faea52cdcf11e642aab4",
        )
        self.assertEqual(
            sha256_json(self.builder.PAGE_DEFS),
            "af4cd8f1ffd242110355d3fc700aa52769817dbb532e044993c98051c0b2f0a0",
        )

    def test_every_static_content_branch_and_unknown_fallback_are_exact(self) -> None:
        reports = [object()]
        with ExitStack() as stack:
            composers = {
                name: stack.enter_context(
                    mock.patch.object(
                        self.builder,
                        name,
                        return_value=f"content:{page_key}",
                    )
                )
                for page_key, name, _takes_reports, _injector in CONTENT_CASES
            }
            injectors = {
                name: stack.enter_context(mock.patch.object(self.builder, name))
                for name in {
                    injector
                    for _key, _composer, _takes_reports, injector in CONTENT_CASES
                    if injector is not None
                }
            }
            placeholder = stack.enter_context(
                mock.patch.object(
                    self.builder,
                    "placeholder_page_section",
                    return_value="content:unknown",
                )
            )
            for page_key, composer, takes_reports, injector in CONTENT_CASES:
                with self.subTest(page_key=page_key):
                    content, returned_injector = self.builder._static_page_content(
                        page_key, reports
                    )
                    self.assertEqual(content, f"content:{page_key}")
                    self.assertIs(
                        returned_injector,
                        injectors[injector] if injector else None,
                    )
                    expected = mock.call(reports) if takes_reports else mock.call()
                    self.assertEqual(composers[composer].call_args, expected)
            self.assertEqual(
                self.builder._static_page_content("unknown", reports),
                ("content:unknown", None),
            )
            placeholder.assert_called_once_with("unknown")

    def test_render_plan_alert_bypass_injection_and_unknown_failure_are_exact(self) -> None:
        reports = [object(), object()]
        captured = []
        injector = mock.Mock(return_value="injected")
        with (
            mock.patch.object(
                self.builder,
                "_static_page_content",
                return_value=("home-content", injector),
            ) as content,
            mock.patch.object(
                self.builder,
                "inject_reactive_table_assets",
                return_value="reactive-shell",
            ),
            mock.patch.object(self.builder, "active_alert_count", return_value=2),
            mock.patch.object(
                self.builder,
                "active_alert_highest_severity_class",
                return_value="high",
            ),
            mock.patch.object(
                self.builder,
                "build_nav_html",
                return_value="<nav>home</nav>",
            ),
            mock.patch.object(
                self.builder,
                "compose_static_page",
                side_effect=lambda shell, plan: captured.append((shell, plan)) or "composed",
            ),
        ):
            self.assertEqual(
                self.builder.render_static_page("shell", "home", reports),
                "injected",
            )
        content.assert_called_once_with("home", reports)
        injector.assert_called_once_with("composed")
        shell, plan = captured[0]
        self.assertEqual(shell, "reactive-shell")
        self.assertEqual(
            dataclasses.asdict(plan),
            {
                "page_key": "home",
                "title": "Home",
                "subtitle": "Executive SOC metrics and trends",
                "navigation_html": "<nav>home</nav>",
                "content_html": "home-content",
                "alert_contracts": (
                    self.builder.ALERTS_REACTIVE_FALLBACK,
                    self.builder.ALERTS_PAGE_SCROLL_STABILIZER,
                    self.builder.PINNED_ALERT_ROW_SCROLL_SYNC,
                    self.builder.ALERT_COLUMN_SINGLE_WRAP_CONTRACT,
                ),
            },
        )
        with mock.patch.object(
            self.builder,
            "_static_page_content",
            side_effect=AssertionError("alerts must bypass content dispatch"),
        ):
            self.builder.render_static_page("shell", "alerts", [])
        with self.assertRaises(KeyError) as raised:
            self.builder.render_static_page("shell", "unknown", reports)
        self.assertEqual(raised.exception.args, ("unknown",))

    def test_write_site_pages_preserves_publication_order_and_arguments(self) -> None:
        reports = [object()]
        paths = [Path("status.json"), Path("beacon.json"), Path("history.json")]
        details = [Path("detail-a.html"), Path("detail-b.html")]
        pages = [Path("home.html"), Path("index.html")]
        with (
            mock.patch.object(self.builder, "build_html", return_value="shell") as build,
            mock.patch.object(self.builder, "copy_static_assets") as copy_assets,
            mock.patch.object(self.builder, "write_status_json", return_value=paths[0]),
            mock.patch.object(self.builder, "write_n8n_beacon_json", return_value=paths[1]),
            mock.patch.object(
                self.builder,
                "write_n8n_beacon_history_json",
                return_value=paths[2],
            ),
            mock.patch.object(self.builder, "write_detail_fragments", return_value=details),
            mock.patch.object(self.builder, "_publication_paths", return_value="paths") as config,
            mock.patch.object(self.builder, "publish_static_pages", return_value=pages) as publish,
        ):
            self.assertEqual(
                self.builder.write_site_pages(reports),
                [*paths, *details, *pages],
            )
        build.assert_called_once_with(reports)
        copy_assets.assert_called_once_with()
        config.assert_called_once_with()
        publish.assert_called_once_with(
            "paths",
            self.builder.PAGE_DEFS,
            shell_html="shell",
            reports=reports,
            render_page=sys.modules[
                "dashboard_builder_publication"
            ].render_static_page,
        )


if __name__ == "__main__":
    unittest.main()
