#!/usr/bin/env python3
"""Contracts for the extracted SOC alert report factory."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
FACTORY_PATH = SCRIPTS / "dashboard_alert_report_factory.py"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def report_row() -> dict[str, object]:
    return {
        "alert_id": "alert-1",
        "alert_group_key": "stable-group",
        "alert_json": '{"source":{"ip":"10.0.0.7","port":51515},'
                      '"destination":{"ip":"203.0.113.8","port":443},'
                      '"rule_id":"rule-7"}',
        "raw_alert_count": 2,
        "total_seen_count": 5,
        "seen_count": 3,
        "first_seen": "2026-08-01T01:00:00Z",
        "last_seen": "2026-08-01T01:05:00Z",
        "timestamp": "2026-08-01T01:04:00Z",
        "rule_name": "Example Rule",
        "event_dataset": "suricata.alert",
        "severity": 2,
        "severity_label": "medium",
        "triage_level": "medium",
        "source_ip": "",
        "source_port": None,
        "destination_ip": "",
        "destination_port": None,
        "filter_status": "accepted",
        "filter_reason": "eligible",
        "enrichment_json": "{}",
        "member_timeline": [],
    }


class DashboardAlertReportFactoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.factory = load_module("dashboard_alert_report_factory", FACTORY_PATH)
        cls.builder = load_module("alert_report_factory_test_builder", BUILDER_PATH)

    def services(self):
        return self.factory.AlertReportFactoryServices(
            finalize_detail_report_html=lambda rendered, timeline, issues: (
                f'<article data-issues="{len(issues)}">{timeline}{rendered}</article>'
            ),
        )

    def test_factory_builds_complete_model_from_normalized_row(self) -> None:
        row = report_row()
        config = self.factory.AlertReportFactoryConfig(Path("alerts.sqlite3"), (), Path("pcap"))
        analyses = {
            "alert-1": {
                "response": {
                    "bluf": "Evidence-backed result.",
                    "_analysis_model": "gpt-test",
                    "tuning_recommendation": "review",
                    "tuning_reason": "Repeated activity",
                    "recommended_tuning_actions": [" Validate scope ", ""],
                }
            }
        }

        report = self.factory.build_alert_report(
            row, {}, analyses, {}, set(), {"empty": True}, "medium", config, self.services(),
        )

        self.assertEqual(report.title, "[MEDIUM] Example Rule")
        self.assertEqual(report.rel_source, "SQLite alert-store")
        self.assertEqual(report.repeat_count, 5)
        self.assertEqual(report.source_endpoint, "10.0.0.7:51515")
        self.assertEqual(report.destination_endpoint, "203.0.113.8:443")
        self.assertEqual(report.rule_id, "rule-7")
        self.assertEqual(report.ai_status_key, "analyzed")
        self.assertEqual(report.tuning_recommendation, "review")
        self.assertEqual(report.recommended_tuning_actions, ["Validate scope"])
        self.assertIn("Evidence-backed result.", report.rendered_html)

    def test_attached_markdown_uses_relative_source_and_stat_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory)
            source = source_root / "nested" / "alert.md"
            attachment = (source, "## Analyst Notes\n\nAttached evidence.", types.SimpleNamespace(st_size=321))
            config = self.factory.AlertReportFactoryConfig(Path("alerts.sqlite3"), (source_root,), Path("pcap"))

            report = self.factory.build_alert_report(
                report_row(), {"alert-1": attachment}, {}, {}, set(), {"empty": True},
                "medium", config, self.services(),
            )

        self.assertEqual(report.source, source)
        self.assertEqual(report.rel_source, "nested/alert.md")
        self.assertEqual(report.size, 321)
        self.assertIn("Attached evidence.", report.rendered_html)

    def test_missing_rule_name_retains_the_legacy_report_identity(self) -> None:
        row = report_row()
        row["rule_name"] = ""
        config = self.factory.AlertReportFactoryConfig(Path("alerts.sqlite3"), (), Path("pcap"))

        report = self.factory.build_alert_report(
            row, {}, {}, {}, set(), {"empty": True}, "medium", config, self.services(),
        )

        self.assertEqual(report.title, "[MEDIUM] Security Onion Alert")
        self.assertEqual(report.rule_name, report.title)

    def test_markdown_summary_excludes_structure_and_fenced_code(self) -> None:
        text = "\n".join([
            "# Heading",
            "```json",
            '{"secret":"not prose"}',
            "```",
            "---",
            "> [Visible] (**alpha**)",
            "Second line",
        ])

        self.assertEqual(
            self.factory.summarize_markdown(text),
            "Visible alpha Second line",
        )

    def test_markdown_summary_preserves_regex_and_normalizer_order(self) -> None:
        trace: list[tuple[object, ...]] = []
        original_match = self.factory.re.match
        original_sub = self.factory.re.sub

        def traced_match(pattern: str, text: str):
            trace.append(("match", pattern, text))
            return original_match(pattern, text)

        def traced_sub(pattern: str, replacement: str, text: str) -> str:
            trace.append(("sub", pattern, replacement, text))
            return original_sub(pattern, replacement, text)

        def traced_normalize(value: str) -> str:
            trace.append(("normalize", value))
            return value

        text = "\n".join([
            "# Heading", "```", "hidden", "```", "---",
            "> [Visible] (**alpha**)", "[_]()", "Second",
        ])
        with (
            mock.patch.object(self.factory.re, "match", side_effect=traced_match),
            mock.patch.object(self.factory.re, "sub", side_effect=traced_sub),
            mock.patch.object(
                self.factory,
                "normalize_iso_display_text",
                side_effect=traced_normalize,
            ),
        ):
            summary = self.factory.summarize_markdown(text)

        self.assertEqual(summary, "Visible alpha Second")
        self.assertEqual(
            trace,
            [
                ("match", r"^[-*_]{3,}$", "---"),
                ("match", r"^[-*_]{3,}$", "> [Visible] (**alpha**)"),
                ("sub", r"[`*_>#\[\]()]+", " ", "> [Visible] (**alpha**)"),
                ("sub", r"\s+", " ", "   Visible   alpha "),
                ("normalize", "Visible alpha"),
                ("match", r"^[-*_]{3,}$", "[_]()"),
                ("sub", r"[`*_>#\[\]()]+", " ", "[_]()"),
                ("sub", r"\s+", " ", " "),
                ("normalize", ""),
                ("match", r"^[-*_]{3,}$", "Second"),
                ("sub", r"[`*_>#\[\]()]+", " ", "Second"),
                ("sub", r"\s+", " ", "Second"),
                ("normalize", "Second"),
                ("normalize", "Visible alpha Second"),
            ],
        )

    def test_markdown_summary_calls_split_strip_and_prefixes_in_order(self) -> None:
        trace: list[tuple[object, ...]] = []

        class LineProbe(str):
            def startswith(self, prefix: str, *args: object) -> bool:
                trace.append(("startswith", prefix))
                return super().startswith(prefix, *args)

        class RawProbe:
            def strip(self) -> LineProbe:
                trace.append(("strip",))
                return LineProbe("visible")

        class TextProbe:
            def splitlines(self) -> list[RawProbe]:
                trace.append(("splitlines",))
                return [RawProbe()]

        with mock.patch.object(
            self.factory.re,
            "match",
            side_effect=lambda pattern, text: trace.append(("match", pattern, text)),
        ):
            summary = self.factory.summarize_markdown(TextProbe())  # type: ignore[arg-type]

        self.assertEqual(summary, "visible")
        self.assertEqual(
            trace,
            [
                ("splitlines",), ("strip",), ("startswith", "```"),
                ("startswith", "#"), ("match", r"^[-*_]{3,}$", "visible"),
            ],
        )

    def test_markdown_summary_preserves_strict_bounds_and_fallback(self) -> None:
        self.assertEqual(self.factory.summarize_markdown("abc\ndef", 5), "abc …")
        self.assertEqual(self.factory.summarize_markdown("abc", 0), "ab…")
        self.assertEqual(self.factory.summarize_markdown("abc", -1), "a…")
        self.assertEqual(
            self.factory.summarize_markdown("# heading\n```\nhidden\n```"),
            "No summary text available yet.",
        )

    def test_build_report_preserves_phase_and_model_projection_order(self) -> None:
        row = object()
        trace: list[tuple[object, ...]] = []
        model = object()
        raw = {"raw": True}
        source = Path("source.md")
        config = self.factory.AlertReportFactoryConfig(Path("db"), (), Path("pcap"))
        services = self.services()
        row_values = {
            "raw_alert_count": 2,
            "total_seen_count": 5,
            "seen_count": 3,
            "alert_id": "alert-1",
            "filter_status": "accepted",
            "filter_reason": "eligible",
            "rule_name": "Rule",
            "first_seen": "first",
            "last_seen": "last",
        }
        workflow = self.factory.ReportWorkflowEvidence(
            {"analysis": True},
            {
                "tuning_recommendation": " REVIEW ",
                "tuning_reason": " reason ",
            },
            ("ai-key", "AI label", "AI detail"),
            ("enrichment-key", "Enrichment label", "Enrichment detail", 7, 2, 1),
            ("pcap-key", "PCAP label", "PCAP detail"),
            "pcap markdown",
        )
        network = self.factory.ReportNetworkIdentity(
            "source-ip", "source-port", "destination-ip", "destination-port",
            "dataset", "rule-id",
        )

        def row_item(candidate: object, key: str, default: object = None) -> object:
            trace.append(("row", candidate, key, default))
            return row_values.get(key, default)

        def safe_int(value: object) -> int:
            trace.append(("safe-int", value))
            return int(value)  # type: ignore[arg-type]

        def alert_report(**kwargs: object) -> object:
            trace.append(("model", tuple(kwargs)))
            self.assertEqual(kwargs["source"], source)
            self.assertIs(kwargs["ai_analysis"], workflow.ai_analysis)
            self.assertEqual(kwargs["summary"], "accepted: eligible. Seen 5 time(s). summary")
            return model

        with (
            mock.patch.object(
                self.factory,
                "raw_alert_object",
                side_effect=lambda candidate: trace.append(("raw", candidate)) or raw,
            ),
            mock.patch.object(self.factory, "row_item", side_effect=row_item),
            mock.patch.object(self.factory, "safe_int", side_effect=safe_int),
            mock.patch.object(
                self.factory,
                "report_group_key",
                side_effect=lambda candidate: trace.append(("group", candidate)) or "group",
            ),
            mock.patch.object(
                self.factory,
                "workflow_evidence",
                side_effect=lambda *args: trace.append(("workflow", args)) or workflow,
            ),
            mock.patch.object(
                self.factory,
                "source_attachment",
                side_effect=lambda *args: trace.append(("attachment", args))
                or (source, "relative.md", "source text", 123),
            ),
            mock.patch.object(
                self.factory,
                "report_detail_html",
                side_effect=lambda *args: trace.append(("detail", args))
                or ("detail text", "rendered html"),
            ),
            mock.patch.object(
                self.factory,
                "severity_label_from_row",
                side_effect=lambda candidate: trace.append(("severity", candidate)) or "Medium",
            ),
            mock.patch.object(
                self.factory,
                "network_identity",
                side_effect=lambda *args: trace.append(("network", args)) or network,
            ),
            mock.patch.object(
                self.factory,
                "report_timestamp",
                side_effect=lambda candidate: trace.append(("timestamp", candidate)) or 1234.5,
            ),
            mock.patch.object(
                self.factory,
                "summarize_markdown",
                side_effect=lambda *args: trace.append(("summarize", args)) or "summary",
            ),
            mock.patch.object(
                self.factory,
                "endpoint_label",
                side_effect=lambda *args: trace.append(("endpoint", args)) or ":".join(args),
            ),
            mock.patch.object(
                self.factory,
                "tuning_actions",
                side_effect=lambda response: trace.append(("actions", response)) or ["action"],
            ),
            mock.patch.object(self.factory, "AlertReport", side_effect=alert_report),
        ):
            result = self.factory.build_alert_report(
                row,
                {"alert-1": (source, "stored", object())},
                {"analysis": {}},
                {"prompt": {}},
                {"running"},
                {"pcap": object()},
                "medium",
                config,
                services,
            )

        self.assertIs(result, model)
        self.assertEqual(
            trace[-4:],
            [
                ("row", row, "first_seen", None),
                ("row", row, "last_seen", None),
                ("actions", workflow.ai_response),
                (
                    "model",
                    (
                        "title", "source", "rel_source", "mtime", "size", "digest",
                        "rendered_html", "summary", "criticality", "criticality_rank",
                        "alert_source", "filter_status", "source_ip", "source_port",
                        "destination_ip", "destination_port", "source_endpoint",
                        "destination_endpoint", "rule_id", "rule_name", "raw_alert_count",
                        "total_seen_count", "repeat_count", "first_seen", "last_seen",
                        "alert_group_key", "alert_ts", "ai_status_key", "ai_status_label",
                        "ai_status_detail", "enrichment_status_key",
                        "enrichment_status_label", "enrichment_status_detail",
                        "enrichment_record_count", "enrichment_skip_count",
                        "enrichment_error_count", "pcap_status_key", "pcap_status_label",
                        "pcap_status_detail", "tuning_recommendation", "tuning_reason",
                        "recommended_tuning_actions", "ai_analysis",
                    ),
                ),
            ],
        )
        self.assertEqual(
            [entry[0] for entry in trace],
            [
                "raw", "row", "safe-int", "row", "safe-int", "row", "safe-int",
                "group", "row", "workflow", "attachment", "detail", "severity", "row",
                "row", "network", "timestamp", "row", "summarize", "row", "endpoint",
                "endpoint", "row", "row", "actions", "model",
            ],
        )

    def test_builder_reexports_factory_and_value_helpers(self) -> None:
        self.assertIs(self.builder.build_alert_report, self.factory.build_alert_report)
        self.assertIs(self.builder.clean_endpoint_part, self.factory.clean_endpoint_part)
        self.assertIs(self.builder.endpoint_label, self.factory.endpoint_label)
        self.assertIs(self.builder.summarize_markdown, self.factory.summarize_markdown)

    def test_module_is_bounded_and_deployed_once(self) -> None:
        source = FACTORY_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 320)
        for forbidden in ("sqlite3", "subprocess", "urllib", "read_text(", "write_text(", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_report_factory.py"), 2)


if __name__ == "__main__":
    unittest.main()
