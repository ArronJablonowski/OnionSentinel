"""Characterization for dashboard page composition and compatibility seams."""
from __future__ import annotations

import dataclasses
import datetime as dt
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

from dashboard_executive_metrics import (  # noqa: E402
    EnrichmentCacheMetrics,
    HourlyIntakeBucket,
    HourlyIntakeMetrics,
)


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "dashboard_builder_page_composition_test",
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


def executive_metrics() -> tuple[HourlyIntakeMetrics, EnrichmentCacheMetrics]:
    hourly = HourlyIntakeMetrics(
        buckets=(
            HourlyIntakeBucket(
                start_utc=dt.datetime(2026, 7, 21, 21, tzinfo=dt.timezone.utc),
                count=7,
                current=True,
            ),
        ),
        source="pipeline_stage_events",
        exact=True,
        note="Synthetic exact intake.",
    )
    cache = EnrichmentCacheMetrics(
        available=True,
        entries=10,
        fresh_entries=8,
        stale_entries=2,
        payload_bytes=2048,
        l1_hits=4,
        l2_hits=3,
        misses=1,
        coalesced=2,
        provider_loads=1,
        stale_fallbacks=1,
        runtime_available=True,
    )
    return hourly, cache


def synthetic_report(builder, digest: str, tuning: str, repeat: int, rank: int, status: str):
    return builder.AlertReport(
        title=f"Synthetic {digest}",
        source=Path("synthetic.md"),
        rel_source="synthetic.md",
        mtime=0.0,
        size=256,
        digest=digest,
        rendered_html="",
        summary="Repeated behavior warrants review.",
        criticality="High",
        criticality_rank=rank,
        alert_source="suricata.alert",
        filter_status="accepted",
        source_ip="192.0.2.10",
        source_port="41000",
        destination_ip="198.51.100.20",
        destination_port="443",
        source_endpoint="192.0.2.10:41000",
        destination_endpoint="198.51.100.20:443",
        rule_id="synthetic-rule",
        rule_name="Synthetic repeated outbound scan",
        raw_alert_count=repeat,
        total_seen_count=repeat,
        repeat_count=repeat,
        first_seen="2026-07-20  08:00:00-06:00",
        last_seen="2026-07-20  09:00:00-06:00",
        alert_group_key=f"synthetic-group-{digest}",
        alert_ts=1.0,
        ai_status_key=status,
        ai_status_label="Analyzed",
        ai_status_detail="AI artifact available",
        enrichment_status_key="enriched",
        enrichment_status_label="Enriched",
        enrichment_status_detail="Two sources",
        enrichment_record_count=2,
        enrichment_skip_count=0,
        enrichment_error_count=0,
        pcap_status_key="analyzed",
        pcap_status_label="Analyzed",
        pcap_status_detail="Parsed PCAP evidence available",
        tuning_recommendation=tuning,
        tuning_reason="Repeated expected traffic creates avoidable review volume.",
        recommended_tuning_actions=["Threshold only this verified route."],
        ai_analysis={
            "generated_at": "2026-07-20T09:05:00-06:00",
            "response": {
                "detection_outcome": "true_positive_benign",
                "bluf": "The traffic is real but expected.",
                "summary": "A narrowly scoped threshold is appropriate.",
                "public_enrichment_findings": ["Synthetic enrichment finding"],
                "pcap_analysis_findings": ["Synthetic PCAP finding"],
                "recommended_next_steps": ["Backtest before deployment"],
            },
        },
    )


class DashboardBuilderPageCompositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = load_builder()

    def test_flat_namespaces_and_signatures_are_exact(self) -> None:
        namespaces = {
            "facade": sorted(
                name for name in dir(self.builder) if not name.startswith("__")
            ),
            "runtime": sorted(
                name for name in vars(self.builder._runtime)
                if not name.startswith("__")
            ),
            "pages": sorted(
                name for name in vars(sys.modules["dashboard_builder_pages"])
                if not name.startswith("__")
            ),
            "publication": sorted(
                name for name in vars(sys.modules["dashboard_builder_publication"])
                if not name.startswith("__")
            ),
        }
        self.assertEqual(
            {name: (len(values), sha256_json(values)) for name, values in namespaces.items()},
            {
                "facade": (480, "75c4d9372093624308e6a2e89b821fd7ba7a4d7bee1e3bd5a355ebb8d54324bd"),
                "runtime": (476, "89daaf45d42d993672554f021a6ad286d6085706a9a2ed5e7fde464bf84267ca"),
                "pages": (476, "89daaf45d42d993672554f021a6ad286d6085706a9a2ed5e7fde464bf84267ca"),
                "publication": (476, "89daaf45d42d993672554f021a6ad286d6085706a9a2ed5e7fde464bf84267ca"),
            },
        )
        signatures = {
            name: str(inspect.signature(getattr(self.builder, name)))
            for name in (
                "pct",
                "counter_top",
                "_executive_home_view",
                "executive_home_section",
                "_siem_recommendation_view",
                "siem_engineering_page_section",
                "render_static_page",
                "write_site_pages",
                "main",
            )
        }
        self.assertEqual(
            sha256_json(signatures),
            "13f055294a2104f709ac9b2fe6583a4d76936e8fad4bba6c1c2c0f3e1d6331e6",
        )

    def test_executive_view_model_and_rendered_bytes_are_exact(self) -> None:
        hourly, cache = executive_metrics()
        view = self.builder._executive_home_view([], hourly, cache)
        rendered = self.builder.executive_home_section([], hourly, cache)
        self.assertEqual(
            sha256_json(dataclasses.asdict(view)),
            "51a412bf3599737dd8c70cdf0973a4ba2d5cc0108dc33e7e1b5c1d23d6deeb60",
        )
        self.assertEqual(
            hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "75d7e23e18accd9a35cb3b31d2cf5c04bf813e2e6ac35ce32d4af2caf049c1ce",
        )

    def test_siem_view_model_order_and_rendered_bytes_are_exact(self) -> None:
        reports = [
            synthetic_report(self.builder, "a" * 12, "threshold", 8, 4, "analyzed"),
            synthetic_report(self.builder, "b" * 12, "none", 5, 3, "queued"),
        ]
        settings = {
            "mode": "hybrid",
            "ollama_model": "local:test",
            "cloud_model": "cloud:test",
        }
        captured = []
        with mock.patch.object(
            self.builder,
            "load_soc_ai_settings",
            return_value=settings,
        ):
            rendered = self.builder.siem_engineering_page_section(reports)
            with mock.patch.object(
                self.builder,
                "render_siem_engineering_page",
                side_effect=lambda view: captured.append(view) or "captured",
            ):
                self.assertEqual(
                    self.builder.siem_engineering_page_section(reports),
                    "captured",
                )
        view = captured[0]
        self.assertEqual(
            sha256_json(dataclasses.asdict(view)),
            "16be36bc8e18e1d9f467c7188101433a1eeb2bc7451c4277635f4b48fb6d48f2",
        )
        self.assertEqual(
            hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "33e1184cc0236fcc895e71a80ff820179a41cc5be9f12979195f548c0e7efe80",
        )
        self.assertEqual([item.digest for item in view.actionable], ["a" * 12])
        self.assertEqual([item.digest for item in view.repeated], ["b" * 12])

    def test_facade_override_reaches_every_current_composed_owner(self) -> None:
        hourly, cache = executive_metrics()
        original = self.builder.render_executive_home
        with mock.patch.object(
            self.builder,
            "render_executive_home",
            return_value="override",
        ):
            self.assertEqual(
                self.builder.executive_home_section([], hourly, cache),
                "override",
            )
            owners = [
                module for module in self.builder._runtime.BUILDER_MODULES
                if hasattr(module, "render_executive_home")
            ]
            self.assertEqual(len(owners), 6)
            self.assertTrue(all(
                module.render_executive_home is self.builder.render_executive_home
                for module in owners
            ))
        self.assertIs(self.builder.render_executive_home, original)


if __name__ == "__main__":
    unittest.main()
