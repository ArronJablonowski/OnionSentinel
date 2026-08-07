"""Behavior contracts for the modular Mac Studio LAN Portal home page."""
from __future__ import annotations

import datetime as dt
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_home_dashboard import (  # noqa: E402
    HomeDashboardSources,
    compose_home_dashboard,
    render_home_dashboard,
)


NOW = dt.datetime(2026, 8, 7, 18, 0, tzinfo=dt.timezone.utc)


@dataclass(frozen=True)
class Report:
    rid: str
    title: str
    rel: str


class HomeDashboardTests(unittest.TestCase):
    def reports(self) -> list[Report]:
        return [
            Report("soc-id", "SOC Alerts", "Cybersecurity/SOC Alerts/index.html"),
            Report("athf-id", "Threat Hunt Command Center", "Threat Hunting/ATHF/index.html"),
            Report("radar-id", "Cyber Security Event Radar", "Cybersecurity/Cyber Security Event Radar/index.html"),
            Report("library-id", "Resource Library", "Resource Library/index.html"),
            Report("project-id", "Web App Projects Dashboard", "Web App Projects/index.html"),
            Report("llm-id", "Local LLM Benchmark Dashboard", "Benchmarks/index.html"),
        ]

    def sources(self, *, timestamp: float | None = None,
                uptime: tuple[str, str, bool] = ("2 days", "healthy", False)) -> HomeDashboardSources:
        return HomeDashboardSources(
            system_uptime=lambda: uptime,
            portal_last_updated=lambda _reports: timestamp,
            prioritized_updates=lambda: ("3", "updates pending", 3, "brew"),
            latest_hermes_backup=lambda: ("Today", "backup detail", False),
            local_disk_usage=lambda: (25, 100, 25.0),
            human_size=lambda value: f"{value} bytes",
            relative_time=lambda _value: "90 minutes ago",
            format_timestamp=lambda value: value.isoformat(),
            soc_alerts_report=lambda reports: next((item for item in reports if item.title == "SOC Alerts"), None),
            now=lambda: NOW,
        )

    def test_composition_preserves_metric_policy_and_explicit_card_order(self) -> None:
        timestamp = (NOW - dt.timedelta(minutes=90)).timestamp()
        view = compose_home_dashboard(self.reports(), self.sources(timestamp=timestamp))

        self.assertEqual([metric.label for metric in view.metrics], [
            "System uptime", "Updates", "Last Hermes backup", "Local disk free", "Latest Portal update",
        ])
        self.assertEqual(view.metrics[0].css_class, " stat-ok")
        self.assertEqual(view.metrics[1].css_class, " stat-alert")
        self.assertEqual(view.metrics[3].css_class, " stat-ok")
        self.assertEqual(view.metrics[4].css_class, " stat-alert")
        self.assertIn("90 minutes ago", view.metrics[4].detail)
        self.assertEqual([card.title for card in view.cyber_cards], [
            "SOC Alerts", "ATHF Command Center", "Cyber Security Event Radar", "Cybersecurity Library",
        ])
        self.assertEqual([card.title for card in view.portal_cards], ["Web App Projects", "LLM Dashboard"])
        self.assertEqual(view.cyber_cards[2].permanent_artifact, "cyber-security-event-radar")

    def test_missing_update_and_reports_keep_stable_empty_state(self) -> None:
        sources = self.sources(timestamp=None)
        sources = HomeDashboardSources(
            **{**sources.__dict__, "soc_alerts_report": lambda _reports: None}
        )
        view = compose_home_dashboard([], sources)
        rendered = render_home_dashboard(view).decode()

        self.assertEqual(view.metrics[-1].value, "None")
        self.assertEqual(view.cyber_cards, ())
        self.assertEqual(view.portal_cards, ())
        self.assertNotIn('aria-label="Cyber Portal"', rendered)
        self.assertNotIn('aria-label="Portal links"', rendered)

    def test_renderer_escapes_collected_metric_values_and_report_ids(self) -> None:
        reports = [
            Report('soc-id" onclick="alert(1)', "SOC Alerts", "Cybersecurity/SOC Alerts/index.html"),
        ]
        view = compose_home_dashboard(
            reports,
            self.sources(uptime=("<script>unsafe</script>", 'detail" onmouseover="bad', True)),
        )
        rendered = render_home_dashboard(view).decode()

        self.assertIn("&lt;script&gt;unsafe&lt;/script&gt;", rendered)
        self.assertNotIn("<script>unsafe</script>", rendered)
        self.assertIn("detail&quot; onmouseover=&quot;bad", rendered)
        self.assertIn("soc-id&quot; onclick=&quot;alert(1)", rendered)
        self.assertNotIn('href="/view/soc-id" onclick=', rendered)
        self.assertIn("DISK_METRIC_REFRESH_MS", rendered)
        self.assertIn("hero-refresh", rendered)


if __name__ == "__main__":
    unittest.main()
