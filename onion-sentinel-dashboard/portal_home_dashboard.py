"""View model and escaped renderer for the Mac Studio LAN Portal home page."""
from __future__ import annotations

import datetime as dt
import html
from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from portal_home_dashboard_assets import HOME_DASHBOARD_CSS, HOME_DASHBOARD_JS


class HomeReport(Protocol):
    rid: str
    title: str
    rel: str


@dataclass(frozen=True)
class HomeDashboardSources:
    system_uptime: Callable[[], tuple[str, str, bool]]
    portal_last_updated: Callable[[Sequence[HomeReport]], float | None]
    prioritized_updates: Callable[[], tuple[str, str, int, str]]
    latest_hermes_backup: Callable[[], tuple[str, str, bool]]
    local_disk_usage: Callable[[], tuple[int, int, float]]
    human_size: Callable[[int], str]
    relative_time: Callable[[float], str]
    format_timestamp: Callable[[dt.datetime], str]
    soc_alerts_report: Callable[[Sequence[HomeReport]], HomeReport | None]
    now: Callable[[], dt.datetime]


@dataclass(frozen=True)
class HomeMetric:
    label: str
    value: str
    detail: str
    href: str
    css_class: str = ""


@dataclass(frozen=True)
class HomeCard:
    title: str
    description: str
    icon: str
    report_id: str
    permanent_artifact: str = ""


@dataclass(frozen=True)
class HomeDashboardView:
    metrics: tuple[HomeMetric, ...]
    cyber_cards: tuple[HomeCard, ...]
    portal_cards: tuple[HomeCard, ...]


@dataclass(frozen=True)
class _CardSpec:
    section: str
    title: str
    description: str
    icon: str
    title_contains: tuple[str, ...] = ()
    title_exact: tuple[str, ...] = ()
    rel_contains: tuple[str, ...] = ()
    permanent_artifact: str = ""


CARD_SPECS = (
    _CardSpec("cyber", "ATHF Command Center", "Threat hunts, ATT&CK coverage, CQL, and Elastic KQL", "🛡️",
              title_contains=("Threat Hunt Command Center",), rel_contains=("Threat Hunting/ATHF/index.html",)),
    _CardSpec("cyber", "Daily Threat Briefs", "Standalone CTI dashboard and searchable brief archive", "🛰️",
              title_contains=("Daily Threat Brief Dashboard",), rel_contains=("Threat Intel/index.html",)),
    _CardSpec("cyber", "Cyber Security Event Radar", "Denver metro cybersecurity events over the next six months", "📡",
              title_exact=("Cyber Security Event Radar",), rel_contains=("Cybersecurity/Cyber Security Event Radar/index.html",),
              permanent_artifact="cyber-security-event-radar"),
    _CardSpec("cyber", "Elastic Osquery Cheatsheet", "Windows, macOS, and Linux endpoint hunt queries", "🧬",
              title_contains=("Elastic Osquery Threat Hunting Cheatsheet",),
              rel_contains=("Elastic Osquery Threat Hunting Cheatsheet",)),
    _CardSpec("cyber", "KQL/OQL MITRE Map", "Elastic KQL and Security Onion OQL mapped to ATT&CK", "🧭",
              title_contains=("Elastic KQL and Security Onion OQL MITRE ATT&CK Mapping",),
              rel_contains=("KQL_OQL_Mapped_to_Mitre/MITRE_KQL_Mapping_Portable.html",)),
    _CardSpec("cyber", "Sigma Guide", "Detection engineering, threat hunting, sigma-cli, and rule tuning", "Σ",
              title_exact=("Sigma Detection Engineering Guide",),
              rel_contains=("Sigma Detection Engineering Guide/index.html",)),
    _CardSpec("cyber", "Cybersecurity Library", "Books, talk slides, posters, tools, certificates, and cybersecurity cheatsheets", "📚",
              title_exact=("Cybersecurity Library", "Resource Library"),
              rel_contains=("Cybersecurity Library/index.html", "Resource Library/index.html")),
    _CardSpec("portal", "Product Research", "Searchable entrepreneurial product research report archive", "📈",
              title_exact=("Product Research Dashboard",), rel_contains=("Product Research/index.html",)),
    _CardSpec("portal", "Web App Projects", "Interactive prototypes and project demos hosted on the LAN Portal", "🧩",
              title_exact=("Web App Projects Dashboard",), rel_contains=("Web App Projects/index.html",)),
    _CardSpec("portal", "Portal Architecture", "Web server upgrade triggers, SQLite guidance, and migration path", "🧭",
              title_contains=("LAN Portal Web Server Architecture",), rel_contains=("LAN Portal Web Server Architecture",)),
    _CardSpec("portal", "LLM Dashboard", "Local Ollama/OpenClaw inventory and benchmarks", "🧠",
              title_contains=("Local LLM Benchmark Dashboard",), rel_contains=("Local LLM Benchmark Dashboard",)),
)


def _metric(label: str, value: object, detail: object, href: str, warning: bool,
            *, healthy_class: bool = False) -> HomeMetric:
    css_class = " stat-alert" if warning else (" stat-ok" if healthy_class else "")
    return HomeMetric(label, str(value), str(detail), href, css_class)


def _portal_update_metric(reports: Sequence[HomeReport], sources: HomeDashboardSources) -> HomeMetric:
    timestamp = sources.portal_last_updated(reports)
    if not timestamp:
        return HomeMetric("Latest Portal update", "None", "No portal update timestamp recorded.",
                          "/metrics/portal-update")
    updated = dt.datetime.fromtimestamp(timestamp).astimezone()
    age_seconds = max(0.0, (sources.now().astimezone() - updated).total_seconds())
    detail = f"Latest portal update: {sources.format_timestamp(updated)} · {int(age_seconds // 60)} minutes ago"
    return _metric("Latest Portal update", sources.relative_time(timestamp), detail,
                   "/metrics/portal-update", age_seconds > 3600)


def _metrics(reports: Sequence[HomeReport], sources: HomeDashboardSources) -> tuple[HomeMetric, ...]:
    uptime_value, uptime_detail, uptime_warning = sources.system_uptime()
    updates_value, updates_detail, updates_count, _updates_source = sources.prioritized_updates()
    backup_value, backup_detail, backup_warning = sources.latest_hermes_backup()
    free, total, percent_free = sources.local_disk_usage()
    disk_detail = (
        f"{sources.human_size(free)} free of {sources.human_size(total)} total · {percent_free:.1f}% free"
    )
    return (
        _metric("System uptime", uptime_value, uptime_detail, "/metrics/system-uptime",
                uptime_warning, healthy_class=True),
        _metric("Updates", updates_value, updates_detail, "/admin", updates_count != 0,
                healthy_class=True),
        _metric("Last Hermes backup", backup_value, backup_detail, "/metrics/hermes-backups", backup_warning),
        _metric("Local disk free", sources.human_size(free), disk_detail, "/metrics/local-disk",
                percent_free <= 20.0, healthy_class=True),
        _portal_update_metric(reports, sources),
    )


def _matches(report: HomeReport, spec: _CardSpec) -> bool:
    return (
        report.title in spec.title_exact
        or any(value in report.title for value in spec.title_contains)
        or any(value in report.rel for value in spec.rel_contains)
    )


def _card(report: HomeReport, spec: _CardSpec) -> HomeCard:
    return HomeCard(spec.title, spec.description, spec.icon, str(report.rid), spec.permanent_artifact)


def _cards(reports: Sequence[HomeReport], sources: HomeDashboardSources) -> tuple[tuple[HomeCard, ...], tuple[HomeCard, ...]]:
    cyber: list[HomeCard] = []
    portal: list[HomeCard] = []
    soc_report = sources.soc_alerts_report(reports)
    if soc_report:
        cyber.append(HomeCard(
            "SOC Alerts", "Security Onion alert automation reports and detailed network findings",
            "🚨", str(soc_report.rid),
        ))
    for spec in CARD_SPECS:
        report = next((item for item in reports if _matches(item, spec)), None)
        if report:
            (cyber if spec.section == "cyber" else portal).append(_card(report, spec))
    return tuple(cyber), tuple(portal)


def compose_home_dashboard(reports: Sequence[HomeReport], sources: HomeDashboardSources) -> HomeDashboardView:
    """Collect the home-page metrics and explicit report links."""
    cyber, portal = _cards(reports, sources)
    return HomeDashboardView(_metrics(reports, sources), cyber, portal)


def _render_metric(metric: HomeMetric) -> str:
    return (
        f'<a class="stat{metric.css_class}" href="{html.escape(metric.href, quote=True)}" '
        f'title="{html.escape(metric.detail, quote=True)}"><span>{html.escape(metric.label)}</span>'
        f'<strong>{html.escape(metric.value)}</strong></a>'
    )


def _render_card(card: HomeCard) -> str:
    artifact = (
        f' data-permanent-artifact="{html.escape(card.permanent_artifact, quote=True)}"'
        if card.permanent_artifact else ""
    )
    return (
        f'<a class="app-card"{artifact} href="/view/{html.escape(card.report_id, quote=True)}/" '
        f'target="_blank" rel="noopener"><span class="app-card-icon">{html.escape(card.icon)}</span>'
        f'<span><b>{html.escape(card.title)}</b><span>{html.escape(card.description)}</span></span></a>'
    )


def _render_section(title: str, aria_label: str, cards: tuple[HomeCard, ...], css_class: str = "") -> str:
    if not cards:
        return ""
    return (
        f'<section class="mobile-apps{css_class}" aria-label="{html.escape(aria_label, quote=True)}">'
        f'<h2>{html.escape(title)}</h2><div class="app-strip">'
        + "".join(_render_card(card) for card in cards)
        + "</div></section>"
    )


def render_home_dashboard(view: HomeDashboardView) -> bytes:
    """Render an escaped home page without accessing host or report state."""
    metrics = "".join(_render_metric(metric) for metric in view.metrics)
    cyber = _render_section("Cyber Portal", "Cyber Portal", view.cyber_cards, " cyber-portal")
    portal = _render_section("Portal Links", "Portal links", view.portal_cards)
    page = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Mac Studio LAN Portal</title>
<style>{HOME_DASHBOARD_CSS}</style>
</head>
<body>
<div class="shell">
  <section class="hero">
    <div class="hero-row">
      <div class="kicker">● Private LAN Portal</div>
      <button class="hero-refresh" type="button" aria-label="Refresh Mac Studio LAN Portal and metrics" title="Refresh Mac Studio LAN Portal and metrics" aria-busy="false">
        <span class="hero-refresh-icon" aria-hidden="true">↻</span>
      </button>
    </div>
    <h1>Mac Studio LAN Portal</h1>
  </section>
  <section class="stats">{metrics}</section>
  {cyber}
  {portal}
  <div class="footer">Generated live by report_portal.py · metrics refresh from configured local checks · dashboard links are explicit only</div>
</div>
<script>{HOME_DASHBOARD_JS}</script>
</body>
</html>'''
    return page.encode("utf-8")
