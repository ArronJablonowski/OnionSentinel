"""Static dashboard publication and compatibility entrypoint behavior."""
from __future__ import annotations

from dashboard_builder_contract import *  # noqa: F403
from dashboard_builder_settings import *  # noqa: F403
from dashboard_builder_report_core import *  # noqa: F403
from dashboard_builder_reports import *  # noqa: F403
from dashboard_builder_pages import *  # noqa: F403
from dashboard_builder_pages import _publication_paths  # noqa: F401


def inject_threat_hunter_assets(text: str) -> str:
    return inject_threat_hunter_page_assets(
        inject_siem_engineering_assets(text)
    )










def copy_static_assets() -> None:
    """Copy dashboard image/logo assets beside the generated static pages."""
    publish_static_assets(_publication_paths())


def _static_page_content(page_key: str, reports: list[AlertReport]) -> tuple[str, object | None]:
    if page_key == 'home':
        return executive_home_section(reports), inject_executive_home_assets
    if page_key == 'flow':
        return flow_page_section(reports), inject_flow_assets
    if page_key == 'system_health':
        return system_health_page_section(), inject_system_health_assets
    if page_key == 'investigations':
        return incident_response_page_section(), None
    if page_key == 'asset_inventory':
        return asset_inventory_page_section(), None
    if page_key == 'software_inventory':
        return software_inventory_page_section(), None
    if page_key == 'ac_hunter':
        return ac_hunter_page_section(), None
    if page_key == 'settings':
        return settings_page_section(), inject_settings_assets
    if page_key == 'siem_engineering':
        return siem_engineering_page_section(reports), inject_siem_engineering_assets
    if page_key == 'cyber_threat_intel':
        return cyber_threat_intel_page_section(reports), inject_cyber_threat_intel_assets
    if page_key == 'threat_hunter':
        return threat_hunter_page_section(reports), inject_threat_hunter_assets
    if page_key == 'reports':
        return reports_page_section(reports), inject_reports_assets
    if page_key == 'logs':
        return logs_page_section(), None
    return placeholder_page_section(page_key), None


def render_static_page(shell_html: str, page_key: str, reports: list[AlertReport]) -> str:
    page = PAGE_BY_KEY[page_key]
    content_html, asset_injector = (None, None) if page_key == 'alerts' else _static_page_content(page_key, reports)
    rendered = compose_static_page(
        inject_reactive_table_assets(shell_html),
        StaticPagePlan(
            page_key=page_key, title=page['title'], subtitle=page['subtitle'],
            navigation_html=build_nav_html(
                page_key, active_alert_count(reports), active_alert_highest_severity_class(reports)
            ),
            content_html=content_html,
            alert_contracts=(ALERTS_REACTIVE_FALLBACK, ALERTS_PAGE_SCROLL_STABILIZER,
                             PINNED_ALERT_ROW_SCROLL_SYNC, ALERT_COLUMN_SINGLE_WRAP_CONTRACT),
        ),
    )
    return asset_injector(rendered) if asset_injector else rendered


def write_site_pages(reports: list[AlertReport]) -> list[Path]:
    shell_html = build_html(reports)
    copy_static_assets()
    written: list[Path] = [write_status_json(reports), write_n8n_beacon_json(reports), write_n8n_beacon_history_json(), *write_detail_fragments(reports)]
    written.extend(
        publish_static_pages(
            _publication_paths(), PAGE_DEFS, shell_html=shell_html,
            reports=reports, render_page=render_static_page,
        )
    )
    return written


def main() -> int:
    reports = load_reports()
    written = write_site_pages(reports)
    print(f'Wrote {INDEX}')
    print('pages=' + ','.join(path.name for path in written))
    print(f'reports={len(reports)} bytes={sum(r.size for r in reports)} source={DB_PATH} markdown_corpus={SOURCE_DIR}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
