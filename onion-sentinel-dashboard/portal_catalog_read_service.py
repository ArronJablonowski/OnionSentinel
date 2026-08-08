"""Application dispatch for report catalog index and metric reads."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from portal_catalog_routes import CatalogRoute


@dataclass(frozen=True)
class CatalogReadCallbacks:
    scan_reports: Callable[[], list]
    render_system_uptime: Callable[[], bytes]
    render_updates: Callable[[], bytes]
    render_macos_updates: Callable[[], bytes]
    render_hermes_backups: Callable[[], bytes]
    render_local_disk: Callable[[], bytes]
    render_portal_update: Callable[[list], bytes]


@dataclass(frozen=True)
class CatalogReadResult:
    status: int
    payload: list[dict] | bytes
    encoded: bool = False
    content_type: str = "application/json; charset=utf-8"


def project_report_catalog(reports: list) -> list[dict]:
    return [
        {
            "id": report.rid,
            "title": report.title,
            "path": report.rel,
            "category": report.category,
            "mtime": report.mtime,
            "size": report.size,
        }
        for report in reports
    ]


def dispatch_catalog_read(
    route: CatalogRoute,
    callbacks: CatalogReadCallbacks,
) -> CatalogReadResult | None:
    """Dispatch catalog index and metric routes without eager catalog scans."""
    if route.operation == "catalog_index":
        return CatalogReadResult(
            200, project_report_catalog(callbacks.scan_reports()),
        )
    renderers = {
        "metric_system_uptime": callbacks.render_system_uptime,
        "metric_updates": callbacks.render_updates,
        "metric_macos_updates": callbacks.render_macos_updates,
        "metric_hermes_backups": callbacks.render_hermes_backups,
        "metric_local_disk": callbacks.render_local_disk,
    }
    renderer = renderers.get(route.operation or "")
    if renderer is not None:
        return CatalogReadResult(200, renderer(), True, "text/html; charset=utf-8")
    if route.operation == "metric_portal_update":
        return CatalogReadResult(
            200,
            callbacks.render_portal_update(callbacks.scan_reports()),
            True,
            "text/html; charset=utf-8",
        )
    return None
