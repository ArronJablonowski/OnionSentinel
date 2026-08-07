"""Pure report-catalog and static-asset route classification."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote


CATALOG_EXACT_OPERATIONS = {
    '/api/reports': 'catalog_index',
    '/metrics/system-uptime': 'metric_system_uptime',
    '/metrics/updates': 'metric_updates',
    '/metrics/macos-updates': 'metric_macos_updates',
    '/metrics/hermes-backups': 'metric_hermes_backups',
    '/metrics/local-disk': 'metric_local_disk',
    '/metrics/portal-update': 'metric_portal_update',
    '/qr_landing_source.pdf': 'qr_landing_source',
    '/open/qr_landing_source.pdf': 'qr_landing_source',
}
FOREST_ASSET_PREFIXES = (
    '/forest_room5_assets/',
    '/open/forest_room5_assets/',
)


@dataclass(frozen=True)
class CatalogRoute:
    path: str
    operation: str | None
    report_id: str | None = None
    asset_path: str | None = None

    @property
    def requires_catalog_scan(self) -> bool:
        return self.operation in {'catalog_index', 'metric_portal_update'}


def classify_catalog_route(path: str) -> CatalogRoute:
    """Classify routes handled after the operational page/API boundary."""
    operation = CATALOG_EXACT_OPERATIONS.get(path)
    if operation is not None:
        return CatalogRoute(path=path, operation=operation)

    for prefix in FOREST_ASSET_PREFIXES:
        if path.startswith(prefix):
            return CatalogRoute(
                path=path,
                operation='forest_asset',
                asset_path=unquote(path[len(prefix):]),
            )
    if path.startswith('/view/'):
        parts = path[len('/view/'):].split('/', 1)
        return CatalogRoute(
            path=path,
            operation='view_report',
            report_id=unquote(parts[0]).strip(),
            asset_path=unquote(parts[1]) if len(parts) > 1 else '',
        )
    if path.startswith('/open/'):
        return CatalogRoute(
            path=path,
            operation='open_report',
            report_id=unquote(path[len('/open/'):]).strip('/'),
        )
    if path.startswith('/download/'):
        return CatalogRoute(
            path=path,
            operation='download_report',
            report_id=unquote(path[len('/download/'):]).strip('/'),
        )
    return CatalogRoute(path=path, operation=None)
