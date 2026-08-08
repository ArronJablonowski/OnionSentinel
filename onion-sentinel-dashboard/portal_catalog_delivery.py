"""Traversal-safe static and report catalog delivery policy."""
from __future__ import annotations

from dataclasses import dataclass, field
import mimetypes
from pathlib import Path
from typing import Callable, Protocol
from urllib.parse import quote

from portal_catalog_routes import CatalogRoute


class CatalogReport(Protocol):
    rid: str
    path: Path


@dataclass(frozen=True)
class CatalogDeliveryCallbacks:
    reports_by_id: Callable[[], dict[str, CatalogReport]]


@dataclass(frozen=True)
class CatalogDeliveryResult:
    status: int
    body: bytes = b""
    content_type: str = "text/plain; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)
    redirect: str = ""


def _asset_content_type(target: Path) -> str:
    content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    return "text/html; charset=utf-8" if target.suffix.lower() in {".html", ".htm"} else content_type


def _read_asset(target: Path) -> CatalogDeliveryResult:
    if not target.is_file():
        return CatalogDeliveryResult(404, b"Asset not found")
    try:
        body = target.read_bytes()
    except Exception as exc:
        return CatalogDeliveryResult(500, str(exc).encode())
    return CatalogDeliveryResult(200, body, _asset_content_type(target))


def _contained_target(base: Path, asset_path: str) -> Path | None:
    base = base.resolve()
    target = (base / asset_path).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        return None
    return target


def _report_view(
    route: CatalogRoute,
    report: CatalogReport,
) -> CatalogDeliveryResult:
    asset_path = route.asset_path or ""
    if asset_path in {"", "/"}:
        return _read_asset(report.path)
    target = _contained_target(report.path.parent, asset_path)
    return CatalogDeliveryResult(403, b"Forbidden") if target is None else (
        _read_asset(target)
    )


def _report_download(report: CatalogReport) -> CatalogDeliveryResult:
    try:
        body = report.path.read_bytes()
    except Exception as exc:
        return CatalogDeliveryResult(500, str(exc).encode())
    content_type = mimetypes.guess_type(report.path.name)[0] or "text/html; charset=utf-8"
    return CatalogDeliveryResult(
        200,
        body,
        content_type,
        {"Content-Disposition": f"attachment; filename={quote(report.path.name)}"},
    )


def deliver_catalog_route(
    route: CatalogRoute,
    *,
    forest_asset_root: Path,
    qr_landing_source: Path,
    callbacks: CatalogDeliveryCallbacks,
) -> CatalogDeliveryResult | None:
    """Resolve and deliver one classified static/report route."""
    if route.operation == "forest_asset":
        target = _contained_target(forest_asset_root, route.asset_path or "")
        return CatalogDeliveryResult(403, b"Forbidden") if target is None else (
            _read_asset(target)
        )
    if route.operation == "qr_landing_source":
        return _read_asset(qr_landing_source)
    if route.operation not in {"view_report", "open_report", "download_report"}:
        return None
    report = callbacks.reports_by_id().get(route.report_id or "")
    if report is None:
        return CatalogDeliveryResult(404, b"Report not found")
    if route.operation == "view_report":
        return _report_view(route, report)
    if route.operation == "open_report":
        return CatalogDeliveryResult(302, redirect=f"/view/{report.rid}/")
    return _report_download(report)
