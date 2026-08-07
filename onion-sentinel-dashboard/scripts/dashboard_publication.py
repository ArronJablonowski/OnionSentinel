"""Atomic filesystem publication for generated Onion Sentinel dashboards."""
from __future__ import annotations

import json
import re
import shutil
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from atomic_io import atomic_write_json, atomic_write_text


class PublishedReport(Protocol):
    digest: str
    rendered_html: str
    alert_ts: float
    rule_id: str
    rule_name: str
    source_ip: str
    destination_ip: str
    destination_port: str
    criticality: str
    ai_status_key: str
    ai_status_label: str
    ai_status_detail: str


@dataclass(frozen=True)
class DashboardPublicationPaths:
    out_dir: Path
    detail_dir: Path
    status_json: Path
    beacon_json: Path
    beacon_history_json: Path
    source_beacon_json: Path
    source_beacon_history_json: Path
    asset_source_dirs: tuple[Path, ...] = ()


def status_payload(
    reports: Sequence[PublishedReport],
    *,
    generated_at: str,
    ai_state: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the fast-changing dashboard status document without I/O."""
    return {
        'generated_at': generated_at,
        'poll_interval_ms': 5000,
        'ai': dict(ai_state),
        'reports': {
            report.digest: {
                'ai_status_key': report.ai_status_key,
                'ai_status_label': report.ai_status_label,
                'ai_status_detail': report.ai_status_detail,
            }
            for report in reports
        },
    }


def seed_beacon_payload(
    reports: Sequence[PublishedReport],
    *,
    generated_at: str,
    report_time: Callable[[float], str],
) -> dict[str, Any]:
    """Build the deterministic fallback beacon used before live intake."""
    latest = max(reports, key=lambda report: report.alert_ts) if reports else None
    return {
        'generated_at': report_time(latest.alert_ts) if latest else generated_at,
        'stage': 'seeded',
        'ok': True,
        'status': 'seeded_from_dashboard',
        'alert_id': latest.rule_id if latest else None,
        'rule_name': latest.rule_name if latest else None,
        'source_ip': latest.source_ip if latest else None,
        'destination_ip': latest.destination_ip if latest else None,
        'destination_port': latest.destination_port if latest else None,
        'triage_level': latest.criticality.lower() if latest else None,
        'filter_status': None,
        'notification_status': None,
        'error': None,
    }


def publish_status_json(
    reports: Sequence[PublishedReport],
    paths: DashboardPublicationPaths,
    *,
    generated_at: str,
    ai_state: Mapping[str, Any],
) -> Path:
    return atomic_write_json(
        paths.status_json,
        status_payload(reports, generated_at=generated_at, ai_state=ai_state),
    )


def _read_json(path: Path) -> tuple[bool, Any]:
    try:
        return True, json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False, None


def publish_beacon_json(
    reports: Sequence[PublishedReport],
    paths: DashboardPublicationPaths,
    *,
    generated_at: str,
    report_time: Callable[[float], str],
) -> Path:
    source_valid, source = _read_json(paths.source_beacon_json)
    payload = source if source_valid else seed_beacon_payload(
        reports, generated_at=generated_at, report_time=report_time
    )
    return atomic_write_json(paths.beacon_json, payload)


def publish_beacon_history_json(paths: DashboardPublicationPaths) -> Path:
    source_valid, source = _read_json(paths.source_beacon_history_json)
    payload = source if source_valid and isinstance(source, list) else []
    return atomic_write_json(paths.beacon_history_json, payload)


def publish_detail_fragments(
    reports: Sequence[PublishedReport], paths: DashboardPublicationPaths
) -> list[Path]:
    """Atomically replace current fragments, then remove stale safe names."""
    paths.detail_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    current_names: set[str] = set()
    for report in reports:
        if not re.fullmatch(r'[a-f0-9]{12}', report.digest):
            continue
        destination = paths.detail_dir / f'{report.digest}.html'
        atomic_write_text(
            destination,
            f'<div class="markdown-body">{report.rendered_html}</div>\n',
        )
        written.append(destination)
        current_names.add(destination.name)
    for stale_path in paths.detail_dir.glob('*.html'):
        if stale_path.name not in current_names:
            stale_path.unlink(missing_ok=True)
    return written


def copy_static_assets(paths: DashboardPublicationPaths) -> None:
    destination = paths.out_dir / 'assets'
    destination.mkdir(parents=True, exist_ok=True)
    for source_root in paths.asset_source_dirs:
        if not source_root.exists():
            continue
        try:
            if source_root.resolve() == destination.resolve():
                continue
        except FileNotFoundError:
            pass
        for source in source_root.rglob('*'):
            if not source.is_file():
                continue
            target = destination / source.relative_to(source_root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def publish_static_pages(
    paths: DashboardPublicationPaths,
    page_definitions: Iterable[tuple[str, str, str, str]],
    *,
    shell_html: str,
    reports: Sequence[PublishedReport],
    render_page: Callable[[str, str, Sequence[PublishedReport]], str],
) -> list[Path]:
    """Publish canonical routes and compatibility aliases atomically."""
    written: list[Path] = []
    for key, filename, _title, _subtitle in page_definitions:
        destination = paths.out_dir / filename
        atomic_write_text(destination, render_page(shell_html, key, reports))
        written.append(destination)
    for filename, page_key in (
        ('soc-alerts.html', 'alerts'),
        ('siem-tuning.html', 'siem_engineering'),
    ):
        destination = paths.out_dir / filename
        atomic_write_text(destination, render_page(shell_html, page_key, reports))
        written.append(destination)
    return written
