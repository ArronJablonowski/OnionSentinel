"""Read primary Markdown reports and build disaster-recovery report models."""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from dashboard_alert_detail_markdown import markdown_to_html
from dashboard_alert_detail_sections import CRITICALITY_LABELS
from dashboard_alert_report_factory import clean_endpoint_part, endpoint_label, summarize_markdown
from dashboard_alert_report_model import AlertReport, CRITICALITY_ORDER
from dashboard_time_format import parse_iso_timestamp


@dataclass(frozen=True)
class ReportRepositoryConfig:
    """Explicit read-only Markdown discovery policy."""

    sources: tuple[Path, ...]
    supported_suffixes: frozenset[str]
    derived_directories: frozenset[str]


def extract_markdown_alert_id(text: str) -> str | None:
    """Return the alert ID embedded in a generated Markdown report."""
    patterns = (
        r"^alert_id:\s*[\"']?(.+?)[\"']?\s*$",
        r"^-\s*\*\*Alert ID:\*\*\s*(.+?)\s*$",
        r'"alert_id"\s*:\s*"([^"]+)"',
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        value = match.group(1).strip().strip("\"'") if match else ""
        if value:
            return value
    return None


def clean_title_from_markdown(text: str, path: Path) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") and (title := stripped.lstrip("#").strip()):
            return title[:180]
    return path.stem.replace("_", " ").replace("-", " ").strip().title() or path.name


def detect_criticality(text: str, title: str, path: Path) -> tuple[str, int]:
    """Extract criticality from title, content, and path with stable ordering."""
    joined = "\n".join([title, path.name, *text.splitlines()[:40]])
    patterns = (
        r"\[\s*(critical|high|medium|low|informational|info)\s*\]",
        r"\btriage\s+level\s*[:=]\s*[\"']?(critical|high|medium|low|informational|info)\b",
        r"\bseverity\s*[:=]\s*[\"']?(critical|high|medium|low|informational|info)\b",
        r"\bpriority\s*[:=]\s*[\"']?(critical|high|medium|low|informational|info)\b",
    )
    for pattern in patterns:
        if match := re.search(pattern, joined, flags=re.IGNORECASE):
            key = match.group(1).lower()
            return CRITICALITY_LABELS[key], CRITICALITY_ORDER[key]
    return "Informational", CRITICALITY_ORDER["informational"]


def extract_network_endpoints(text: str) -> tuple[str, str, str, str]:
    """Extract source/destination IP and port from common report shapes."""
    traffic = re.search(
        r"\bTraffic:\*?\*?\s*([0-9a-fA-F:.]+):(\d+)\s*(?:->|→|-)\s*([0-9a-fA-F:.]+):(\d+)",
        text,
        flags=re.IGNORECASE,
    )
    if traffic:
        return traffic.group(1), traffic.group(2), traffic.group(3), traffic.group(4)
    source = _json_endpoint(text, "source")
    destination = _json_endpoint(text, "destination")
    return (
        clean_endpoint_part(source[0] or _front_matter_value(text, "source_ip")),
        clean_endpoint_part(source[1] or _front_matter_value(text, "source_port", digits=True)),
        clean_endpoint_part(destination[0] or _front_matter_value(text, "(?:destination|dest)_ip")),
        clean_endpoint_part(destination[1] or _front_matter_value(text, "(?:destination|dest)_port", digits=True)),
    )


def _json_endpoint(text: str, name: str) -> tuple[str, str]:
    match = re.search(
        rf'"{name}"\s*:\s*\{{(?P<body>.*?)\n\s*\}}',
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    body = match.group("body") if match else ""
    values: list[str] = []
    for field in ("ip", "port"):
        value = re.search(rf'"{field}"\s*:\s*(?:"([^"]+)"|(\d+))', body, flags=re.IGNORECASE)
        values.append((value.group(1) or value.group(2)) if value else "")
    return values[0], values[1]


def _front_matter_value(text: str, field: str, *, digits: bool = False) -> str:
    value = r"(\d+)" if digits else r"[^\"'\n]+"
    match = re.search(rf"^{field}:\s*[\"']?({value})", text, flags=re.IGNORECASE | re.MULTILINE)
    return match.group(1) if match else ""


def extract_rule_identity(text: str, title: str) -> tuple[str, str]:
    rule_id = re.search(r'"rule_id"\s*:\s*"?([^",\n]+)"?', text, flags=re.IGNORECASE)
    rule_name = re.search(r'"rule_name"\s*:\s*"([^"]+)"', text, flags=re.IGNORECASE)
    if not rule_name:
        rule_name = re.search(r"\|\s*Rule name\s*\|\s*([^|]+?)\s*\|", text, flags=re.IGNORECASE)
    return (
        clean_endpoint_part(rule_id.group(1) if rule_id else ""),
        clean_endpoint_part(rule_name.group(1) if rule_name else title),
    )


def extract_alert_timestamp(text: str, fallback_ts: float) -> float:
    patterns = (
        r'"timestamp"\s*:\s*"([^"]+)"',
        r"\|\s*Timestamp\s*\|\s*([^|]+?)\s*\|",
        r"^generated_at:\s*([^\n]+)",
        r"^-\s*\*\*Generated:\*\*\s*([^\n]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        timestamp = parse_iso_timestamp(match.group(1)) if match else None
        if timestamp is not None:
            return timestamp
    return fallback_ts


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    except OSError:
        return None


def _unique_sources(config: ReportRepositoryConfig):
    visited: set[Path] = set()
    for source in config.sources:
        try:
            resolved_source = source.resolve()
        except OSError:
            continue
        if resolved_source in visited or not source.is_dir():
            continue
        visited.add(resolved_source)
        yield source, resolved_source


def _eligible_source_file(
    path: Path,
    resolved_source: Path,
    config: ReportRepositoryConfig,
) -> Path | None:
    if not path.is_file() or path.name.startswith("."):
        return None
    if path.suffix.lower() not in config.supported_suffixes:
        return None
    try:
        relative = path.resolve().relative_to(resolved_source)
    except (OSError, ValueError):
        return None
    if relative.parts and relative.parts[0].lower() in config.derived_directories:
        return None
    return relative


def _source_files(config: ReportRepositoryConfig):
    for source, resolved_source in _unique_sources(config):
        for path in sorted(source.rglob("*"), key=lambda item: str(item).lower()):
            if relative := _eligible_source_file(path, resolved_source, config):
                yield source, path, relative


def index_markdown_reports(config: ReportRepositoryConfig) -> dict[str, tuple[Path, str, os.stat_result]]:
    """Index primary reports by alert ID; later source precedence is preserved."""
    indexed: dict[str, tuple[Path, str, os.stat_result]] = {}
    for _, path, _ in _source_files(config):
        text = _read_text(path)
        alert_id = extract_markdown_alert_id(text or "")
        if not text or not alert_id:
            continue
        try:
            indexed[alert_id] = (path, text, path.stat())
        except OSError:
            continue
    return indexed


def _fallback_report(source: Path, path: Path, relative: Path, text: str) -> AlertReport | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    title = clean_title_from_markdown(text, path)
    criticality, rank = detect_criticality(text, title, path)
    source_ip, source_port, destination_ip, destination_port = extract_network_endpoints(text)
    rule_id, rule_name = extract_rule_identity(text, title)
    unavailable = "SQLite alert-store is unavailable; {} status cannot be resolved"
    return AlertReport(
        title=title, source=path, rel_source=str(relative), mtime=stat.st_mtime,
        size=stat.st_size, digest=hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:12],
        rendered_html=markdown_to_html(text), summary=summarize_markdown(text),
        criticality=criticality, criticality_rank=rank, alert_source="markdown",
        filter_status="markdown", source_ip=source_ip, source_port=source_port,
        destination_ip=destination_ip, destination_port=destination_port,
        source_endpoint=endpoint_label(source_ip, source_port),
        destination_endpoint=endpoint_label(destination_ip, destination_port),
        rule_id=rule_id, rule_name=rule_name, raw_alert_count=1, total_seen_count=1,
        repeat_count=1, first_seen="n/a", last_seen="n/a", alert_group_key=rule_name,
        alert_ts=extract_alert_timestamp(text, stat.st_mtime), ai_status_key="not-queued",
        ai_status_label="Not queued", ai_status_detail=unavailable.format("AI"),
        enrichment_status_key="none", enrichment_status_label="None",
        enrichment_status_detail=unavailable.format("enrichment"), enrichment_record_count=0,
        enrichment_skip_count=0, enrichment_error_count=0, pcap_status_key="none",
        pcap_status_label="None", pcap_status_detail=unavailable.format("PCAP analysis"),
        tuning_recommendation="none", tuning_reason="", recommended_tuning_actions=[],
        ai_analysis={},
    )


def load_markdown_fallback_reports(config: ReportRepositoryConfig) -> list[AlertReport]:
    """Build deterministic report models when SQLite is unavailable."""
    reports: list[AlertReport] = []
    for source, path, relative in _source_files(config):
        text = _read_text(path)
        report = _fallback_report(source, path, relative, text) if text is not None else None
        if report:
            reports.append(report)
    return sorted(
        reports,
        key=lambda report: (report.criticality_rank, report.mtime, report.title.lower()),
        reverse=True,
    )
