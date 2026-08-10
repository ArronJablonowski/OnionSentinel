"""Read-only HTML report catalog discovery and projection."""
from __future__ import annotations

import hashlib
import html
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Report:
    rid: str
    title: str
    path: Path
    rel: str
    category: str
    size: int
    mtime: float
    is_index: bool


def title_from_html(path: Path) -> str:
    name_title = path.stem.replace("_", " ").strip()
    try:
        data = path.read_text(errors="ignore")[:20000]
        title_match = re.search(r"<title[^>]*>(.*?)</title>", data, flags=re.I | re.S)
        if title_match:
            title = html.unescape(re.sub(r"\s+", " ", title_match.group(1)).strip())
            if title:
                return title
        heading_match = re.search(r"<h1[^>]*>(.*?)</h1>", data, flags=re.I | re.S)
        if heading_match:
            title = html.unescape(re.sub(r"<[^>]+>", "", heading_match.group(1))).strip()
            if title:
                return title
    except Exception:
        pass
    return name_title or path.name


def _project_category(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root)
        return f"Project: {rel.parts[0]}" if rel.parts else "Projects"
    except Exception:
        return "Projects"


def category_for(path: Path, home: Path) -> str:
    source = str(path)
    category_patterns = (
        (("/report_portal/library/Threat Intel/", "Daily Threat Intel Briefs"), "Threat Intel"),
        (("/report_portal/library/Threat Hunting/", "/ThreatHunting/ATHF/"), "Threat Hunting"),
        (("/report_portal/library/Product Research/", "entrepreneurial_product_research_reports", "entrepreneurial_research"), "Product Research"),
        (("/report_portal/library/Cybersecurity Library/", "Cybersecurity Library Web"), "Cybersecurity"),
        (("/report_portal/library/Cybersecurity/", "Sigma Learning Web"), "Cybersecurity"),
        (("/report_portal/library/Resource Library/", "Resource Library Web"), "Cybersecurity"),
        (("/report_portal/library/Portal Operations/", "LAN Portal Web Server Architecture"), "Portal Operations"),
        (("/report_portal/library/Web App Projects/", "Web App Projects Web"), "Web App Projects"),
        (("/report_portal/library/Local AI/", "Local LLM Benchmark Dashboard"), "Local AI"),
    )
    for patterns, category in category_patterns:
        if any(pattern in source for pattern in patterns):
            return category
    if "/report_portal/library/Projects/" in source:
        return _project_category(path, home / "report_portal" / "library" / "Projects")
    if "/gitProjects/" in source:
        return _project_category(path, home / "gitProjects")
    if "/report_portal/library/Prototype Web App/" in source or "forest_room" in path.name.lower():
        return "Prototype: Web app"
    return "Reports"


def should_skip_dir(path: Path, excluded_names: set[str]) -> bool:
    return path.name in excluded_names or path.name.startswith(".")


def report_id(path: Path) -> str:
    return hashlib.sha1(str(path).encode()).hexdigest()[:16]


def _candidate_paths(
    scan_roots: Sequence[Path],
    standalone_html: Sequence[Path],
    excluded_names: set[str],
) -> list[Path]:
    paths: list[Path] = []
    for root in scan_roots:
        if not root.exists():
            continue
        if root.is_file() and root.suffix.lower() in (".html", ".htm"):
            paths.append(root)
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                name
                for name in dirnames
                if not should_skip_dir(Path(dirpath) / name, excluded_names)
            ]
            paths.extend(
                Path(dirpath) / filename
                for filename in filenames
                if filename.lower().endswith((".html", ".htm"))
            )
    paths.extend(path for path in standalone_html if path.exists())
    return paths


def scan_reports(
    *,
    home: Path,
    scan_roots: Sequence[Path],
    standalone_html: Sequence[Path],
    excluded_names: set[str],
) -> list[Report]:
    seen: set[Path] = set()
    reports: list[Report] = []
    for candidate in _candidate_paths(scan_roots, standalone_html, excluded_names):
        try:
            path = candidate.resolve()
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            stat = path.stat()
            try:
                rel = str(path.relative_to(home))
            except Exception:
                rel = str(path)
            reports.append(Report(
                rid=report_id(path),
                title=title_from_html(path),
                path=path,
                rel=rel,
                category=category_for(path, home),
                size=stat.st_size,
                mtime=stat.st_mtime,
                is_index=path.name.lower() in ("index.html", "index.htm"),
            ))
        except Exception:
            continue
    return sorted(reports, key=lambda report: (report.mtime, report.title.lower()), reverse=True)


def soc_alerts_report(reports: Sequence[Report]) -> Report | None:
    return next(
        (
            report
            for report in reports
            if report.title == "SOC Alerts"
            or "Cybersecurity/SOC Alerts/index.html" in report.rel
        ),
        None,
    )


def soc_alerts_default_path(reports: Sequence[Report]) -> str | None:
    report = soc_alerts_report(reports)
    return f"/view/{report.rid}/" if report else None


def is_daily_threat_brief_file(report: Report) -> bool:
    return (
        report.category == "Threat Intel"
        and not report.is_index
        and report.path.name.endswith(" - Daily Threat Intel Brief.html")
    )


def human_size(size: int) -> str:
    value: int | float = size
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{value} B"
        value /= 1024
    return f"{value:.1f} TB"
