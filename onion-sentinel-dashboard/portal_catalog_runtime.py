"""Runtime wiring for report discovery, default selection, and library sizing."""
from __future__ import annotations

from typing import Any


def local_ip(r: Any) -> str:
    candidates = []
    try:
        sock = r.socket.socket(r.socket.AF_INET, r.socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        candidates.append(sock.getsockname()[0])
        sock.close()
    except Exception:
        pass
    try:
        candidates.append(r.socket.gethostbyname(r.socket.gethostname()))
    except Exception:
        pass
    for ip in candidates:
        if ip and not ip.startswith("127."):
            return ip
    return "127.0.0.1"


def title_from_html(r: Any, path: Any) -> str:
    return r.read_report_title(path)


def category_for(r: Any, path: Any) -> str:
    return r.classify_report_category(path, r.HOME)


def should_skip_dir(r: Any, path: Any) -> bool:
    return r.exclude_report_directory(path, r.EXCLUDE_DIR_NAMES)


def report_id(r: Any, path: Any) -> str:
    return r.derive_report_id(path)


def scan_reports(r: Any) -> list[Any]:
    return r.discover_reports(
        home=r.HOME, scan_roots=r.SCAN_ROOTS,
        standalone_html=r.STANDALONE_HTML,
        excluded_names=r.EXCLUDE_DIR_NAMES,
    )


def soc_alerts_report(r: Any, reports: list[Any]) -> Any | None:
    return r.select_soc_alerts_report(reports)


def soc_alerts_default_path(r: Any, reports: list[Any]) -> str | None:
    return r.project_soc_alerts_default_path(reports)


def is_daily_threat_brief_file(r: Any, report: Any) -> bool:
    return r.classify_daily_threat_brief(report)


def human_size(r: Any, n: int) -> str:
    return r.format_human_size(n)


def artifact_library_disk_usage(r: Any) -> int:
    total = 0
    seen = set()
    for configured_root in r.SCAN_ROOTS:
        for path in _artifact_files(r, configured_root):
            try:
                resolved = path.resolve()
                if resolved in seen or not resolved.is_file():
                    continue
                seen.add(resolved)
                stat_result = resolved.stat()
                total += (
                    int(getattr(stat_result, "st_blocks", 0) or 0) * 512
                    or stat_result.st_size
                )
            except Exception:
                continue
    return total


def _artifact_files(r: Any, configured_root: Any) -> list[Any]:
    if not configured_root.exists():
        return []
    try:
        root = configured_root.resolve()
    except Exception:
        return []
    if root.is_file():
        return [root]
    files = []
    for dirpath, dirnames, filenames in r.os.walk(root):
        dirnames[:] = [
            name for name in dirnames
            if not r.should_skip_dir(r.Path(dirpath) / name)
        ]
        files.extend(r.Path(dirpath) / name for name in filenames)
    return files
