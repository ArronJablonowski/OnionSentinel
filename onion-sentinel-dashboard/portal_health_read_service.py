"""Health response composition for the legacy portal runtime."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence


def inspect_scan_root(root: Path) -> dict:
    info = {
        "path": str(root),
        "exists": root.exists(),
        "is_dir": root.is_dir(),
        "html_here": 0,
        "error": None,
    }
    try:
        info["html_here"] = sum(1 for _ in root.glob("*.html")) if info["exists"] else 0
    except Exception as exc:
        info["error"] = repr(exc)
    return info


def compose_portal_health(
    reports: Sequence[object],
    roots: Iterable[Path],
    *,
    local_address: str,
    generated_at: str,
) -> dict:
    return {
        "ok": True,
        "reports": len(reports),
        "ip": local_address,
        "time": generated_at,
        "roots": [inspect_scan_root(root) for root in roots],
    }
