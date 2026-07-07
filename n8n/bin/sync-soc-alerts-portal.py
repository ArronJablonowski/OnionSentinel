#!/usr/bin/env python3
"""Mirror the generated Onion Sentinel dashboard into the LAN portal.

The Mac Studio also has a broad local portal sync job for unrelated dashboards.
The AI scheduler uses this narrower script so SOC alert analysis does not depend
on Obsidian or other local notebook paths that are outside the disaster-recovery
repo.
"""
from __future__ import annotations

import datetime as dt
import shutil
from pathlib import Path


HOME = Path.home()
SOURCE = HOME / "SOC Alerts Web"
DESTINATION = HOME / "report_portal" / "library" / "Cybersecurity" / "SOC Alerts"
LAST_UPDATED_FILE = HOME / "report_portal" / ".last_updated"
EXCLUDE_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules"}


def copy_tree(source: Path, destination: Path) -> int:
    """Copy changed files only, preserving the generated dashboard directory."""
    changed = 0
    for path in source.rglob("*"):
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        rel = path.relative_to(source)
        target = destination / rel
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not path.is_file():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        should_copy = True
        if target.exists():
            src_stat = path.stat()
            dst_stat = target.stat()
            should_copy = src_stat.st_size != dst_stat.st_size or int(src_stat.st_mtime) > int(dst_stat.st_mtime)
        if should_copy:
            shutil.copy2(path, target)
            changed += 1
    return changed


def main() -> int:
    if not SOURCE.exists():
        print(f"SOC dashboard source missing: {SOURCE}")
        return 2
    DESTINATION.mkdir(parents=True, exist_ok=True)
    changed = copy_tree(SOURCE, DESTINATION)
    LAST_UPDATED_FILE.parent.mkdir(parents=True, exist_ok=True)
    LAST_UPDATED_FILE.write_text(f"{dt.datetime.now().astimezone().isoformat()}\n", encoding="utf-8")
    print(f"synced {SOURCE} -> {DESTINATION} ({changed} changed file(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
