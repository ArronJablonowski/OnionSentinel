"""Safe lifecycle helpers for runtime-only broker-managed PCAP artifacts."""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any


REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,140}")


def tool_completed(tool: object) -> bool:
    """Require a configured parser and at least one successful command."""
    if not isinstance(tool, dict) or not tool.get("available"):
        return False
    commands = tool.get("commands")
    return isinstance(commands, list) and bool(commands) and all(
        isinstance(command, dict) and command.get("ok") is True for command in commands
    )


def analysis_completed(analysis: object) -> bool:
    """Raw packets are disposable only after both independent parsers succeed."""
    if not isinstance(analysis, dict) or not analysis.get("pcap_files"):
        return False
    return tool_completed(analysis.get("zeek")) and tool_completed(analysis.get("tshark"))


def validated_request_dir(artifact_root: Path, request_id: object) -> Path:
    """Resolve one request directory without allowing traversal or root deletion."""
    value = str(request_id or "").strip()
    if not REQUEST_ID_PATTERN.fullmatch(value):
        raise ValueError("invalid PCAP request id for artifact cleanup")
    root = artifact_root.expanduser().resolve()
    target = (root / value).resolve()
    if target.parent != root or target == root:
        raise ValueError("unsafe PCAP artifact cleanup target")
    return target


def delete_request_artifacts(artifact_root: Path, request_id: object) -> dict[str, Any]:
    """Delete exactly one broker request directory and report reclaimed bytes."""
    target = validated_request_dir(artifact_root, request_id)
    if not target.exists():
        return {"deleted": False, "bytes": 0, "files": 0}
    if not target.is_dir():
        raise ValueError("PCAP request artifact path is not a directory")
    files = [path for path in target.rglob("*") if path.is_file()]
    reclaimed = sum(path.stat().st_size for path in files)
    shutil.rmtree(target)
    return {"deleted": True, "bytes": reclaimed, "files": len(files)}
