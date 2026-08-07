"""Parsed PCAP artifact admission, indexing, and newest-record selection."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


JsonObject = dict[str, object]


@dataclass(frozen=True)
class PcapArtifactSources:
    paths: Callable[[], Iterable[Path]]
    read_record: Callable[[Path], object]
    modified_time: Callable[[Path], float]


def has_parsed_pcap(record: JsonObject) -> bool:
    """Admit only capture-bearing artifacts with Zeek or TShark output."""
    pcap_files = record.get("pcap_files")
    pcap_files = pcap_files if isinstance(pcap_files, list) else []
    if not pcap_files:
        return False
    zeek = record.get("zeek")
    tshark = record.get("tshark")
    zeek = zeek if isinstance(zeek, dict) else {}
    tshark = tshark if isinstance(tshark, dict) else {}
    return bool(zeek.get("available") or tshark.get("available"))


def empty_pcap_index() -> JsonObject:
    return {
        "request_ids": set(), "alert_ids": set(), "group_ids": set(),
        "size_by_alert_id": {}, "size_by_group_id": {},
    }


def _record(path: Path, sources: PcapArtifactSources) -> JsonObject | None:
    try:
        value = sources.read_record(path)
    except Exception:
        return None
    return value if isinstance(value, dict) and has_parsed_pcap(value) else None


def _request(record: JsonObject) -> dict:
    value = record.get("request")
    return value if isinstance(value, dict) else {}


def _capture_size(item: object) -> int:
    if not isinstance(item, dict):
        return 0
    try:
        return max(0, int(item.get("size_bytes") or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _capture_identity(item: dict, request_id: str, position: int) -> str:
    return str(
        item.get("sha256") or item.get("artifact_sha256") or item.get("path")
        or item.get("file") or f"{request_id}:{position}"
    ).strip()


def _add_identity(index: JsonObject, request: dict) -> None:
    for key, bucket in (
        ("request_id", "request_ids"), ("alert_id", "alert_ids"), ("group_id", "group_ids"),
    ):
        value = str(request.get(key) or "").strip()
        if value:
            index[bucket].add(value)


def _add_size(index: JsonObject, seen: dict[str, set[tuple[str, str]]],
              request: dict, identity: str, capture_bytes: int) -> None:
    for request_key, size_key in (
        ("alert_id", "size_by_alert_id"), ("group_id", "size_by_group_id"),
    ):
        value = str(request.get(request_key) or "").strip()
        artifact_key = (value, identity)
        if not value or artifact_key in seen[size_key]:
            continue
        seen[size_key].add(artifact_key)
        sizes = index[size_key]
        sizes[value] = int(sizes.get(value, 0)) + capture_bytes


def _index_record(index: JsonObject, seen: dict[str, set[tuple[str, str]]],
                  record: JsonObject) -> None:
    request = _request(record)
    _add_identity(index, request)
    files = record.get("pcap_files")
    files = files if isinstance(files, list) else []
    request_id = str(request.get("request_id") or "").strip()
    for position, item in enumerate(files):
        capture_bytes = _capture_size(item)
        if not capture_bytes or not isinstance(item, dict):
            continue
        identity = _capture_identity(item, request_id, position)
        _add_size(index, seen, request, identity, capture_bytes)


def build_pcap_analysis_index(sources: PcapArtifactSources) -> JsonObject:
    """Build a de-duplicated index from all admitted parsed artifacts."""
    index = empty_pcap_index()
    seen = {"size_by_alert_id": set(), "size_by_group_id": set()}
    for path in sources.paths():
        record = _record(path, sources)
        if record is not None:
            _index_record(index, seen, record)
    return index


def newest_pcap_analysis_record(group_id: str, sources: PcapArtifactSources) -> JsonObject | None:
    """Return the newest admitted artifact for one dashboard group."""
    group_id = str(group_id or "").strip()
    if not group_id:
        return None
    matches: list[tuple[float, JsonObject]] = []
    for path in sources.paths():
        record = _record(path, sources)
        if record is None or str(_request(record).get("group_id") or "").strip() != group_id:
            continue
        selected = dict(record)
        selected["_analysis_path"] = str(path)
        try:
            matches.append((sources.modified_time(path), selected))
        except OSError:
            continue
    return max(matches, key=lambda item: item[0])[1] if matches else None
