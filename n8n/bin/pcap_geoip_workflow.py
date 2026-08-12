"""Bounded, offline MaxMind lookup workflow for compact PCAP evidence."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, NamedTuple


class GeoipPolicy(NamedTuple):
    database_types: frozenset[str]
    lookup_order: tuple[str, ...]
    max_lookups: int


class GeoipDependencies(NamedTuple):
    public_ip: Callable[[object], str]
    sanitize: Callable[[object, int], str]
    compact_record: Callable[..., dict[str, Any]]


def _normalized_paths(
    database_paths: dict[str, Path] | Path,
    policy: GeoipPolicy,
) -> dict[str, Path]:
    if isinstance(database_paths, Path):
        database_paths = {"city": database_paths}
    return {
        database_type: Path(path).expanduser()
        for database_type, path in database_paths.items()
        if database_type in policy.database_types
    }


def _initial_summary(
    paths: dict[str, Path], policy: GeoipPolicy,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "available": False,
        "network_access": "none-offline-database-only",
        "public_ip_candidates": 0,
        "lookups_attempted": 0,
        "records": [],
        "databases": {},
    }
    for database_type in policy.lookup_order:
        path = paths.get(database_type)
        if path is None:
            continue
        summary["databases"][database_type] = {
            "state": "missing",
            "database": path.name,
            "lookups_attempted": 0,
            "records_found": 0,
            "records_not_found": 0,
            "lookup_errors": 0,
        }
    return summary


def _candidate_contexts(
    candidates: Any,
    policy: GeoipPolicy,
    dependencies: GeoipDependencies,
) -> dict[str, dict[str, Any]]:
    rows = candidates.most_common(("ip", "role"), policy.max_lookups * 2)
    by_ip: dict[str, dict[str, Any]] = {}
    for item in rows:
        address = dependencies.public_ip(item.get("ip"))
        if not address:
            continue
        current = by_ip.setdefault(address, {"count": 0, "roles": []})
        current["count"] += int(item.get("count") or 0)
        role = dependencies.sanitize(item.get("role"), 24)
        if role:
            current["roles"].append(role)
    return by_ip


def _ready_paths(paths: dict[str, Path]) -> dict[str, Path]:
    return {
        database_type: path
        for database_type, path in paths.items()
        if path.is_file()
    }


def _reader_module(summary: dict[str, Any]):
    try:
        import maxminddb  # type: ignore
    except ImportError:
        summary["reason"] = (
            "maxminddb Python reader is not installed in the Onion Sentinel runtime"
        )
        return None
    return maxminddb


def _open_readers(
    reader_module: Any,
    ready_paths: dict[str, Path],
    summary: dict[str, Any],
    dependencies: GeoipDependencies,
    opened_readers: dict[str, Any],
) -> dict[str, Any]:
    readers: dict[str, Any] = {}
    for database_type, path in ready_paths.items():
        status = summary["databases"][database_type]
        try:
            reader = reader_module.open_database(str(path))
            opened_readers[database_type] = reader
            metadata = reader.metadata()
        except Exception as exc:
            status["state"] = "unreadable"
            status["error"] = dependencies.sanitize(exc, 240)
            continue
        sanitized_type = dependencies.sanitize(
            getattr(metadata, "database_type", ""), 120
        )
        readers[database_type] = reader
        status["state"] = "ready"
        status["database_type"] = sanitized_type
    return readers


def _lookup_record(
    database_type: str,
    reader: Any,
    address: str,
    context: dict[str, Any],
    summary: dict[str, Any],
    merged: dict[str, Any],
    sources: list[str],
    dependencies: GeoipDependencies,
) -> None:
    status = summary["databases"][database_type]
    status["lookups_attempted"] += 1
    summary["lookups_attempted"] += 1
    try:
        record = reader.get(address)
    except Exception:
        status["lookup_errors"] += 1
        return
    if not isinstance(record, dict):
        status["records_not_found"] += 1
        return
    status["records_found"] += 1
    sources.append(database_type)
    compact = dependencies.compact_record(
        address, record, context["roles"], context["count"]
    )
    for key, value in compact.items():
        if key not in {"ip", "roles", "packet_observations"} and key not in merged:
            merged[key] = value


def _lookup_address(
    address: str,
    context: dict[str, Any],
    readers: dict[str, Any],
    summary: dict[str, Any],
    policy: GeoipPolicy,
    dependencies: GeoipDependencies,
) -> None:
    merged: dict[str, Any] = {
        "ip": address,
        "roles": sorted(set(context["roles"])),
        "packet_observations": context["count"],
    }
    sources: list[str] = []
    for database_type in policy.lookup_order:
        reader = readers.get(database_type)
        if reader is not None:
            _lookup_record(
                database_type,
                reader,
                address,
                context,
                summary,
                merged,
                sources,
                dependencies,
            )
    if sources:
        merged["database_sources"] = sources
        summary["records"].append(merged)


def _lookup_candidates(
    contexts: dict[str, dict[str, Any]],
    readers: dict[str, Any],
    summary: dict[str, Any],
    policy: GeoipPolicy,
    dependencies: GeoipDependencies,
) -> None:
    ordered = sorted(
        contexts.items(),
        key=lambda item: (-item[1]["count"], item[0]),
    )[:policy.max_lookups]
    for address, context in ordered:
        _lookup_address(
            address, context, readers, summary, policy, dependencies
        )


def _close_readers(readers: dict[str, Any]) -> None:
    for reader in readers.values():
        reader.close()


def _finalize_summary(
    summary: dict[str, Any], readers: dict[str, Any],
) -> dict[str, Any]:
    summary["available"] = bool(readers)
    summary["records_found"] = len(summary["records"])
    summary["records_not_found"] = sum(
        int(status.get("records_not_found") or 0)
        for status in summary["databases"].values()
    )
    summary["lookup_errors"] = sum(
        int(status.get("lookup_errors") or 0)
        for status in summary["databases"].values()
    )
    if not readers:
        summary["reason"] = "Configured MaxMind MMDB files could not be opened"
    return summary


def summarize_geoip(
    candidates: Any,
    database_paths: dict[str, Path] | Path,
    *,
    policy: GeoipPolicy,
    dependencies: GeoipDependencies,
) -> dict[str, Any]:
    """Perform bounded lookups using only configured local MMDB readers."""
    paths = _normalized_paths(database_paths, policy)
    summary = _initial_summary(paths, policy)
    contexts = _candidate_contexts(candidates, policy, dependencies)
    summary["public_ip_candidates"] = len(contexts)
    ready = _ready_paths(paths)
    if not ready:
        summary["reason"] = "No configured MaxMind MMDB files are installed"
        return summary
    reader_module = _reader_module(summary)
    if reader_module is None:
        return summary
    readers: dict[str, Any] = {}
    opened_readers: dict[str, Any] = {}
    try:
        readers = _open_readers(
            reader_module,
            ready,
            summary,
            dependencies,
            opened_readers,
        )
        _lookup_candidates(contexts, readers, summary, policy, dependencies)
    finally:
        _close_readers(opened_readers)
    return _finalize_summary(summary, readers)
