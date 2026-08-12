"""Bounded per-capture Zeek execution, aggregation, and evidence projection."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, NamedTuple


LOG_NAMES = {
    "conn": ("conn.log",),
    "dns": ("dns.log",),
    "tls": ("ssl.log", "tls.log"),
    "http": ("http.log",),
    "files": ("files.log",),
    "notice": ("notice.log",),
    "weird": ("weird.log",),
}


class ZeekPolicy(NamedTuple):
    summary_fields: dict[str, tuple[str, ...]]
    heavy_hitter_capacity: int
    query_index_limit: int
    summary_limit: int
    parser_timeout_seconds: int


class ZeekDependencies(NamedTuple):
    tool_path: Callable[[str, str], str | None]
    safe_filename: Callable[[object], str]
    run_command: Callable[..., dict[str, Any]]
    aggregate_log: Callable[..., None]
    counter_factory: Callable[[int], Any]
    coverage_factory: Callable[[], Any]
    reservoir_factory: Callable[[int], Any]
    remove_tree: Callable[..., None]


class ZeekState(NamedTuple):
    commands: list[dict[str, Any]]
    counters: dict[str, Any]
    coverage: dict[str, Any]
    query_samples: dict[str, Any]
    files_processed: int


def _initial_state(
    policy: ZeekPolicy, dependencies: ZeekDependencies,
) -> ZeekState:
    counters = {
        key: dependencies.counter_factory(policy.heavy_hitter_capacity)
        for key in LOG_NAMES
    }
    coverage = {key: dependencies.coverage_factory() for key in LOG_NAMES}
    samples = {
        key: dependencies.reservoir_factory(policy.query_index_limit)
        for key in LOG_NAMES
    }
    return ZeekState([], counters, coverage, samples, 0)


def _aggregate_capture_logs(
    capture_dir: Path,
    state: ZeekState,
    policy: ZeekPolicy,
    dependencies: ZeekDependencies,
) -> None:
    for log_key, candidates in LOG_NAMES.items():
        path = next(
            (
                capture_dir / name
                for name in candidates
                if (capture_dir / name).exists()
            ),
            None,
        )
        if path is not None:
            dependencies.aggregate_log(
                path,
                policy.summary_fields[log_key],
                state.counters[log_key],
                state.coverage[log_key],
                state.query_samples[log_key],
                log_key,
            )


def _run_capture(
    zeek: str,
    pcap: Path,
    index: int,
    zeek_dir: Path,
    state: ZeekState,
    policy: ZeekPolicy,
    dependencies: ZeekDependencies,
) -> bool:
    token = dependencies.safe_filename(pcap.stem)
    capture_dir = zeek_dir / f"{index:04d}-{token}"
    capture_dir.mkdir(parents=True, exist_ok=False)
    try:
        result = dependencies.run_command(
            [zeek, "-C", "LogAscii::use_json=T", "-r", str(pcap)],
            cwd=capture_dir,
            timeout=policy.parser_timeout_seconds,
        )
        state.commands.append({
            key: result[key]
            for key in ("ok", "returncode", "stderr", "command")
        })
        _aggregate_capture_logs(capture_dir, state, policy, dependencies)
        return bool(result["ok"])
    finally:
        dependencies.remove_tree(capture_dir, ignore_errors=True)


def _coverage_projection(
    pcap_files: list[Path], state: ZeekState,
) -> dict[str, Any]:
    counts = {
        key: state.coverage[key].total_records for key in LOG_NAMES
    }
    valid = [
        item
        for item in state.coverage.values()
        if item.first_timestamp is not None
    ]
    return {
        "record_counts": counts,
        "coverage": {
            "pcap_files_total": len(pcap_files),
            "pcap_files_processed": state.files_processed,
            "records_aggregated": sum(counts.values()),
            "first_timestamp_epoch": min(
                (item.first_timestamp for item in valid), default=None
            ),
            "last_timestamp_epoch": max(
                (item.last_timestamp for item in valid), default=None
            ),
            "per_log": {
                key: state.coverage[key].as_dict() for key in LOG_NAMES
            },
            "complete": (
                state.files_processed == len(pcap_files)
                and all(item.get("ok") for item in state.commands)
            ),
        },
    }


def _sampling_projection(
    state: ZeekState, policy: ZeekPolicy,
) -> dict[str, Any]:
    return {
        "strategy": "full-stream-bounded-heavy-hitters",
        "heavy_hitter_capacity_per_log": policy.heavy_hitter_capacity,
        "query_index_strategy": "deterministic-reservoir-per-log",
        "query_index_limit_per_log": policy.query_index_limit,
        "query_index_records": {
            key: len(state.query_samples[key].records()) for key in LOG_NAMES
        },
        "records_truncated_before_aggregation": {
            key: False for key in LOG_NAMES
        },
        "invalid_json_lines": {
            key: state.coverage[key].malformed_records for key in LOG_NAMES
        },
    }


def _summary_projection(
    state: ZeekState, policy: ZeekPolicy,
) -> dict[str, Any]:
    output_names = {
        "conn": "top_connections",
        "dns": "dns_queries",
        "tls": "tls_sni",
        "http": "http_hosts",
        "files": "files",
        "notice": "notices",
        "weird": "weird",
    }
    return {
        output_names[key]: state.counters[key].most_common(
            policy.summary_fields[key], policy.summary_limit
        )
        for key in LOG_NAMES
    }


def _query_index_projection(state: ZeekState) -> dict[str, Any]:
    output_names = {
        "conn": "connections",
        "dns": "dns",
        "tls": "tls",
        "http": "http",
        "files": "files",
        "notice": "notices",
        "weird": "weird",
    }
    return {
        output_names[key]: state.query_samples[key].records()
        for key in LOG_NAMES
    }


def _final_projection(
    pcap_files: list[Path], state: ZeekState, policy: ZeekPolicy,
) -> dict[str, Any]:
    coverage = _coverage_projection(pcap_files, state)
    return {
        "available": True,
        "commands": state.commands,
        "record_counts": coverage["record_counts"],
        "coverage": coverage["coverage"],
        "sampling": _sampling_projection(state, policy),
        **_summary_projection(state, policy),
        "_local_query_index": _query_index_projection(state),
    }


def run_zeek(
    pcap_files: list[Path],
    work_dir: Path,
    *,
    policy: ZeekPolicy,
    dependencies: ZeekDependencies,
) -> dict[str, Any]:
    zeek = dependencies.tool_path("ZEEK_BIN", "zeek")
    if not zeek:
        return {
            "available": False,
            "reason": "zeek executable not found on PATH or ZEEK_BIN",
        }
    zeek_dir = work_dir / "zeek"
    zeek_dir.mkdir(parents=True, exist_ok=True)
    state = _initial_state(policy, dependencies)
    processed = 0
    for index, pcap in enumerate(pcap_files):
        if _run_capture(
            zeek,
            pcap,
            index,
            zeek_dir,
            state,
            policy,
            dependencies,
        ):
            processed += 1
    state = state._replace(files_processed=processed)
    return _final_projection(pcap_files, state, policy)
