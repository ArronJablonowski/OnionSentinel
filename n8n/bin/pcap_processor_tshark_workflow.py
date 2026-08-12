"""Bounded TShark process streaming and result orchestration."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from pcap_processor_tshark_contract import tshark_command
from pcap_processor_tshark_parser import parse_tshark_line
from pcap_processor_tshark_projection import project_tshark_result
from pcap_processor_tshark_state import TsharkState


def _limits(configuration: dict[str, Any]) -> dict[str, int]:
    return {
        "sample_limit": configuration["sample_limit"],
        "summary_limit": configuration["summary_limit"],
        "heavy_hitter_capacity": configuration["heavy_hitter_capacity"],
        "query_index_limit": configuration["query_index_limit"],
        "icmp_pair_state_limit": configuration["icmp_pair_state_limit"],
        "icmp_abnormal_min_frame_bytes": configuration[
            "icmp_abnormal_min_frame_bytes"
        ],
    }


def _failed_stream(command: list[str], error: Exception) -> dict[str, Any]:
    return {
        "ok": False,
        "returncode": 124,
        "stderr": str(error),
        "command": command,
        "line_count": 0,
        "stream_bytes": 0,
    }


def _stream_file(
    executable: str,
    pcap: Path,
    state: TsharkState,
    dependencies: dict[str, Any],
    configuration: dict[str, Any],
) -> None:
    file_coverage = dependencies["CoverageTracker"]()
    command = tshark_command(
        executable,
        pcap,
        configuration["occurrence_separator"],
    )

    def on_line(line: str) -> None:
        parse_tshark_line(line, file_coverage, state, dependencies)

    try:
        stream_result = dependencies["stream_isolated_lines"](
            command,
            on_line,
            timeout_seconds=configuration["timeout_seconds"],
        )
    except (dependencies["BoundedProcessError"], OSError) as error:
        stream_result = _failed_stream(command, error)
    state.commands.append({"type": "full_field_stream", **stream_result})
    if stream_result.get("ok"):
        state.files_processed += 1
    state.per_file.append(
        {
            "pcap": pcap.name,
            **file_coverage.as_dict(),
            "ok": bool(stream_result.get("ok")),
        }
    )


def run_tshark(
    pcap_files: list[Path],
    maxmind_db_paths: dict[str, Path] | Path | None,
    markers: list[dict[str, Any]] | None,
    selected_scope: dict[str, Any] | None,
    dependencies: dict[str, Any],
    configuration: dict[str, Any],
) -> dict[str, Any]:
    """Stream every capture once, then compose bounded derived evidence."""
    executable = dependencies["tool_path"]("TSHARK_BIN", "tshark")
    if not executable:
        return {
            "available": False,
            "reason": "tshark executable not found on PATH or TSHARK_BIN",
        }
    state = TsharkState(
        dependencies,
        _limits(configuration),
        markers,
        selected_scope,
    )
    for pcap in pcap_files:
        _stream_file(executable, pcap, state, dependencies, configuration)
    return project_tshark_result(
        pcap_files,
        maxmind_db_paths,
        state,
        dependencies,
    )
