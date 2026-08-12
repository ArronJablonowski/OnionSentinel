"""Compatibility facade for PCAP request storage and artifact admission."""
from __future__ import annotations

from pcap_processor_contract import *  # noqa: F401,F403


def request_from_row(row: sqlite3.Row) -> dict[str, Any]:
    from pcap_processor_storage_requests import request_from_row as owner

    return owner(row)


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    from pcap_processor_storage_requests import table_columns as owner

    return owner(conn, table, rows)


def pending_requests(db_path: Path, request_id: str | None, limit: int, out_dir: Path, overwrite: bool) -> list[dict[str, Any]]:
    from pcap_processor_storage_requests import pending_requests as owner

    return owner(
        db_path,
        request_id,
        limit,
        out_dir,
        overwrite,
        {
            "analysis_json_path": analysis_json_path,
            "rows": rows,
            "sqlite3": sqlite3,
            "table_columns": table_columns,
        },
    )


def signature_context_for_request(
    db_path: Path,
    request: dict[str, Any],
    playbook_path: Path = DEFAULT_DETECTION_PLAYBOOKS,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    from pcap_processor_storage_requests import signature_context_for_request as owner

    return owner(
        db_path,
        request,
        playbook_path,
        {
            "extract_rule_context": extract_rule_context,
            "load_detection_playbooks": load_detection_playbooks,
            "resolve_detection_playbook": resolve_detection_playbook,
            "sqlite3": sqlite3,
            "table_columns": table_columns,
        },
    )


def _timestamp_epoch(value: object) -> float | None:
    from pcap_processor_storage_scope import timestamp_epoch

    return timestamp_epoch(value, dt)


def icmp_evidence_scope(request: dict[str, Any]) -> dict[str, Any]:
    from pcap_processor_storage_scope import icmp_evidence_scope as owner

    return owner(
        request,
        {
            "dt": dt,
            "ipaddress": ipaddress,
            "max_window_seconds": MAX_SELECTION_WINDOW_SECONDS,
            "sanitize_evidence_text": sanitize_evidence_text,
        },
    )


def _icmp_scope_match(
    source: str,
    destination: str,
    timestamp: float | None,
    scope: dict[str, Any],
) -> tuple[bool, str]:
    from pcap_processor_storage_scope import icmp_scope_match

    return icmp_scope_match(source, destination, timestamp, scope)


def analysis_json_path(out_dir: Path, request_id: str) -> Path:
    from pcap_processor_storage_artifacts import analysis_json_path as owner

    return owner(out_dir, request_id, safe_filename)


def candidate_artifact_paths(request: dict[str, Any], artifact_dir: Path) -> list[Path]:
    from pcap_processor_storage_artifacts import candidate_artifact_paths as owner

    return owner(request, artifact_dir, safe_filename)


def local_artifact_path(request: dict[str, Any], artifact_dir: Path) -> Path:
    from pcap_processor_storage_artifacts import local_artifact_path as owner

    return owner(request, artifact_dir, safe_filename)


def fetch_remote_artifact(request: dict[str, Any], artifact_dir: Path, ssh_target: str, ssh_bin: str = "ssh") -> dict[str, Any]:
    from pcap_processor_storage_artifacts import fetch_remote_artifact as owner

    return owner(
        request,
        artifact_dir,
        ssh_target,
        ssh_bin,
        {
            "BoundedProcessError": BoundedProcessError,
            "local_artifact_path": local_artifact_path,
            "max_remote_artifact_bytes": MAX_REMOTE_ARTIFACT_BYTES,
            "max_tool_stderr_bytes": MAX_TOOL_STDERR_BYTES,
            "re": re,
            "remote_fetch_timeout_seconds": REMOTE_FETCH_TIMEOUT_SECONDS,
            "require_runtime_capacity": require_runtime_capacity,
            "run_bounded_command_to_file": run_bounded_command_to_file,
            "sha256_file": sha256_file,
        },
    )


def safe_extract_tar(path: Path, destination: Path) -> None:
    from pcap_processor_storage_artifacts import safe_extract_tar as owner

    owner(
        path,
        destination,
        {
            "max_archive_members": MAX_ARCHIVE_MEMBERS,
            "max_extracted_bytes": MAX_EXTRACTED_BYTES,
            "require_runtime_capacity": require_runtime_capacity,
            "tarfile": tarfile,
        },
    )


def materialize_pcap_files(request: dict[str, Any], args: argparse.Namespace, work_dir: Path, direct_pcap: Path | None = None) -> tuple[list[Path], str]:
    from pcap_processor_storage_artifacts import materialize_pcap_files as owner

    return owner(
        request,
        args,
        work_dir,
        direct_pcap,
        {
            "candidate_artifact_paths": candidate_artifact_paths,
            "fetch_remote_artifact": fetch_remote_artifact,
            "max_pcap_files": MAX_PCAP_FILES,
            "pcap_suffixes": PCAP_SUFFIXES,
            "safe_extract_tar": safe_extract_tar,
        },
    )


def scan_json_lines(path: Path, limit: int = LOG_LIMIT) -> dict[str, Any]:
    from pcap_processor_storage_records import scan_json_lines as owner

    return owner(path, limit, json)


def load_json_lines(path: Path, limit: int = LOG_LIMIT) -> list[dict[str, Any]]:
    """Compatibility wrapper for callers that only need the bounded sample."""
    return scan_json_lines(path, limit)["records"]


def top_values(records: list[dict[str, Any]], *fields: str) -> list[dict[str, Any]]:
    from pcap_processor_storage_records import top_values as owner

    return owner(records, fields, Counter, SUMMARY_LIMIT)
