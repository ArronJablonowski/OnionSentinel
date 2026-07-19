#!/usr/bin/env python3
"""Parse fulfilled PCAP broker artifacts into LLM-safe evidence summaries.

Raw PCAPs are intentionally runtime-only. This worker runs on the Mac Studio,
where Zeek, TShark, Ollama, and the local SOC corpus live. It converts copied
PCAP artifacts into bounded JSON/Markdown summaries that can be included in SOC
Analyst prompt packages without handing binary packets or raw payloads to a
model.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from pcap_lifecycle import analysis_completed, delete_request_artifacts
from disk_capacity import require_runtime_capacity
from bounded_http import BoundedHttpError, read_bounded_json
from bounded_process import BoundedProcessError, run_bounded_command, run_bounded_command_to_file


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_ARTIFACT_DIR = HOME / "n8n-local" / "pcap-evidence" / "artifacts"
DEFAULT_OUT_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
DEFAULT_WAKE = Path(os.environ.get(
    "PCAP_ANALYSIS_WAKE_PATH",
    HOME / "n8n-local" / "run" / "pcap-analysis.wake",
))
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
LOG_LIMIT = 2000
SUMMARY_LIMIT = 20
MAX_TOOL_STDOUT_BYTES = max(64 * 1024, int(os.environ.get("PCAP_TOOL_MAX_STDOUT_BYTES", str(2 * 1024 * 1024))))
MAX_TOOL_STDERR_BYTES = max(16 * 1024, int(os.environ.get("PCAP_TOOL_MAX_STDERR_BYTES", str(512 * 1024))))
TSHARK_SUMMARY_PACKET_LIMIT = max(200, int(os.environ.get("PCAP_TSHARK_SUMMARY_PACKET_LIMIT", "5000")))
MAX_ARCHIVE_MEMBERS = max(1, int(os.environ.get("PCAP_MAX_ARCHIVE_MEMBERS", "2048")))
MAX_EXTRACTED_BYTES = max(1, int(os.environ.get("PCAP_MAX_EXTRACTED_BYTES", str(40 * 1024 * 1024 * 1024))))
MAX_PCAP_FILES = max(1, int(os.environ.get("PCAP_MAX_FILES", "256")))
MAX_REMOTE_ARTIFACT_BYTES = max(
    1,
    int(os.environ.get("PCAP_MAX_REMOTE_ARTIFACT_BYTES", str(40 * 1024 * 1024 * 1024))),
)
REMOTE_FETCH_TIMEOUT_SECONDS = max(30, int(os.environ.get("PCAP_REMOTE_FETCH_TIMEOUT_SECONDS", "3600")))
MAX_CONTROL_RESPONSE_BYTES = 64 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parse PCAP broker artifacts with Zeek and TShark")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="Alert-store SQLite DB")
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR, help="Runtime-only copied PCAP artifact directory")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="PCAP analysis JSON/Markdown output directory")
    parser.add_argument("--wake-file", type=Path, default=DEFAULT_WAKE, help="Consumable launchd wake marker")
    parser.add_argument("--request-id", help="Process one PCAP broker request id")
    parser.add_argument("--pcap", type=Path, help="Parse a local PCAP directly, without reading pcap_requests")
    parser.add_argument("--alert-id", help="Alert id to attach when --pcap is used")
    parser.add_argument("--group-id", help="Group id to attach when --pcap is used")
    parser.add_argument("--limit", type=int, default=5, help="Maximum fulfilled requests to process per run")
    parser.add_argument("--fetch-remote", action="store_true", help="Fetch fulfilled Security Onion artifacts before parsing")
    parser.add_argument("--ssh-target", default=os.environ.get("PCAP_ARTIFACT_SSH_TARGET", ""), help="SSH target used with --fetch-remote, for example user@security-onion")
    parser.add_argument("--ssh-bin", default=os.environ.get("PCAP_ARTIFACT_SSH_BIN", "ssh"), help="SSH executable for artifact fetch")
    parser.add_argument("--overwrite", action="store_true", help="Rebuild existing analysis artifacts")
    parser.add_argument("--retain-artifact", action="store_true", help="Keep a successfully parsed broker artifact for controlled troubleshooting")
    parser.add_argument("--alert-store-url", default=os.environ.get("ALERT_STORE_URL", "http://127.0.0.1:8787"), help="Alert-store base URL for durable parser status")
    parser.add_argument("--stdout", action="store_true", help="Print JSON summaries after processing")
    args = parser.parse_args()
    if args.limit <= 0:
        parser.error("--limit must be positive")
    if args.request_id and args.pcap:
        parser.error("--request-id and --pcap are mutually exclusive")
    return args


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def consume_wake_marker(path: Path) -> None:
    """Remove the current event so arrivals during parsing trigger a rerun."""
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        print(f"PCAP wake marker could not be consumed: {error}", file=sys.stderr)


def signal_follow_up(path: Path) -> None:
    """Request another bounded pass when this run filled its batch."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(f"{project_now()} pcap-batch-remains\n", encoding="utf-8")
        path.chmod(0o600)
    except OSError as error:
        print(f"PCAP follow-up wake failed: {error}", file=sys.stderr)


def safe_filename(value: object) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "pcap")).strip("-")
    return (cleaned or "pcap")[:140]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tool_path(env_name: str, executable: str) -> str | None:
    configured = os.environ.get(env_name)
    if configured:
        return configured if Path(configured).exists() else None
    found = shutil.which(executable)
    if found:
        return found
    for prefix in (Path("/opt/homebrew/bin"), Path("/usr/local/bin")):
        candidate = prefix / executable
        if candidate.exists():
            return str(candidate)
    return None


def run_command(command: list[str], cwd: Path | None = None, timeout: int = 120) -> dict[str, Any]:
    try:
        proc = run_bounded_command(
            command,
            timeout_seconds=timeout,
            max_stdout_bytes=MAX_TOOL_STDOUT_BYTES,
            max_stderr_bytes=MAX_TOOL_STDERR_BYTES,
            cwd=cwd,
        )
    except FileNotFoundError:
        return {"ok": False, "returncode": 127, "stdout": "", "stderr": f"not found: {command[0]}", "command": command}
    except BoundedProcessError as exc:
        return {"ok": False, "returncode": 124, "stdout": "", "stderr": str(exc), "command": command}
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "command": command,
    }


def rows(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
    return conn.execute(sql, tuple(params)).fetchall()


def request_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(item["name"]) for item in rows(conn, f"PRAGMA table_info({table})")}


def pending_requests(db_path: Path, request_id: str | None, limit: int, out_dir: Path, overwrite: bool) -> list[dict[str, Any]]:
    if not db_path.exists():
        return []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        columns = table_columns(conn, "pcap_requests")
        order_column = "completed_at" if "completed_at" in columns else "updated_at"
        if request_id:
            candidates = rows(conn, "SELECT * FROM pcap_requests WHERE request_id = ? AND status = 'fulfilled'", [request_id])
        else:
            # Do not LIMIT before excluding existing analysis artifacts. Doing
            # so repeatedly selected the newest already-processed rows and
            # starved older fulfilled captures forever.
            candidates = conn.execute(
                f"""
                SELECT *
                FROM pcap_requests
                WHERE status = 'fulfilled'
                ORDER BY {order_column} DESC, created_at DESC
                """
            )
        found: list[sqlite3.Row] = []
        for item in candidates:
            item_request_id = str(item["request_id"] or "")
            durable_incomplete = "analysis_status" in columns and str(item["analysis_status"] or "") != "completed"
            if overwrite or durable_incomplete or not analysis_json_path(out_dir, item_request_id).exists():
                found.append(item)
                if len(found) >= limit:
                    break
    finally:
        conn.close()
    return [request_from_row(item) for item in found]


def analysis_json_path(out_dir: Path, request_id: str) -> Path:
    return out_dir / f"{safe_filename(request_id)}-pcap-analysis.json"


def candidate_artifact_paths(request: dict[str, Any], artifact_dir: Path) -> list[Path]:
    request_id = safe_filename(request.get("request_id"))
    candidates: list[Path] = []
    remote_name = Path(str(request.get("artifact_path") or "capture.pcap")).name
    request_dir = artifact_dir / request_id
    candidates.append(request_dir / remote_name)
    candidates.extend(sorted(request_dir.glob("*.pcap")))
    candidates.extend(sorted(request_dir.glob("*.pcapng")))
    candidates.extend(sorted(request_dir.glob("*.tar")))
    candidates.extend(sorted(request_dir.glob("*.tar.gz")))
    candidates.extend(sorted(request_dir.glob("*.tgz")))
    return list(dict.fromkeys(candidates))


def local_artifact_path(request: dict[str, Any], artifact_dir: Path) -> Path:
    request_id = safe_filename(request.get("request_id"))
    remote_name = Path(str(request.get("artifact_path") or "capture.pcap")).name
    return artifact_dir / request_id / remote_name


def fetch_remote_artifact(request: dict[str, Any], artifact_dir: Path, ssh_target: str, ssh_bin: str = "ssh") -> dict[str, Any]:
    artifact_path = str(request.get("artifact_path") or "")
    expected_sha256 = str(request.get("artifact_sha256") or "")
    expected_size = request.get("artifact_size_bytes")
    if not artifact_path or not ssh_target:
        return {"ok": False, "reason": "remote fetch not configured"}
    if not re.fullmatch(r"/nsm/pcapout/onion-sentinel/[A-Za-z0-9._/-]+", artifact_path):
        return {"ok": False, "reason": "remote artifact path is outside the Onion Sentinel PCAP output directory"}
    if ".." in Path(artifact_path).parts:
        return {"ok": False, "reason": "remote artifact path contains traversal components"}

    try:
        expected_size_int = int(expected_size) if expected_size not in (None, "") else None
    except (TypeError, ValueError):
        return {"ok": False, "reason": "remote artifact size metadata is invalid"}
    if expected_size_int is not None and (expected_size_int < 0 or expected_size_int > MAX_REMOTE_ARTIFACT_BYTES):
        return {"ok": False, "reason": "remote artifact exceeds the configured transfer ceiling"}

    destination = local_artifact_path(request, artifact_dir)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destination.with_suffix(destination.suffix + ".tmp")
    command = [ssh_bin, "-o", "BatchMode=yes", "-T", ssh_target, "sudo", "-n", "cat", artifact_path]
    transfer_ceiling = expected_size_int if expected_size_int is not None else MAX_REMOTE_ARTIFACT_BYTES
    require_runtime_capacity(destination.parent, max(1, transfer_ceiling), label="remote PCAP artifact fetch")
    try:
        proc = run_bounded_command_to_file(
            command,
            temp_path,
            timeout_seconds=REMOTE_FETCH_TIMEOUT_SECONDS,
            max_stdout_bytes=max(1, transfer_ceiling),
            max_stderr_bytes=MAX_TOOL_STDERR_BYTES,
        )
    except (BoundedProcessError, OSError) as error:
        temp_path.unlink(missing_ok=True)
        return {"ok": False, "reason": str(error)[:240]}
    if proc.returncode != 0:
        temp_path.unlink(missing_ok=True)
        return {"ok": False, "reason": proc.stderr[:240] or f"ssh exited {proc.returncode}"}
    if expected_size_int is not None and temp_path.stat().st_size != expected_size_int:
        temp_path.unlink(missing_ok=True)
        return {"ok": False, "reason": "downloaded artifact size did not match broker metadata"}
    if expected_sha256 and sha256_file(temp_path) != expected_sha256:
        temp_path.unlink(missing_ok=True)
        return {"ok": False, "reason": "downloaded artifact sha256 did not match broker metadata"}
    temp_path.replace(destination)
    destination.chmod(0o600)
    return {"ok": True, "path": str(destination)}


def safe_extract_tar(path: Path, destination: Path) -> None:
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError(f"archive has too many members: {len(members)} > {MAX_ARCHIVE_MEMBERS}")
        expanded_bytes = sum(max(0, int(member.size or 0)) for member in members if member.isfile())
        if expanded_bytes > MAX_EXTRACTED_BYTES:
            raise ValueError(f"archive expands beyond limit: {expanded_bytes} > {MAX_EXTRACTED_BYTES}")
        require_runtime_capacity(
            destination,
            expanded_bytes,
            label="PCAP archive extraction",
        )
        for member in members:
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise ValueError(f"unsupported archive member type: {member.name}")
            target = (destination / member.name).resolve()
            if target != destination.resolve() and destination.resolve() not in target.parents:
                raise ValueError(f"unsafe tar member path: {member.name}")
        archive.extractall(destination, members=members)


def materialize_pcap_files(request: dict[str, Any], args: argparse.Namespace, work_dir: Path, direct_pcap: Path | None = None) -> tuple[list[Path], str]:
    if direct_pcap:
        return [direct_pcap], "direct"
    if getattr(args, "fetch_remote", False) and not any(path.exists() for path in candidate_artifact_paths(request, args.artifact_dir)):
        fetched = fetch_remote_artifact(
            request,
            args.artifact_dir,
            getattr(args, "ssh_target", ""),
            getattr(args, "ssh_bin", "ssh"),
        )
        if not fetched.get("ok"):
            return [], f"artifact-fetch-failed: {fetched.get('reason')}"
    candidates = candidate_artifact_paths(request, args.artifact_dir)
    direct_candidates = [candidate for candidate in candidates if candidate.exists() and candidate.suffix.lower() in PCAP_SUFFIXES]
    if direct_candidates:
        pcaps = list(dict.fromkeys(direct_candidates))
        if len(pcaps) > MAX_PCAP_FILES:
            raise ValueError(f"artifact directory contains too many PCAP files: {len(pcaps)} > {MAX_PCAP_FILES}")
        return sorted(pcaps), "copied-artifact"
    for candidate in candidates:
        if not candidate.exists():
            continue
        if candidate.suffix.lower() == ".tar" or candidate.name.endswith((".tar.gz", ".tgz")):
            extract_dir = work_dir / "extract"
            extract_dir.mkdir(parents=True, exist_ok=True)
            safe_extract_tar(candidate, extract_dir)
            pcaps = [path for path in extract_dir.rglob("*") if path.is_file() and path.suffix.lower() in PCAP_SUFFIXES]
            if len(pcaps) > MAX_PCAP_FILES:
                raise ValueError(f"archive contains too many PCAP files: {len(pcaps)} > {MAX_PCAP_FILES}")
            return sorted(pcaps), "extracted-artifact"
    return [], "artifact-not-copied-to-mac"


def scan_json_lines(path: Path, limit: int = LOG_LIMIT) -> dict[str, Any]:
    """Stream a Zeek JSONL log while retaining only a bounded sample.

    Record counts remain exact, but the retained objects are capped before
    aggregation. This keeps memory proportional to ``limit`` even when an
    offline capture produces millions of Zeek records.
    """
    records: list[dict[str, Any]] = []
    valid_records = 0
    invalid_lines = 0
    if not path.exists():
        return {
            "records": records,
            "valid_records": valid_records,
            "invalid_lines": invalid_lines,
            "truncated": False,
        }
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                invalid_lines += 1
                continue
            if not isinstance(parsed, dict):
                invalid_lines += 1
                continue
            valid_records += 1
            if len(records) < max(0, limit):
                records.append(parsed)
    return {
        "records": records,
        "valid_records": valid_records,
        "invalid_lines": invalid_lines,
        "truncated": valid_records > len(records),
    }


def load_json_lines(path: Path, limit: int = LOG_LIMIT) -> list[dict[str, Any]]:
    """Compatibility wrapper for callers that only need the bounded sample."""
    return scan_json_lines(path, limit)["records"]


def top_values(records: list[dict[str, Any]], *fields: str) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, ...]] = Counter()
    for record in records:
        values = tuple(str(record.get(field) or "") for field in fields)
        if any(values):
            counts[values] += 1
    return [
        {"count": count, **{field: value for field, value in zip(fields, values)}}
        for values, count in counts.most_common(SUMMARY_LIMIT)
    ]


def run_zeek(pcap_files: list[Path], work_dir: Path) -> dict[str, Any]:
    zeek = tool_path("ZEEK_BIN", "zeek")
    if not zeek:
        return {"available": False, "reason": "zeek executable not found on PATH or ZEEK_BIN"}
    zeek_dir = work_dir / "zeek"
    zeek_dir.mkdir(parents=True, exist_ok=True)
    commands: list[dict[str, Any]] = []
    log_names = {
        "conn": ("conn.log",),
        "dns": ("dns.log",),
        "tls": ("ssl.log", "tls.log"),
        "http": ("http.log",),
        "files": ("files.log",),
        "notice": ("notice.log",),
        "weird": ("weird.log",),
    }
    samples: dict[str, list[dict[str, Any]]] = {key: [] for key in log_names}
    record_counts: Counter[str] = Counter()
    invalid_lines: Counter[str] = Counter()

    for index, pcap in enumerate(pcap_files):
        # Zeek uses fixed output names. A distinct workspace per capture keeps
        # one run from overwriting or silently mixing another capture's logs.
        capture_dir = zeek_dir / f"{index:04d}-{safe_filename(pcap.stem)}"
        capture_dir.mkdir(parents=True, exist_ok=False)
        result = run_command(
            [zeek, "-C", "LogAscii::use_json=T", "-r", str(pcap)],
            cwd=capture_dir,
            timeout=300,
        )
        commands.append({key: result[key] for key in ("ok", "returncode", "stderr", "command")})
        for log_key, candidates in log_names.items():
            path = next((capture_dir / name for name in candidates if (capture_dir / name).exists()), None)
            if path is None:
                continue
            remaining = max(0, LOG_LIMIT - len(samples[log_key]))
            scan = scan_json_lines(path, remaining)
            samples[log_key].extend(scan["records"])
            record_counts[log_key] += int(scan["valid_records"])
            invalid_lines[log_key] += int(scan["invalid_lines"])
        shutil.rmtree(capture_dir, ignore_errors=True)
        if not result["ok"]:
            break
    return {
        "available": True,
        "commands": commands,
        "record_counts": {key: record_counts[key] for key in log_names},
        "sampling": {
            "sample_limit_per_log": LOG_LIMIT,
            "sampled_records": {key: len(samples[key]) for key in log_names},
            "records_truncated": {key: record_counts[key] > len(samples[key]) for key in log_names},
            "invalid_json_lines": {key: invalid_lines[key] for key in log_names},
        },
        "top_connections": top_values(samples["conn"], "id.orig_h", "id.resp_h", "id.resp_p", "proto", "service"),
        "dns_queries": top_values(samples["dns"], "query", "qtype_name", "rcode_name"),
        "tls_sni": top_values(samples["tls"], "server_name", "id.orig_h", "id.resp_h"),
        "http_hosts": top_values(samples["http"], "host", "uri", "method", "status_code"),
        "files": top_values(samples["files"], "mime_type", "filename", "seen_bytes"),
        "notices": top_values(samples["notice"], "note", "msg"),
        "weird": top_values(samples["weird"], "name", "addl"),
    }


def run_tshark(pcap_files: list[Path]) -> dict[str, Any]:
    tshark = tool_path("TSHARK_BIN", "tshark")
    if not tshark:
        return {"available": False, "reason": "tshark executable not found on PATH or TSHARK_BIN"}
    commands = []
    packet_samples = []
    for pcap in pcap_files[:3]:
        hierarchy = run_command(
            [tshark, "-r", str(pcap), "-c", str(TSHARK_SUMMARY_PACKET_LIMIT), "-q", "-z", "io,phs"],
            timeout=180,
        )
        conversations = run_command(
            [
                tshark,
                "-r",
                str(pcap),
                "-c",
                str(TSHARK_SUMMARY_PACKET_LIMIT),
                "-q",
                "-z",
                "conv,tcp",
                "-z",
                "conv,udp",
            ],
            timeout=180,
        )
        fields = run_command(
            [
                tshark,
                "-r",
                str(pcap),
                "-c",
                "200",
                "-T",
                "fields",
                "-E",
                "header=y",
                "-E",
                "separator=\\t",
                "-e",
                "frame.time_epoch",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "tcp.srcport",
                "-e",
                "tcp.dstport",
                "-e",
                "udp.srcport",
                "-e",
                "udp.dstport",
                "-e",
                "_ws.col.Protocol",
                "-e",
                "frame.len",
                "-e",
                "dns.qry.name",
                "-e",
                "tls.handshake.extensions_server_name",
                "-e",
                "http.host",
                "-e",
                "http.request.uri",
            ],
            timeout=180,
        )
        commands.extend([
            {"type": "protocol_hierarchy", **{key: hierarchy[key] for key in ("ok", "returncode", "stderr", "command")}},
            {"type": "conversations", **{key: conversations[key] for key in ("ok", "returncode", "stderr", "command")}},
            {"type": "field_sample", **{key: fields[key] for key in ("ok", "returncode", "stderr", "command")}},
        ])
        packet_samples.append({
            "pcap": str(pcap),
            "protocol_hierarchy": hierarchy["stdout"][:12000],
            "conversations": conversations["stdout"][:12000],
            "field_sample_tsv": fields["stdout"][:12000],
        })
    return {
        "available": True,
        "commands": commands,
        "summary_packet_limit": TSHARK_SUMMARY_PACKET_LIMIT,
        "pcap_file_limit": 3,
        "samples": packet_samples,
    }


def build_markdown(analysis: dict[str, Any]) -> str:
    request = analysis.get("request", {})
    zeek = analysis.get("zeek", {})
    tshark = analysis.get("tshark", {})
    lines = [
        "---",
        "type: soc-pcap-analysis",
        f"generated_at: {json.dumps(analysis.get('generated_at'))}",
        f"request_id: {json.dumps(request.get('request_id'))}",
        f"alert_id: {json.dumps(request.get('alert_id'))}",
        f"group_id: {json.dumps(request.get('group_id'))}",
        "tags:",
        "  - security-onion",
        "  - pcap-analysis",
        "---",
        "",
        f"# PCAP Analysis - {request.get('request_id') or 'direct capture'}",
        "",
        f"- **Generated:** {analysis.get('generated_at')}",
        f"- **Alert ID:** {request.get('alert_id') or 'n/a'}",
        f"- **Group ID:** {request.get('group_id') or 'n/a'}",
        f"- **Artifact state:** {analysis.get('artifact_state')}",
        f"- **PCAP files parsed:** {len(analysis.get('pcap_files') or [])}",
        "",
        "## Zeek Findings",
        "",
    ]
    if not zeek.get("available"):
        lines.append(f"- Zeek unavailable: {zeek.get('reason')}")
    else:
        lines.append(f"- Record counts: `{json.dumps(zeek.get('record_counts', {}), sort_keys=True)}`")
        for title, key in (
            ("Top Connections", "top_connections"),
            ("DNS Queries", "dns_queries"),
            ("TLS SNI", "tls_sni"),
            ("HTTP Hosts", "http_hosts"),
            ("Notices", "notices"),
            ("Weird Activity", "weird"),
        ):
            values = zeek.get(key) if isinstance(zeek.get(key), list) else []
            lines.extend(["", f"### {title}", "", json.dumps(values[:10], indent=2, sort_keys=True) if values else "n/a"])
    lines.extend(["", "## TShark Findings", ""])
    if not tshark.get("available"):
        lines.append(f"- TShark unavailable: {tshark.get('reason')}")
    else:
        for sample in tshark.get("samples", [])[:2]:
            lines.extend([
                f"### {Path(sample.get('pcap', 'capture')).name}",
                "",
                "#### Protocol Hierarchy",
                "",
                "```text",
                str(sample.get("protocol_hierarchy") or "").strip() or "n/a",
                "```",
                "",
                "#### Conversations",
                "",
                "```text",
                str(sample.get("conversations") or "").strip() or "n/a",
                "```",
            ])
    lines.extend([
        "",
        "## Evidence Limits",
        "",
        "- Raw packet payloads are not written to the LLM prompt package.",
        "- Zeek and TShark output is bounded so high-volume captures do not overwhelm local analysis.",
        "- A missing local artifact means the broker fulfilled metadata exists, but the capture has not been copied to the Mac Studio evidence directory yet.",
        "",
    ])
    return "\n".join(lines)


def atomic_write_text(path: Path, content: str) -> None:
    """Publish complete derived evidence before raw packets become disposable."""
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    temp_path.replace(path)


def report_analysis_status(base_url: str, request_id: str, status: str, error: str = "") -> None:
    payload = json.dumps({"request_id": request_id, "status": status, "error": error[:1000]}).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/pcap/analysis-status",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"alert-store analysis status returned HTTP {response.status}")
        try:
            result = read_bounded_json(response, max_bytes=MAX_CONTROL_RESPONSE_BYTES)
        except BoundedHttpError as exc:
            raise RuntimeError(f"invalid alert-store analysis status response: {exc}") from exc
        if not result.get("ok", False):
            raise RuntimeError(str(result.get("reason") or "alert-store rejected analysis status"))


def process_one(request: dict[str, Any], args: argparse.Namespace, direct_pcap: Path | None = None) -> dict[str, Any]:
    request_id = safe_filename(request.get("request_id") or (direct_pcap.stem if direct_pcap else "pcap"))
    with tempfile.TemporaryDirectory(prefix="onion-sentinel-pcap-") as temp_name:
        work_dir = Path(temp_name)
        pcap_files, artifact_state = materialize_pcap_files(request, args, work_dir, direct_pcap)
        pcap_meta = [
            {
                "path": str(path),
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in pcap_files
            if path.exists()
        ]
        analysis = {
            "analysis_type": "soc-pcap-analysis",
            "generated_at": project_now(),
            "request": request,
            "artifact_state": artifact_state,
            "pcap_files": pcap_meta,
            "tool_paths": {
                "zeek": tool_path("ZEEK_BIN", "zeek"),
                "zeek_cut": tool_path("ZEEK_CUT_BIN", "zeek-cut"),
                "tshark": tool_path("TSHARK_BIN", "tshark"),
            },
            "zeek": run_zeek(pcap_files, work_dir) if pcap_files else {"available": False, "reason": artifact_state},
            "tshark": run_tshark(pcap_files) if pcap_files else {"available": False, "reason": artifact_state},
        }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = analysis_json_path(args.out_dir, request_id)
    md_path = args.out_dir / f"{request_id}-pcap-analysis.md"
    atomic_write_text(json_path, json.dumps(analysis, indent=2, sort_keys=True) + "\n")
    atomic_write_text(md_path, build_markdown(analysis))
    # Re-open both outputs before deleting runtime packet data. A parser failure,
    # partial output write, direct/manual PCAP, or operator retain flag preserves
    # the source artifact for troubleshooting and retry.
    json.loads(json_path.read_text(encoding="utf-8"))
    if not md_path.read_text(encoding="utf-8").strip():
        raise RuntimeError("PCAP Markdown analysis output is empty")
    cleanup = {"deleted": False, "bytes": 0, "files": 0}
    if direct_pcap is None and not getattr(args, "retain_artifact", False) and analysis_completed(analysis):
        cleanup = delete_request_artifacts(args.artifact_dir, request.get("request_id"))
    analysis["raw_artifact_cleanup"] = cleanup
    # Preserve cleanup telemetry when possible. The already validated first
    # version remains durable if this metadata-only rewrite is interrupted.
    atomic_write_text(json_path, json.dumps(analysis, indent=2, sort_keys=True) + "\n")
    analysis["_json_path"] = str(json_path)
    analysis["_markdown_path"] = str(md_path)
    return analysis


def main() -> int:
    args = parse_args()
    require_runtime_capacity(args.out_dir, 0, label="PCAP analysis")
    consume_wake_marker(args.wake_file)
    failed_count = 0
    if args.pcap:
        request = {
            "request_id": safe_filename(args.pcap.stem),
            "alert_id": args.alert_id,
            "group_id": args.group_id,
            "artifact_path": str(args.pcap),
            "status": "manual",
        }
        processed = [process_one(request, args, args.pcap)]
    else:
        requests = pending_requests(args.db, args.request_id, args.limit, args.out_dir, args.overwrite)
        processed = []
        for request in requests:
            request_id = safe_filename(request.get("request_id"))
            existing = analysis_json_path(args.out_dir, request_id)
            try:
                report_analysis_status(args.alert_store_url, request_id, "processing")
                if existing.exists() and not args.overwrite:
                    analysis = json.loads(existing.read_text(encoding="utf-8"))
                    analysis["_json_path"] = str(existing)
                    analysis["_markdown_path"] = str(existing.with_name(existing.name.replace("-pcap-analysis.json", "-pcap-analysis.md")))
                else:
                    analysis = process_one(request, args)
                report_analysis_status(args.alert_store_url, request_id, "completed")
                processed.append(analysis)
            except Exception as exc:
                failed_count += 1
                try:
                    report_analysis_status(args.alert_store_url, request_id, "failed", str(exc))
                except Exception as status_exc:
                    print(f"status update failed for {request_id}: {status_exc}", file=sys.stderr)
                print(f"PCAP analysis failed for {request_id}: {exc}", file=sys.stderr)
        if not args.request_id and len(requests) >= args.limit:
            # A full batch may have more durable work behind it. Recreate the
            # consumed marker so launchd drains the next bounded batch without
            # waiting for the five-minute recovery timer.
            signal_follow_up(args.wake_file)
    if args.stdout:
        print(json.dumps(processed, indent=2, sort_keys=True))
    else:
        for item in processed:
            print(item["_markdown_path"])
            print(item["_json_path"])
    return 1 if failed_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
