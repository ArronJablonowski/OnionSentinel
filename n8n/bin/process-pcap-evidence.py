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
import subprocess
import tarfile
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_ARTIFACT_DIR = HOME / "n8n-local" / "pcap-evidence" / "artifacts"
DEFAULT_OUT_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
LOG_LIMIT = 2000
SUMMARY_LIMIT = 20


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parse PCAP broker artifacts with Zeek and TShark")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="Alert-store SQLite DB")
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR, help="Runtime-only copied PCAP artifact directory")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="PCAP analysis JSON/Markdown output directory")
    parser.add_argument("--request-id", help="Process one PCAP broker request id")
    parser.add_argument("--pcap", type=Path, help="Parse a local PCAP directly, without reading pcap_requests")
    parser.add_argument("--alert-id", help="Alert id to attach when --pcap is used")
    parser.add_argument("--group-id", help="Group id to attach when --pcap is used")
    parser.add_argument("--limit", type=int, default=5, help="Maximum fulfilled requests to process per run")
    parser.add_argument("--overwrite", action="store_true", help="Rebuild existing analysis artifacts")
    parser.add_argument("--stdout", action="store_true", help="Print JSON summaries after processing")
    args = parser.parse_args()
    if args.limit <= 0:
        parser.error("--limit must be positive")
    if args.request_id and args.pcap:
        parser.error("--request-id and --pcap are mutually exclusive")
    return args


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


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
        proc = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except FileNotFoundError:
        return {"ok": False, "returncode": 127, "stdout": "", "stderr": f"not found: {command[0]}", "command": command}
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "returncode": 124, "stdout": exc.stdout or "", "stderr": f"timeout after {timeout}s", "command": command}
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
            found = rows(conn, "SELECT * FROM pcap_requests WHERE request_id = ?", [request_id])
        else:
            found = rows(
                conn,
                f"""
                SELECT *
                FROM pcap_requests
                WHERE status = 'fulfilled'
                ORDER BY {order_column} DESC, created_at DESC
                LIMIT ?
                """,
                [limit],
            )
    finally:
        conn.close()
    requests = [request_from_row(item) for item in found]
    if overwrite:
        return requests
    return [
        item
        for item in requests
        if not analysis_json_path(out_dir, str(item.get("request_id") or "")).exists()
    ]


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


def safe_extract_tar(path: Path, destination: Path) -> None:
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if not str(target).startswith(str(destination.resolve())):
                raise ValueError(f"unsafe tar member path: {member.name}")
        archive.extractall(destination)


def materialize_pcap_files(request: dict[str, Any], artifact_dir: Path, work_dir: Path, direct_pcap: Path | None = None) -> tuple[list[Path], str]:
    if direct_pcap:
        return [direct_pcap], "direct"
    for candidate in candidate_artifact_paths(request, artifact_dir):
        if not candidate.exists():
            continue
        if candidate.suffix.lower() in PCAP_SUFFIXES:
            return [candidate], "copied-artifact"
        if candidate.suffix.lower() == ".tar" or candidate.name.endswith((".tar.gz", ".tgz")):
            extract_dir = work_dir / "extract"
            extract_dir.mkdir(parents=True, exist_ok=True)
            safe_extract_tar(candidate, extract_dir)
            pcaps = [path for path in extract_dir.rglob("*") if path.is_file() and path.suffix.lower() in PCAP_SUFFIXES]
            return sorted(pcaps), "extracted-artifact"
    return [], "artifact-not-copied-to-mac"


def load_json_lines(path: Path, limit: int = LOG_LIMIT) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if len(records) >= limit:
            break
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
    return records


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
    commands = []
    for pcap in pcap_files:
        result = run_command([zeek, "-C", "LogAscii::use_json=T", "-r", str(pcap)], cwd=zeek_dir, timeout=300)
        commands.append({key: result[key] for key in ("ok", "returncode", "stderr", "command")})
        if not result["ok"]:
            break
    conn = load_json_lines(zeek_dir / "conn.log")
    dns = load_json_lines(zeek_dir / "dns.log")
    tls = load_json_lines(zeek_dir / "ssl.log") or load_json_lines(zeek_dir / "tls.log")
    http = load_json_lines(zeek_dir / "http.log")
    files = load_json_lines(zeek_dir / "files.log")
    notices = load_json_lines(zeek_dir / "notice.log")
    weird = load_json_lines(zeek_dir / "weird.log")
    return {
        "available": True,
        "commands": commands,
        "record_counts": {
            "conn": len(conn),
            "dns": len(dns),
            "tls": len(tls),
            "http": len(http),
            "files": len(files),
            "notice": len(notices),
            "weird": len(weird),
        },
        "top_connections": top_values(conn, "id.orig_h", "id.resp_h", "id.resp_p", "proto", "service"),
        "dns_queries": top_values(dns, "query", "qtype_name", "rcode_name"),
        "tls_sni": top_values(tls, "server_name", "id.orig_h", "id.resp_h"),
        "http_hosts": top_values(http, "host", "uri", "method", "status_code"),
        "files": top_values(files, "mime_type", "filename", "seen_bytes"),
        "notices": top_values(notices, "note", "msg"),
        "weird": top_values(weird, "name", "addl"),
    }


def run_tshark(pcap_files: list[Path]) -> dict[str, Any]:
    tshark = tool_path("TSHARK_BIN", "tshark")
    if not tshark:
        return {"available": False, "reason": "tshark executable not found on PATH or TSHARK_BIN"}
    commands = []
    packet_samples = []
    for pcap in pcap_files[:3]:
        hierarchy = run_command([tshark, "-r", str(pcap), "-q", "-z", "io,phs"], timeout=180)
        conversations = run_command([tshark, "-r", str(pcap), "-q", "-z", "conv,tcp", "-z", "conv,udp"], timeout=180)
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
    return {"available": True, "commands": commands, "samples": packet_samples}


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


def process_one(request: dict[str, Any], args: argparse.Namespace, direct_pcap: Path | None = None) -> dict[str, Any]:
    request_id = safe_filename(request.get("request_id") or (direct_pcap.stem if direct_pcap else "pcap"))
    with tempfile.TemporaryDirectory(prefix="onion-sentinel-pcap-") as temp_name:
        work_dir = Path(temp_name)
        pcap_files, artifact_state = materialize_pcap_files(request, args.artifact_dir, work_dir, direct_pcap)
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
    json_path.write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(build_markdown(analysis), encoding="utf-8")
    analysis["_json_path"] = str(json_path)
    analysis["_markdown_path"] = str(md_path)
    return analysis


def main() -> int:
    args = parse_args()
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
        processed = [process_one(request, args) for request in requests]
    if args.stdout:
        print(json.dumps(processed, indent=2, sort_keys=True))
    else:
        for item in processed:
            print(item["_markdown_path"])
            print(item["_json_path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
