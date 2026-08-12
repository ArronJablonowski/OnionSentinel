"""PCAP request storage, artifact admission, extraction, and bounded input I/O."""
from __future__ import annotations

from pcap_processor_contract import *  # noqa: F401,F403

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


def signature_context_for_request(
    db_path: Path,
    request: dict[str, Any],
    playbook_path: Path = DEFAULT_DETECTION_PLAYBOOKS,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Load the exact alert rule and its exact-ID playbook without DB writes.

    The returned rule context includes a bounded ``playbook_policy`` object so
    a missing, unreadable, or invalid registry can never be confused with a
    valid registry that simply has no exact playbook for this rule.
    """
    alert_id = str(request.get("alert_id") or "").strip()
    if not alert_id:
        return {
            "playbook_policy": {
                "status": "not_evaluated",
                "fail_closed": True,
                "evidence_gap": "No selected alert id was supplied for exact detection-playbook resolution.",
            },
        }, None
    if not db_path.exists():
        return {
            "playbook_policy": {
                "status": "alert_database_missing",
                "fail_closed": True,
                "evidence_gap": "The alert database was unavailable for exact detection-playbook resolution.",
            },
        }, None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        columns = table_columns(conn, "alerts")
        if "alert_id" not in columns:
            return {
                "playbook_policy": {
                    "status": "alert_schema_unsupported",
                    "fail_closed": True,
                    "evidence_gap": "The alert database lacks the alert_id column required for exact rule resolution.",
                },
            }, None
        projection = ", ".join(
            column if column in columns else f"NULL AS {column}"
            for column in ("alert_json", "raw_event_json", "rule_id")
        )
        row = conn.execute(
            f"SELECT {projection} FROM alerts WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return {
            "playbook_policy": {
                "status": "alert_not_found",
                "fail_closed": True,
                "evidence_gap": "The selected alert was not found for exact detection-playbook resolution.",
            },
        }, None
    context = extract_rule_context(row["alert_json"], row["raw_event_json"], row["rule_id"])
    try:
        playbook_path.stat()
    except FileNotFoundError:
        context["playbook_policy"] = {
            "status": "registry_missing",
            "fail_closed": True,
            "evidence_gap": "The detection-playbook registry is missing; playbook-specific conclusions are unavailable.",
        }
        return context, None
    except OSError:
        context["playbook_policy"] = {
            "status": "registry_unreadable",
            "fail_closed": True,
            "evidence_gap": "The detection-playbook registry could not be read; playbook-specific conclusions are unavailable.",
        }
        return context, None
    try:
        registry = load_detection_playbooks(playbook_path)
        playbook = resolve_detection_playbook(registry, context)
    except OSError:
        context["playbook_policy"] = {
            "status": "registry_unreadable",
            "fail_closed": True,
            "evidence_gap": "The detection-playbook registry could not be read; playbook-specific conclusions are unavailable.",
        }
        return context, None
    except (UnicodeError, ValueError):
        context["playbook_policy"] = {
            "status": "registry_invalid",
            "fail_closed": True,
            "evidence_gap": "The detection-playbook registry failed validation; playbook-specific conclusions are unavailable.",
        }
        return context, None
    if registry.get("version") == 0:
        context["playbook_policy"] = {
            "status": "registry_missing",
            "fail_closed": True,
            "evidence_gap": "The detection-playbook registry is missing; playbook-specific conclusions are unavailable.",
        }
        return context, None
    if not isinstance(playbook, dict):
        context["playbook_policy"] = {
            "status": "no_exact_playbook",
            "fail_closed": True,
            "registry_version": registry.get("version"),
            "evidence_gap": "No exact detection playbook matched the selected rule identity.",
        }
        return context, None
    context["playbook_policy"] = {
        "status": "exact_playbook_matched",
        "fail_closed": False,
        "registry_version": registry.get("version"),
        "evidence_gap": "",
    }
    return context, playbook


def _timestamp_epoch(value: object) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("  ", "T").replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp()


def icmp_evidence_scope(request: dict[str, Any]) -> dict[str, Any]:
    """Build the bounded endpoint/time scope used for alert-associated ICMP."""
    source_ip = sanitize_evidence_text(request.get("source_ip"), 64)
    destination_ip = sanitize_evidence_text(request.get("destination_ip"), 64)
    try:
        source_ip = str(ipaddress.ip_address(source_ip)) if source_ip else ""
    except ValueError:
        source_ip = ""
    try:
        destination_ip = str(ipaddress.ip_address(destination_ip)) if destination_ip else ""
    except ValueError:
        destination_ip = ""

    first_epoch = _timestamp_epoch(request.get("first_seen"))
    last_epoch = _timestamp_epoch(request.get("last_seen"))
    start_epoch: float | None = None
    end_epoch: float | None = None
    if first_epoch is not None and last_epoch is not None:
        first_epoch, last_epoch = sorted((first_epoch, last_epoch))
        try:
            requested_window = int(request.get("max_window_seconds") or 120)
        except (TypeError, ValueError):
            requested_window = 120
        window_seconds = max(30, min(MAX_SELECTION_WINDOW_SECONDS, requested_window))
        duration = max(0, int(last_epoch - first_epoch))
        if duration > window_seconds:
            start_epoch, end_epoch = last_epoch - window_seconds, last_epoch
        else:
            padding = max(0, (window_seconds - duration) // 2)
            start_epoch, end_epoch = first_epoch - padding, last_epoch + padding
    return {
        "selected_alert_id": sanitize_evidence_text(request.get("alert_id"), 256),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "window_start_epoch": start_epoch,
        "window_end_epoch": end_epoch,
        "window_basis": "bounded-pcap-request-window" if start_epoch is not None else "unavailable",
    }


def _icmp_scope_match(
    source: str,
    destination: str,
    timestamp: float | None,
    scope: dict[str, Any],
) -> tuple[bool, str]:
    selected_source = str(scope.get("source_ip") or "")
    selected_destination = str(scope.get("destination_ip") or "")
    if selected_source and selected_destination:
        if {source, destination} != {selected_source, selected_destination}:
            return False, "endpoint"
    elif selected_source or selected_destination:
        selected = selected_source or selected_destination
        if selected not in {source, destination}:
            return False, "endpoint"
    start_epoch = scope.get("window_start_epoch")
    end_epoch = scope.get("window_end_epoch")
    if isinstance(start_epoch, (int, float)) and isinstance(end_epoch, (int, float)):
        if timestamp is None:
            return False, "missing_timestamp"
        if timestamp < float(start_epoch) or timestamp > float(end_epoch):
            return False, "time"
    return True, ""


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
