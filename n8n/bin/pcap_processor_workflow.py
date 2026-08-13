"""PCAP evidence report rendering, persistence, and workflow orchestration."""
from __future__ import annotations

from pcap_processor_contract import *  # noqa: F401,F403
from pcap_processor_storage import *  # noqa: F401,F403
from pcap_processor_zeek import *  # noqa: F401,F403
from pcap_processor_tshark import *  # noqa: F401,F403

def build_markdown(analysis: dict[str, Any]) -> str:
    renderer = __import__("pcap_markdown_renderer")
    return renderer.render_markdown(analysis)


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
    workflow = __import__("pcap_processor_workflow_phases")
    return workflow.process_one(
        request,
        args,
        direct_pcap,
        policy=workflow.WorkflowPolicy(
            default_db=DEFAULT_DB,
            default_detection_playbooks=DEFAULT_DETECTION_PLAYBOOKS,
            default_ai_settings=DEFAULT_AI_SETTINGS,
        ),
        dependencies=workflow.WorkflowDependencies(
            safe_filename=safe_filename,
            signature_context=signature_context_for_request,
            marker_specs=detection_marker_specs,
            materialize=materialize_pcap_files,
            sha256_file=sha256_file,
            run_zeek=run_zeek,
            configured_maxmind_paths=configured_maxmind_db_paths,
            icmp_scope=icmp_evidence_scope,
            run_tshark=run_tshark,
            project_now=project_now,
            tool_path=tool_path,
            analysis_json_path=analysis_json_path,
            atomic_write_text=atomic_write_text,
            build_markdown=build_markdown,
            analysis_completed=analysis_completed,
            delete_request_artifacts=delete_request_artifacts,
        ),
    )


def _manual_request(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "request_id": safe_filename(args.pcap.stem),
        "alert_id": args.alert_id,
        "group_id": args.group_id,
        "artifact_path": str(args.pcap),
        "status": "manual",
    }


def _existing_analysis(existing: Path) -> dict[str, Any]:
    analysis = json.loads(existing.read_text(encoding="utf-8"))
    analysis["_json_path"] = str(existing)
    analysis["_markdown_path"] = str(
        existing.with_name(
            existing.name.replace("-pcap-analysis.json", "-pcap-analysis.md")
        )
    )
    return analysis


def _report_pending_failure(
    args: argparse.Namespace, request_id: str, error: Exception
) -> None:
    try:
        report_analysis_status(
            args.alert_store_url, request_id, "failed", str(error)
        )
    except Exception as status_error:
        print(
            f"status update failed for {request_id}: {status_error}",
            file=sys.stderr,
        )
    print(f"PCAP analysis failed for {request_id}: {error}", file=sys.stderr)


def _process_pending_request(
    request: dict[str, Any], args: argparse.Namespace
) -> tuple[bool, Any]:
    request_id = safe_filename(request.get("request_id"))
    existing = analysis_json_path(args.out_dir, request_id)
    try:
        report_analysis_status(args.alert_store_url, request_id, "processing")
        if existing.exists() and not args.overwrite:
            analysis = _existing_analysis(existing)
        else:
            analysis = process_one(request, args)
        report_analysis_status(args.alert_store_url, request_id, "completed")
        return True, analysis
    except Exception as error:
        _report_pending_failure(args, request_id, error)
        return False, None


def _pending_analyses(args: argparse.Namespace) -> tuple[list[Any], int]:
    requests = pending_requests(
        args.db, args.request_id, args.limit, args.out_dir, args.overwrite
    )
    processed: list[Any] = []
    failed_count = 0
    for request in requests:
        succeeded, analysis = _process_pending_request(request, args)
        if succeeded:
            processed.append(analysis)
        else:
            failed_count += 1
    if not args.request_id and len(requests) >= args.limit:
        signal_follow_up(args.wake_file)
    return processed, failed_count


def _emit_processed(args: argparse.Namespace, processed: list[Any]) -> None:
    if args.stdout:
        print(json.dumps(processed, indent=2, sort_keys=True))
    else:
        for item in processed:
            print(item["_markdown_path"])
            print(item["_json_path"])


def main() -> int:
    args = parse_args()
    require_runtime_capacity(args.out_dir, 0, label="PCAP analysis")
    consume_wake_marker(args.wake_file)
    if args.pcap:
        processed = [process_one(_manual_request(args), args, args.pcap)]
        failed_count = 0
    else:
        processed, failed_count = _pending_analyses(args)
    _emit_processed(args, processed)
    return 1 if failed_count else 0
