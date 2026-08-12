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
