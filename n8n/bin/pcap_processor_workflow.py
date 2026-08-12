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
    request_id = safe_filename(request.get("request_id") or (direct_pcap.stem if direct_pcap else "pcap"))
    rule_context, playbook = signature_context_for_request(
        Path(getattr(args, "db", DEFAULT_DB)),
        request,
        Path(getattr(args, "detection_playbooks", DEFAULT_DETECTION_PLAYBOOKS)),
    )
    playbook_policy = (
        rule_context.get("playbook_policy")
        if isinstance(rule_context.get("playbook_policy"), dict)
        else {
            "status": "not_evaluated",
            "fail_closed": True,
            "evidence_gap": "Detection-playbook policy status was unavailable.",
        }
    )
    markers = detection_marker_specs(rule_context, playbook)
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
        zeek = run_zeek(pcap_files, work_dir) if pcap_files else {"available": False, "reason": artifact_state}
        settings_path = Path(getattr(args, "ai_settings", DEFAULT_AI_SETTINGS))
        tshark = run_tshark(
            pcap_files,
            configured_maxmind_db_paths(settings_path),
            markers,
            icmp_evidence_scope(request),
        ) if pcap_files else {"available": False, "reason": artifact_state}
        analysis = {
            "analysis_type": "soc-pcap-analysis",
            "generated_at": project_now(),
            "request": request,
            "detection_context": {
                "policy_status": str(playbook_policy.get("status") or "not_evaluated")[:80],
                "policy_fail_closed": bool(playbook_policy.get("fail_closed", True)),
                "evidence_gaps": (
                    [str(playbook_policy.get("evidence_gap") or "")[:500]]
                    if str(playbook_policy.get("evidence_gap") or "")
                    else []
                ),
                "playbook_registry_version": playbook_policy.get("registry_version"),
                "rule": {
                    "sid": rule_context.get("sid"),
                    "revision": rule_context.get("revision"),
                    "name": rule_context.get("name"),
                    "ruleset": rule_context.get("ruleset"),
                    "rule_sha256": (
                        (rule_context.get("parsed_rule") or {}).get("rule_sha256")
                        if isinstance(rule_context.get("parsed_rule"), dict)
                        else ""
                    ),
                },
                "playbook": {
                    "id": playbook.get("id"),
                    "version": playbook.get("version"),
                    "status": playbook.get("status"),
                } if isinstance(playbook, dict) else None,
            },
            "artifact_state": artifact_state,
            "pcap_files": pcap_meta,
            "tool_paths": {
                "zeek": tool_path("ZEEK_BIN", "zeek"),
                "zeek_cut": tool_path("ZEEK_CUT_BIN", "zeek-cut"),
                "tshark": tool_path("TSHARK_BIN", "tshark"),
            },
            "coverage": {
                "pcap_files_total": len(pcap_meta),
                "source_bytes": sum(int(item.get("size_bytes") or 0) for item in pcap_meta),
                "zeek": zeek.get("coverage") if isinstance(zeek.get("coverage"), dict) else {},
                "tshark": tshark.get("coverage") if isinstance(tshark.get("coverage"), dict) else {},
                "complete": bool(
                    pcap_meta
                    and isinstance(zeek.get("coverage"), dict)
                    and zeek["coverage"].get("complete")
                    and isinstance(tshark.get("coverage"), dict)
                    and tshark["coverage"].get("complete")
                ),
            },
            "evidence_security": {
                "raw_packet_payloads_included": False,
                "packet_derived_strings_trust": "untrusted-evidence-only",
                "follow_up_query_mode": "sanitized-derived-evidence-allowlist",
                "parser_network_access": (
                    "denied-by-sandbox-exec"
                    if sys.platform == "darwin" and shutil.which("sandbox-exec")
                    else "not-enforced-by-operating-system"
                ),
                "hosted_packet_samples_allowed": False,
            },
            "zeek": zeek,
            "tshark": tshark,
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
