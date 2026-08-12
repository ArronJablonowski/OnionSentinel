"""Bounded PCAP analysis composition, publication, and artifact custody phases."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any, Callable, NamedTuple


class WorkflowPolicy(NamedTuple):
    default_db: Path
    default_detection_playbooks: Path
    default_ai_settings: Path


class WorkflowDependencies(NamedTuple):
    safe_filename: Callable[[object], str]
    signature_context: Callable[..., tuple[dict[str, Any], Any]]
    marker_specs: Callable[..., Any]
    materialize: Callable[..., tuple[list[Path], str]]
    sha256_file: Callable[[Path], str]
    run_zeek: Callable[..., dict[str, Any]]
    configured_maxmind_paths: Callable[[Path], dict[str, Path]]
    icmp_scope: Callable[[dict[str, Any]], Any]
    run_tshark: Callable[..., dict[str, Any]]
    project_now: Callable[[], str]
    tool_path: Callable[[str, str], str | None]
    analysis_json_path: Callable[[Path, str], Path]
    atomic_write_text: Callable[[Path, str], None]
    build_markdown: Callable[[dict[str, Any]], str]
    analysis_completed: Callable[[dict[str, Any]], bool]
    delete_request_artifacts: Callable[[Path, object], dict[str, Any]]


def _request_identity(
    request: dict[str, Any],
    direct_pcap: Path | None,
    dependencies: WorkflowDependencies,
) -> str:
    fallback = direct_pcap.stem if direct_pcap else "pcap"
    return dependencies.safe_filename(request.get("request_id") or fallback)


def _detection_inputs(
    request: dict[str, Any],
    args: Any,
    policy: WorkflowPolicy,
    dependencies: WorkflowDependencies,
) -> tuple[dict[str, Any], Any, dict[str, Any], Any]:
    rule_context, playbook = dependencies.signature_context(
        Path(getattr(args, "db", policy.default_db)),
        request,
        Path(
            getattr(
                args,
                "detection_playbooks",
                policy.default_detection_playbooks,
            )
        ),
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
    markers = dependencies.marker_specs(rule_context, playbook)
    return rule_context, playbook, playbook_policy, markers


def _pcap_metadata(
    pcap_files: list[Path], dependencies: WorkflowDependencies,
) -> list[dict[str, Any]]:
    return [
        {
            "path": str(path),
            "name": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": dependencies.sha256_file(path),
        }
        for path in pcap_files
        if path.exists()
    ]


def _detection_context(
    rule_context: dict[str, Any],
    playbook: Any,
    playbook_policy: dict[str, Any],
) -> dict[str, Any]:
    return {
        "policy_status": str(
            playbook_policy.get("status") or "not_evaluated"
        )[:80],
        "policy_fail_closed": bool(
            playbook_policy.get("fail_closed", True)
        ),
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
    }


def _tool_paths(dependencies: WorkflowDependencies) -> dict[str, str | None]:
    return {
        "zeek": dependencies.tool_path("ZEEK_BIN", "zeek"),
        "zeek_cut": dependencies.tool_path("ZEEK_CUT_BIN", "zeek-cut"),
        "tshark": dependencies.tool_path("TSHARK_BIN", "tshark"),
    }


def _coverage(
    pcap_meta: list[dict[str, Any]],
    zeek: dict[str, Any],
    tshark: dict[str, Any],
) -> dict[str, Any]:
    zeek_coverage = (
        zeek.get("coverage") if isinstance(zeek.get("coverage"), dict) else {}
    )
    tshark_coverage = (
        tshark.get("coverage")
        if isinstance(tshark.get("coverage"), dict)
        else {}
    )
    return {
        "pcap_files_total": len(pcap_meta),
        "source_bytes": sum(
            int(item.get("size_bytes") or 0) for item in pcap_meta
        ),
        "zeek": zeek_coverage,
        "tshark": tshark_coverage,
        "complete": bool(
            pcap_meta
            and isinstance(zeek.get("coverage"), dict)
            and zeek["coverage"].get("complete")
            and isinstance(tshark.get("coverage"), dict)
            and tshark["coverage"].get("complete")
        ),
    }


def _evidence_security() -> dict[str, Any]:
    return {
        "raw_packet_payloads_included": False,
        "packet_derived_strings_trust": "untrusted-evidence-only",
        "follow_up_query_mode": "sanitized-derived-evidence-allowlist",
        "parser_network_access": (
            "denied-by-sandbox-exec"
            if sys.platform == "darwin" and shutil.which("sandbox-exec")
            else "not-enforced-by-operating-system"
        ),
        "hosted_packet_samples_allowed": False,
    }


def _analysis_document(
    request: dict[str, Any],
    rule_context: dict[str, Any],
    playbook: Any,
    playbook_policy: dict[str, Any],
    artifact_state: str,
    pcap_meta: list[dict[str, Any]],
    zeek: dict[str, Any],
    tshark: dict[str, Any],
    dependencies: WorkflowDependencies,
) -> dict[str, Any]:
    generated_at = dependencies.project_now()
    detection = _detection_context(rule_context, playbook, playbook_policy)
    tools = _tool_paths(dependencies)
    coverage = _coverage(pcap_meta, zeek, tshark)
    security = _evidence_security()
    return {
        "analysis_type": "soc-pcap-analysis",
        "generated_at": generated_at,
        "request": request,
        "detection_context": detection,
        "artifact_state": artifact_state,
        "pcap_files": pcap_meta,
        "tool_paths": tools,
        "coverage": coverage,
        "evidence_security": security,
        "zeek": zeek,
        "tshark": tshark,
    }


def _analyze_artifacts(
    request: dict[str, Any],
    args: Any,
    direct_pcap: Path | None,
    rule_context: dict[str, Any],
    playbook: Any,
    playbook_policy: dict[str, Any],
    markers: Any,
    policy: WorkflowPolicy,
    dependencies: WorkflowDependencies,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="onion-sentinel-pcap-"
    ) as temp_name:
        work_dir = Path(temp_name)
        pcap_files, artifact_state = dependencies.materialize(
            request, args, work_dir, direct_pcap
        )
        pcap_meta = _pcap_metadata(pcap_files, dependencies)
        zeek = (
            dependencies.run_zeek(pcap_files, work_dir)
            if pcap_files
            else {"available": False, "reason": artifact_state}
        )
        settings_path = Path(
            getattr(args, "ai_settings", policy.default_ai_settings)
        )
        tshark = (
            dependencies.run_tshark(
                pcap_files,
                dependencies.configured_maxmind_paths(settings_path),
                markers,
                dependencies.icmp_scope(request),
            )
            if pcap_files
            else {"available": False, "reason": artifact_state}
        )
        return _analysis_document(
            request,
            rule_context,
            playbook,
            playbook_policy,
            artifact_state,
            pcap_meta,
            zeek,
            tshark,
            dependencies,
        )


def _verified_publication(
    analysis: dict[str, Any],
    request_id: str,
    args: Any,
    dependencies: WorkflowDependencies,
) -> tuple[Path, Path]:
    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = dependencies.analysis_json_path(args.out_dir, request_id)
    md_path = args.out_dir / f"{request_id}-pcap-analysis.md"
    dependencies.atomic_write_text(
        json_path, json.dumps(analysis, indent=2, sort_keys=True) + "\n"
    )
    dependencies.atomic_write_text(
        md_path, dependencies.build_markdown(analysis)
    )
    json.loads(json_path.read_text(encoding="utf-8"))
    if not md_path.read_text(encoding="utf-8").strip():
        raise RuntimeError("PCAP Markdown analysis output is empty")
    return json_path, md_path


def _cleanup_artifacts(
    analysis: dict[str, Any],
    request: dict[str, Any],
    args: Any,
    direct_pcap: Path | None,
    dependencies: WorkflowDependencies,
) -> dict[str, Any]:
    cleanup = {"deleted": False, "bytes": 0, "files": 0}
    if (
        direct_pcap is None
        and not getattr(args, "retain_artifact", False)
        and dependencies.analysis_completed(analysis)
    ):
        cleanup = dependencies.delete_request_artifacts(
            args.artifact_dir, request.get("request_id")
        )
    return cleanup


def process_one(
    request: dict[str, Any],
    args: Any,
    direct_pcap: Path | None,
    *,
    policy: WorkflowPolicy,
    dependencies: WorkflowDependencies,
) -> dict[str, Any]:
    request_id = _request_identity(request, direct_pcap, dependencies)
    rule_context, playbook, playbook_policy, markers = _detection_inputs(
        request, args, policy, dependencies
    )
    analysis = _analyze_artifacts(
        request,
        args,
        direct_pcap,
        rule_context,
        playbook,
        playbook_policy,
        markers,
        policy,
        dependencies,
    )
    json_path, md_path = _verified_publication(
        analysis, request_id, args, dependencies
    )
    analysis["raw_artifact_cleanup"] = _cleanup_artifacts(
        analysis, request, args, direct_pcap, dependencies
    )
    dependencies.atomic_write_text(
        json_path, json.dumps(analysis, indent=2, sort_keys=True) + "\n"
    )
    analysis["_json_path"] = str(json_path)
    analysis["_markdown_path"] = str(md_path)
    return analysis
