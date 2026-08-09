"""Concrete legacy adapters for the package-owned AI pipeline stages."""
from __future__ import annotations

import os
import sys
from typing import Any, Callable, Mapping


def write_outputs(
    bindings: Mapping[str, Any],
    prompt_path: Any,
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    args: Any,
    analysis_id: str,
) -> tuple[Any, Any, str]:
    """Bind package-owned rendering and publication to legacy runtime values."""
    b = bindings
    generated_at = b["project_now"]()
    reporting = b["_reporting_markdown"]()
    publication = b["_reporting_publication"]()
    plan = publication.build_plan(
        prompt_path,
        prompt_package,
        response,
        args,
        analysis_id,
        generated_at=generated_at,
        safe_filename=b["safe_filename"],
        filename_timestamp=b["filename_timestamp"],
        render_markdown=lambda package, result, generated, json_path: (
            reporting.render(
                package,
                result,
                generated,
                json_path,
                normalize_correlation=b["normalize_correlation_assessment"],
                safe_filename=b["safe_filename"],
                bounded_text_list=b["bounded_text_list"],
            )
        ),
        saved_response_input_mode=b["SAVED_RESPONSE_INPUT_MODE"],
        default_second_opinion_prompt_file=(
            b["DEFAULT_SECOND_OPINION_PROMPT_FILE"]
        ),
    )
    return publication.publish(plan)


def prepare_runtime(
    bindings: Mapping[str, Any],
    module: Any,
    context: Any,
    *,
    args: Any,
    run_id: str,
    prompt_path: Any,
    prompt_package: dict[str, Any],
    settings: dict[str, Any],
    agent_role: str,
    memory_frozen: bool,
    started_at: Any,
    active_record_path: Any,
    resource_monitor: Any,
) -> Any:
    b = bindings
    inputs = module.PreparationInputs(
        run_id, prompt_package, settings, agent_role, memory_frozen,
        args.reanalysis_attempt_id, args.investigation_harness_policy,
        args.investigation_harness_db, b["INVESTIGATION_QUERY_CONTRACT"],
        b["MAX_INVESTIGATION_QUERY_ROUNDS"],
        b["MAX_INVESTIGATION_QUERIES_TOTAL"],
        b["MAX_INVESTIGATION_QUERIES_PER_ROUND"], args.max_prompt_bytes,
        args.max_response_bytes,
    )
    ports = module.PreparationPorts(
        enabled_routes=b["enabled_agent_model_routes"],
        canonical_route=b["canonical_model_route"],
        load_harness_policy=b["load_investigation_harness_policy"],
        harness_activation=lambda enabled, assigned, reviewer: (
            b["should_start_onion_sentinel_harness"](
                policy_enabled=enabled, assigned_route=assigned,
                reviewer_route=reviewer)),
        start_harness=lambda request, policy: b["start_harness_run"](
            run_id=request.run_id, prompt_package=request.prompt_package,
            role=request.role, assigned_route=request.assigned_route,
            configuration=request.configuration,
            reanalysis_attempt_id=request.reanalysis_attempt_id,
            policy_path=request.policy_path, db_path=request.database_path,
            policy=policy),
        build_running_record=lambda: b["build_llm_log_record"](
            run_id=run_id, status="running", started_at=started_at,
            finished_at=None, runtime_seconds=None, prompt_path=prompt_path,
            prompt_package=prompt_package, settings=settings, response=None,
            json_path=None, md_path=None, resource_monitor=resource_monitor),
        write_running_record=lambda record: b["atomic_write_json"](
            active_record_path, record),
        publish_phase=lambda record, phase, route, reason: (
            b["publish_current_analysis_phase"](
                record, settings, phase=phase, model_route=route,
                trigger_reason=reason, active_record_path=active_record_path)),
        start_monitor=resource_monitor.start,
        process_id=os.getpid,
        warn=lambda message: print(f"warning: {message}", file=sys.stderr),
    )
    return module.prepare(context, inputs, ports)


def analysis_review_ports(
    bindings: Mapping[str, Any],
    module: Any,
    *,
    args: Any,
    prompt_package: dict[str, Any],
    settings: dict[str, Any],
    agent_role: str,
    live_osquery_config: dict[str, Any],
    enrichment_config: dict[str, Any],
    controlled_identity: dict[str, Any] | None,
    harness_runtime: Any,
    observe_harness: Callable[[Callable[[], Any]], Any],
    update_phase: Callable[[str, str, str], None],
) -> Any:
    b = bindings
    evidence_config = getattr(
        args, "incident_evidence_config", b["DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE"])
    pivot_dir = getattr(
        args, "investigation_pivot_dir", b["DEFAULT_INVESTIGATION_PIVOT_DIR"])
    return module.AnalysisReviewPorts(
        load_saved_response=lambda: b["sanitize_saved_response_input"](
            b["load_json"](args.response_json, args.max_response_bytes)),
        run_primary_analysis=lambda: b["analyze_with_config"](
            prompt_package, args, agent_role=agent_role, settings=settings,
            live_osquery_config=live_osquery_config,
            enrichment_config=enrichment_config,
            security_onion_config_path=evidence_config,
            investigation_pivot_dir=pivot_dir, phase_callback=update_phase,
            harness_runtime=harness_runtime),
        validate_primary=lambda candidate: b["validate_response"](
            candidate, prompt_package),
        observe_primary=lambda candidate: observe_harness(
            lambda: harness_runtime.record_response(
                candidate, decision_id="primary",
                decision_type="primary-analysis", hypothesis_revision=50)
            if harness_runtime is not None else None),
        review_trigger=lambda candidate: b["second_opinion_trigger"](
            candidate, prompt_package),
        run_configured_review=lambda candidate, force_reason: (
            b["apply_configured_second_opinion"](
                prompt_package, candidate, args, settings, agent_role,
                phase_callback=update_phase, harness_runtime=harness_runtime,
                force_review_reason=force_reason,
                live_osquery_config=live_osquery_config,
                enrichment_config=enrichment_config,
                security_onion_config_path=evidence_config,
                investigation_pivot_dir=pivot_dir)),
        apply_saved_review_gate=lambda candidate: b["apply_saved_response_review_gate"](
            prompt_package, candidate),
        notify_saved_post_processing=lambda: b["notify_analysis_phase"](
            update_phase, "post_processing"),
        controlled_reviewer_gate=lambda candidate, trigger, frozen: (
            b["precommit_controlled_evaluation_reviewer_gate"](
                prompt_package, candidate, settings, agent_role,
                trigger_reason=trigger, freeze_enabled=frozen)),
        require_result_routes=lambda candidate: (
            b["require_controlled_evaluation_result_routes"](
                controlled_identity, candidate)),
        observe_reviewer=lambda candidate: observe_harness(
            lambda: harness_runtime.record_response(
                candidate, decision_id="independent-review",
                decision_type="independent-review", hypothesis_revision=75)
            if harness_runtime is not None else None),
    )
