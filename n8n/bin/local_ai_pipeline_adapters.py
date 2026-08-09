"""Concrete legacy adapters for the package-owned AI pipeline stages."""
from __future__ import annotations

import json
import os
import sys
import time
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


def bootstrap_pipeline(
    bindings: Mapping[str, Any],
    module: Any,
    pipeline_module: Any,
    args: Any,
) -> Any:
    """Bind package startup to legacy paths and controlled-runtime ports."""
    b = bindings
    return module.bootstrap(
        args,
        environment=os.environ,
        policy=module.BootstrapPolicy(
            freeze_memory_env=b["EVALUATION_FREEZE_MEMORY_ENV"],
            path_defaults=pipeline_module.RuntimePathDefaults(
                log_dir=b["DEFAULT_LLM_LOG_DIR"],
                index_queue_dir=b["DEFAULT_ANALYSIS_INDEX_QUEUE_DIR"],
                index_quarantine_dir=b["DEFAULT_ANALYSIS_INDEX_QUARANTINE_DIR"],
                memory_receipt_dir=b["DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR"],
                memory_pending_dir=b["DEFAULT_MEMORY_WRITEBACK_PENDING_DIR"],
                memory_committed_dir=b["DEFAULT_MEMORY_WRITEBACK_COMMITTED_DIR"],
            ),
        ),
        ports=module.BootstrapPorts(
            controlled_runtime=b["controlled_evaluation_runtime"],
            controlled_output_dir=b["controlled_evaluation_output_dir"],
            consume_token=b["consume_controlled_evaluation_token"],
            result_identity=lambda controlled, attempt: (
                b["controlled_evaluation_result_identity"](
                    controlled, reanalysis_attempt_id=attempt
                )
            ),
            boolean_setting=b["boolean_setting"],
            flush_queue=lambda url, enabled: b["flush_analysis_index_queue"](
                url, memory_writeback_enabled=enabled
            ),
            emit=lambda payload: print(json.dumps(payload)),
        ),
    )


def memory_guard_ports(
    bindings: Mapping[str, Any],
    module: Any,
    harness: Any,
    observe: Callable[[Callable[[], Any]], Any],
) -> Any:
    """Bind memory-guard policy to the current harness and journal helpers."""
    b = bindings
    return module.MemoryGuardPorts(
        promotion_decision=lambda candidate, shared: (
            harness.memory_promotion_decision(
                candidate, has_shared_candidates=shared, human_approved=False
            )
            if harness is not None
            else None
        ),
        decision_is_effective=lambda decision: b["policy_decision_is_effective"](
            harness.policy.mode, decision
        ),
        record_audit=lambda audit: observe(
            lambda: harness.store.append_event(
                harness.run_id,
                "policy.memory-promotion",
                "post-processing",
                audit,
                idempotency_key="policy.memory-promotion",
            )
        ),
        apply_freeze=lambda allowed, reason, frozen: b[
            "apply_evaluation_memory_freeze"
        ](allowed, reason, freeze_enabled=frozen),
        plan=lambda candidates, allowed, reason: b["memory_writeback_plan"](
            candidates, allowed=allowed, eligibility_reason=reason
        ),
        reviewer_eligibility=b["second_opinion_memory_eligibility"],
        controlled_claim_digest=b["controlled_evaluation_claim_digest"],
    )


def publication_ports(
    bindings: Mapping[str, Any],
    module: Any,
    *,
    args: Any,
    run_id: str,
    prompt_path: Any,
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    started_at: Any,
    runtime_paths: Any,
    harness: Any,
    observe: Callable[[Callable[[], Any]], Any],
) -> Any:
    """Bind atomic publication and authoritative index submission ports."""
    b = bindings
    return module.PublicationPorts(
        write_outputs=lambda: write_outputs(
            b, prompt_path, prompt_package, response, args, run_id
        ),
        build_payload=lambda generated, artifact: b["analysis_index_payload"](
            run_id,
            prompt_package,
            response,
            args.reanalysis_attempt_id,
            started_at,
            generated,
            artifact,
        ),
        preflight=lambda: observe(
            lambda: harness.preflight_completion(operation_id="pre-index-commit")
            if harness is not None
            else None
        ),
        queue=lambda payload, controlled: b["queue_analysis_index"](
            payload, queue_dir=runtime_paths.index_queue_dir
        )
        if controlled
        else b["queue_analysis_index"](payload),
        submit=lambda payload, controlled: b["post_controlled_analysis_index"](
            payload, args.alert_store_url
        )
        if controlled
        else b["post_analysis_index"](payload, args.alert_store_url),
        quarantine=lambda path, payload, exc: b["quarantine_analysis_index"](
            path,
            payload,
            exc,
            quarantine_dir=runtime_paths.index_quarantine_dir,
        ),
        discard_memory=lambda: b["discard_pending_memory_writeback"](
            run_id, pending_dir=runtime_paths.memory_pending_dir
        ),
    )


def memory_promotion_ports(
    bindings: Mapping[str, Any],
    module: Any,
    *,
    run_id: str,
    response_digest: str,
    runtime_paths: Any,
    agent_role: str,
    role_memory_file: Any,
    shared_memory_file: Any,
    prompt_path: Any,
    guards: Any,
) -> Any:
    """Bind post-commit memory promotion to the configured runtime paths."""
    b = bindings
    return module.MemoryPromotionPorts(
        promote_staged=lambda: b["mark_memory_writeback_committed"](
            run_id,
            expected_response_digest=response_digest,
            pending_dir=runtime_paths.memory_pending_dir,
            committed_dir=runtime_paths.memory_committed_dir,
        ),
        process_staged=lambda task: b["process_committed_memory_writeback"](
            task, receipt_dir=runtime_paths.memory_receipt_dir
        ),
        persist_direct=lambda: b["persist_postcommit_memory_writeback"](
            analysis_id=run_id,
            agent_role=agent_role,
            role_memory_file=role_memory_file,
            shared_memory_file=shared_memory_file,
            source_artifact=str(prompt_path),
            primary_candidates=guards.primary_candidates,
            primary_allowed=guards.primary_allowed,
            primary_reason=guards.primary_reason,
            reviewer_candidates=guards.reviewer_candidates,
            reviewer_allowed=guards.reviewer_allowed,
            reviewer_reason=guards.reviewer_reason,
            receipt_dir=runtime_paths.memory_receipt_dir,
        ),
        error_digest=b["canonical_payload_digest"],
        warn=b["best_effort_warning"],
    )


def finalize_pipeline_telemetry(
    bindings: Mapping[str, Any],
    module: Any,
    *,
    status: str,
    error: str,
    monitor_started: bool,
    harness: Any,
    resource_monitor: Any,
    started_at: Any,
    started_monotonic: float,
    run_id: str,
    prompt_path: Any,
    prompt_package: dict[str, Any],
    settings: dict[str, Any],
    args: Any,
    response: dict[str, Any] | None,
    json_path: Any,
    md_path: Any,
    runtime_paths: Any,
    running_record: dict[str, Any],
    active_record_path: Any,
) -> None:
    """Finalize telemetry without changing the pipeline's terminal outcome."""
    b = bindings
    module.finalize(
        module.FinalizationInputs(
            status,
            error,
            bool(prompt_path or prompt_package),
            monitor_started,
            harness,
        ),
        module.FinalizationPorts(
            fail_harness=lambda reason: harness.fail(reason),
            stop_monitor=resource_monitor.stop,
            build_record=lambda: b["build_llm_log_record"](
                run_id=run_id,
                status=status,
                started_at=started_at,
                finished_at=b["project_now"](),
                runtime_seconds=time.monotonic() - started_monotonic,
                prompt_path=prompt_path,
                prompt_package=prompt_package,
                settings=settings or b["effective_ai_settings"](args),
                response=response,
                json_path=json_path,
                md_path=md_path,
                resource_monitor=resource_monitor,
                error=error,
                runtime_observation=running_record,
            ),
            append_record=lambda record: b["append_jsonl"](
                runtime_paths.log_file, record
            ),
            write_current=lambda record: b["atomic_write_json"](
                runtime_paths.current_file, record
            ),
            cleanup_active=lambda: active_record_path.unlink(missing_ok=True),
            warn=b["best_effort_warning"],
        ),
    )


def finalize_harness_completion(
    bindings: Mapping[str, Any],
    module: Any,
    harness: Any,
    *,
    run_id: str,
    response_digest: str,
    commit_receipt: dict[str, Any],
    json_path: Any,
    md_path: Any,
    response: dict[str, Any],
    memory_frozen: bool,
    memory_receipt: dict[str, Any] | None,
    memory_receipt_path: Any,
) -> None:
    """Complete the optional harness only after authoritative commit."""
    if harness is None:
        return
    b = bindings
    inputs = module.HarnessCompletionInputs(
        analysis_id=run_id,
        submitted_response_sha256=response_digest,
        commit_receipt=commit_receipt,
        json_path=json_path,
        markdown_path=md_path,
        response=response,
        evaluation_memory_frozen=memory_frozen,
        memory_receipt=memory_receipt,
        memory_receipt_path=memory_receipt_path,
    )
    ports = module.HarnessCompletionPorts(
        digest=b["canonical_payload_digest"],
        record_memory_writeback=harness.record_memory_writeback,
        observe_runtime=harness.observe_postcommit_runtime,
        complete=lambda payload: harness.complete(payload, check_budget=False),
        warn=b["best_effort_warning"],
    )
    module.finalize_harness(inputs, ports)


def print_committed_outputs(
    bindings: Mapping[str, Any],
    markdown_path: Any,
    json_path: Any,
    response: dict[str, Any],
    include_response: bool,
) -> None:
    """Print already-committed artifact paths as a best-effort CLI courtesy."""
    try:
        print(markdown_path)
        print(json_path)
        if include_response:
            print(json.dumps(response, indent=2, sort_keys=True))
    except Exception as exc:
        bindings["best_effort_warning"](
            "committed analysis output could not be printed: "
            f"{type(exc).__name__}"
        )


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
