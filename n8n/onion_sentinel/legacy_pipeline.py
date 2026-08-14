"""Package-owned orchestration for the legacy local-analysis entry point.

The executable supplies runtime-specific callables as a binding map. This
module owns stage order and transaction boundaries without importing the
hyphenated compatibility script or any provider credentials.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from . import pipeline
from . import preparation
from . import startup
from .analysis.persistence import memory_policy
from .analysis.persistence import postcommit
from .analysis.persistence import transaction
from .analysis.query import audit as query_audit


@dataclass
class RunState:
    args: Any
    controlled: bool
    runtime_paths: Any
    memory_frozen: bool
    controlled_identity: dict[str, Any] | None
    prompt_path: Path | None
    started_at: str
    started_monotonic: float
    run_id: str
    context: pipeline.RuntimeContext
    active_record_path: Path
    resource_monitor: Any
    prompt_package: dict[str, Any] = field(default_factory=dict)
    settings: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] | None = None
    json_path: Path | None = None
    markdown_path: Path | None = None
    running_record: dict[str, Any] = field(default_factory=dict)
    status: str = "failure"
    error: str = ""
    monitor_started: bool = False
    harness: Any = None
    prepared: Any = None
    observe_harness: Callable[[Callable[[], Any]], Any] | None = None


def _initialize(
    b: Mapping[str, Any], adapters: Any,
) -> tuple[RunState | None, int | None]:
    args = b["parse_args"]()
    bootstrap = adapters.bootstrap_pipeline(b, startup, pipeline, args)
    if bootstrap.exit_code is not None:
        return None, bootstrap.exit_code
    prompt_path = args.prompt_package
    started_at = b["project_now"]()
    started_monotonic = b["time"].monotonic()
    run_id = b["hashlib"].sha1(
        f"{started_at}:{prompt_path or ''}:{b['os'].getpid()}".encode("utf-8")
    ).hexdigest()[:16]
    context = pipeline.RuntimeContext(
        run_id,
        arguments=args,
        controlled_evaluation=bootstrap.controlled,
        runtime_dir=bootstrap.runtime_dir,
        paths=bootstrap.runtime_paths,
        prompt_path=prompt_path,
    )
    active_record_path = b["active_analysis_record_path"](
        run_id, active_dir=bootstrap.runtime_paths.active_dir)
    return RunState(
        args=args,
        controlled=bootstrap.controlled,
        runtime_paths=bootstrap.runtime_paths,
        memory_frozen=bootstrap.memory_frozen,
        controlled_identity=bootstrap.controlled_identity,
        prompt_path=prompt_path,
        started_at=started_at,
        started_monotonic=started_monotonic,
        run_id=run_id,
        context=context,
        active_record_path=active_record_path,
        resource_monitor=b["SystemResourceMonitor"](),
    ), None


def _load_and_prepare(
    b: Mapping[str, Any], adapters: Any, state: RunState,
) -> tuple[str, Any, Any]:
    startup.reconcile_deferred_results(
        controlled=state.controlled,
        memory_frozen=state.memory_frozen,
        alert_store_url=state.args.alert_store_url,
        flush_queue=lambda url, enabled: b["flush_analysis_index_queue"](
            url, memory_writeback_enabled=enabled),
    )
    attested = b["_startup_runtime_adapter"]().load_and_attest(
        b, startup, state.context, state.args, state.controlled_identity)
    state.prompt_path = attested.prompt_path
    state.prompt_package = attested.prompt_package
    b["attach_agent_memory_context_contract"](
        state.prompt_package,
        evaluation_frozen=state.memory_frozen,
    )
    state.settings = attested.settings
    state.prepared = adapters.prepare_runtime(
        b, preparation, state.context, args=state.args,
        run_id=state.run_id, prompt_path=state.prompt_path,
        prompt_package=state.prompt_package, settings=state.settings,
        agent_role=attested.agent_role,
        memory_frozen=state.memory_frozen, started_at=state.started_at,
        active_record_path=state.active_record_path,
        resource_monitor=state.resource_monitor,
    )
    state.harness = state.prepared.harness
    state.running_record = state.prepared.running_record
    state.monitor_started = state.prepared.monitor_started
    state.observe_harness = state.prepared.observe
    return attested.agent_role, attested, state.prepared.update_phase


def _analyze_and_guard(
    b: Mapping[str, Any], adapters: Any, state: RunState,
    agent_role: str, attested: Any, update_phase: Any,
) -> Any:
    analysis = pipeline.run_analysis_review(
        state.context,
        policy=pipeline.AnalysisReviewPolicy(
            saved_response=bool(state.args.response_json),
            controlled_reviewer_required=bool(
                state.controlled_identity is not None
                and state.controlled_identity.get("reviewer_required") is True
            ),
            freeze_enabled=state.memory_frozen,
        ),
        ports=adapters.analysis_review_ports(
            b, pipeline, args=state.args,
            prompt_package=state.prompt_package, settings=state.settings,
            agent_role=agent_role,
            live_osquery_config=attested.live_osquery_config,
            enrichment_config=attested.enrichment_config,
            controlled_identity=state.controlled_identity,
            harness_runtime=state.harness,
            observe_harness=state.observe_harness,
            update_phase=update_phase,
        ),
    )
    state.response = analysis.response
    query_audit.attach_incident_attestation(
        state.response, state.prompt_package, agent_role=agent_role,
        dependencies=query_audit.IncidentAttestationDependencies(
            query_audit=b["incident_query_audit"],
            osquery_audit=b["incident_osquery_audit"],
            live_osquery_audit=b["incident_live_osquery_audit"],
        ),
    )
    return memory_policy.apply_memory_guards(
        state.response,
        policy=memory_policy.MemoryGuardPolicy(
            state.memory_frozen, state.controlled_identity),
        ports=adapters.memory_guard_ports(
            b, memory_policy, state.harness, state.observe_harness),
    )


def _stage_memory(
    b: Mapping[str, Any], state: RunState, agent_role: str, guards: Any,
) -> tuple[str, Any, Path, Path]:
    assert state.observe_harness is not None and state.response is not None
    role_file = Path(
        str(state.prompt_package.get("agent_memory_file") or "")
    ).expanduser()
    shared_file = Path(
        str(state.prompt_package.get("shared_memory_file") or "")
    ).expanduser()
    state.observe_harness(
        lambda: state.harness.preflight_completion(
            operation_id="pre-side-effects")
        if state.harness is not None else None)
    state.observe_harness(
        lambda: state.harness.record_response(
            state.response, decision_id="final",
            decision_type="post-review-analysis", hypothesis_revision=100)
        if state.harness is not None else None)
    state.context.advance(
        pipeline.Stage.DETERMINISTIC_GUARDS, "final guards applied")
    response_digest = b["canonical_payload_digest"](state.response)
    task = b["stage_memory_writeback_task"](
        analysis_id=state.run_id, response_digest=response_digest,
        agent_role=agent_role, role_memory_file=role_file,
        shared_memory_file=shared_file,
        source_artifact=str(state.prompt_path),
        primary_candidates=guards.primary_candidates,
        primary_allowed=guards.primary_allowed,
        primary_reason=guards.primary_reason,
        reviewer_candidates=guards.reviewer_candidates,
        reviewer_allowed=guards.reviewer_allowed,
        reviewer_reason=guards.reviewer_reason,
        pending_dir=state.runtime_paths.memory_pending_dir,
    )
    return response_digest, task, role_file, shared_file


def _publish(
    b: Mapping[str, Any], adapters: Any, state: RunState,
) -> Any:
    assert state.response is not None and state.observe_harness is not None
    state.context.advance(pipeline.Stage.VALIDATE, "commit inputs validated")
    publication = transaction.publish(
        policy=transaction.PublicationPolicy(
            controlled=state.controlled,
            controlled_identity=state.controlled_identity,
            submission_error=b["AnalysisIndexSubmissionError"],
            indeterminate_message=b[
                "CONTROLLED_RESULT_SUBMISSION_INDETERMINATE"],
        ),
        ports=adapters.publication_ports(
            b, transaction, args=state.args, run_id=state.run_id,
            prompt_path=state.prompt_path,
            prompt_package=state.prompt_package, response=state.response,
            started_at=state.started_at, runtime_paths=state.runtime_paths,
            harness=state.harness, observe=state.observe_harness,
        ),
    )
    state.json_path = publication.json_path
    state.markdown_path = publication.markdown_path
    state.status = "success"
    state.context.artifacts = (state.json_path, state.markdown_path)
    state.context.advance(pipeline.Stage.COMMIT, "analysis index committed")
    return publication


def _finish_postcommit(
    b: Mapping[str, Any], adapters: Any, state: RunState, *,
    agent_role: str, guards: Any, response_digest: str, staged_task: Any,
    role_file: Path, shared_file: Path, publication: Any,
) -> None:
    promotion = transaction.promote_memory(
        analysis_id=state.run_id, staged_task=staged_task,
        pending_index_path=publication.pending_index_path,
        ports=adapters.memory_promotion_ports(
            b, transaction, run_id=state.run_id,
            response_digest=response_digest,
            runtime_paths=state.runtime_paths, agent_role=agent_role,
            role_memory_file=role_file, shared_memory_file=shared_file,
            prompt_path=state.prompt_path, guards=guards,
        ),
    )
    adapters.finalize_harness_completion(
        b, postcommit, state.harness, run_id=state.run_id,
        response_digest=response_digest,
        commit_receipt=publication.commit_receipt,
        json_path=state.json_path, md_path=state.markdown_path,
        response=state.response, memory_frozen=state.memory_frozen,
        memory_receipt=promotion.receipt,
        memory_receipt_path=promotion.receipt_path,
    )
    state.context.advance(
        pipeline.Stage.POST_COMMIT, "post-commit work finalized")
    adapters.print_committed_outputs(
        b, state.markdown_path, state.json_path,
        state.response, state.args.stdout)
    state.context.advance(
        pipeline.Stage.COMPLETE, "analysis pipeline completed")


def _execute(b: Mapping[str, Any], adapters: Any, state: RunState) -> int:
    agent_role, attested, update_phase = _load_and_prepare(b, adapters, state)
    guards = _analyze_and_guard(
        b, adapters, state, agent_role, attested, update_phase)
    digest, task, role_file, shared_file = _stage_memory(
        b, state, agent_role, guards)
    publication = _publish(b, adapters, state)
    _finish_postcommit(
        b, adapters, state, agent_role=agent_role, guards=guards,
        response_digest=digest, staged_task=task, role_file=role_file,
        shared_file=shared_file, publication=publication,
    )
    return 0


def _finalize(b: Mapping[str, Any], adapters: Any, state: RunState) -> None:
    from . import telemetry

    adapters.finalize_pipeline_telemetry(
        b, telemetry, status=state.status, error=state.error,
        monitor_started=state.monitor_started, harness=state.harness,
        resource_monitor=state.resource_monitor,
        started_at=state.started_at,
        started_monotonic=state.started_monotonic, run_id=state.run_id,
        prompt_path=state.prompt_path,
        prompt_package=state.prompt_package, settings=state.settings,
        args=state.args, response=state.response,
        json_path=state.json_path, md_path=state.markdown_path,
        runtime_paths=state.runtime_paths,
        running_record=(
            state.prepared.running_record
            if state.prepared else state.running_record
        ),
        active_record_path=state.active_record_path,
    )


def run(bindings: Mapping[str, Any], adapters: Any) -> int:
    """Run the complete lifecycle while preserving legacy failure semantics."""
    state, exit_code = _initialize(bindings, adapters)
    if state is None:
        assert exit_code is not None
        return exit_code
    try:
        return _execute(bindings, adapters, state)
    except SystemExit as exc:
        state.error = str(exc) if str(exc) else f"SystemExit({exc.code})"
        state.context.fail_if_active(state.error)
        raise
    except Exception as exc:
        state.error = str(exc)
        state.context.fail_if_active(state.error)
        raise
    finally:
        _finalize(bindings, adapters, state)
