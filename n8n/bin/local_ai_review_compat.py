"""Legacy reviewer, adjudication, and post-review compatibility delegates."""
from __future__ import annotations

from local_ai_runtime_contract import *  # noqa: F403

class ReviewerValidationError(ValueError):
    """An independent review failed its identity or evidence-isolation contract."""


def reviewer_validation_failure(
    *, attempt: int, call_id: str, error: ReviewerValidationError,
    input_value: Any, response: dict[str, Any],
) -> dict[str, Any]:
    """Return bounded validator telemetry without retaining model output."""
    return _review_runtime_adapter().validation_failure(
        globals(), attempt=attempt, call_id=call_id, error=error,
        input_value=input_value, response=response,
    )


def reviewer_repair_guidance(validation_message: str) -> list[str]:
    """Translate validator output into bounded field-specific repair steps."""
    return _review_runtime_adapter().repair_guidance(globals(), validation_message)


def reviewer_repair_error_category(validation_message: str) -> str:
    """Classify a validator failure without echoing rejected observables."""
    return _review_runtime_adapter().repair_error_category(
        globals(), validation_message
    )



class ControlledEvaluationReviewerGateError(RuntimeError):
    """A controlled evaluation cannot commit without its reviewer decision."""


def reviewer_case_id(prompt_package: dict[str, Any]) -> str:
    return _review_runtime_adapter().case_id(globals(), prompt_package)


def reviewer_evidence_hash(review_package: dict[str, Any]) -> str:
    """Bind the reviewer response to its blind model-visible package."""
    return _review_runtime_adapter().evidence_hash(globals(), review_package)


def independent_reviewer_package(
    prompt_package: dict[str, Any],
    *, hosted: bool = False,
) -> dict[str, Any]:
    """Build the exact route-safe blind evidence view sent to the reviewer."""
    return _review_runtime_adapter().independent_package(
        globals(), prompt_package, hosted=hosted
    )


def _response_strings(value: Any) -> list[str]:
    return _review_text().response_strings(value)


def _review_repetition_reasons(response: dict[str, Any]) -> list[str]:
    """Detect repeated unrelated boilerplate without policing ordinary prose."""
    return _review_text().repetition_reasons(response)


def validate_reviewer_response(
    response: dict[str, Any],
    review_package: dict[str, Any],
) -> dict[str, Any]:
    """Fail closed on stale, foreign, repetitive, or ungrounded reviewer output."""
    return _review_runtime_adapter().validate_reviewer(
        globals(), response, review_package
    )


def apply_reviewer_supplemental_pivot(
    prompt_package: dict[str, Any],
    reviewer_response: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    agent_role: str,
    route: str,
    reviewer_prompt: Path,
    *,
    live_osquery_config: dict[str, Any] | None,
    enrichment_config: dict[str, Any] | None,
    security_onion_config_path: Path,
    investigation_pivot_dir: Path,
    harness_runtime: OnionSentinelHarnessRun | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return _review_runtime_adapter().supplemental_pivot(
        globals(), prompt_package, reviewer_response, args, settings,
        agent_role, route, reviewer_prompt,
        live_osquery_config=live_osquery_config,
        enrichment_config=enrichment_config,
        security_onion_config_path=security_onion_config_path,
        investigation_pivot_dir=investigation_pivot_dir,
        harness_runtime=harness_runtime,
    )


def second_opinion_trigger(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None = None,
) -> str:
    """Return the deterministic reason an independent review is warranted."""
    return _review_runtime_adapter().trigger(globals(), response, prompt_package)


def compare_analysis_results(
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
) -> dict[str, Any]:
    """Compare independent conclusions without model self-arbitration."""
    return _review_runtime_adapter().compare(
        globals(), primary_response, reviewer_response
    )



class DisagreementAdjudicationValidationError(ValueError):
    """A bounded adjudicator response violated its closed decision contract."""


def disagreement_adjudication_package(
    prompt_package: dict[str, Any],
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    comparison: dict[str, Any],
    *,
    hosted: bool,
) -> dict[str, Any]:
    """Build a route-safe package containing two immutable disputed positions."""
    return _review_runtime_adapter().adjudication_package(
        globals(), prompt_package, primary_response, reviewer_response,
        comparison, hosted=hosted,
    )


def validate_disagreement_adjudication(
    response: Any,
    package: dict[str, Any],
) -> dict[str, Any]:
    """Validate identity, closed choices, disputed fields, and evidence citations."""
    return _review_runtime_adapter().validate_adjudication(
        globals(), response, package
    )


def run_bounded_disagreement_adjudication(
    prompt_package: dict[str, Any],
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    comparison: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    agent_role: str,
    phase_callback: Callable[[str, str, str], None] | None = None,
    harness_runtime: OnionSentinelHarnessRun | None = None,
) -> dict[str, Any]:
    """Run at most two validation-bounded adjudicator calls in shadow mode."""
    return _review_runtime_adapter().run_adjudication(
        globals(), prompt_package, primary_response, reviewer_response,
        comparison, args, settings, agent_role,
        phase_callback=phase_callback, harness_runtime=harness_runtime,
    )


def second_opinion_memory_eligibility(second_opinion: Any) -> tuple[bool, str]:
    return _review_authorization().memory_eligibility(second_opinion)


def reviewer_automation_authorization(
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    return _review_runtime_adapter().automation_authorization(
        globals(), primary_response, reviewer_response, comparison
    )


def apply_material_disagreement_gate(
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    return _review_disagreement().apply(
        primary_response, reviewer_response, comparison
    )


def apply_analytical_adjudication_projection(
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    adjudication: Any,
) -> bool:
    return _review_projection().apply(
        primary_response, reviewer_response, adjudication
    )


def memory_writeback_plan(
    candidates: Any,
    *,
    allowed: bool,
    eligibility_reason: str,
) -> dict[str, Any]:
    """Describe a commit-gated memory operation without changing memory."""
    return _persistence_runtime_adapter().memory_writeback_plan(
        globals(), candidates, allowed=allowed,
        eligibility_reason=eligibility_reason)


def persist_postcommit_memory_writeback(
    *,
    analysis_id: str,
    agent_role: str,
    role_memory_file: Path,
    shared_memory_file: Path,
    source_artifact: str,
    primary_candidates: Any,
    primary_allowed: bool,
    primary_reason: str,
    reviewer_candidates: Any,
    reviewer_allowed: bool,
    reviewer_reason: str,
    receipt_dir: Path = DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR,
) -> tuple[dict[str, Any], Path | None]:
    """Persist eligible memory only after the alert store has committed.

    Candidate text is never copied into the receipt or harness trace. A failed
    post-commit write is supplemental and must not invalidate the authoritative
    analysis or cause the model job to be retried.
    """

    return _persistence_runtime_adapter().persist_postcommit_memory_writeback(
        globals(), analysis_id=analysis_id, agent_role=agent_role,
        role_memory_file=role_memory_file, shared_memory_file=shared_memory_file,
        source_artifact=source_artifact, primary_candidates=primary_candidates,
        primary_allowed=primary_allowed, primary_reason=primary_reason,
        reviewer_candidates=reviewer_candidates,
        reviewer_allowed=reviewer_allowed, reviewer_reason=reviewer_reason,
        receipt_dir=receipt_dir)


def apply_review_required_gate(
    response: dict[str, Any], *, status: str, reason: str,
) -> dict[str, Any]:
    return _review_gates().required(
        response, status=status, reason=reason
    )


def apply_review_completed_automation_gate(
    response: dict[str, Any], *, reason: str,
) -> dict[str, Any]:
    return _review_gates().completed(response, reason=reason)


def apply_saved_response_review_gate(
    prompt_package: dict[str, Any],
    primary_response: dict[str, Any],
) -> dict[str, Any]:
    """Keep offline primary fixtures from bypassing a required live review.

    ``--response-json`` deliberately suppresses model calls, so a caller-
    supplied reviewer result is not independently executed or validated by
    this run. Consequential primary output remains useful for manual testing,
    but it cannot authorize automation or memory promotion.
    """
    return _review_runtime_adapter().saved_response_gate(
        globals(), prompt_package, primary_response
    )


def sanitize_saved_response_input(response: dict[str, Any]) -> dict[str, Any]:
    """Remove caller-supplied runtime attestations from an offline fixture."""
    return _review_runtime_adapter().sanitize_saved_response(response)


def apply_configured_second_opinion(
    prompt_package: dict[str, Any],
    primary_response: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    agent_role: str,
    phase_callback: Callable[[str, str, str], None] | None = None,
    harness_runtime: OnionSentinelHarnessRun | None = None,
    force_review_reason: str = "",
    live_osquery_config: dict[str, Any] | None = None,
    enrichment_config: dict[str, Any] | None = None,
    security_onion_config_path: Path = DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE,
    investigation_pivot_dir: Path = DEFAULT_INVESTIGATION_PIVOT_DIR,
) -> dict[str, Any]:
    """Run the configured independent-review workflow through injected ports."""
    return _review_runtime_adapter().configured_second_opinion(
        globals(), prompt_package, primary_response, args, settings, agent_role,
        phase_callback=phase_callback, harness_runtime=harness_runtime,
        force_review_reason=force_review_reason,
        live_osquery_config=live_osquery_config,
        enrichment_config=enrichment_config,
        security_onion_config_path=security_onion_config_path,
        investigation_pivot_dir=investigation_pivot_dir,
    )


def precommit_controlled_evaluation_reviewer_gate(
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    settings: dict[str, Any],
    agent_role: str,
    *,
    trigger_reason: str,
    freeze_enabled: bool,
) -> dict[str, Any] | None:
    """Require one validated reviewer decision before evaluation persistence.

    Production deliberately retains its advisory reviewer behavior. A frozen
    controlled evaluation is different: when an independently configured
    reviewer was triggered, a primary-only result would be incomplete yet
    could otherwise reach the artifact and alert-store commit boundary.
    Revalidate the single retained reviewer response and its bounded repair
    grammar before the caller records the decision in the harness ledger.
    """
    return _review_runtime_adapter().precommit_reviewer_gate(
        globals(), prompt_package, response, settings, agent_role,
        trigger_reason=trigger_reason,
        freeze_enabled=freeze_enabled,
    )


def analyze_with_config(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    agent_role: str = "soc-analyst",
    settings: dict[str, Any] | None = None,
    live_osquery_config: dict[str, Any] | None = None,
    enrichment_config: dict[str, Any] | None = None,
    security_onion_config_path: Path = DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE,
    investigation_pivot_dir: Path = DEFAULT_INVESTIGATION_PIVOT_DIR,
    phase_callback: Callable[[str, str, str], None] | None = None,
    harness_runtime: OnionSentinelHarnessRun | None = None,
) -> dict[str, Any]:
    """Run exactly the model assigned to the requested cyber-security agent.

    Provider-level enablement defines the approved model roster; the agent map
    owns execution. Avoiding implicit failover prevents a run from silently
    changing its model, cost, privacy boundary, or analytical behavior.
    """
    settings = settings or effective_ai_settings(args)
    evaluation_harness_run = bool(
        harness_runtime is not None
        and boolean_setting(os.environ.get(EVALUATION_FREEZE_MEMORY_ENV))
    )
    module = _primary_execution()
    primary = module.execute(
        prompt_package, args, settings, agent_role,
        phase_callback=phase_callback,
        harness_runtime=harness_runtime,
        policy=module.Policy(
            agent_roles=frozenset(CYBER_SECURITY_AGENT_ROLES),
            evaluation_harness_run=evaluation_harness_run,
        ),
        dependencies=_primary_execution_dependencies(),
    )
    return apply_investigation_query_loop(
        prompt_package,
        primary,
        args,
        settings,
        agent_role,
        live_osquery_config=live_osquery_config,
        enrichment_config=enrichment_config,
        security_onion_config_path=security_onion_config_path,
        investigation_pivot_dir=investigation_pivot_dir,
        harness_runtime=harness_runtime,
    )

__all__ = tuple(
    name for name, value in globals().items()
    if getattr(value, "__module__", None) == __name__
)

