"""Concrete independent-review and adjudication bindings.

Review modules own policy and state transitions. This adapter projects the
legacy runner's live callables and limits into those modules without importing
the executable or duplicating review decisions in the compatibility facade.
"""
from __future__ import annotations

from typing import Any, Mapping


def catalog_policy(b: Mapping[str, Any]) -> Any:
    module = b["_review_catalogs"]()
    return module.Policy(
        observable_max=b["REVIEW_OBSERVABLE_MAX"],
        observable_kinds=b["REVIEW_OBSERVABLE_KINDS"],
        ipv4_pattern=b["REVIEW_IPV4_RE"],
        domain_pattern=b["REVIEW_DOMAIN_RE"],
        taxonomy_field_paths=b["REVIEW_TAXONOMY_FIELD_PATHS"],
        artifact_field_paths=b["REVIEW_ARTIFACT_FIELD_PATHS"],
        artifact_suffixes=b["REVIEW_ARTIFACT_SUFFIXES"],
        rule_label_field_paths=b["REVIEW_RULE_LABEL_FIELD_PATHS"],
    )


def catalog_dependencies(b: Mapping[str, Any]) -> Any:
    module = b["_review_catalogs"]()
    return module.Dependencies(
        bounded_reference=b["_bounded_reference"],
        reviewer_safe_copy=lambda value: b["model_safe_copy"](
            value, reviewer_safe=True),
    )


def known_field_paths(b: Mapping[str, Any]) -> frozenset[str]:
    paths = {
        "dns.question.name", "event.dataset", "event.module", "host.name",
        "network.community_id", "process.name", "rule.id", "rule.name",
        "rule.uuid", "suricata.flags", "source.ip", "destination.ip", "user.name",
    }
    for pack in b["INVESTIGATION_QUERY_PACK_DEFINITIONS"].values():
        for field in pack.get("fields", []):
            parts = str(field).lower().split(".")
            for length in range(2, len(parts) + 1):
                paths.add(".".join(parts[:length]))
    return frozenset(paths)


def observable_catalog(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
) -> list[dict[str, str]]:
    return b["_review_catalogs"]().observables(
        prompt_package, b["_review_catalog_policy"](),
        b["_review_catalog_dependencies"]())


def taxonomy_catalog(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
) -> list[str]:
    return b["_review_catalogs"]().taxonomy(
        prompt_package, b["_review_catalog_policy"](),
        b["_review_catalog_dependencies"]())


def artifact_catalog(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
) -> list[str]:
    return b["_review_catalogs"]().artifacts(
        prompt_package, b["_review_catalog_policy"](),
        b["_review_catalog_dependencies"]())


def rule_shorthand_catalog(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
) -> list[str]:
    return b["_review_catalogs"]().rule_shorthands(
        prompt_package, b["_review_catalog_policy"](),
        b["_review_catalog_dependencies"]())


def validation_failure(
    b: Mapping[str, Any], *, attempt: int, call_id: str, error: Exception,
    input_value: Any, response: dict[str, Any],
) -> dict[str, Any]:
    return b["_review_contracts"]().validation_failure(
        attempt=attempt, call_id=call_id, error=error,
        input_value=input_value, response=response,
        schema=b["REVIEW_VALIDATION_FAILURE_SCHEMA"],
        message_max=b["REVIEW_VALIDATION_MESSAGE_MAX"],
        digest_json=b["harness_digest_json"],
    )


def repair_guidance(b: Mapping[str, Any], message: str) -> list[str]:
    return b["_review_contracts"]().repair_guidance(
        message, message_max=b["REVIEW_VALIDATION_MESSAGE_MAX"]
    )


def repair_error_category(b: Mapping[str, Any], message: str) -> str:
    return b["_review_contracts"]().repair_error_category(
        message, message_max=b["REVIEW_VALIDATION_MESSAGE_MAX"]
    )


def case_id(b: Mapping[str, Any], prompt_package: dict[str, Any]) -> str:
    return b["_review_contracts"]().case_id(
        prompt_package, bounded_reference=b["_bounded_reference"],
        model_safe_copy=b["model_safe_copy"],
    )


def evidence_hash(b: Mapping[str, Any], package: dict[str, Any]) -> str:
    return b["_review_contracts"]().evidence_hash(
        package, model_safe_copy=b["model_safe_copy"]
    )


def independent_package(
    b: Mapping[str, Any], prompt_package: dict[str, Any], *, hosted: bool = False,
) -> dict[str, Any]:
    return b["_review_package"]().build(
        prompt_package, hosted=hosted,
        max_queries=b["MAX_INVESTIGATION_QUERIES_PER_ROUND"],
        model_safe_copy=b["model_safe_copy"],
        attach_evidence_contract=b["attach_evidence_reference_contract"],
        case_id=b["reviewer_case_id"],
        observable_catalog=b["reviewer_observable_catalog"],
        taxonomy_catalog=b["reviewer_non_domain_taxonomy_catalog"],
        artifact_catalog=b["reviewer_non_domain_artifact_catalog"],
        rule_shorthand_catalog=b["reviewer_non_domain_rule_shorthand_catalog"],
        evidence_hash=b["reviewer_evidence_hash"],
    )


def validate_reviewer(
    b: Mapping[str, Any], response: dict[str, Any], package: dict[str, Any],
) -> dict[str, Any]:
    module = b["_review_validation"]()
    dependencies = module.Dependencies(
        error_type=b["ReviewerValidationError"],
        evidence_hash=b["reviewer_evidence_hash"],
        taxonomy_catalog=b["reviewer_non_domain_taxonomy_catalog"],
        artifact_catalog=b["reviewer_non_domain_artifact_catalog"],
        rule_shorthand_catalog=b["reviewer_non_domain_rule_shorthand_catalog"],
        bounded_reference=b["_bounded_reference"],
        response_strings=b["_response_strings"],
        repetition_reasons=b["_review_repetition_reasons"],
        ipv4_re=b["REVIEW_IPV4_RE"], domain_re=b["REVIEW_DOMAIN_RE"],
        community_id_re=b["REVIEW_COMMUNITY_ID_RE"],
        known_field_paths=b["REVIEW_KNOWN_FIELD_PATHS"],
        non_domain_suffixes=b["REVIEW_NON_DOMAIN_SUFFIXES"],
        required_keys=frozenset(b["REQUIRED_KEYS"]).union(
            b["STRICT_FACTORED_REQUIRED_KEYS"]
        ),
        observable_max=b["REVIEW_OBSERVABLE_MAX"],
        evidence_used_max=b["REVIEW_EVIDENCE_USED_MAX"],
        hypotheses_max=b["REVIEW_HYPOTHESES_MAX"],
    )
    return module.validate(response, package, dependencies)


def supplemental_pivot(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
    reviewer_response: dict[str, Any], args: Any, settings: dict[str, Any],
    agent_role: str, route: str, reviewer_prompt: Any, *,
    live_osquery_config: dict[str, Any] | None,
    enrichment_config: dict[str, Any] | None,
    security_onion_config_path: Any, investigation_pivot_dir: Any,
    harness_runtime: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return b["_review_supplemental"]().execute(
        prompt_package, reviewer_response, args, settings, agent_role, route,
        reviewer_prompt, live_osquery_config=live_osquery_config,
        enrichment_config=enrichment_config,
        security_onion_config_path=security_onion_config_path,
        investigation_pivot_dir=investigation_pivot_dir,
        harness_runtime=harness_runtime,
        deps=b["_review_supplemental_dependencies"](),
    )


def trigger(
    b: Mapping[str, Any], response: dict[str, Any],
    prompt_package: dict[str, Any] | None = None,
) -> str:
    return b["_review_comparison"]().trigger(
        response, prompt_package,
        control_tuning_values=b["CONTROL_TUNING_VALUES"],
        consequential_outcomes=b["CONSEQUENTIAL_CLOSURE_OUTCOMES"],
    )


def compare(
    b: Mapping[str, Any], primary: dict[str, Any], reviewer: dict[str, Any],
) -> dict[str, Any]:
    return b["_review_comparison"]().compare(
        primary, reviewer, control_tuning_values=b["CONTROL_TUNING_VALUES"],
        non_escalatory_values=b["NON_ESCALATORY_HANDLING_VALUES"],
        boolean_setting=b["boolean_setting"],
    )


def adjudication_package(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
    primary: dict[str, Any], reviewer: dict[str, Any],
    comparison: dict[str, Any], *, hosted: bool,
) -> dict[str, Any]:
    module = b["_review_adjudication"]()
    deps = module.PackageDependencies(
        independent_package=b["independent_reviewer_package"],
        case_id=b["reviewer_case_id"], model_safe_copy=b["model_safe_copy"],
    )
    return module.build_package(
        prompt_package, primary, reviewer, comparison,
        hosted=hosted, deps=deps,
    )


def validate_adjudication(
    b: Mapping[str, Any], response: Any, package: dict[str, Any],
) -> dict[str, Any]:
    module = b["_review_adjudication"]()
    deps = module.ValidationDependencies(
        error_type=b["DisagreementAdjudicationValidationError"],
        bounded_reference=b["_bounded_reference"],
    )
    return module.validate(response, package, deps)


def run_adjudication(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
    primary: dict[str, Any], reviewer: dict[str, Any],
    comparison: dict[str, Any], args: Any, settings: dict[str, Any],
    agent_role: str, phase_callback: Any = None, harness_runtime: Any = None,
) -> dict[str, Any]:
    module = b["_review_adjudication_workflow"]()
    return module.run(
        module.Context(
            prompt_package=prompt_package, primary_response=primary,
            reviewer_response=reviewer, comparison=comparison, args=args,
            settings=settings, agent_role=agent_role,
            phase_callback=phase_callback, harness_runtime=harness_runtime,
        ),
        policy=module.Policy(
            default_prompt_file=b["DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT_FILE"]
        ),
        dependencies=b["_review_adjudication_workflow_dependencies"](),
    )


def automation_authorization(
    b: Mapping[str, Any], primary: dict[str, Any], reviewer: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    return b["_review_authorization"]().automation_authorization(
        primary, reviewer, comparison, b["_review_authorization_dependencies"]()
    )


def saved_response_gate(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
    primary: dict[str, Any],
) -> dict[str, Any]:
    """Prevent an offline fixture from asserting live runtime attestations."""
    for key in list(primary):
        if str(key).startswith("_analysis_"):
            primary.pop(key, None)
    primary.pop("_second_opinion", None)
    primary.pop("_disagreement_adjudication", None)
    primary["_analysis_input_mode"] = b["SAVED_RESPONSE_INPUT_MODE"]
    review_trigger = b["second_opinion_trigger"](primary, prompt_package)
    if not review_trigger:
        primary["final_disposition_status"] = "primary_not_reviewed"
        return primary
    reason = (
        "Saved-response mode did not execute the required independent reviewer: "
        f"{review_trigger}"
    )
    b["apply_review_required_gate"](
        primary, status="review_required_failed", reason=reason
    )
    primary["_second_opinion"] = {
        "status": "review_required_failed", "trigger": review_trigger,
        "model_route": "", "error": reason,
    }
    b["reconcile_incident_response_report"](primary, prompt_package)
    return primary


def sanitize_saved_response(response: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in response.items()
        if isinstance(key, str) and not key.startswith("_")
    }


def configured_second_opinion(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
    primary: dict[str, Any], args: Any, settings: dict[str, Any],
    agent_role: str, phase_callback: Any = None, harness_runtime: Any = None,
    force_review_reason: str = "",
    live_osquery_config: dict[str, Any] | None = None,
    enrichment_config: dict[str, Any] | None = None,
    security_onion_config_path: Any = None, investigation_pivot_dir: Any = None,
) -> dict[str, Any]:
    module = b["_review_workflow"]()
    return module.execute(
        module.Context(
            prompt_package=prompt_package, primary_response=primary,
            args=args, settings=settings, agent_role=agent_role,
            phase_callback=phase_callback, harness_runtime=harness_runtime,
            force_review_reason=force_review_reason,
            live_osquery_config=live_osquery_config,
            enrichment_config=enrichment_config,
            security_onion_config_path=security_onion_config_path,
            investigation_pivot_dir=investigation_pivot_dir,
            strict_harness_observation=bool(
                harness_runtime is not None
                and b["boolean_setting"](
                    b["os"].environ.get(b["EVALUATION_FREEZE_MEMORY_ENV"])
                )
            ),
        ),
        module.Policy(default_prompt_file=b["DEFAULT_SECOND_OPINION_PROMPT_FILE"]),
        b["_review_workflow_dependencies"](),
    )


def precommit_reviewer_gate(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
    response: dict[str, Any], settings: dict[str, Any], agent_role: str, *,
    trigger_reason: str, freeze_enabled: bool,
) -> dict[str, Any] | None:
    module = b["_evaluation_reviewer_gate"]()
    return module.enforce(
        prompt_package, response, settings, agent_role,
        trigger_reason=trigger_reason, freeze_enabled=freeze_enabled,
        policy=module.Policy(
            attestation_schema="onion-sentinel-independent-review-validation-v1"
        ),
        dependencies=b["_evaluation_reviewer_gate_dependencies"](),
    )
