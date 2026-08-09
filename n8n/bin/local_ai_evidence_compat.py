"""Legacy hosted-evidence and reviewer-catalog compatibility delegates."""
from __future__ import annotations

def _redact_unshared_asset_owners(asset_context: Any) -> Any:
    """Remove owner aliases that operators did not approve for external review."""
    return _evidence_runtime_adapter().redact_unshared_asset_owners(asset_context)


def _reviewed_hosted_sha256_evidence_path(
    path: tuple[object, ...],
) -> bool:
    """Allow SHA-256 only at positively projected Elastic source paths."""
    return _evidence_runtime_adapter().reviewed_sha256_path(globals(), path)


def _exact_hosted_columnar_envelope(
    value: Any,
    *,
    require_encoded_accounting: bool,
) -> bool:
    """Recognize only the runtime-owned top-level columnar envelope."""
    return _evidence_runtime_adapter().exact_hosted_columnar_envelope(
        globals(), value, require_encoded_accounting=require_encoded_accounting)


def _refinalize_hosted_columnar_envelope(value: Any) -> Any:
    """Refresh self-accounting after hosted string redaction."""
    return _evidence_runtime_adapter().refinalize_hosted_columnar_envelope(
        globals(), value)


def _sanitize_hosted_investigation_evidence(
    value: Any,
    path: tuple[str, ...] = (),
    *,
    preserve_columnar_rows: bool = False,
) -> Any:
    """Keep safe facts/query provenance while removing hosted-sensitive values."""
    return _evidence_runtime_adapter().sanitize_hosted_evidence(
        globals(), value, path, preserve_columnar_rows=preserve_columnar_rows)


def model_safe_copy(
    value: Any,
    *,
    hosted: bool = False,
    reviewer_safe: bool = False,
    _path: tuple[object, ...] = (),
) -> Any:
    """Copy model evidence while enforcing transport-specific disclosure rules.

    ``detection_validation`` is deterministic collector evidence and remains
    available on every route. Asset owner aliases are more sensitive: a hosted
    model or independent reviewer receives them only when that individual asset
    record explicitly opts in.
    """
    return _evidence_runtime_adapter().model_safe_copy(
        globals(), value, hosted=hosted, reviewer_safe=reviewer_safe,
        path=_path)


def synchronize_hosted_investigation_contract(
    prompt_package: dict[str, Any],
) -> dict[str, Any]:
    """Bind validation to a verified fixed point of hosted redaction.

    Work on an isolated top-level copy and mutate the caller only after a
    bounded convergence check. This keeps prompt admission transactional if a
    future transport rule is accidentally non-idempotent.
    """
    return _evidence_runtime_adapter().synchronize_hosted_contract(
        globals(), prompt_package)




def _bounded_reference(value: Any) -> str:
    return _evidence_runtime_adapter().bounded_reference(globals(), value)


def evidence_source_class(source: Any) -> str:
    """Group multiple citations from one underlying source into one signal."""
    return _evidence_runtime_adapter().source_class(globals(), source)


def result_bound_query_reference(
    query_digest: Any,
    result_digest: Any = "",
    *,
    namespace: str = "query",
    label: Any = "",
) -> tuple[str, str]:
    """Return an immutable query evidence ref and its strongest safe digest.

    A query digest identifies the statement, not the returned snapshot. When a
    collector supplies a result digest, include it in the reference so a later
    execution of the same query cannot collide with or silently reuse evidence
    from a different result set.
    """
    return _evidence_runtime_adapter().result_bound_reference(
        globals(), query_digest, result_digest,
        namespace=namespace, label=label)


def evidence_reference_contract(prompt_package: dict[str, Any]) -> dict[str, Any]:
    return _evidence_runtime_adapter().reference_contract(
        globals(), prompt_package)


def attach_evidence_reference_contract(
    prompt_package: dict[str, Any],
) -> dict[str, Any]:
    return _evidence_runtime_adapter().attach_reference_contract(
        globals(), prompt_package)


def validate_evidence_references(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    return _evidence_runtime_adapter().validate_references(
        globals(), response, prompt_package)


def reviewer_observable_catalog(prompt_package: dict[str, Any]) -> list[dict[str, str]]:
    """Return exact observables that an independent reviewer may mention."""
    return _review_runtime_adapter().observable_catalog(globals(), prompt_package)


def reviewer_non_domain_taxonomy_catalog(
    prompt_package: dict[str, Any],
) -> list[str]:
    """Return collector-typed dotted dataset/module labels, not DNS names."""
    return _review_runtime_adapter().taxonomy_catalog(globals(), prompt_package)


def reviewer_non_domain_artifact_catalog(
    prompt_package: dict[str, Any],
) -> list[str]:
    """Return exact script-like names from collector-owned command/path fields."""
    return _review_runtime_adapter().artifact_catalog(globals(), prompt_package)


def reviewer_non_domain_rule_shorthand_catalog(
    prompt_package: dict[str, Any],
) -> list[str]:
    """Return collector-typed detector-rule shorthands such as ET.BPFDoor."""
    return _review_runtime_adapter().rule_shorthand_catalog(
        globals(), prompt_package)

__all__ = tuple(
    name for name, value in globals().items()
    if getattr(value, "__module__", None) == __name__
)

