"""Top-level composition of collector-owned evidence reference contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol


class ReferenceRegistry(Protocol):
    def add(self, reference: Any, **kwargs: Any) -> None: ...
    def contract(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Dependencies:
    registry_factory: Callable[[], ReferenceRegistry]
    traverse: Callable[[Any, tuple[str, ...], ReferenceRegistry], None]
    process_columnar: Callable[[Any, ReferenceRegistry], bool]
    has_structured_authorization: Callable[[dict[str, Any] | None], bool]


SECTION_REFERENCES = {
    "alert": True,
    "grouped_alert_context": True,
    "public_enrichment": False,
    "detection_validation": True,
    "asset_context": False,
    "analyst_state": False,
}
TRAVERSED_SECTIONS = (
    "grouped_alert_context",
    "public_enrichment",
    "pcap_evidence",
    "detection_validation",
    "asset_context",
    "incident_response_evidence",
    "live_osquery_evidence",
)


def _add_section_references(
    prompt_package: dict[str, Any], registry: ReferenceRegistry,
) -> None:
    for section, corroborating in SECTION_REFERENCES.items():
        if prompt_package.get(section) not in (None, {}, []):
            registry.add(
                section, source=section, source_class=section,
                corroborating=corroborating,
            )
    alert = prompt_package.get("alert")
    if isinstance(alert, dict) and alert.get("alert_id"):
        registry.add(
            f"alert:{alert.get('alert_id')}",
            source="alert", source_class="alert",
        )


def _add_authorization_references(
    prompt_package: dict[str, Any], registry: ReferenceRegistry,
    deps: Dependencies,
) -> None:
    if not deps.has_structured_authorization(prompt_package):
        return
    authorization = prompt_package.get("authorization_evidence")
    assert isinstance(authorization, dict)
    for entry in authorization["entries"]:
        registry.add(
            entry["evidence_ref"], source="authorization_evidence.entries",
            source_class="authorization_evidence", status="operator_authorized",
        )


def _ac_hunter_identity(context: dict[str, Any]) -> tuple[str, str] | None:
    reference = context.get("evidence_ref")
    digest = context.get("evidence_digest")
    if not isinstance(reference, str) or not isinstance(digest, str):
        return None
    normalized_digest = digest.strip().lower()
    valid_digest = (
        len(normalized_digest) == 64
        and all(character in "0123456789abcdef" for character in normalized_digest)
    )
    if not valid_digest or reference != f"ac-hunter:{normalized_digest}":
        return None
    return reference, normalized_digest


def _add_ac_hunter_reference(
    prompt_package: dict[str, Any], registry: ReferenceRegistry,
) -> None:
    context = prompt_package.get("ac_hunter_evidence")
    if not isinstance(context, dict) or context.get("available") is not True:
        return
    identity = _ac_hunter_identity(context)
    if identity is None:
        return
    reference, normalized_digest = identity
    status = str(context.get("status") or "")
    returned = context.get("returned")
    valid_returned = (
        isinstance(returned, int)
        and not isinstance(returned, bool)
        and returned >= 0
    )
    registry.add(
        reference,
        source="ac_hunter_evidence",
        source_class="behavioral_context",
        corroborating=status == "fresh" and valid_returned and returned > 0,
        status=status,
        returned=returned,
        evidence_digest=normalized_digest,
        require_valid_count=True,
    )


def build(
    prompt_package: dict[str, Any], deps: Dependencies,
) -> dict[str, Any]:
    """Build the bounded allowlist of model-citeable collector references."""
    registry = deps.registry_factory()
    _add_section_references(prompt_package, registry)
    _add_authorization_references(prompt_package, registry, deps)
    _add_ac_hunter_reference(prompt_package, registry)
    iterative = prompt_package.get("investigation_query_results")
    columnar_claimed = deps.process_columnar(iterative, registry)
    for section in TRAVERSED_SECTIONS:
        deps.traverse(prompt_package.get(section), (section,), registry)
    if not columnar_claimed:
        deps.traverse(iterative, ("investigation_query_results",), registry)
    return registry.contract()


def attach(
    prompt_package: dict[str, Any], deps: Dependencies,
) -> dict[str, Any]:
    prompt_package["evidence_reference_contract"] = build(prompt_package, deps)
    return prompt_package
