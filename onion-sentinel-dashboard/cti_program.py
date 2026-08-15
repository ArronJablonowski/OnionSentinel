"""Exact compatibility facade for the owner-managed CTI program workspace."""
from __future__ import annotations

from cti_program_contract import *  # noqa: F403
from cti_program_validation import *  # noqa: F403
from cti_program_store import *  # noqa: F403

# Keep required compatibility symbols visible to static release-contract checks
# while preserving the exact objects and runtime namespace imported above.
CTIProgramError = CTIProgramError  # type: ignore[name-defined]  # noqa: F405
CTIProgramConflict = CTIProgramConflict  # type: ignore[name-defined]  # noqa: F405
normalize_program = normalize_program  # type: ignore[name-defined]  # noqa: F405
load_program = load_program  # type: ignore[name-defined]  # noqa: F405
save_program = save_program  # type: ignore[name-defined]  # noqa: F405
program_digest = program_digest  # type: ignore[name-defined]  # noqa: F405
public_response = public_response  # type: ignore[name-defined]  # noqa: F405

# Keep the historical compatibility namespace exact. The additive lifecycle
# implementation is intentionally reached through normalize/public_response,
# not by expanding this legacy facade with its private schema machinery.
for __compat_hidden__ in (
    "AUDIT_FIELDS",
    "CONFIDENCE_LEVELS",
    "DIGEST_RE",
    "ENTITY_FIELDS",
    "ENTITY_TYPES",
    "EVIDENCE_FIELDS",
    "EVIDENCE_KINDS",
    "INFORMATION_CREDIBILITY_LEVELS",
    "INTELLIGENCE_FIELDS",
    "INVESTIGATION_USE",
    "LIFECYCLE_STATES",
    "LIFECYCLE_STATE_SET",
    "MAX_AUDIT_HISTORY",
    "MAX_INTELLIGENCE",
    "MAX_REQUIREMENTS",
    "REFERENCE_RE",
    "REQUIREMENT_FIELDS",
    "REQUIREMENT_STATUSES",
    "SOURCE_COLLECTION_STATUSES",
    "_entity",
    "_evidence",
    "_evidence_reference",
    "_intelligence",
    "_life_date",
    "_life_enum",
    "_life_identifier",
    "_life_list",
    "_life_text",
    "_requirement",
    "_timestamp",
    "_failure_code",
    "_parsed_timestamp",
    "_require_timestamp_order",
    "_require_handling_coverage",
    "_validate_primary_links",
    "_validate_evidence_links",
    "_validate_entity_links",
    "_intelligence_collections",
    "_intelligence_timing",
    "_audit_entry",
    "intelligence_freshness",
    "project_investigation_context",
    "normalize_audit_history",
    "normalize_intelligence",
    "normalize_requirements",
    "validate_intelligence_links",
    "append_audit_event",
    "_expected_revision",
    "_save_candidate",
    "_write_candidate",
):
    globals().pop(__compat_hidden__, None)
del __compat_hidden__
