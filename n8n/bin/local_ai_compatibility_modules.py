"""Ordered module registry for the local AI compatibility facade."""
from __future__ import annotations

import local_ai_conclusion_review_dependency_compat as conclusion_review
import local_ai_conclusion_compat as conclusion
import local_ai_dependency_compat as dependency
import local_ai_evidence_compat as evidence
import local_ai_evaluation_routing_compat as evaluation_routing
import local_ai_investigation_compat as investigation
import local_ai_provider_compat as provider
import local_ai_query_dependency_compat as query_dependency
import local_ai_review_compat as review
import local_ai_runtime_compat as runtime


COMPATIBILITY_MODULES = (
    runtime,
    dependency,
    query_dependency,
    conclusion_review,
    evaluation_routing,
    evidence,
    investigation,
    provider,
    review,
    conclusion,
)

__all__ = ("COMPATIBILITY_MODULES",)
