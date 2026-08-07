"""Stable package boundaries for the Onion Sentinel runtime.

The executable compatibility wrappers remain in ``n8n/bin`` while behavior is
incrementally extracted into this package. Package modules must never import a
legacy wrapper.
"""

from .composition import invoke_legacy_entrypoint
from .pipeline import (
    AnalysisReviewPolicy,
    AnalysisReviewPorts,
    AnalysisReviewResult,
    RuntimeContext,
    RuntimePathDefaults,
    RuntimePaths,
    Stage,
    run_analysis_review,
)
from .runtime import RuntimeDependencies

__all__ = [
    "AnalysisReviewPolicy",
    "AnalysisReviewPorts",
    "AnalysisReviewResult",
    "RuntimeContext",
    "RuntimeDependencies",
    "RuntimePathDefaults",
    "RuntimePaths",
    "Stage",
    "invoke_legacy_entrypoint",
    "run_analysis_review",
]
