"""Compatibility facade for conclusion-safe detection validation results."""
from __future__ import annotations

from detection_validation_rule import *  # noqa: F401,F403
from detection_validation_packet import *  # noqa: F401,F403
from detection_validation_features import *  # noqa: F401,F403
from detection_validation_policy import *  # noqa: F401,F403
from detection_validation_policy import (  # noqa: F401
    _evaluate_numeric_predicate,
    _infer_stun_response_xbits_state,
    _validated_stun_rule_semantics,
)


def build_detection_validation(
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    playbook: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic rule-intent assessment; never infer maliciousness."""
    from detection_validation_result_workflow import build_detection_validation as build

    return build(
        rule_context,
        packet_features,
        playbook,
        _evaluate_numeric_predicate,
        _infer_stun_response_xbits_state,
        _validated_stun_rule_semantics,
    )
