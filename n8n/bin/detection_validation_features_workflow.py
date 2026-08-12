"""Public workflow orchestration for detection packet feature aggregation."""
from __future__ import annotations

from typing import Any, Iterable

from detection_validation_packet import MAX_GROUP_PACKETS
from detection_validation_features_markers import decode_marker_values
from detection_validation_features_observation import observe_row
from detection_validation_features_projection import project_features
from detection_validation_features_state import FeatureState


def extract_group_packet_features(
    grouped_rows: Iterable[object],
    markers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Decode stored packet copies and return bounded, raw-payload-free semantics."""
    marker_values = decode_marker_values(markers)
    state = FeatureState(marker_values)
    for row in grouped_rows:
        if state.candidate_count >= MAX_GROUP_PACKETS:
            state.truncated = True
            break
        observe_row(row, marker_values, state)
    return project_features(marker_values, state)
