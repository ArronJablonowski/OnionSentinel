#!/usr/bin/env python3
"""Import-compatible facade for deterministic detection validation."""
from __future__ import annotations

import sys
from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from detection_validation_rule import *  # noqa: E402,F401,F403
from detection_validation_packet import *  # noqa: E402,F401,F403
from detection_validation_packet import (  # noqa: E402,F401
    _content_match_positions,
    _ordered_deployed_content_constraints,
)
from detection_validation_features import *  # noqa: E402,F401,F403
from detection_validation_policy import *  # noqa: E402,F401,F403
from detection_validation_result import *  # noqa: E402,F401,F403

__all__ = [
    "PLAYBOOK_SCHEMA",
    "VALIDATION_SCHEMA",
    "APPLICATION_STICKY_BUFFERS",
    "build_detection_validation",
    "extract_group_packet_features",
    "extract_rule_context",
    "load_detection_playbooks",
    "marker_specs",
    "parse_suricata_rule",
    "resolve_detection_playbook",
]
