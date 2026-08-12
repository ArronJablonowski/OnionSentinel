"""Shared constants and bounded primitives for detection rule validation."""

from __future__ import annotations

import base64
import collections
import hashlib
import ipaddress
import json
import math
import re
import struct
from pathlib import Path
from typing import Any, Iterable


PLAYBOOK_SCHEMA = "onion-sentinel-detection-playbooks-v1"
VALIDATION_SCHEMA = "onion-sentinel-detection-validation-v1"
MAX_PLAYBOOK_BYTES = 512 * 1024
MAX_PACKET_BYTES = 128 * 1024
MAX_PACKET_BASE64_CHARS = ((MAX_PACKET_BYTES + 2) // 3) * 4
MAX_GROUP_PACKETS = 5000
MAX_MARKERS = 16
MAX_MARKER_MATCHES_PER_PACKET = 16
MAX_COUNTER_VALUES = 64
SID_RE = re.compile(r"(?:^|;)\s*sid\s*:\s*(\d+)\s*(?:;|$)", re.IGNORECASE)
REV_RE = re.compile(r"(?:^|;)\s*rev\s*:\s*(\d+)\s*(?:;|$)", re.IGNORECASE)
APPLICATION_STICKY_BUFFERS = {
    "dns.query",
    "http.host",
    "http.method",
    "http.server",
    "http.uri",
    "http.user_agent",
    "tls.sni",
}


def _json_object(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _nested(value: object, dotted_path: str) -> object:
    current = value
    for part in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _row_value(row: object, key: str) -> object:
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[key]  # type: ignore[index]
    except (IndexError, KeyError, TypeError):
        return None
