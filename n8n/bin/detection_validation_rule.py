#!/usr/bin/env python3
"""Deterministic detection-intent validation over trusted alert evidence.

This module never exposes raw packet bytes to a model. It parses the deployed
Suricata rule and packet copies already present in Security Onion alert
documents, then emits only bounded predicate observations, counts, hashes, and
marker offsets. Exact-ID playbooks can add threat-behavior discriminators that
are intentionally stricter than the deployed rule.
"""
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


def _split_rule_options(text: str) -> list[str]:
    options: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for character in text:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "\\":
            current.append(character)
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
            current.append(character)
            continue
        if character == ";" and not quoted:
            option = "".join(current).strip()
            if option:
                options.append(option)
            current = []
            continue
        current.append(character)
    option = "".join(current).strip()
    if option:
        options.append(option)
    return options


def _decode_suricata_content(value: str) -> bytes:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        text = text[1:-1]
    output = bytearray()
    index = 0
    while index < len(text):
        if text[index] == "|":
            end = text.find("|", index + 1)
            if end < 0:
                break
            for token in text[index + 1:end].split():
                if re.fullmatch(r"[0-9A-Fa-f]{2}", token):
                    output.append(int(token, 16))
            index = end + 1
            continue
        if text[index] == "\\" and index + 1 < len(text):
            index += 1
        output.extend(text[index].encode("latin-1", "replace"))
        index += 1
    return bytes(output)


def _safe_ascii(value: bytes) -> str:
    if not value or len(value) > 80:
        return ""
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in value)


def parse_suricata_rule(rule_text: object) -> dict[str, Any]:
    """Parse bounded, decision-relevant Suricata rule predicates."""
    text = str(rule_text or "").strip()
    if not text or "(" not in text or ")" not in text:
        return {
            "available": False,
            "rule_sha256": hashlib.sha256(text.encode()).hexdigest() if text else "",
            "predicates": [],
            "contents": [],
            "state_operations": [],
        }
    header, option_text = text.split("(", 1)
    option_text = option_text.rsplit(")", 1)[0]
    header_parts = header.split()
    protocol = header_parts[1].lower() if len(header_parts) > 1 else ""
    options = _split_rule_options(option_text)
    scalar_options: dict[str, list[str]] = collections.defaultdict(list)
    contents: list[dict[str, Any]] = []
    state_operations: list[dict[str, str]] = []
    unsupported_match_options: list[dict[str, str]] = []
    current_content: dict[str, Any] | None = None
    current_buffer = ""
    current_buffer_modifiers: dict[str, object] = {}
    for raw_option in options:
        key, separator, raw_value = raw_option.partition(":")
        normalized_key = key.strip().lower()
        value = raw_value.strip() if separator else ""
        normalized_buffer = (
            "dns.query"
            if normalized_key == "dns_query"
            else normalized_key
        )
        if normalized_buffer in APPLICATION_STICKY_BUFFERS:
            current_buffer = normalized_buffer
            current_buffer_modifiers = {}
            current_content = None
            continue
        if normalized_key == "pkt_data":
            current_buffer = ""
            current_buffer_modifiers = {}
            current_content = None
            continue
        if normalized_key == "content":
            content_value = value.lstrip()
            negated = content_value.startswith("!")
            if negated:
                content_value = content_value[1:].lstrip()
            decoded = _decode_suricata_content(content_value)
            current_content = {
                "sha256": hashlib.sha256(decoded).hexdigest(),
                "length": len(decoded),
                "printable": _safe_ascii(decoded),
                "_bytes_hex": decoded.hex(),
                "negated": negated,
                "modifiers": dict(current_buffer_modifiers),
                "buffer": current_buffer,
            }
            contents.append(current_content)
            continue
        if normalized_key in {"dotprefix", "bsize"}:
            modifier_value: object = value if separator else True
            current_buffer_modifiers[normalized_key] = modifier_value
            if current_content is not None:
                current_content["modifiers"][normalized_key] = modifier_value
            continue
        if normalized_key in {
            "offset", "depth", "distance", "within", "startswith", "endswith",
            "nocase", "rawbytes",
        } and current_content is not None:
            current_content["modifiers"][normalized_key] = value if separator else True
            continue
        if normalized_key == "fast_pattern":
            # Performance-only selection does not change rule semantics and
            # must not detach later distance/within modifiers from content.
            continue
        current_content = None
        if normalized_key in {"xbits", "flowbits"}:
            parts = [part.strip() for part in value.split(",")]
            state_operations.append({
                "kind": normalized_key,
                "operation": parts[0] if parts else "",
                "name": parts[1] if len(parts) > 1 else "",
                "track": ",".join(parts[2:]) if len(parts) > 2 else "",
            })
            continue
        scalar_options[normalized_key].append(value)
        if normalized_key not in {
            "msg", "sid", "rev", "gid", "reference", "url", "classtype",
            "metadata", "target", "tag", "noalert", "priority", "itype",
            "icode", "icmp_id", "icmp_seq", "flow", "threshold",
        }:
            unsupported_match_options.append(
                {"option": normalized_key[:80], "value_sha256": hashlib.sha256(value.encode()).hexdigest()}
            )

    def numeric_predicate(name: str) -> tuple[str, int | str] | None:
        values = scalar_options.get(name) or []
        if not values:
            return None
        value = values[0].strip()
        if re.fullmatch(r"-?\d+", value):
            return "equals", int(value)
        return "unsupported_expression", value[:80]

    sid_match = SID_RE.search(";" + option_text + ";")
    rev_match = REV_RE.search(";" + option_text + ";")
    predicates = []
    for field, option_name in (
        ("icmp.type", "itype"),
        ("icmp.code", "icode"),
        ("icmp.identifier", "icmp_id"),
        ("icmp.sequence", "icmp_seq"),
    ):
        parsed_numeric = numeric_predicate(option_name)
        if parsed_numeric is not None:
            operator, expected = parsed_numeric
            predicates.append({
                "field": field,
                "operator": operator,
                "expected": expected,
                "required": True,
                "source": "deployed_rule",
            })
    public_contents = []
    for index, item in enumerate(contents[:MAX_MARKERS], 1):
        public_contents.append({
            "id": f"deployed-content-{index}",
            "sha256": item["sha256"],
            "length": item["length"],
            "printable": item["printable"],
            "hex": item["_bytes_hex"],
            "negated": item["negated"],
            "modifiers": item["modifiers"],
            "buffer": item["buffer"],
        })
    return {
        "available": True,
        "protocol": protocol,
        "sid": sid_match.group(1) if sid_match else "",
        "revision": int(rev_match.group(1)) if rev_match else None,
        "rule_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "predicates": predicates,
        "contents": public_contents,
        "state_operations": state_operations,
        "unsupported_match_options": unsupported_match_options[:64],
    }


def extract_rule_context(
    alert_payload: object,
    raw_event_payload: object = None,
    database_rule_id: object = None,
) -> dict[str, Any]:
    alert = _json_object(alert_payload)
    raw = _json_object(raw_event_payload)
    if not raw:
        raw = _json_object(_nested(alert, "security_onion.raw_event"))
    message = _json_object(raw.get("message"))
    raw_rule = str(
        _nested(raw, "rule.rule")
        or _nested(message, "alert.rule")
        or _nested(alert, "security_onion.raw_event.rule.rule")
        or ""
    )[:16000]
    parsed = parse_suricata_rule(raw_rule)
    def numeric_suricata_sid(value: object) -> str:
        if isinstance(value, bool) or value in (None, ""):
            return ""
        text = str(value).strip()
        if not re.fullmatch(r"[0-9]{1,20}", text):
            return ""
        number = int(text)
        if number < 1 or number > 0xFFFFFFFF:
            return ""
        return str(number)

    # Security Onion exports ECS rule.id as a UUID. That identifies the stored
    # rule record; it is not the numeric Suricata signature ID used by
    # playbooks. Prefer explicit signature_id values and the deployed rule sid,
    # accepting database/rule.id fallbacks only when they are actually numeric.
    sid_values = [
        _nested(message, "alert.signature_id"),
        _nested(raw, "alert.signature_id"),
        _nested(alert, "alert.signature_id"),
        alert.get("signature_id"),
        parsed.get("sid"),
        database_rule_id,
        alert.get("rule_id"),
        _nested(raw, "rule.id"),
    ]
    sid_candidates = {
        candidate
        for candidate in (numeric_suricata_sid(value) for value in sid_values)
        if candidate
    }
    sid = next(
        (
            candidate
            for candidate in (numeric_suricata_sid(value) for value in sid_values)
            if candidate
        ),
        "",
    )
    record_rule_id = str(
        database_rule_id
        or alert.get("rule_id")
        or _nested(raw, "rule.id")
        or ""
    ).strip()[:200]
    revision_value = (
        _nested(raw, "rule.rev")
        or _nested(message, "alert.rev")
        or parsed.get("revision")
    )
    revision_candidates: set[int] = set()
    for value in (
        _nested(raw, "rule.rev"),
        _nested(message, "alert.rev"),
        parsed.get("revision"),
    ):
        try:
            if value not in (None, ""):
                revision_candidates.add(int(value))
        except (TypeError, ValueError):
            continue
    try:
        revision = int(revision_value) if revision_value not in (None, "") else None
    except (TypeError, ValueError):
        revision = None
    return {
        "sid": sid,
        "record_rule_id": record_rule_id,
        "revision": revision,
        "name": str(
            alert.get("rule_name")
            or _nested(raw, "rule.name")
            or _nested(message, "alert.signature")
            or ""
        )[:500],
        "ruleset": str(
            alert.get("rule_ruleset")
            or _nested(raw, "rule.ruleset")
            or ""
        )[:200],
        "category": str(
            alert.get("rule_category")
            or _nested(message, "alert.category")
            or ""
        )[:300],
        "reference": str(alert.get("rule_reference") or "")[:1000],
        "raw_rule": raw_rule,
        "parsed_rule": parsed,
        "identity_conflicts": {
            "sid": sorted(sid_candidates) if len(sid_candidates) > 1 else [],
            "revision": sorted(revision_candidates) if len(revision_candidates) > 1 else [],
        },
    }


def _icmp_from_packet(packet: bytes, linktype: int = 1) -> dict[str, Any] | None:
    if not packet or len(packet) > MAX_PACKET_BYTES:
        return None
    offset = 0
    ethertype = 0
    if linktype == 1:
        if len(packet) < 14:
            return None
        ethertype = struct.unpack("!H", packet[12:14])[0]
        offset = 14
        while ethertype in {0x8100, 0x88A8, 0x9100}:
            if len(packet) < offset + 4:
                return None
            ethertype = struct.unpack("!H", packet[offset + 2:offset + 4])[0]
            offset += 4
    elif packet[0] >> 4 == 4:
        ethertype = 0x0800
    elif packet[0] >> 4 == 6:
        ethertype = 0x86DD
    if ethertype == 0x0800:
        if len(packet) < offset + 20:
            return None
        ihl = (packet[offset] & 0x0F) * 4
        if ihl < 20 or len(packet) < offset + ihl + 8 or packet[offset + 9] != 1:
            return None
        total_length = struct.unpack("!H", packet[offset + 2:offset + 4])[0]
        end = min(len(packet), offset + max(total_length, ihl + 8))
        source = str(ipaddress.ip_address(packet[offset + 12:offset + 16]))
        destination = str(ipaddress.ip_address(packet[offset + 16:offset + 20]))
        icmp_offset = offset + ihl
    elif ethertype == 0x86DD:
        if len(packet) < offset + 48 or packet[offset + 6] != 58:
            return None
        payload_length = struct.unpack("!H", packet[offset + 4:offset + 6])[0]
        end = min(len(packet), offset + 40 + payload_length)
        source = str(ipaddress.ip_address(packet[offset + 8:offset + 24]))
        destination = str(ipaddress.ip_address(packet[offset + 24:offset + 40]))
        icmp_offset = offset + 40
    else:
        return None
    if end < icmp_offset + 8:
        return None
    icmp_type, code = packet[icmp_offset], packet[icmp_offset + 1]
    identifier, sequence = struct.unpack("!HH", packet[icmp_offset + 4:icmp_offset + 8])
    return {
        "family": "icmpv6" if ethertype == 0x86DD else "icmp",
        "type": icmp_type,
        "code": code,
        "identifier": identifier,
        "sequence": sequence,
        "source_ip": source,
        "destination_ip": destination,
        "frame_bytes": len(packet),
        "_payload": packet[icmp_offset + 8:end],
    }
