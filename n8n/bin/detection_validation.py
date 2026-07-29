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


def _network_packet_envelope(packet: bytes, linktype: int = 1) -> dict[str, Any] | None:
    """Return bounded IP transport metadata without exposing packet contents."""
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
        if len(packet) < offset + 20 or packet[offset] >> 4 != 4:
            return None
        ihl = (packet[offset] & 0x0F) * 4
        if ihl < 20 or len(packet) < offset + ihl:
            return None
        total_length = struct.unpack("!H", packet[offset + 2:offset + 4])[0]
        if total_length < ihl:
            return None
        end = min(len(packet), offset + total_length)
        return {
            "family": "ipv4",
            "protocol_number": int(packet[offset + 9]),
            "transport_offset": offset + ihl,
            "end": end,
        }
    if ethertype == 0x86DD:
        if len(packet) < offset + 40 or packet[offset] >> 4 != 6:
            return None
        payload_length = struct.unpack("!H", packet[offset + 4:offset + 6])[0]
        end = min(len(packet), offset + 40 + payload_length)
        return {
            "family": "ipv6",
            "protocol_number": int(packet[offset + 6]),
            "transport_offset": offset + 40,
            "end": end,
        }
    return None


def _udp_from_packet(
    packet: bytes,
    envelope: dict[str, Any],
) -> dict[str, Any] | None:
    if int(envelope.get("protocol_number", -1)) != 17:
        return None
    offset = int(envelope.get("transport_offset") or 0)
    end = int(envelope.get("end") or 0)
    if offset < 0 or end < offset + 8 or len(packet) < offset + 8:
        return None
    source_port, destination_port, udp_length = struct.unpack(
        "!HHH", packet[offset:offset + 6]
    )
    if udp_length < 8 or offset + udp_length > end:
        return None
    return {
        "source_port": source_port,
        "destination_port": destination_port,
        "payload_length": udp_length - 8,
        "_payload": packet[offset + 8:offset + udp_length],
    }


def _stun_binding_semantics(payload: bytes) -> dict[str, Any] | None:
    """Recognize a complete RFC 5389 STUN message without retaining identifiers."""
    if len(payload) < 20:
        return None
    message_type, message_length, magic_cookie = struct.unpack("!HHI", payload[:8])
    if message_type & 0xC000 or magic_cookie != 0x2112A442:
        return None
    if message_length % 4 or 20 + message_length > len(payload):
        return None
    method = (
        (message_type & 0x000F)
        | ((message_type & 0x00E0) >> 1)
        | ((message_type & 0x3E00) >> 2)
    )
    message_class = ((message_type & 0x0010) >> 4) | ((message_type & 0x0100) >> 7)
    if method != 0x001:
        return None
    kind = {
        0: "binding_request",
        1: "binding_indication",
        2: "binding_success_response",
        3: "binding_error_response",
    }.get(message_class)
    if kind is None:
        return None
    return {
        "kind": kind,
        "declared_body_bytes": message_length,
    }


def _bounded_counter(counter: collections.Counter[int]) -> list[dict[str, int]]:
    return [
        {"value": int(value), "count": int(count)}
        for value, count in counter.most_common(MAX_COUNTER_VALUES)
    ]


def _bounded_text_counter(counter: collections.Counter[str]) -> list[dict[str, Any]]:
    return [
        {"value": str(value)[:80], "count": int(count)}
        for value, count in counter.most_common(MAX_COUNTER_VALUES)
    ]


def _entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts = collections.Counter(payload)
    length = len(payload)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def marker_specs(rule_context: dict[str, Any], playbook: dict[str, Any] | None) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    parsed_rule = rule_context.get("parsed_rule")
    if isinstance(parsed_rule, dict):
        for item in parsed_rule.get("contents", []) if isinstance(parsed_rule.get("contents"), list) else []:
            if not isinstance(item, dict) or not str(item.get("hex") or ""):
                continue
            specs.append({
                "id": str(item.get("id") or f"deployed-content-{len(specs) + 1}")[:100],
                "hex": str(item.get("hex") or "")[:512],
                "modifiers": dict(item.get("modifiers") or {}) if isinstance(item.get("modifiers"), dict) else {},
                "buffer": str(item.get("buffer") or "")[:80],
                "negated": bool(item.get("negated")),
                "source": "deployed_rule",
            })
    if isinstance(playbook, dict):
        values = playbook.get("marker_predicates")
        for item in values if isinstance(values, list) else []:
            if not isinstance(item, dict) or not str(item.get("hex") or ""):
                continue
            applies = (
                {str(value) for value in item.get("applies_to_sids", [])}
                if isinstance(item.get("applies_to_sids"), list)
                else set()
            )
            if applies and str(rule_context.get("sid") or "") not in applies:
                continue
            specs.append({
                "id": str(item.get("id") or f"playbook-marker-{len(specs) + 1}")[:100],
                "hex": str(item.get("hex") or "")[:512],
                "expected_offset": item.get("expected_offset"),
                "modifiers": {},
                "negated": False,
                "source": "playbook",
            })
    unique: list[dict[str, Any]] = []
    seen = set()
    for item in specs:
        key = (item["id"], item["hex"].lower())
        if key not in seen and len(unique) < MAX_MARKERS:
            seen.add(key)
            unique.append(item)
    return unique


def _nonnegative_modifier(value: object) -> int | None:
    text = str(value or "").strip()
    if not re.fullmatch(r"\d+", text):
        return None
    return int(text)


def _content_constraint(
    payload: bytes,
    marker: bytes,
    spec: dict[str, Any],
) -> bool | None:
    """Evaluate the supported subset of Suricata payload-content semantics."""
    positions = _content_match_positions(payload, marker, spec)
    if positions is None:
        return None
    present = bool(positions)
    return not present if bool(spec.get("negated")) else present


def _content_evaluation_supported(
    spec: dict[str, Any],
    *,
    application_buffer: str | None = None,
) -> bool:
    """Return whether a content clause can use the supplied bounded buffer."""
    if spec.get("source") != "deployed_rule":
        return True
    buffer_name = str(spec.get("buffer") or "").strip().lower()
    modifiers = (
        spec.get("modifiers")
        if isinstance(spec.get("modifiers"), dict)
        else {}
    )
    if application_buffer is None:
        if buffer_name not in {"", "pkt_data"}:
            return False
        if any(name in modifiers for name in ("dotprefix", "bsize")):
            return False
    elif buffer_name != application_buffer:
        return False
    if "rawbytes" in modifiers:
        return False
    if "bsize" in modifiers and _nonnegative_modifier(
        modifiers.get("bsize")
    ) is None:
        return False
    return True


def _content_match_positions(
    payload: bytes,
    marker: bytes,
    spec: dict[str, Any],
    *,
    previous_match_end: int | None = None,
    application_buffer: str | None = None,
) -> list[int] | None:
    """Return bounded matches for one absolute or cursor-relative content clause."""
    if not _content_evaluation_supported(
        spec,
        application_buffer=application_buffer,
    ):
        return None
    modifiers = spec.get("modifiers") if isinstance(spec.get("modifiers"), dict) else {}
    if "bsize" in modifiers:
        expected_size = _nonnegative_modifier(modifiers.get("bsize"))
        if expected_size is None:
            return None
        if len(payload) != expected_size:
            return []
    if application_buffer is not None and "dotprefix" in modifiers:
        # Suricata's dotprefix transform gives a domain buffer one virtual
        # leading dot so `.example.com` also matches the apex `example.com`.
        payload = b"." + payload.lstrip(b".")
    relative = "distance" in modifiers or "within" in modifiers
    if relative and any(key in modifiers for key in ("offset", "depth")):
        return None
    if relative:
        if previous_match_end is None:
            return None
        distance = 0
        if "distance" in modifiers:
            distance = _nonnegative_modifier(modifiers.get("distance"))
            if distance is None:
                return None
        start = previous_match_end + distance
        end = len(payload)
        if "within" in modifiers:
            within = _nonnegative_modifier(modifiers.get("within"))
            if within is None:
                return None
            end = min(len(payload), start + within)
    else:
        start = 0
        if "offset" in modifiers:
            start = _nonnegative_modifier(modifiers.get("offset"))
            if start is None:
                return None
        end = len(payload)
        if "depth" in modifiers:
            depth = _nonnegative_modifier(modifiers.get("depth"))
            if depth is None:
                return None
            end = min(len(payload), start + depth)
    if start < 0 or start > len(payload) or end < start:
        return []
    haystack = payload.lower() if "nocase" in modifiers else payload
    needle = marker.lower() if "nocase" in modifiers else marker
    if "startswith" in modifiers:
        if start <= 0 and len(needle) <= end and haystack.startswith(needle):
            return [0]
        return []
    if "endswith" in modifiers:
        position = len(haystack) - len(needle)
        if position >= start and position + len(needle) <= end and haystack.endswith(needle):
            return [position]
        return []
    positions: list[int] = []
    cursor = start
    while len(positions) < MAX_MARKER_MATCHES_PER_PACKET:
        position = haystack.find(needle, cursor, end)
        if position < 0:
            break
        positions.append(position)
        cursor = position + 1
    return positions


def _ordered_deployed_content_constraints(
    payload: bytes,
    marker_values: list[tuple[dict[str, Any], bytes]],
    *,
    application_buffer: str | None = None,
) -> dict[str, bool | None]:
    """Evaluate deployed content clauses in rule order with bounded cursor paths."""
    results: dict[str, bool | None] = {}
    cursors: set[int | None] = {None}
    cursor_unknown = False
    current_buffer: str | None = None
    for spec, marker in marker_values:
        if spec.get("source") != "deployed_rule":
            continue
        marker_id = str(spec["id"])
        modifiers = spec.get("modifiers") if isinstance(spec.get("modifiers"), dict) else {}
        relative = "distance" in modifiers or "within" in modifiers
        buffer_name = str(spec.get("buffer") or "pkt_data").strip().lower()
        if buffer_name != current_buffer:
            current_buffer = buffer_name
            cursors = {None}
            cursor_unknown = False
        if relative and not cursors:
            results[marker_id] = None if cursor_unknown else False
            continue
        if relative:
            candidate_cursors = sorted(
                cursors,
                key=lambda value: -1 if value is None else value,
            )
        else:
            candidate_cursors = [None]
        supported = True
        satisfied = False
        next_cursors: set[int | None] = set()
        for previous_end in candidate_cursors[:MAX_MARKER_MATCHES_PER_PACKET]:
            positions = _content_match_positions(
                payload,
                marker,
                spec,
                previous_match_end=previous_end,
                application_buffer=application_buffer,
            )
            if positions is None:
                supported = False
                continue
            if spec.get("negated"):
                if not positions:
                    satisfied = True
                    if relative:
                        next_cursors.add(previous_end)
                    else:
                        next_cursors.update(cursors)
                continue
            if positions:
                satisfied = True
                next_cursors.update(
                    position + len(marker)
                    for position in positions[:MAX_MARKER_MATCHES_PER_PACKET]
                )
        if not supported:
            results[marker_id] = None
            cursors = set()
            cursor_unknown = True
            continue
        results[marker_id] = satisfied
        cursors = next_cursors if satisfied else set()
        cursor_unknown = False
    return results


def _bounded_application_buffers(
    raw: dict[str, Any],
    message: dict[str, Any],
    alert: dict[str, Any],
    marker_values: list[tuple[dict[str, Any], bytes]] | None = None,
) -> dict[str, bytes]:
    """Project Suricata application evidence without retaining raw payloads."""
    decoded_value = (
        _nested(raw, "network.data.decoded")
        or message.get("payload_printable")
        or ""
    )
    decoded = (
        str(decoded_value)
        if isinstance(decoded_value, str)
        and len(decoded_value.encode("utf-8", "replace")) <= MAX_PACKET_BYTES
        else ""
    )
    buffers: dict[str, bytes] = {}
    if decoded:
        lines = re.split(r"\r?\n", decoded)
        if lines:
            request = lines[0].split()
            if len(request) >= 2 and re.fullmatch(
                r"[A-Z]{2,16}",
                request[0],
            ):
                buffers["http.method"] = request[0].encode(
                    "latin-1",
                    "replace",
                )
                buffers["http.uri"] = request[1].encode(
                    "latin-1",
                    "replace",
                )
        for line in lines[1:256]:
            name, separator, value = line.partition(":")
            if not separator:
                continue
            key = {
                "host": "http.host",
                "server": "http.server",
                "user-agent": "http.user_agent",
            }.get(name.strip().lower())
            if key and value.strip():
                buffers[key] = value.strip().encode(
                    "latin-1",
                    "replace",
                )[:MAX_PACKET_BYTES]

    dns_name = str(
        _nested(raw, "dns.query.name")
        or _nested(raw, "dns.question.name")
        or _nested(raw, "dns.query_name")
        or _nested(alert, "dns.query_name")
        or _nested(message, "dns.rrname")
        or ""
    ).strip().rstrip(".")
    if dns_name and len(dns_name.encode("utf-8", "replace")) <= 253:
        buffers["dns.query"] = dns_name.encode("utf-8", "replace")

    tls_name = str(
        _nested(raw, "tls.server.name")
        or _nested(raw, "tls.sni")
        or _nested(alert, "tls.server.name")
        or _nested(alert, "tls.sni")
        or _nested(message, "tls.sni")
        or ""
    ).strip().rstrip(".")
    if not tls_name and decoded:
        # Suricata's decoded ClientHello projection contains the SNI as a
        # bounded printable hostname. Select only a single canonical domain
        # token; ambiguity remains unsupported instead of guessing.
        candidates = {
            value.rstrip(".").lower()
            for value in re.findall(
                r"(?i)(?<![A-Za-z0-9-])"
                r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                r"[A-Za-z]{2,63}(?![A-Za-z0-9-])",
                decoded,
            )
            if len(value) <= 253
        }
        tls_markers = {
            marker.decode("latin-1", "ignore").lower().lstrip(".")
            for spec, marker in marker_values or []
            if str(spec.get("buffer") or "").strip().lower() == "tls.sni"
        }
        matching = {
            candidate
            for candidate in candidates
            if any(
                candidate == marker or candidate.endswith(f".{marker}")
                for marker in tls_markers
                if marker
            )
        }
        if len(matching) == 1:
            tls_name = next(iter(matching))
    if tls_name and len(tls_name.encode("utf-8", "replace")) <= 253:
        buffers["tls.sni"] = tls_name.encode("utf-8", "replace")
    return buffers


def extract_group_packet_features(
    grouped_rows: Iterable[object],
    markers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Decode stored packet copies and return bounded, raw-payload-free semantics."""
    marker_values: list[tuple[dict[str, Any], bytes]] = []
    for item in markers or []:
        try:
            decoded = bytes.fromhex(str(item.get("hex") or ""))
        except ValueError:
            continue
        if decoded:
            marker_values.append((item, decoded))
    type_counts: collections.Counter[int] = collections.Counter()
    code_counts: collections.Counter[int] = collections.Counter()
    identifiers: collections.Counter[int] = collections.Counter()
    sequences: collections.Counter[int] = collections.Counter()
    payload_lengths: collections.Counter[int] = collections.Counter()
    frame_lengths: collections.Counter[int] = collections.Counter()
    marker_offsets: dict[str, collections.Counter[int]] = {
        str(item["id"]): collections.Counter() for item, _ in marker_values
    }
    marker_packets: collections.Counter[str] = collections.Counter()
    marker_constraint_evaluated: collections.Counter[str] = collections.Counter()
    marker_constraint_satisfied: collections.Counter[str] = collections.Counter()
    marker_constraint_violated: collections.Counter[str] = collections.Counter()
    marker_constraint_unsupported: set[str] = set()
    entropies: list[float] = []
    parsed_packet_count = 0
    content_packet_count = 0
    icmp_packet_count = 0
    udp_packet_count = 0
    unsupported_protocol_packets = 0
    protocol_counts: collections.Counter[str] = collections.Counter()
    udp_payload_lengths: collections.Counter[int] = collections.Counter()
    stun_kinds: collections.Counter[str] = collections.Counter()
    stun_body_lengths: collections.Counter[int] = collections.Counter()
    candidate_count = 0
    parse_errors = 0
    truncated = False

    def observe_content(
        payload: bytes,
        selected_markers: list[tuple[dict[str, Any], bytes]],
        *,
        application_buffer: str | None = None,
    ) -> bool:
        if not selected_markers:
            return False
        ordered_constraints = _ordered_deployed_content_constraints(
            payload,
            selected_markers,
            application_buffer=application_buffer,
        )
        for spec, marker in selected_markers:
            marker_id = str(spec["id"])
            if spec.get("source") == "deployed_rule":
                constraint = ordered_constraints.get(marker_id)
            else:
                constraint = _content_constraint(payload, marker, spec)
            if constraint is None:
                marker_constraint_unsupported.add(marker_id)
            else:
                marker_constraint_evaluated[marker_id] += 1
                if constraint:
                    marker_constraint_satisfied[marker_id] += 1
                else:
                    marker_constraint_violated[marker_id] += 1
            if not _content_evaluation_supported(
                spec,
                application_buffer=application_buffer,
            ):
                continue
            modifiers = (
                spec.get("modifiers")
                if isinstance(spec.get("modifiers"), dict)
                else {}
            )
            haystack = payload.lower() if "nocase" in modifiers else payload
            needle = marker.lower() if "nocase" in modifiers else marker
            start = 0
            matches = 0
            while matches < MAX_MARKER_MATCHES_PER_PACKET:
                position = haystack.find(needle, start)
                if position < 0:
                    break
                marker_offsets[marker_id][position] += 1
                matches += 1
                start = position + 1
            if matches:
                marker_packets[marker_id] += 1
        return True

    for row in grouped_rows:
        if candidate_count >= MAX_GROUP_PACKETS:
            truncated = True
            break
        raw = _json_object(_row_value(row, "raw_event_json"))
        alert = _json_object(_row_value(row, "alert_json"))
        if not raw:
            raw = _json_object(_nested(alert, "security_onion.raw_event"))
        message = _json_object(raw.get("message"))
        application_buffers = _bounded_application_buffers(
            raw,
            message,
            alert,
            marker_values,
        )
        packet_text = str(message.get("packet") or "").strip()
        if not packet_text:
            continue
        candidate_count += 1
        if len(packet_text) > MAX_PACKET_BASE64_CHARS:
            parse_errors += 1
            continue
        try:
            packet = base64.b64decode(packet_text, validate=True)
        except (ValueError, TypeError):
            parse_errors += 1
            continue
        try:
            linktype = int(_nested(message, "packet_info.linktype") or 1)
        except (TypeError, ValueError):
            linktype = 1
        envelope = _network_packet_envelope(packet, linktype)
        if not envelope:
            parse_errors += 1
            continue
        protocol_number = int(envelope.get("protocol_number", -1))
        protocol_name = {
            1: "icmp",
            6: "tcp",
            17: "udp",
            58: "icmpv6",
        }.get(protocol_number, f"ip_protocol_{protocol_number}")
        protocol_counts[protocol_name] += 1
        row_has_content = False
        for buffer_name, buffer_payload in application_buffers.items():
            selected = [
                (spec, marker)
                for spec, marker in marker_values
                if str(spec.get("buffer") or "").strip().lower()
                == buffer_name
            ]
            row_has_content = (
                observe_content(
                    buffer_payload,
                    selected,
                    application_buffer=buffer_name,
                )
                or row_has_content
            )
        if protocol_number in {1, 58}:
            parsed = _icmp_from_packet(packet, linktype)
            if not parsed:
                parse_errors += 1
                continue
            parsed_packet_count += 1
            icmp_packet_count += 1
            payload = parsed.pop("_payload")
            type_counts[parsed["type"]] += 1
            code_counts[parsed["code"]] += 1
            identifiers[parsed["identifier"]] += 1
            sequences[parsed["sequence"]] += 1
            payload_lengths[len(payload)] += 1
            frame_lengths[parsed["frame_bytes"]] += 1
            entropies.append(_entropy(payload))
        elif protocol_number == 17:
            parsed = _udp_from_packet(packet, envelope)
            if not parsed:
                parse_errors += 1
                continue
            parsed_packet_count += 1
            udp_packet_count += 1
            payload = parsed.pop("_payload")
            udp_payload_lengths[len(payload)] += 1
            stun = _stun_binding_semantics(payload)
            if stun:
                stun_kinds[str(stun["kind"])] += 1
                stun_body_lengths[int(stun["declared_body_bytes"])] += 1
        else:
            # A valid, currently unsupported transport is not a parse error.
            parsed_packet_count += 1
            unsupported_protocol_packets += 1
            if row_has_content:
                content_packet_count += 1
            continue
        raw_markers = [
            (spec, marker)
            for spec, marker in marker_values
            if str(spec.get("buffer") or "").strip().lower()
            in {"", "pkt_data"}
        ]
        row_has_content = observe_content(payload, raw_markers) or row_has_content
        if row_has_content:
            content_packet_count += 1
    marker_results = []
    for spec, marker in marker_values:
        marker_id = str(spec["id"])
        expected_raw = spec.get("expected_offset")
        try:
            expected_offset = int(expected_raw) if expected_raw not in (None, "") else None
        except (TypeError, ValueError):
            expected_offset = None
        offset_counts = marker_offsets[marker_id]
        marker_results.append({
            "id": marker_id,
            "source": spec.get("source"),
            "sha256": hashlib.sha256(marker).hexdigest(),
            "length": len(marker),
            "packets_with_marker": int(marker_packets[marker_id]),
            "observations": int(sum(offset_counts.values())),
            "expected_offset": expected_offset,
            "expected_offset_observations": int(offset_counts.get(expected_offset, 0)) if expected_offset is not None else None,
            "offsets": _bounded_counter(offset_counts),
            "constraint_supported": (
                marker_id not in marker_constraint_unsupported
                and _content_evaluation_supported(
                    spec,
                    application_buffer=(
                        str(spec.get("buffer") or "").strip().lower()
                        or None
                    ),
                )
            ),
            "packets_evaluated_for_constraint": int(marker_constraint_evaluated[marker_id]),
            "packets_satisfying_constraint": int(marker_constraint_satisfied[marker_id]),
            "packets_violating_constraint": int(marker_constraint_violated[marker_id]),
        })
    return {
        "source": "stored-security-onion-alert-packet-copies",
        "application_evidence_source": (
            "stored-security-onion-suricata-application-projection"
        ),
        "raw_payloads_included": False,
        "candidate_packets": candidate_count,
        "packets_parsed": parsed_packet_count,
        "content_packets_parsed": content_packet_count,
        "packet_protocols": _bounded_text_counter(protocol_counts),
        "unsupported_protocol_packets": unsupported_protocol_packets,
        "icmp_packets_parsed": icmp_packet_count,
        "udp_packets_parsed": udp_packet_count,
        "udp_payload_lengths": _bounded_counter(udp_payload_lengths),
        "stun": {
            "packets_parsed": int(sum(stun_kinds.values())),
            "message_types": _bounded_text_counter(stun_kinds),
            "declared_body_lengths": _bounded_counter(stun_body_lengths),
            "magic_cookie_valid_packets": int(sum(stun_kinds.values())),
            "transaction_ids_included": False,
            "raw_payloads_included": False,
        },
        "parse_errors": parse_errors,
        "truncated": truncated,
        "icmp_types": _bounded_counter(type_counts),
        "icmp_codes": _bounded_counter(code_counts),
        "icmp_identifiers": _bounded_counter(identifiers),
        "icmp_sequences": _bounded_counter(sequences),
        "payload_lengths": _bounded_counter(payload_lengths),
        "frame_lengths": _bounded_counter(frame_lengths),
        "payload_entropy": {
            "minimum": round(min(entropies), 4) if entropies else None,
            "maximum": round(max(entropies), 4) if entropies else None,
            "average": round(sum(entropies) / len(entropies), 4) if entropies else None,
        },
        "markers": marker_results,
    }


def load_detection_playbooks(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_PLAYBOOK_BYTES:
            raise ValueError("detection playbook registry exceeds its byte limit")
        with path.open("rb") as handle:
            raw = handle.read(MAX_PLAYBOOK_BYTES + 1)
    except FileNotFoundError:
        return {"schema": PLAYBOOK_SCHEMA, "version": 0, "playbooks": []}
    if len(raw) > MAX_PLAYBOOK_BYTES:
        raise ValueError("detection playbook registry exceeds its byte limit")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != PLAYBOOK_SCHEMA:
        raise ValueError("unsupported detection playbook registry")
    if payload.get("version") != 1:
        raise ValueError("unsupported detection playbook registry version")
    playbooks = payload.get("playbooks")
    if not isinstance(playbooks, list):
        raise ValueError("detection playbooks must be a list")
    if len(playbooks) > 500:
        raise ValueError("detection playbook registry has too many playbooks")
    validated: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for index, playbook in enumerate(playbooks):
        if not isinstance(playbook, dict):
            raise ValueError(f"playbooks[{index}] must be an object")
        identifier = str(playbook.get("id") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", identifier):
            raise ValueError(f"playbooks[{index}].id is invalid")
        if identifier in identifiers:
            raise ValueError(f"duplicate detection playbook id: {identifier}")
        identifiers.add(identifier)
        if not isinstance(playbook.get("version"), int) or int(playbook["version"]) < 1:
            raise ValueError(f"{identifier}.version must be a positive integer")
        match = playbook.get("match")
        if not isinstance(match, dict):
            raise ValueError(f"{identifier}.match must be an object")
        sids = match.get("sids", [])
        revisions = match.get("revisions", [])
        if not isinstance(sids, list) or any(not re.fullmatch(r"\d{1,20}", str(value)) for value in sids):
            raise ValueError(f"{identifier}.match.sids is invalid")
        if not isinstance(revisions, list) or any(
            not isinstance(value, int) or value < 1 for value in revisions
        ):
            raise ValueError(f"{identifier}.match.revisions is invalid")
        ruleset = str(match.get("ruleset") or "")
        if len(ruleset) > 200 or not (sids or revisions or ruleset):
            raise ValueError(f"{identifier}.match must define a bounded exact scope")
        rule_sha256 = str(match.get("rule_sha256") or "")
        if rule_sha256 and not re.fullmatch(r"[0-9a-f]{64}", rule_sha256):
            raise ValueError(f"{identifier}.match.rule_sha256 is invalid")
        for collection_name in ("required_predicates", "supporting_predicates"):
            predicates = playbook.get(collection_name, [])
            if not isinstance(predicates, list) or len(predicates) > 64:
                raise ValueError(f"{identifier}.{collection_name} is invalid")
            for predicate in predicates:
                if not isinstance(predicate, dict):
                    raise ValueError(f"{identifier}.{collection_name} entries must be objects")
                if str(predicate.get("field") or "") not in {
                    "icmp.type",
                    "icmp.code",
                    "icmp.identifier",
                    "icmp.sequence",
                    "icmp.payload_length",
                    "frame.length",
                }:
                    raise ValueError(f"{identifier}.{collection_name} field is unsupported")
                if str(predicate.get("operator") or "equals") not in {"equals", "contains"}:
                    raise ValueError(f"{identifier}.{collection_name} operator is unsupported")
                applies_to_sids = predicate.get("applies_to_sids", [])
                if not isinstance(applies_to_sids, list) or any(
                    not re.fullmatch(r"\d{1,20}", str(value))
                    for value in applies_to_sids
                ):
                    raise ValueError(f"{identifier}.{collection_name} applies_to_sids is invalid")
                expected = predicate.get("expected", predicate.get("value"))
                expected_values = expected if isinstance(expected, list) else [expected]
                if not expected_values:
                    raise ValueError(f"{identifier}.{collection_name} expected value is missing")
                try:
                    [int(value) for value in expected_values]
                except (TypeError, ValueError) as error:
                    raise ValueError(f"{identifier}.{collection_name} expected value is invalid") from error
        marker_predicates = playbook.get("marker_predicates", [])
        if not isinstance(marker_predicates, list) or len(marker_predicates) > MAX_MARKERS:
            raise ValueError(f"{identifier}.marker_predicates is invalid")
        for marker in marker_predicates:
            if not isinstance(marker, dict):
                raise ValueError(f"{identifier}.marker_predicates entries must be objects")
            marker_hex = str(marker.get("hex") or "")
            if (
                not marker_hex
                or len(marker_hex) > 512
                or len(marker_hex) % 2
                or not re.fullmatch(r"[0-9A-Fa-f]+", marker_hex)
            ):
                raise ValueError(f"{identifier}.marker_predicates hex is invalid")
            expected_offset = marker.get("expected_offset")
            if expected_offset is not None and (
                not isinstance(expected_offset, int)
                or expected_offset < 0
                or expected_offset > MAX_PACKET_BYTES
            ):
                raise ValueError(f"{identifier}.marker_predicates expected_offset is invalid")
            applies_to_sids = marker.get("applies_to_sids", [])
            if not isinstance(applies_to_sids, list) or any(
                not re.fullmatch(r"\d{1,20}", str(value))
                for value in applies_to_sids
            ):
                raise ValueError(f"{identifier}.marker_predicates applies_to_sids is invalid")
        validated.append(playbook)
    return {
        "schema": PLAYBOOK_SCHEMA,
        "version": payload.get("version"),
        "generated_at": payload.get("generated_at"),
        "playbooks": validated,
    }


def resolve_detection_playbook(
    registry: dict[str, Any],
    rule_context: dict[str, Any],
) -> dict[str, Any] | None:
    sid = str(rule_context.get("sid") or "")
    revision = rule_context.get("revision")
    ruleset = str(rule_context.get("ruleset") or "").strip().casefold()
    conflicts = rule_context.get("identity_conflicts")
    if isinstance(conflicts, dict) and any(conflicts.get(key) for key in ("sid", "revision")):
        return None
    parsed_rule = rule_context.get("parsed_rule")
    rule_sha256 = (
        str(parsed_rule.get("rule_sha256") or "")
        if isinstance(parsed_rule, dict)
        else ""
    )
    for playbook in registry.get("playbooks", []) if isinstance(registry.get("playbooks"), list) else []:
        if not isinstance(playbook, dict):
            continue
        match = playbook.get("match") if isinstance(playbook.get("match"), dict) else {}
        sids = {str(value) for value in match.get("sids", [])} if isinstance(match.get("sids"), list) else set()
        revisions = set(match.get("revisions", [])) if isinstance(match.get("revisions"), list) else set()
        expected_ruleset = str(match.get("ruleset") or "").strip().casefold()
        expected_rule_sha256 = str(match.get("rule_sha256") or "")
        if sids and sid not in sids:
            continue
        if revisions and revision not in revisions:
            continue
        if expected_ruleset and expected_ruleset != ruleset:
            continue
        if expected_rule_sha256 and expected_rule_sha256 != rule_sha256:
            continue
        if sids or revisions or expected_ruleset:
            return playbook
    return None


def _observed_values(features: dict[str, Any], field: str) -> list[int]:
    key = {
        "icmp.type": "icmp_types",
        "icmp.code": "icmp_codes",
        "icmp.identifier": "icmp_identifiers",
        "icmp.sequence": "icmp_sequences",
        "icmp.payload_length": "payload_lengths",
        "frame.length": "frame_lengths",
    }.get(field)
    if not key:
        return []
    return [
        int(item["value"])
        for item in features.get(key, [])
        if isinstance(item, dict) and isinstance(item.get("value"), int)
    ]


def _evaluate_numeric_predicate(
    predicate: dict[str, Any],
    features: dict[str, Any],
    *,
    source: str,
) -> dict[str, Any]:
    field = str(predicate.get("field") or "")
    observed = _observed_values(features, field)
    operator = str(predicate.get("operator") or "equals")
    expected = predicate.get("expected", predicate.get("value"))
    expected_values = expected if isinstance(expected, list) else [expected]
    try:
        normalized_expected: list[int] | list[str] = [int(value) for value in expected_values]
    except (TypeError, ValueError):
        normalized_expected = [str(value)[:80] for value in expected_values]
    if operator not in {"equals", "contains"}:
        status = "unknown"
    elif not observed or not normalized_expected or not all(
        isinstance(value, int) for value in normalized_expected
    ):
        status = "unknown"
    elif operator == "equals":
        status = "matched" if set(observed).issubset(set(normalized_expected)) else "mismatched"
    elif operator == "contains":
        status = "matched" if set(normalized_expected).intersection(observed) else "mismatched"
    else:
        status = "unknown"
    return {
        "id": str(predicate.get("id") or field)[:100],
        "field": field,
        "operator": operator,
        "expected": normalized_expected,
        "observed": observed,
        "status": status,
        "required": bool(predicate.get("required")),
        "source": source,
        "reason": str(predicate.get("reason") or "")[:1000],
    }


def _infer_stun_response_xbits_state(
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    state_operation: dict[str, Any],
) -> bool:
    """Infer only the deployed STUN-response xbit from exact validated alert packets."""
    if (
        str(rule_context.get("sid") or "") != "2016150"
        or rule_context.get("revision") != 4
        or str(rule_context.get("name") or "")
        != "ET INFO Session Traversal Utilities for NAT (STUN Binding Response)"
    ):
        return False
    parsed_rule = rule_context.get("parsed_rule")
    if not isinstance(parsed_rule, dict) or parsed_rule.get("protocol") != "udp":
        return False
    conflicts = rule_context.get("identity_conflicts")
    if isinstance(conflicts, dict) and any(
        conflicts.get(key) for key in ("sid", "revision")
    ):
        return False
    if (
        str(state_operation.get("kind") or "").strip().casefold() != "xbits"
        or str(state_operation.get("operation") or "").strip().casefold() != "isset"
        or str(state_operation.get("name") or "").strip().casefold() != "et.stun"
        or str(state_operation.get("track") or "").strip().casefold() != "track ip_dst"
    ):
        return False
    candidate_packets = int(packet_features.get("candidate_packets") or 0)
    content_packets = int(packet_features.get("content_packets_parsed") or 0)
    stun = packet_features.get("stun")
    if not isinstance(stun, dict):
        return False
    message_types = {
        str(item.get("value") or ""): int(item.get("count") or 0)
        for item in stun.get("message_types", [])
        if isinstance(item, dict)
    }
    return bool(
        candidate_packets > 0
        and candidate_packets == content_packets
        and int(stun.get("packets_parsed") or 0) == candidate_packets
        and message_types.get("binding_success_response") == candidate_packets
        and not int(packet_features.get("parse_errors") or 0)
        and packet_features.get("truncated") is not True
        and packet_features.get("source")
        == "stored-security-onion-alert-packet-copies"
    )


def _validated_stun_rule_semantics(
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
) -> bool:
    """Validate the bounded STUN SID family with the RFC 5389 parser."""
    expected = {
        ("2016149", 4): "binding_request",
        ("2016150", 4): "binding_success_response",
        ("2033078", 5): "binding_request",
    }.get(
        (
            str(rule_context.get("sid") or ""),
            rule_context.get("revision"),
        )
    )
    if not expected:
        return False
    conflicts = rule_context.get("identity_conflicts")
    if isinstance(conflicts, dict) and any(
        conflicts.get(key) for key in ("sid", "revision")
    ):
        return False
    candidate_packets = int(packet_features.get("candidate_packets") or 0)
    stun = packet_features.get("stun")
    if not isinstance(stun, dict):
        return False
    message_types = {
        str(item.get("value") or ""): int(item.get("count") or 0)
        for item in stun.get("message_types", [])
        if isinstance(item, dict)
    }
    return bool(
        candidate_packets > 0
        and int(stun.get("packets_parsed") or 0) == candidate_packets
        and message_types.get(expected) == candidate_packets
        and not int(packet_features.get("parse_errors") or 0)
        and packet_features.get("truncated") is not True
    )


def build_detection_validation(
    rule_context: dict[str, Any],
    packet_features: dict[str, Any],
    playbook: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic rule-intent assessment; never infer maliciousness."""
    predicate_results: list[dict[str, Any]] = []
    parsed_rule = rule_context.get("parsed_rule")
    if isinstance(parsed_rule, dict):
        for item in parsed_rule.get("predicates", []) if isinstance(parsed_rule.get("predicates"), list) else []:
            if isinstance(item, dict):
                predicate_results.append(_evaluate_numeric_predicate(item, packet_features, source="deployed_rule"))
        for index, item in enumerate(
            parsed_rule.get("state_operations", [])
            if isinstance(parsed_rule.get("state_operations"), list)
            else [],
            1,
        ):
            if not isinstance(item, dict):
                continue
            operation = str(item.get("operation") or "").strip().lower()
            if operation not in {"isset", "isnotset"}:
                continue
            inferred_stun_state = _infer_stun_response_xbits_state(
                rule_context,
                packet_features,
                item,
            )
            predicate_results.append(
                {
                    "id": f"deployed-state-{index}",
                    "field": f"{str(item.get('kind') or 'state')}.state",
                    "operator": operation,
                    "expected": "required state is intentionally not disclosed",
                    "observed": (
                        {
                            "state": "inferred_satisfied",
                            "engine_trace_observed": False,
                        }
                        if inferred_stun_state
                        else None
                    ),
                    "status": "matched" if inferred_stun_state else "unknown",
                    "required": True,
                    "source": "deployed_rule",
                    "reason": (
                        "STUN-specific inference from the exact stored Suricata SID 2016150 "
                        "alert and a validated RFC 5389 Binding-success packet; the xbits "
                        "engine state was not independently observed in a rule-engine trace"
                        if inferred_stun_state
                        else "stateful rule precondition requires a trusted Suricata rule-engine trace"
                    ),
                    "provenance": (
                        {
                            "kind": "inference",
                            "basis": [
                                "exact_suricata_alert",
                                "validated_stun_binding_success_packet",
                            ],
                            "engine_trace_observed": False,
                            "scope": "suricata_sid_2016150_only",
                        }
                        if inferred_stun_state
                        else {
                            "kind": "unobserved",
                            "engine_trace_observed": False,
                        }
                    ),
                }
            )
    if isinstance(playbook, dict):
        predicates = playbook.get("required_predicates")
        for item in predicates if isinstance(predicates, list) else []:
            if not isinstance(item, dict):
                continue
            applies = {str(value) for value in item.get("applies_to_sids", [])} if isinstance(item.get("applies_to_sids"), list) else set()
            if applies and str(rule_context.get("sid") or "") not in applies:
                continue
            item = {**item, "required": True}
            predicate_results.append(_evaluate_numeric_predicate(item, packet_features, source="playbook"))
        predicates = playbook.get("supporting_predicates")
        for item in predicates if isinstance(predicates, list) else []:
            if not isinstance(item, dict):
                continue
            applies = {str(value) for value in item.get("applies_to_sids", [])} if isinstance(item.get("applies_to_sids"), list) else set()
            if applies and str(rule_context.get("sid") or "") not in applies:
                continue
            predicate_results.append(_evaluate_numeric_predicate(item, packet_features, source="playbook"))

    marker_lookup = {
        str(item.get("id")): item
        for item in packet_features.get("markers", [])
        if isinstance(item, dict)
    }
    if isinstance(parsed_rule, dict):
        contents = (
            parsed_rule.get("contents")
            if isinstance(parsed_rule.get("contents"), list)
            else []
        )
        for item in contents:
            if not isinstance(item, dict):
                continue
            marker_id = str(item.get("id") or "")
            observation = marker_lookup.get(marker_id, {})
            modifiers = item.get("modifiers") if isinstance(item.get("modifiers"), dict) else {}
            buffer_name = str(item.get("buffer") or "").strip().lower()
            expected_offset_raw = modifiers.get("offset")
            try:
                expected_offset = (
                    int(expected_offset_raw)
                    if expected_offset_raw not in (None, "")
                    else None
                )
            except (TypeError, ValueError):
                expected_offset = None
            observed_count = int(observation.get("observations") or 0)
            expected_count = observation.get("expected_offset_observations")
            constraint_supported = observation.get("constraint_supported") is True
            evaluated = int(observation.get("packets_evaluated_for_constraint") or 0)
            satisfied = int(observation.get("packets_satisfying_constraint") or 0)
            violated = int(observation.get("packets_violating_constraint") or 0)
            content_packets = int(
                packet_features.get("content_packets_parsed")
                or packet_features.get("icmp_packets_parsed")
                or 0
            )
            complete = (
                int(packet_features.get("candidate_packets") or 0) > 0
                and int(packet_features.get("candidate_packets") or 0)
                == content_packets
                and not int(packet_features.get("parse_errors") or 0)
                and packet_features.get("truncated") is not True
            )
            if not content_packets or not constraint_supported:
                status = "unknown"
            elif violated:
                status = "mismatched"
            elif complete and evaluated == content_packets and satisfied == evaluated:
                status = "matched"
            else:
                status = "unknown"
            if buffer_name:
                predicate_field = buffer_name
            elif parsed_rule.get("protocol") == "icmp":
                predicate_field = "icmp.payload_marker"
            elif parsed_rule.get("protocol") == "udp":
                predicate_field = "udp.payload_marker"
            else:
                predicate_field = "packet.payload_marker"
            predicate_results.append(
                {
                    "id": marker_id,
                    "field": predicate_field,
                    "operator": "not_contains" if item.get("negated") else "contains",
                    "expected": {
                        "sha256": observation.get("sha256") or item.get("sha256"),
                        "length": observation.get("length") or item.get("length"),
                        "search_offset": expected_offset,
                        "depth": modifiers.get("depth"),
                        "buffer": buffer_name or None,
                        "dotprefix": bool(modifiers.get("dotprefix")),
                        "bsize": modifiers.get("bsize"),
                        "negated": bool(item.get("negated")),
                    },
                    "observed": {
                        "packets_with_marker": int(observation.get("packets_with_marker") or 0),
                        "observations": observed_count,
                        "offsets": observation.get("offsets") or [],
                        "packets_evaluated_for_constraint": evaluated,
                        "packets_satisfying_constraint": satisfied,
                        "packets_violating_constraint": violated,
                    },
                    "status": status,
                    "required": True,
                    "source": "deployed_rule",
                    "reason": (
                        "unsupported sticky-buffer, transform, or buffer-size "
                        "evaluation requires a trusted Suricata rule-engine trace"
                        if not constraint_supported
                        else (
                            "supported application sticky-buffer evidence was "
                            "not present in the supplied alert projection"
                            if buffer_name and not evaluated
                            else "deployed rule content predicate"
                        )
                    ),
                }
            )
    if isinstance(playbook, dict):
        predicates = playbook.get("marker_predicates")
        for item in predicates if isinstance(predicates, list) else []:
            if not isinstance(item, dict):
                continue
            applies = {str(value) for value in item.get("applies_to_sids", [])} if isinstance(item.get("applies_to_sids"), list) else set()
            if applies and str(rule_context.get("sid") or "") not in applies:
                continue
            marker_id = str(item.get("id") or "")
            observation = marker_lookup.get(marker_id, {})
            expected_offset = item.get("expected_offset")
            observed_count = int(observation.get("observations") or 0)
            expected_count = observation.get("expected_offset_observations")
            if not packet_features.get("icmp_packets_parsed"):
                status = "unknown"
            elif expected_offset is not None:
                if int(expected_count or 0) > 0:
                    status = "matched"
                elif int(packet_features.get("parse_errors") or 0) or packet_features.get("truncated") is True:
                    status = "unknown"
                else:
                    status = "mismatched"
            else:
                if observed_count > 0:
                    status = "matched"
                elif int(packet_features.get("parse_errors") or 0) or packet_features.get("truncated") is True:
                    status = "unknown"
                else:
                    status = "mismatched"
            predicate_results.append({
                "id": marker_id,
                "field": "icmp.payload_marker",
                "operator": "at_offset" if expected_offset is not None else "contains",
                "expected": {
                    "sha256": observation.get("sha256"),
                    "length": observation.get("length"),
                    "offset": expected_offset,
                },
                "observed": {
                    "packets_with_marker": int(observation.get("packets_with_marker") or 0),
                    "observations": observed_count,
                    "expected_offset_observations": expected_count,
                    "offsets": observation.get("offsets") or [],
                },
                "status": status,
                "required": bool(item.get("required")),
                "source": "playbook",
                "reason": str(item.get("reason") or "")[:1000],
            })

    if isinstance(parsed_rule, dict):
        for index, item in enumerate(
            parsed_rule.get("unsupported_match_options", [])
            if isinstance(parsed_rule.get("unsupported_match_options"), list)
            else [],
            1,
        ):
            if not isinstance(item, dict):
                continue
            predicate_results.append(
                {
                    "id": f"deployed-unsupported-{index}",
                    "field": f"suricata.{str(item.get('option') or 'unknown')}",
                    "operator": "unsupported",
                    "expected": {"value_sha256": item.get("value_sha256")},
                    "observed": None,
                    "status": "unknown",
                    "required": True,
                    "source": "deployed_rule",
                    "reason": "installed rule constraint is outside the deterministic validator's supported subset",
                }
            )

    required = [item for item in predicate_results if item.get("required")]
    identity_conflicts = rule_context.get("identity_conflicts")
    identity_conflict = bool(
        isinstance(identity_conflicts, dict)
        and any(identity_conflicts.get(key) for key in ("sid", "revision"))
    )
    if identity_conflict:
        intent_match = "unknown"
    elif any(item.get("status") == "mismatched" for item in required):
        intent_match = "mismatch"
    elif required and (
        all(item.get("status") == "matched" for item in required)
        or (
            _validated_stun_rule_semantics(
                rule_context,
                packet_features,
            )
            and all(
                item.get("status") == "matched"
                or str(item.get("field") or "") == "udp.payload_marker"
                for item in required
            )
        )
    ):
        intent_match = "match"
    else:
        intent_match = "unknown"
    installed_fields = {
        str(item.get("field")) for item in predicate_results
        if item.get("source") == "deployed_rule"
    }
    playbook_required_fields = {
        str(item.get("field")) for item in required if item.get("source") == "playbook"
    }
    missing_installed_constraints = sorted(playbook_required_fields.difference(installed_fields))
    event_status = "observed" if packet_features.get("packets_parsed") else "unknown"
    return {
        "schema": VALIDATION_SCHEMA,
        "event_status": event_status,
        "event_observed": True if event_status == "observed" else None,
        "rule_intent_match": intent_match,
        "rule_intent_basis": (
            "validated_rfc5389_stun_semantics"
            if _validated_stun_rule_semantics(
                rule_context,
                packet_features,
            )
            else "deployed_rule_predicates"
        ),
        "rule": {
            "sid": rule_context.get("sid"),
            "revision": rule_context.get("revision"),
            "name": rule_context.get("name"),
            "ruleset": rule_context.get("ruleset"),
            "rule_sha256": (
                parsed_rule.get("rule_sha256")
                if isinstance(parsed_rule, dict)
                else ""
            ),
            "identity_status": "conflict" if identity_conflict else "consistent",
            "identity_conflicts": identity_conflicts if identity_conflict else {},
        },
        "playbook": {
            "id": playbook.get("id"),
            "version": playbook.get("version"),
            "status": playbook.get("status"),
            "intent": playbook.get("intent"),
            "known_false_positive_risk": playbook.get("known_false_positive_risk"),
            "references": playbook.get("references") or [],
        } if isinstance(playbook, dict) else None,
        "predicate_results": predicate_results,
        "rule_drift": {
            "detected": bool(missing_installed_constraints),
            "missing_installed_constraints": missing_installed_constraints,
        },
        "packet_features": packet_features,
        "confidence_limiters": (
            list(playbook.get("confidence_limiters") or [])
            if isinstance(playbook, dict) and isinstance(playbook.get("confidence_limiters"), list)
            else []
        ),
        "interpretation": (
            "The observed packets violate one or more required threat-behavior predicates."
            if intent_match == "mismatch"
            else "The required threat-behavior predicates matched the supplied packet evidence."
            if intent_match == "match"
            else "The supplied evidence cannot deterministically establish the detection intent."
        ),
    }
