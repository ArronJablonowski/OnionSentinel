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
    for raw_option in options:
        key, separator, raw_value = raw_option.partition(":")
        normalized_key = key.strip().lower()
        value = raw_value.strip() if separator else ""
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
                "modifiers": {},
            }
            contents.append(current_content)
            continue
        if normalized_key in {
            "offset", "depth", "distance", "within", "startswith", "endswith",
            "nocase", "rawbytes",
        } and current_content is not None:
            current_content["modifiers"][normalized_key] = value if separator else True
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
            "icode", "icmp_id", "icmp_seq",
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


def _bounded_counter(counter: collections.Counter[int]) -> list[dict[str, int]]:
    return [
        {"value": int(value), "count": int(count)}
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
    modifiers = spec.get("modifiers") if isinstance(spec.get("modifiers"), dict) else {}
    if any(key in modifiers for key in ("distance", "within", "rawbytes")):
        return None
    offset = 0
    if "offset" in modifiers:
        offset = _nonnegative_modifier(modifiers.get("offset"))
        if offset is None:
            return None
    depth: int | None = None
    if "depth" in modifiers:
        depth = _nonnegative_modifier(modifiers.get("depth"))
        if depth is None:
            return None
    if offset > len(payload):
        present = False
    else:
        end = len(payload) if depth is None else min(len(payload), offset + depth)
        haystack = payload.lower() if "nocase" in modifiers else payload
        needle = marker.lower() if "nocase" in modifiers else marker
        if "startswith" in modifiers:
            present = offset == 0 and haystack.startswith(needle)
        elif "endswith" in modifiers:
            position = len(haystack) - len(needle)
            present = (
                position >= offset
                and position + len(needle) <= end
                and haystack.endswith(needle)
            )
        else:
            present = haystack.find(needle, offset, end) >= 0
    return not present if bool(spec.get("negated")) else present


def extract_group_packet_features(
    grouped_rows: Iterable[object],
    markers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Decode stored packet copies and return raw-payload-free ICMP semantics."""
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
    packet_count = 0
    candidate_count = 0
    parse_errors = 0
    truncated = False
    for row in grouped_rows:
        if candidate_count >= MAX_GROUP_PACKETS:
            truncated = True
            break
        raw = _json_object(_row_value(row, "raw_event_json"))
        alert = _json_object(_row_value(row, "alert_json"))
        if not raw:
            raw = _json_object(_nested(alert, "security_onion.raw_event"))
        message = _json_object(raw.get("message"))
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
        parsed = _icmp_from_packet(packet, linktype)
        if not parsed:
            parse_errors += 1
            continue
        packet_count += 1
        payload = parsed.pop("_payload")
        type_counts[parsed["type"]] += 1
        code_counts[parsed["code"]] += 1
        identifiers[parsed["identifier"]] += 1
        sequences[parsed["sequence"]] += 1
        payload_lengths[len(payload)] += 1
        frame_lengths[parsed["frame_bytes"]] += 1
        entropies.append(_entropy(payload))
        for spec, marker in marker_values:
            marker_id = str(spec["id"])
            constraint = _content_constraint(payload, marker, spec)
            if constraint is None:
                marker_constraint_unsupported.add(marker_id)
            else:
                marker_constraint_evaluated[marker_id] += 1
                if constraint:
                    marker_constraint_satisfied[marker_id] += 1
                else:
                    marker_constraint_violated[marker_id] += 1
            start = 0
            matches = 0
            while matches < MAX_MARKER_MATCHES_PER_PACKET:
                position = payload.find(marker, start)
                if position < 0:
                    break
                marker_offsets[marker_id][position] += 1
                matches += 1
                start = position + 1
            if matches:
                marker_packets[marker_id] += 1
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
            "constraint_supported": marker_id not in marker_constraint_unsupported,
            "packets_evaluated_for_constraint": int(marker_constraint_evaluated[marker_id]),
            "packets_satisfying_constraint": int(marker_constraint_satisfied[marker_id]),
            "packets_violating_constraint": int(marker_constraint_violated[marker_id]),
        })
    return {
        "source": "stored-security-onion-alert-packet-copies",
        "raw_payloads_included": False,
        "candidate_packets": candidate_count,
        "icmp_packets_parsed": packet_count,
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
            predicate_results.append(
                {
                    "id": f"deployed-state-{index}",
                    "field": f"{str(item.get('kind') or 'state')}.state",
                    "operator": operation,
                    "expected": "required state is intentionally not disclosed",
                    "observed": None,
                    "status": "unknown",
                    "required": True,
                    "source": "deployed_rule",
                    "reason": "stateful rule precondition requires a trusted Suricata rule-engine trace",
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
            complete = (
                int(packet_features.get("candidate_packets") or 0) > 0
                and int(packet_features.get("candidate_packets") or 0)
                == int(packet_features.get("icmp_packets_parsed") or 0)
                and not int(packet_features.get("parse_errors") or 0)
                and packet_features.get("truncated") is not True
            )
            if not packet_features.get("icmp_packets_parsed") or not constraint_supported:
                status = "unknown"
            elif violated:
                status = "mismatched"
            elif complete and evaluated == int(packet_features.get("icmp_packets_parsed") or 0) and satisfied == evaluated:
                status = "matched"
            else:
                status = "unknown"
            predicate_results.append(
                {
                    "id": marker_id,
                    "field": "icmp.payload_marker",
                    "operator": "not_contains" if item.get("negated") else "contains",
                    "expected": {
                        "sha256": observation.get("sha256") or item.get("sha256"),
                        "length": observation.get("length") or item.get("length"),
                        "search_offset": expected_offset,
                        "depth": modifiers.get("depth"),
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
                        "unsupported content modifiers require a trusted Suricata rule-engine trace"
                        if not constraint_supported
                        else "deployed rule content predicate"
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
    elif required and all(item.get("status") == "matched" for item in required):
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
    event_status = "observed" if packet_features.get("icmp_packets_parsed") else "unknown"
    return {
        "schema": VALIDATION_SCHEMA,
        "event_status": event_status,
        "event_observed": True if event_status == "observed" else None,
        "rule_intent_match": intent_match,
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
