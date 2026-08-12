"""Bounded Suricata option, content, and state-operation parsing."""

from __future__ import annotations

from typing import Any

from detection_validation_rule_contract import (
    APPLICATION_STICKY_BUFFERS,
    MAX_MARKERS,
    REV_RE,
    SID_RE,
    collections,
    hashlib,
    re,
)


_CONTENT_MODIFIERS = {
    "offset",
    "depth",
    "distance",
    "within",
    "startswith",
    "endswith",
    "nocase",
    "rawbytes",
}
_METADATA_OPTIONS = {
    "msg",
    "sid",
    "rev",
    "gid",
    "reference",
    "url",
    "classtype",
    "metadata",
    "target",
    "tag",
    "noalert",
    "priority",
    "itype",
    "icode",
    "icmp_id",
    "icmp_seq",
    "flow",
    "threshold",
}


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
            for token in text[index + 1 : end].split():
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


def _new_state() -> dict[str, Any]:
    return {
        "scalar_options": collections.defaultdict(list),
        "contents": [],
        "state_operations": [],
        "unsupported_match_options": [],
        "current_content": None,
        "current_buffer": "",
        "current_buffer_modifiers": {},
    }


def _normalized_option(raw_option: str) -> tuple[str, str, str]:
    key, separator, raw_value = raw_option.partition(":")
    normalized_key = key.strip().lower()
    value = raw_value.strip() if separator else ""
    return normalized_key, value, separator


def _reset_buffer(state: dict[str, Any], buffer_name: str) -> None:
    state["current_buffer"] = buffer_name
    state["current_buffer_modifiers"] = {}
    state["current_content"] = None


def _consume_buffer_option(state: dict[str, Any], normalized_key: str) -> bool:
    normalized_buffer = "dns.query" if normalized_key == "dns_query" else normalized_key
    if normalized_buffer in APPLICATION_STICKY_BUFFERS:
        _reset_buffer(state, normalized_buffer)
        return True
    if normalized_key == "pkt_data":
        _reset_buffer(state, "")
        return True
    return False


def _append_content(state: dict[str, Any], value: str) -> None:
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
        "modifiers": dict(state["current_buffer_modifiers"]),
        "buffer": state["current_buffer"],
    }
    state["contents"].append(current_content)
    state["current_content"] = current_content


def _consume_modifier(
    state: dict[str, Any],
    normalized_key: str,
    value: str,
    separator: str,
) -> bool:
    current_content = state["current_content"]
    if normalized_key in {"dotprefix", "bsize"}:
        modifier_value: object = value if separator else True
        state["current_buffer_modifiers"][normalized_key] = modifier_value
        if current_content is not None:
            current_content["modifiers"][normalized_key] = modifier_value
        return True
    if normalized_key in _CONTENT_MODIFIERS and current_content is not None:
        current_content["modifiers"][normalized_key] = value if separator else True
        return True
    return normalized_key == "fast_pattern"


def _append_state_operation(state: dict[str, Any], kind: str, value: str) -> None:
    parts = [part.strip() for part in value.split(",")]
    state["state_operations"].append(
        {
            "kind": kind,
            "operation": parts[0] if parts else "",
            "name": parts[1] if len(parts) > 1 else "",
            "track": ",".join(parts[2:]) if len(parts) > 2 else "",
        }
    )


def _record_scalar_option(state: dict[str, Any], key: str, value: str) -> None:
    state["scalar_options"][key].append(value)
    if key not in _METADATA_OPTIONS:
        state["unsupported_match_options"].append(
            {
                "option": key[:80],
                "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
            }
        )


def _apply_rule_option(state: dict[str, Any], raw_option: str) -> None:
    normalized_key, value, separator = _normalized_option(raw_option)
    if _consume_buffer_option(state, normalized_key):
        return
    if normalized_key == "content":
        _append_content(state, value)
        return
    if _consume_modifier(state, normalized_key, value, separator):
        return
    state["current_content"] = None
    if normalized_key in {"xbits", "flowbits"}:
        _append_state_operation(state, normalized_key, value)
        return
    _record_scalar_option(state, normalized_key, value)


def _numeric_predicate(
    scalar_options: dict[str, list[str]], name: str
) -> tuple[str, int | str] | None:
    values = scalar_options.get(name) or []
    if not values:
        return None
    value = values[0].strip()
    if re.fullmatch(r"-?\d+", value):
        return "equals", int(value)
    return "unsupported_expression", value[:80]


def _rule_predicates(scalar_options: dict[str, list[str]]) -> list[dict[str, Any]]:
    predicates = []
    for field, option_name in (
        ("icmp.type", "itype"),
        ("icmp.code", "icode"),
        ("icmp.identifier", "icmp_id"),
        ("icmp.sequence", "icmp_seq"),
    ):
        parsed_numeric = _numeric_predicate(scalar_options, option_name)
        if parsed_numeric is not None:
            operator, expected = parsed_numeric
            predicates.append(
                {
                    "field": field,
                    "operator": operator,
                    "expected": expected,
                    "required": True,
                    "source": "deployed_rule",
                }
            )
    return predicates


def _public_contents(contents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": f"deployed-content-{index}",
            "sha256": item["sha256"],
            "length": item["length"],
            "printable": item["printable"],
            "hex": item["_bytes_hex"],
            "negated": item["negated"],
            "modifiers": item["modifiers"],
            "buffer": item["buffer"],
        }
        for index, item in enumerate(contents[:MAX_MARKERS], 1)
    ]


def _unavailable_rule(text: str) -> dict[str, Any]:
    return {
        "available": False,
        "rule_sha256": hashlib.sha256(text.encode()).hexdigest() if text else "",
        "predicates": [],
        "contents": [],
        "state_operations": [],
    }


def parse_suricata_rule(rule_text: object) -> dict[str, Any]:
    """Parse bounded, decision-relevant Suricata rule predicates."""
    text = str(rule_text or "").strip()
    if not text or "(" not in text or ")" not in text:
        return _unavailable_rule(text)
    header, option_text = text.split("(", 1)
    option_text = option_text.rsplit(")", 1)[0]
    header_parts = header.split()
    protocol = header_parts[1].lower() if len(header_parts) > 1 else ""
    state = _new_state()
    for raw_option in _split_rule_options(option_text):
        _apply_rule_option(state, raw_option)
    sid_match = SID_RE.search(";" + option_text + ";")
    rev_match = REV_RE.search(";" + option_text + ";")
    return {
        "available": True,
        "protocol": protocol,
        "sid": sid_match.group(1) if sid_match else "",
        "revision": int(rev_match.group(1)) if rev_match else None,
        "rule_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "predicates": _rule_predicates(state["scalar_options"]),
        "contents": _public_contents(state["contents"]),
        "state_operations": state["state_operations"],
        "unsupported_match_options": state["unsupported_match_options"][:64],
    }
