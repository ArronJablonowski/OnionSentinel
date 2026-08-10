"""Versioned detection playbooks and deterministic policy evaluation."""
from __future__ import annotations

from detection_validation_rule import *  # noqa: F401,F403
from detection_validation_packet import *  # noqa: F401,F403
from detection_validation_features import *  # noqa: F401,F403
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
