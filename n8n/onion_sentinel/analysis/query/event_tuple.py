"""Normalization and provenance-safe projection of investigation event tuples."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Any, Callable, Type

from . import primitives


FIELDS = (
    "source_ip", "destination_ip", "source_port", "destination_port",
    "transport", "protocol", "community_id", "rule_id",
)
IP_FIELDS = frozenset({"source_ip", "destination_ip"})
PORT_FIELDS = frozenset({"source_port", "destination_port"})
PROTOCOL_FIELDS = frozenset({"transport", "protocol"})
SAFE_ATOM_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,255}$")
SAFE_COMMUNITY_ID_RE = re.compile(r"^[A-Za-z0-9_:+/=-]{1,256}$")


@dataclass(frozen=True)
class Dependencies:
    canonical_digest: Callable[[object], str]
    pack_fields: Callable[[str], object]
    match_semantics: Callable[[str, dict[str, Any], str], str]


def _ip(raw: Any, field: str, error_type: Type[Exception]) -> str:
    try:
        return str(ipaddress.ip_address(str(raw).strip()))
    except ValueError as exc:
        raise error_type(f"elastic/oql event_tuple {field} is invalid") from exc


def _port(raw: Any, field: str, error_type: Type[Exception]) -> int:
    if isinstance(raw, bool):
        raise error_type(f"elastic/oql event_tuple {field} is invalid")
    try:
        port = int(raw)
    except (TypeError, ValueError) as exc:
        raise error_type(f"elastic/oql event_tuple {field} is invalid") from exc
    if port < 0 or port > 65535:
        raise error_type(
            f"elastic/oql event_tuple {field} is outside the port range"
        )
    return port


def _atom(raw: Any, field: str, error_type: Type[Exception]) -> str:
    text = primitives.text(raw, 255)
    if field in PROTOCOL_FIELDS:
        text = text.lower()
    if not SAFE_ATOM_RE.fullmatch(text):
        raise error_type(f"elastic/oql event_tuple {field} is invalid")
    return text


def _community_id(raw: Any, _field: str, error_type: Type[Exception]) -> str:
    text = primitives.text(raw, 256)
    if not SAFE_COMMUNITY_ID_RE.fullmatch(text):
        raise error_type("elastic/oql event_tuple community_id is invalid")
    return text


def _normalizer(field: str) -> Callable[[Any, str, Type[Exception]], Any]:
    if field in IP_FIELDS:
        return _ip
    if field in PORT_FIELDS:
        return _port
    if field == "community_id":
        return _community_id
    return _atom


def normalize(
    value: Any, *, error_type: Type[Exception] = ValueError,
) -> dict[str, Any]:
    """Validate and canonicalize the public, role-aware tuple shape."""
    if not isinstance(value, dict) or not value:
        raise error_type("elastic/oql event_tuple must be a non-empty object")
    unknown = set(value).difference(FIELDS)
    if unknown:
        raise error_type(
            "elastic/oql event_tuple contains unsupported fields: "
            + ", ".join(sorted(unknown))
        )
    clean: dict[str, Any] = {}
    for field in FIELDS:
        if field not in value:
            continue
        clean[field] = _normalizer(field)(value[field], field, error_type)
    return clean


def _candidate(
    entry: Any, requested: dict[str, Any], dependencies: Dependencies,
    error_type: Type[Exception],
) -> tuple[str, str, dict[str, Any], dict[str, Any]] | None:
    if not isinstance(entry, dict):
        return None
    try:
        trusted = normalize(entry.get("event_tuple"), error_type=error_type)
    except error_type:
        return None
    if not all(trusted.get(field) == value for field, value in requested.items()):
        return None
    provenance = {
        "role_semantics": primitives.text(entry.get("role_semantics"), 80),
        "source": primitives.text(entry.get("source"), 80),
        "evidence_ref": primitives.text(entry.get("evidence_ref"), 255),
    }
    return (
        dependencies.canonical_digest(entry),
        dependencies.canonical_digest({
            "event_tuple": trusted,
            "role_semantics": provenance["role_semantics"],
        }),
        trusted,
        provenance,
    )


def _select_candidate(
    permitted: list[Any], requested: dict[str, Any],
    dependencies: Dependencies, error_type: Type[Exception],
) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
    candidates = [
        candidate for entry in permitted
        if (candidate := _candidate(entry, requested, dependencies, error_type))
        is not None
    ]
    if not candidates:
        raise error_type("event_tuple does not match one trusted role-aware tuple")
    return min(candidates, key=lambda item: item[0])


def _project_fields(
    requested: dict[str, Any], trusted: dict[str, Any], pack: str,
    dependencies: Dependencies, error_type: Type[Exception],
) -> dict[str, Any]:
    allowed = set(dependencies.pack_fields(pack))
    projected = {key: value for key, value in requested.items() if key in allowed}
    if not projected:
        raise error_type(f"event_tuple has no fields authenticated by pack {pack}")
    if IP_FIELDS.intersection(trusted) and not IP_FIELDS.intersection(projected):
        raise error_type(
            f"event_tuple projection for pack {pack} must retain a trusted "
            "source or destination IP role"
        )
    return projected


def _audit(
    requested: dict[str, Any], projected: dict[str, Any], pack: str,
    provenance_digest: str, tuple_digest: str, provenance: dict[str, Any],
    dependencies: Dependencies,
) -> dict[str, Any]:
    requested_fields = sorted(requested)
    executed_fields = sorted(projected)
    role_semantics = provenance["role_semantics"]
    result: dict[str, Any] = {
        "schema": "onion-sentinel-event-tuple-projection-v1",
        "pack": pack,
        "provenance_verified": True,
        "projection_applied": requested_fields != executed_fields,
        "requested_fields": requested_fields,
        "executed_fields": executed_fields,
        "dropped_pack_unavailable_fields": sorted(
            set(requested_fields).difference(executed_fields)
        ),
        "trusted_tuple_digest": tuple_digest,
        "trusted_provenance_digest": provenance_digest,
        "role_semantics": role_semantics,
        "match_semantics": dependencies.match_semantics(
            pack, projected, role_semantics
        ),
    }
    for source, target in (
        ("source", "trusted_source"),
        ("evidence_ref", "trusted_evidence_ref"),
    ):
        if provenance[source]:
            result[target] = provenance[source]
    return result


def project(
    value: Any, *, pack: str, authorization_context: Any = None,
    dependencies: Dependencies, error_type: Type[Exception] = ValueError,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Project a tuple onto pack-authenticated fields after provenance proof."""
    requested = normalize(value, error_type=error_type)
    if authorization_context is None:
        return requested, None
    if not isinstance(authorization_context, dict):
        raise error_type("trusted investigation authorization context is invalid")
    permitted = authorization_context.get("permitted_event_tuples")
    if not isinstance(permitted, list) or not permitted:
        raise error_type(
            "event_tuple projection requires trusted role-aware tuple provenance"
        )

    provenance_digest, tuple_digest, trusted_tuple, provenance = _select_candidate(
        permitted, requested, dependencies, error_type
    )
    projected = _project_fields(
        requested, trusted_tuple, pack, dependencies, error_type
    )
    return projected, _audit(
        requested, projected, pack, provenance_digest, tuple_digest,
        provenance, dependencies,
    )
