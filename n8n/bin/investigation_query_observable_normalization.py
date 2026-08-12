"""Exact observable normalization and pack projection policy."""
from __future__ import annotations

from investigation_query_schema import *  # noqa: F401,F403
from investigation_query_normalization_primitives import _require_mapping


def _normalize_observable(kind: str, value: object) -> str:
    text = str(value or "").strip().rstrip(".")
    if kind == "ips":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError as exc:
            raise InvestigationQueryContractError("invalid exact IP observable") from exc
    if kind == "domains":
        if not SAFE_DOMAIN_RE.fullmatch(text):
            raise InvestigationQueryContractError("invalid exact domain observable")
        return text.lower()
    if kind in {"hosts", "users"} and SAFE_ATOM_RE.fullmatch(text):
        return text
    raise InvestigationQueryContractError(f"invalid exact {kind} observable")


def _normalize_observables(
    value: object,
    *,
    per_kind_limit: int,
    total_limit: int,
    require_one: bool,
    label: str,
) -> dict[str, list[str]]:
    data = _require_mapping(value, label)
    if set(data) - set(OBSERVABLE_KINDS):
        raise InvestigationQueryContractError(f"{label} contains an unsupported kind")
    normalized = {
        kind: _normalized_kind_items(
            kind,
            data.get(kind, []),
            per_kind_limit=per_kind_limit,
            label=label,
        )
        for kind in OBSERVABLE_KINDS
    }
    count = sum(len(items) for items in normalized.values())
    if require_one and count == 0:
        raise InvestigationQueryContractError(f"{label} requires an exact observable")
    if count > total_limit:
        raise InvestigationQueryContractError(
            f"{label} exceeds its {total_limit}-value total limit"
        )
    return normalized


def _normalized_kind_items(
    kind: str,
    items: object,
    *,
    per_kind_limit: int,
    label: str,
) -> list[str]:
    if not isinstance(items, list) or len(items) > per_kind_limit:
        raise InvestigationQueryContractError(
            f"{label}.{kind} exceeds its {per_kind_limit}-value limit"
        )
    clean: list[str] = []
    for item in items:
        candidate = _normalize_observable(kind, item)
        if candidate not in clean:
            clean.append(candidate)
    return clean


def pack_observable_fields(pack_name: str) -> dict[str, list[str]]:
    """Return only observable paths that the reviewed pack also projects."""
    projected = set(PACKS[pack_name]["fields"])
    return {
        kind: [field for field in fields if field in projected]
        for kind, fields in OBSERVABLE_FIELDS.items()
    }


def validate_pack_observables(
    observables: dict[str, list[str]],
    pack_name: str,
    *,
    label: str,
) -> None:
    """Reject values that the selected pack cannot possibly represent."""
    fields_by_kind = pack_observable_fields(pack_name)
    unsupported = sorted(
        kind
        for kind, values in observables.items()
        if values and not fields_by_kind.get(kind)
    )
    if unsupported:
        raise InvestigationQueryContractError(
            f"{label} uses observable kind(s) unsupported by pack "
            f"{pack_name}: {', '.join(unsupported)}"
        )
    if not any(
        values and fields_by_kind.get(kind)
        for kind, values in observables.items()
    ):
        raise InvestigationQueryContractError(
            f"{label} has no queryable observable in pack {pack_name}"
        )
