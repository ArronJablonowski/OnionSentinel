"""Provider-neutral normalization for governed Security Onion queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Type

from . import primitives


OBSERVABLE_KINDS = ("ips", "domains", "hosts", "users")


@dataclass(frozen=True)
class Policy:
    purposes: frozenset[str]
    packs: frozenset[str]
    aggregations: frozenset[str]
    maximum_values_per_kind: int = 8
    maximum_total_observables: int = 8


@dataclass(frozen=True)
class Dependencies:
    normalize_window: Callable[[Any, Any], tuple[dict[str, str], dict[str, Any]]]
    project_event_tuple: Callable[
        [Any, str, Any], tuple[dict[str, Any], dict[str, Any] | None]
    ]
    positive_integer: Callable[[Any, int, int, str], int]


def _choice(
    value: Any, *, label: str, choices: frozenset[str],
    error_type: Type[Exception], default: str = "",
) -> str:
    selected = primitives.text(value or default, 64).lower()
    if selected not in choices:
        raise error_type(f"unsupported investigation {label}: {selected or 'missing'}")
    return selected


def _observables(
    value: Any, policy: Policy, error_type: Type[Exception],
) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise error_type("elastic/oql observables must be an object")
    if set(value).difference(OBSERVABLE_KINDS):
        raise error_type("elastic/oql observables contain unsupported categories")
    normalized: dict[str, list[str]] = {}
    for kind in OBSERVABLE_KINDS:
        values = value.get(kind, [])
        if not isinstance(values, list) or len(values) > policy.maximum_values_per_kind:
            raise error_type(
                f"elastic/oql observable {kind} must be an array of at most "
                f"{policy.maximum_values_per_kind} values"
            )
        normalized[kind] = [
            text for item in values
            if (text := primitives.text(item, 255))
        ]
    if not any(normalized.values()):
        raise error_type("elastic/oql request needs at least one exact observable")
    if sum(map(len, normalized.values())) > policy.maximum_total_observables:
        raise error_type(
            "elastic/oql request may use at most "
            f"{policy.maximum_total_observables} total observables"
        )
    return normalized


def normalize(
    parameters: dict[str, Any], *, purpose: str, backend: str,
    time_envelope: Any, authorization_context: Any, policy: Policy,
    dependencies: Dependencies, error_type: Type[Exception] = ValueError,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Normalize one Elastic/OQL proposal without accepting executable syntax."""
    if purpose not in policy.purposes:
        raise error_type(
            "elastic/oql purpose must be one of: "
            + ", ".join(sorted(policy.purposes))
        )
    pack = _choice(
        parameters.get("pack"), label="pack", choices=policy.packs,
        error_type=error_type,
    )
    aggregation = _choice(
        parameters.get("aggregation"), label="aggregation",
        choices=policy.aggregations, error_type=error_type, default="events",
    )
    if aggregation == "anchor_nearest" and backend != "elastic":
        raise error_type(
            "anchor_nearest is available only through compiled Elastic DSL"
        )
    window, window_audit = dependencies.normalize_window(
        parameters.get("window"), time_envelope
    )
    result: dict[str, Any] = {
        "pack": pack,
        "window": window,
        "observables": _observables(
            parameters.get("observables"), policy, error_type
        ),
        "size": dependencies.positive_integer(
            parameters.get("size"), 25, 100, "query size"
        ),
        "aggregation": aggregation,
    }
    normalization: dict[str, Any] = {}
    if window_audit["adjusted"]:
        normalization["window_adjustment"] = window_audit
    if "event_tuple" in parameters:
        projected, audit = dependencies.project_event_tuple(
            parameters["event_tuple"], pack, authorization_context
        )
        result["event_tuple"] = projected
        if audit is not None:
            normalization["event_tuple_projection"] = audit
    return result, normalization
