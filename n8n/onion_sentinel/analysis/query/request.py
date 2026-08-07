"""Common envelope and routing contract for investigation query requests."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable, Mapping, Pattern, Type

from . import primitives


@dataclass(frozen=True)
class Policy:
    backends: frozenset[str]
    parameter_keys: Mapping[str, frozenset[str]]
    query_id_pattern: Pattern[str] = re.compile(
        r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
    )

    @property
    def parameter_union(self) -> frozenset[str]:
        return frozenset().union(*self.parameter_keys.values())


@dataclass(frozen=True)
class Dependencies:
    normalize_parameters: Callable[
        [str, dict[str, Any], str, Any, Any],
        tuple[dict[str, Any], dict[str, Any]],
    ]


def project_parameters(
    backend: str, parameters: dict[str, Any], *, policy: Policy,
    error_type: Type[Exception] = ValueError,
) -> tuple[dict[str, Any], list[str]]:
    """Project a union-shaped model object onto one exact backend schema."""
    allowed = policy.parameter_keys[backend]
    unknown = set(parameters).difference(policy.parameter_union)
    if unknown:
        raise error_type(
            f"unsupported {backend} parameters: "
            + ", ".join(sorted(unknown))
        )
    dropped = sorted(set(parameters).difference(allowed))
    return (
        {key: parameters[key] for key in allowed if key in parameters},
        dropped,
    )


def _identity(
    raw: dict[str, Any], round_number: int, position: int, policy: Policy,
    error_type: Type[Exception],
) -> tuple[str, str, str]:
    backend = primitives.text(raw.get("backend"), 32).lower()
    if backend not in policy.backends:
        raise error_type(
            f"unsupported investigation query backend: {backend or 'missing'}"
        )
    purpose = primitives.text(raw.get("purpose"), 500)
    if not purpose:
        raise error_type("investigation query purpose is required")
    query_id = primitives.text(raw.get("query_id"), 64)
    if not policy.query_id_pattern.fullmatch(query_id):
        query_id = f"round-{round_number}-query-{position}"
    return query_id, backend, purpose


def normalize(
    raw: Any, *, round_number: int, position: int, time_envelope: Any,
    authorization_context: Any, policy: Policy, dependencies: Dependencies,
    error_type: Type[Exception] = ValueError,
) -> dict[str, Any]:
    """Normalize a model proposal without accepting executable provider syntax."""
    if not isinstance(raw, dict):
        raise error_type("each investigation query must be an object")
    unknown = set(raw).difference({"query_id", "backend", "purpose", "parameters"})
    if unknown:
        raise error_type(
            "unsupported investigation query fields: "
            + ", ".join(sorted(unknown))
        )
    query_id, backend, purpose = _identity(
        raw, round_number, position, policy, error_type
    )
    parameters = raw.get("parameters")
    if not isinstance(parameters, dict):
        raise error_type("investigation query parameters must be an object")
    parameters, dropped = project_parameters(
        backend, parameters, policy=policy, error_type=error_type
    )
    normalized_parameters, normalization = dependencies.normalize_parameters(
        backend, parameters, purpose, time_envelope, authorization_context
    )
    if dropped:
        normalization["dropped_cross_backend_parameters"] = dropped
    result = {
        "query_id": query_id,
        "backend": backend,
        "purpose": purpose,
        "parameters": normalized_parameters,
    }
    if normalization:
        result["normalization"] = normalization
    return result
