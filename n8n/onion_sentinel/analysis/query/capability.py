"""Trusted local prerequisites for advertised investigation backends."""

from __future__ import annotations

from typing import Any, Callable


BackendCheck = Callable[[dict[str, Any], dict[str, Any] | None], bool]


def _advertised_descriptor(
    prompt_package: dict[str, Any], backend: str,
) -> dict[str, Any] | None:
    capability = prompt_package.get("investigation_query_capability")
    if not isinstance(capability, dict) or capability.get("enabled") is not True:
        return None
    backends = capability.get("backends")
    descriptor = backends.get(backend) if isinstance(backends, dict) else None
    if not isinstance(descriptor, dict) or descriptor.get("enabled") is not True:
        return None
    return descriptor


def _security_onion_ready(
    prompt_package: dict[str, Any], _config: dict[str, Any] | None,
) -> bool:
    local_context = prompt_package.get("_local_investigation_query_context")
    return bool(
        isinstance(local_context, dict)
        and isinstance(local_context.get("anchor"), dict)
    )


def _pcap_ready(
    prompt_package: dict[str, Any], _config: dict[str, Any] | None,
) -> bool:
    evidence = prompt_package.get("pcap_evidence")
    return bool(
        isinstance(evidence, dict)
        and isinstance(evidence.get("parsed_evidence"), list)
        and evidence.get("parsed_evidence")
    )


def _osquery_ready(
    _prompt_package: dict[str, Any], config: dict[str, Any] | None,
) -> bool:
    return bool(config and config.get("enabled"))


def _advertisement_is_sufficient(
    _prompt_package: dict[str, Any], _config: dict[str, Any] | None,
) -> bool:
    return True


_BACKEND_CHECKS: dict[str, BackendCheck] = {
    "elastic": _security_onion_ready,
    "oql": _security_onion_ready,
    "pcap_zeek": _pcap_ready,
    "osquery": _osquery_ready,
    "enrichment": _advertisement_is_sufficient,
}


def available(
    prompt_package: dict[str, Any], backend: str, *,
    live_osquery_config: dict[str, Any] | None,
) -> bool:
    """Require an enabled advertisement and its trusted local prerequisite."""
    if _advertised_descriptor(prompt_package, backend) is None:
        return False
    check = _BACKEND_CHECKS.get(backend)
    return bool(check and check(prompt_package, live_osquery_config))
