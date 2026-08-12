"""Deterministic admission policy for the AC Hunter client configuration."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Type


ALLOWED_CONFIG_KEYS = {
    "schema",
    "enabled",
    "dataset",
    "relay_host",
    "relay_user",
    "relay_port",
    "ssh_key",
    "known_hosts",
    "credentials_file",
    "cache_file",
    "cache_ttl_seconds",
    "connect_timeout_seconds",
    "timeout_seconds",
    "max_response_bytes",
    "max_stderr_bytes",
}


def _validate_fixed_fields(
    source: Mapping[str, object],
    policy: Mapping[str, object],
    error_type: Type[Exception],
) -> None:
    if (
        set(source) - ALLOWED_CONFIG_KEYS
        or source.get("schema") != policy["schema"]
    ):
        raise error_type("AC Hunter client configuration schema is unsupported")
    if not isinstance(source.get("enabled"), bool):
        raise error_type("AC Hunter enabled must be boolean")
    for key, label in (
        ("dataset", "dataset"),
        ("relay_host", "Relay host"),
        ("relay_user", "Relay user"),
    ):
        if source.get(key) != policy[key]:
            raise error_type(
                f"AC Hunter {label} is outside the fixed allowlist"
            )


def _base_projection(
    source: Mapping[str, object],
    policy: Mapping[str, object],
    *,
    bounded_int: Callable[..., int],
    configured_path: Callable[[object, str], Path],
) -> Dict[str, Any]:
    relay_port = bounded_int(
        source.get("relay_port", policy["relay_port"]),
        minimum=policy["relay_port"],
        maximum=policy["relay_port"],
        label="AC Hunter Relay port",
    )
    return {
        "schema": policy["schema"],
        "enabled": source["enabled"],
        "dataset": policy["dataset"],
        "relay_host": policy["relay_host"],
        "relay_user": policy["relay_user"],
        "relay_port": relay_port,
        "ssh_key": configured_path(source.get("ssh_key"), "AC Hunter SSH key"),
        "known_hosts": configured_path(
            source.get("known_hosts"), "AC Hunter known_hosts"
        ),
        "credentials_file": configured_path(
            source.get("credentials_file"), "AC Hunter credentials file"
        ),
        "cache_file": configured_path(
            source.get("cache_file"), "AC Hunter cache file"
        ),
    }


def _validate_protected_paths(
    normalized: Mapping[str, object],
    *,
    config_path: Path,
    expected_cache: Path,
    error_type: Type[Exception],
) -> None:
    configured_cache = Path(os.path.abspath(str(normalized["cache_file"])))
    canonical_cache = Path(os.path.abspath(str(expected_cache)))
    if configured_cache != canonical_cache:
        raise error_type(
            "AC Hunter cache path is outside the fixed runtime location"
        )
    protected_paths = (
        Path(config_path).expanduser(),
        normalized["ssh_key"],
        normalized["known_hosts"],
        normalized["credentials_file"],
        normalized["cache_file"],
    )
    resolved_paths = [
        Path(candidate).resolve(strict=False) for candidate in protected_paths
    ]
    if len(set(resolved_paths)) != len(resolved_paths):
        raise error_type(
            "AC Hunter configuration, trust, credential, and cache paths "
            "must be distinct"
        )


def _apply_numeric_policy(
    normalized: Dict[str, Any],
    source: Mapping[str, object],
    *,
    max_stderr_bytes: int,
    bounded_int: Callable[..., int],
) -> None:
    for key, default, minimum, maximum in (
        ("cache_ttl_seconds", 300, 30, 3600),
        ("connect_timeout_seconds", 8, 1, 15),
        ("timeout_seconds", 45, 5, 120),
        ("max_response_bytes", 8 * 1024 * 1024, 1024, 8 * 1024 * 1024),
        ("max_stderr_bytes", max_stderr_bytes, 1024, max_stderr_bytes),
    ):
        normalized[key] = bounded_int(
            source.get(key, default),
            minimum=minimum,
            maximum=maximum,
            label=f"AC Hunter {key}",
        )


def normalize_client_config(
    source: Mapping[str, object],
    *,
    config_path: Path,
    expected_cache: Path,
    policy: Mapping[str, object],
    bounded_int: Callable[..., int],
    configured_path: Callable[[object, str], Path],
    error_type: Type[Exception],
) -> Dict[str, Any]:
    """Project one admitted configuration without reading trust contents."""

    _validate_fixed_fields(source, policy, error_type)
    normalized = _base_projection(
        source,
        policy,
        bounded_int=bounded_int,
        configured_path=configured_path,
    )
    _validate_protected_paths(
        normalized,
        config_path=config_path,
        expected_cache=expected_cache,
        error_type=error_type,
    )
    _apply_numeric_policy(
        normalized,
        source,
        max_stderr_bytes=policy["max_stderr_bytes"],
        bounded_int=bounded_int,
    )
    return normalized
