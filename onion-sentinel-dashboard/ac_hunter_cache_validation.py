"""Pure bounded validation for normalized AC Hunter cache trees."""
from __future__ import annotations

from typing import Dict, List

from ac_hunter_config import AcHunterConfigurationError, FORBIDDEN_CACHE_KEYS


def _validate_object(value: Dict[object, object], depth: int) -> None:
    if len(value) > 1000:
        raise AcHunterConfigurationError("AC Hunter cache object is too large")
    for key, item in value.items():
        if not isinstance(key, str) or len(key) > 128:
            raise AcHunterConfigurationError("AC Hunter cache key is invalid")
        if key.lower() in FORBIDDEN_CACHE_KEYS:
            raise AcHunterConfigurationError(
                "AC Hunter cache contains authentication material"
            )
        validate_cache_tree(item, depth + 1)


def _validate_list(value: List[object], depth: int) -> None:
    if len(value) > 5000:
        raise AcHunterConfigurationError("AC Hunter cache list is too large")
    for item in value:
        validate_cache_tree(item, depth + 1)


def _validate_text(value: str) -> None:
    if len(value) > 8192 or any(
        ord(character) < 9 or 13 < ord(character) < 32
        for character in value
    ):
        raise AcHunterConfigurationError("AC Hunter cache text is invalid")


def validate_cache_tree(value: object, depth: int = 0) -> None:
    """Validate one cache subtree without filesystem or service authority."""

    if depth > 12:
        raise AcHunterConfigurationError("AC Hunter cache nesting is invalid")
    if isinstance(value, dict):
        _validate_object(value, depth)
    elif isinstance(value, list):
        _validate_list(value, depth)
    elif isinstance(value, str):
        _validate_text(value)
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise AcHunterConfigurationError("AC Hunter cache value is invalid")
