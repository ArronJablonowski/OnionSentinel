#!/usr/bin/env python3
"""Import-compatible facade for AC Hunter behavioral review."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

import ac_hunter_config as _config
import ac_hunter_service as _service

from ac_hunter_config import *  # noqa: E402,F401,F403
from ac_hunter_config import _dependency, _utc_iso  # noqa: E402,F401
from ac_hunter_transport import *  # noqa: E402,F401,F403
from ac_hunter_transport import _relay_diagnostic  # noqa: E402,F401
from ac_hunter_normalization import *  # noqa: E402,F401,F403
from ac_hunter_scoring import *  # noqa: E402,F401,F403
from ac_hunter_scoring import _score_finding  # noqa: E402,F401
from ac_hunter_collection import *  # noqa: E402,F401,F403
from ac_hunter_service import *  # noqa: E402,F401,F403

_LOAD_CONFIG = _config.load_config
_LOAD_CACHE = _service.load_cache
_ATOMIC_WRITE_CACHE = _service.atomic_write_cache
_AC_HUNTER_REVIEW_SERVICE = _service.AcHunterReviewService

__all__ = [
    "AcHunterApiClient",
    "AcHunterReviewService",
    "RelayTransport",
    "atomic_write_cache",
    "collect",
    "collect_from_relay",
    "database_review_response",
    "deep_review_response",
    "load_cache",
    "load_config",
    "normalize_collection",
    "validate_cache",
]


def _sync_runtime_paths() -> None:
    for module in (_config, _service):
        for name in ("DEFAULT_CONFIG", "DEFAULT_CACHE"):
            if name in globals():
                setattr(module, name, globals()[name])


def load_config(*args: Any, **kwargs: Any) -> Any:
    _sync_runtime_paths()
    return _LOAD_CONFIG(*args, **kwargs)


def load_cache(*args: Any, **kwargs: Any) -> Any:
    _sync_runtime_paths()
    return _LOAD_CACHE(*args, **kwargs)


def atomic_write_cache(*args: Any, **kwargs: Any) -> Any:
    _sync_runtime_paths()
    return _ATOMIC_WRITE_CACHE(*args, **kwargs)


class AcHunterReviewService(_AC_HUNTER_REVIEW_SERVICE):
    """Compatibility service that forwards runtime path overrides."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _sync_runtime_paths()
        super().__init__(*args, **kwargs)

    @classmethod
    def from_config_path(cls, path: Path = DEFAULT_CONFIG) -> "AcHunterReviewService":
        _sync_runtime_paths()
        return cls(_config.load_config(path))
