#!/usr/bin/env python3
"""Executable compatibility facade for Relay health supervision."""
from __future__ import annotations

import functools
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import relay_health_contract as _contract
import relay_health_sanitization as _sanitization
import relay_health_application as _application

_MODULES: tuple[ModuleType, ...] = (
    _contract,
    _sanitization,
    _application,
)
__all__ = [
    "build_pcap_status_event",
    "classify_child_diagnostic",
    "main",
    "run_pcap_broker",
    "run_relay",
    "run_storage_health",
    "sanitize_health_state",
    "summarize_output",
]
_CANONICAL: dict[str, Any] = {}
_DEFAULTS: dict[str, Any] = {}
_WRAPPERS: dict[str, Callable[..., Any]] = {}

# Preserve the original flat module surface used by systemd recovery tooling
# and characterization tests. Uppercase configuration values remain late-bound.
for _module in _MODULES:
    for _name, _value in vars(_module).items():
        if not _name.startswith("_"):
            globals()[_name] = _value
        if callable(_value) and getattr(_value, "__module__", None) == _module.__name__:
            _CANONICAL[_name] = _value
            _DEFAULTS[_name] = _value
        elif _name.isupper():
            _DEFAULTS[_name] = _value


def _forwarded_overrides() -> list[tuple[ModuleType, str, Any]]:
    """Temporarily forward facade-level hooks and configuration overrides."""
    saved: list[tuple[ModuleType, str, Any]] = []
    for name, canonical in _DEFAULTS.items():
        value = globals().get(name, canonical)
        default = _WRAPPERS.get(name, canonical)
        if value is default:
            continue
        for module in _MODULES:
            if name in vars(module):
                saved.append((module, name, getattr(module, name)))
                setattr(module, name, value)
    return saved


def _compatibility_wrapper(name: str, target: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(target)
    def invoke(*args: Any, **kwargs: Any) -> Any:
        saved = _forwarded_overrides()
        try:
            return target(*args, **kwargs)
        finally:
            for module, attr, value in reversed(saved):
                setattr(module, attr, value)

    invoke.__module__ = __name__
    return invoke


for _name, _target in tuple(_CANONICAL.items()):
    _wrapper = _compatibility_wrapper(_name, _target)
    _WRAPPERS[_name] = _wrapper
    globals()[_name] = _wrapper


if __name__ == "__main__":
    sys.exit(main())
