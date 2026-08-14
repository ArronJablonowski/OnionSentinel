#!/usr/bin/env python3
"""Import-compatible composition facade for the Onion Sentinel Relay."""
from __future__ import annotations

import functools
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import relay_core as _core
import relay_pcap_capture_policy as _pcap_capture_policy
import relay_pcap_transport as _pcap_transport
import relay_pcap_delivery as _pcap_delivery
import relay_pcap_service as _pcap_service
import relay_application as _application

_MODULES: tuple[ModuleType, ...] = (
    _core,
    _pcap_capture_policy,
    _pcap_transport,
    _pcap_delivery,
    _pcap_service,
    _application,
)
__all__ = [
    "PcapProgressReporter",
    "WebhookPostError",
    "build_relay_heartbeat",
    "drain_alert_outbox",
    "main",
    "post_json_to_webhook",
    "process_pcap_requests",
    "run_ssh_pull",
]
_CANONICAL: dict[str, Any] = {}
_WRAPPERS: dict[str, Callable[..., Any]] = {}

# Preserve the original flat module surface, including imported standard-library
# modules that recovery tooling and characterization tests patch directly.
for _module in _MODULES:
    for _name, _value in vars(_module).items():
        if not _name.startswith("_"):
            globals()[_name] = _value
        if callable(_value) and getattr(_value, "__module__", None) == _module.__name__:
            _CANONICAL[_name] = _value

# The unlocked helper was callable from the original flat module.
_process_pcap_requests_unlocked = _pcap_service._process_pcap_requests_unlocked
_CANONICAL["_process_pcap_requests_unlocked"] = _process_pcap_requests_unlocked


def _forwarded_overrides() -> list[tuple[ModuleType, str, Any]]:
    """Temporarily forward facade-level patches to implementation modules."""
    saved: list[tuple[ModuleType, str, Any]] = []
    for name, canonical in _CANONICAL.items():
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
            for module, name, value in reversed(saved):
                setattr(module, name, value)

    invoke.__module__ = __name__
    return invoke


for _name, _target in tuple(_CANONICAL.items()):
    # Exception and service classes retain their identity; facade patches of
    # those names are still propagated by wrappers around calling functions.
    if isinstance(_target, type):
        continue
    _wrapper = _compatibility_wrapper(_name, _target)
    _WRAPPERS[_name] = _wrapper
    globals()[_name] = _wrapper


class PcapProgressReporter(_CANONICAL["PcapProgressReporter"]):
    """Compatibility reporter that forwards facade-level test/runtime hooks."""

    def report(self) -> None:
        saved = _forwarded_overrides()
        try:
            super().report()
        finally:
            for module, name, value in reversed(saved):
                setattr(module, name, value)


if __name__ == "__main__":
    sys.exit(main())
