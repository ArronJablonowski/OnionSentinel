#!/usr/bin/env python3
"""Compatibility entrypoint for the modular SOC dashboard builder.

The implementation remains import-compatible through a module proxy so legacy
callers and tests can continue to override runtime paths and collaborators.
"""
from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import dashboard_builder_runtime as _runtime

# Characterization tests intentionally load this compatibility file under
# several module names while replacing renderer modules in ``sys.modules``.
# Refresh the composition root so every load observes those exact collaborators.
_runtime = importlib.reload(_runtime)

_LOCAL_NAMES = {
    "_DashboardBuilderFacade",
    "_LOCAL_NAMES",
    "_override_originals",
    "_runtime",
    "importlib",
    "Path",
    "SCRIPT_DIR",
    "sys",
    "types",
}
_override_originals: dict[str, tuple[object, tuple[tuple[types.ModuleType, object], ...]]] = {}


def build_html(*args: object, **kwargs: object) -> str:
    return _runtime.build_html(*args, **kwargs)


def render_static_page(*args: object, **kwargs: object) -> str:
    return _runtime.render_static_page(*args, **kwargs)


def settings_page_section(*args: object, **kwargs: object) -> str:
    return _runtime.settings_page_section(*args, **kwargs)


def main() -> int:
    return _runtime.main()


class _DashboardBuilderFacade(types.ModuleType):
    """Forward reads and test/runtime overrides to the implementation module."""

    def __getattr__(self, name: str) -> object:
        return getattr(_runtime, name)

    def __setattr__(self, name: str, value: object) -> None:
        if name.startswith("__") or name in _LOCAL_NAMES:
            super().__setattr__(name, value)
            return
        if name not in self.__dict__ and hasattr(_runtime, name):
            _override_originals[name] = (
                getattr(_runtime, name),
                tuple(
                    (module, getattr(module, name))
                    for module in _runtime.BUILDER_MODULES
                    if hasattr(module, name)
                ),
            )
        setattr(_runtime, name, value)
        for module in _runtime.BUILDER_MODULES:
            if hasattr(module, name):
                setattr(module, name, value)
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        if name.startswith("__") or name in _LOCAL_NAMES:
            super().__delattr__(name)
            return
        original = _override_originals.pop(name, None)
        if original is not None:
            runtime_value, module_values = original
            setattr(_runtime, name, runtime_value)
            for module, module_value in module_values:
                setattr(module, name, module_value)
        super().__delattr__(name)

    def __dir__(self) -> list[str]:
        return sorted(set(super().__dir__()) | set(dir(_runtime)))


if __name__ == "__main__":
    raise SystemExit(main())

sys.modules[__name__].__class__ = _DashboardBuilderFacade
