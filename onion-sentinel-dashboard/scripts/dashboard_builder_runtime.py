"""Composed runtime namespace for the modular SOC dashboard builder."""
from __future__ import annotations

import importlib
import sys
import types

_LAYER_NAMES = (
    "dashboard_builder_contract",
    "dashboard_builder_settings",
    "dashboard_builder_report_core",
    "dashboard_builder_reports",
    "dashboard_builder_executive",
    "dashboard_builder_siem",
    "dashboard_builder_pages",
    "dashboard_builder_publication",
)
for _layer_name in _LAYER_NAMES:
    sys.modules.pop(_layer_name, None)

(
    _contract,
    _settings,
    _report_core,
    _reports,
    _executive,
    _siem,
    _pages,
    _publication,
) = tuple(importlib.import_module(name) for name in _LAYER_NAMES)


BUILDER_MODULES: tuple[types.ModuleType, ...] = (
    _contract,
    _settings,
    _report_core,
    _reports,
    _executive,
    _siem,
    _pages,
    _publication,
)

# Keep the historical runtime namespace exact: owner modules participate in
# composition but their private loader aliases were never public facade names.
del _executive, _siem


def _public_namespace(module: types.ModuleType) -> dict[str, object]:
    return {
        name: value
        for name, value in vars(module).items()
        if not name.startswith("__")
    }


# Preserve the historical flat import surface. Later composition layers own
# orchestration wrappers with the same names as lower-level renderers.
for _module in BUILDER_MODULES:
    globals().update(_public_namespace(_module))


# Functions retain their defining module globals. Populate those namespaces
# with the final composition so cross-layer helper lookups remain explicit at
# runtime and compatibility overrides can be forwarded consistently.
_COMPOSED_NAMESPACE = {
    name: value
    for name, value in globals().items()
    if not name.startswith("__")
}
for _module in BUILDER_MODULES:
    vars(_module).update(_COMPOSED_NAMESPACE)


if __name__ == "__main__":
    raise SystemExit(main())
