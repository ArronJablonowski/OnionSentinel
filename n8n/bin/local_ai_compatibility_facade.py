"""Install extracted compatibility functions into the legacy runner namespace."""
from __future__ import annotations

from types import FunctionType, ModuleType
from typing import Any


def _bind_function(function: FunctionType, namespace: dict[str, Any]) -> FunctionType:
    """Clone one function with the compatibility facade as its global scope."""
    rebound = FunctionType(
        function.__code__,
        namespace,
        function.__name__,
        function.__defaults__,
        function.__closure__,
    )
    rebound.__annotations__ = function.__annotations__
    rebound.__dict__.update(function.__dict__)
    rebound.__doc__ = function.__doc__
    rebound.__kwdefaults__ = function.__kwdefaults__
    rebound.__module__ = str(namespace.get("__name__") or function.__module__)
    rebound.__qualname__ = function.__qualname__
    return rebound


def install_facade_functions(
    namespace: dict[str, Any],
    *modules: ModuleType,
) -> None:
    """Re-export module definitions while preserving facade-global patch seams."""
    for module in modules:
        for name in module.__all__:
            value = getattr(module, name)
            if isinstance(value, FunctionType) and value.__module__ == module.__name__:
                value = _bind_function(value, namespace)
            namespace[name] = value


__all__ = ("install_facade_functions",)
