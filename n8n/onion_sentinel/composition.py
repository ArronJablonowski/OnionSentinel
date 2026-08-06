"""Composition seams used by stable legacy executable wrappers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


Entrypoint = Callable[[], int]


@dataclass(frozen=True)
class LegacyCompositionRoot:
    """Validated bridge from a hyphenated compatibility script to a package."""

    main: Entrypoint

    @classmethod
    def from_namespace(cls, namespace: Mapping[str, Any]) -> "LegacyCompositionRoot":
        entrypoint = namespace.get("main")
        if not callable(entrypoint):
            raise RuntimeError("legacy runtime namespace does not expose callable main")
        if getattr(entrypoint, "__name__", "") != "main":
            raise RuntimeError("legacy runtime entry point identity is invalid")
        return cls(main=entrypoint)

    def invoke(self) -> int:
        result = self.main()
        if not isinstance(result, int) or isinstance(result, bool):
            raise RuntimeError("legacy runtime main must return an integer exit code")
        return result


def invoke_legacy_entrypoint(namespace: Mapping[str, Any]) -> int:
    """Invoke the supported wrapper through the package composition boundary."""
    return LegacyCompositionRoot.from_namespace(namespace).invoke()
