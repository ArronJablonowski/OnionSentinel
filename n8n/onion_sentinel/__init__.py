"""Stable package boundaries for the Onion Sentinel runtime.

The executable compatibility wrappers remain in ``n8n/bin`` while behavior is
incrementally extracted into this package. Package modules must never import a
legacy wrapper.
"""

from .composition import invoke_legacy_entrypoint
from .runtime import RuntimeDependencies

__all__ = ["RuntimeDependencies", "invoke_legacy_entrypoint"]
