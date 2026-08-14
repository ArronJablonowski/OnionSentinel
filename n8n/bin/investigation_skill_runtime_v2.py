#!/usr/bin/env python3
"""Verified identity-only runtime adapter for active v2 skill registries."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

import investigation_skill_lifecycle_v2 as lifecycle
import investigation_skill_registry_v2 as registry
import investigation_skill_signing_v2 as signing


def select_active_registry(
    root: str | Path,
    *,
    trusted_keys: Mapping[str, str | Path],
    context: Mapping[str, Any],
    role: str,
    permitted_capabilities: Iterable[str],
    provider: str,
    budget: Mapping[str, Any],
    openssl: str | Path | None = None,
) -> dict[str, Any]:
    """Verify and select identities without executing guidance or a query."""
    verifier = signing.openssl_ed25519_verifier(
        trusted_keys,
        openssl=openssl,
    )
    active = lifecycle.load_current(root, verifier=verifier)
    return registry.select_registry(
        active,
        context,
        role,
        permitted_capabilities,
        provider=provider,
        budget=budget,
        verifier=verifier,
    )
