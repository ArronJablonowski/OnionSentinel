"""Fixed policies for cohort receipts and digest-bound private artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from cohort_artifact_io import (
    AlertStoreReceiptPolicy,
    DigestArtifactPolicy,
    alert_store_response_sha256 as verify_alert_store_response_sha256,
    digest_bound as bind_artifact_digest,
    validate_digest as validate_artifact_digest,
    write_private_json as persist_private_json,
)
from cohort_runner_contracts import (
    ALERT_STORE_CANONICAL_SHA256_JS,
    MAX_STORED_RESPONSE_BYTES,
    SHA256_RE,
    CohortError,
    constant_time_equal,
    sha256_value,
)


def alert_store_receipt_policy() -> AlertStoreReceiptPolicy:
    return AlertStoreReceiptPolicy(
        error=CohortError,
        maximum_response_bytes=MAX_STORED_RESPONSE_BYTES,
        sha256_pattern=SHA256_RE,
        canonical_sha256_javascript=ALERT_STORE_CANONICAL_SHA256_JS,
        node_candidates=(
            Path("/opt/homebrew/bin/node"),
            Path("/usr/local/bin/node"),
            Path("/usr/bin/node"),
        ),
    )


def alert_store_response_sha256(raw_response: str) -> str:
    """Reproduce the alert-store JavaScript response digest exactly."""
    return verify_alert_store_response_sha256(
        raw_response,
        alert_store_receipt_policy(),
    )


def digest_artifact_policy() -> DigestArtifactPolicy:
    return DigestArtifactPolicy(
        error=CohortError,
        sha256_pattern=SHA256_RE,
        sha256_value=sha256_value,
        constant_time_equal=constant_time_equal,
    )


def digest_bound(document: Mapping[str, Any], field: str) -> dict[str, Any]:
    return bind_artifact_digest(document, field, digest_artifact_policy())


def validate_digest(document: Mapping[str, Any], field: str) -> None:
    validate_artifact_digest(document, field, digest_artifact_policy())


def write_private_json(
    path: Path,
    document: Mapping[str, Any],
    *,
    digest_field: str,
    replace: bool = True,
) -> dict[str, Any]:
    """Atomically persist a digest-bound owner-only JSON document."""
    return persist_private_json(
        path,
        document,
        digest_field=digest_field,
        policy=digest_artifact_policy(),
        replace=replace,
    )
