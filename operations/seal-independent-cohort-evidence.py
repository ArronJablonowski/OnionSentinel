#!/usr/bin/env python3
"""Seal independent ground truth against pristine frozen SOC/IR manifests."""
from __future__ import annotations

import argparse
import datetime as dt
import hmac
import json
from pathlib import Path
import sys
from typing import Any, Mapping


OPERATIONS_DIR = Path(__file__).resolve().parent
if str(OPERATIONS_DIR) not in sys.path:
    sys.path.insert(0, str(OPERATIONS_DIR))

from cohort_evaluation_adjudication_service import AdjudicationSealService
from cohort_evaluation_contracts import (
    EVIDENCE_DRAFT_SCHEMA,
    EVIDENCE_SEAL_SCHEMA,
    MAX_GRADED_ROLE_COUNT,
    MAX_INPUT_BYTES,
    SHA256_RE,
    STABLE_GROUP_ID_RE,
    SUPPORTED_ROLES,
)
from cohort_evaluation_private_input import (
    PrivateInputPolicy,
    file_sha256,
    load_private_json,
    private_regular_file,
)
from cohort_evaluation_private_output import write_private_json
from cohort_evidence_sealing import (
    EvidenceSealingPolicy,
    build_evidence_seal,
)
from cohort_manifest_adapters import (
    load_private_manifest,
    ordered_identity_projection,
)
from cohort_runner_contracts import (
    CohortError,
    constant_time_equal,
    sha256_value,
    utc_now,
)


class CohortEvidenceSealError(RuntimeError):
    """Independent evidence could not be sealed safely before dispatch."""


def parse_timestamp(value: Any, label: str) -> dt.datetime:
    text = str(value or "").strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise CohortEvidenceSealError(f"{label} is not ISO-8601") from exc
    if parsed.tzinfo is None:
        raise CohortEvidenceSealError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate_embedded_digest(document: Mapping[str, Any], field: str) -> None:
    expected = str(document.get(field) or "")
    unsigned = dict(document)
    unsigned.pop(field, None)
    if SHA256_RE.fullmatch(expected) is None:
        raise CohortEvidenceSealError(f"{field} is missing or malformed")
    if not hmac.compare_digest(expected, sha256_value(unsigned)):
        raise CohortEvidenceSealError(f"{field} does not match the document")


def _adjudication_service() -> AdjudicationSealService:
    return AdjudicationSealService(
        error=CohortEvidenceSealError,
        parse_timestamp=parse_timestamp,
        hash_value=sha256_value,
        validate_embedded_digest=validate_embedded_digest,
    )


def _policy() -> EvidenceSealingPolicy:
    service = _adjudication_service()
    return EvidenceSealingPolicy(
        error=CohortEvidenceSealError,
        draft_schema=EVIDENCE_DRAFT_SCHEMA,
        seal_schema=EVIDENCE_SEAL_SCHEMA,
        roles=SUPPORTED_ROLES,
        maximum_count=MAX_GRADED_ROLE_COUNT,
        sha256_pattern=SHA256_RE,
        stable_group_id_pattern=STABLE_GROUP_ID_RE,
        utc_now=utc_now,
        sha256_value=sha256_value,
        constant_time_equal=constant_time_equal,
        validate_embedded_digest=validate_embedded_digest,
        normalize_ground_truth=service.normalize_ground_truth,
        ordered_identity_projection=ordered_identity_projection,
    )


def _manifest_argument(value: str) -> tuple[str, Path]:
    role, separator, raw_path = str(value or "").partition("=")
    role = role.strip().lower()
    if not separator or role not in SUPPORTED_ROLES or not raw_path.strip():
        raise argparse.ArgumentTypeError("--manifest must be ROLE=PATH")
    return role, Path(raw_path.strip())


def _expected_count(value: str) -> int:
    try:
        count = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("expected count must be an integer") from exc
    if not 1 <= count <= MAX_GRADED_ROLE_COUNT:
        raise argparse.ArgumentTypeError(
            f"expected count must be between 1 and {MAX_GRADED_ROLE_COUNT}"
        )
    return count


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        action="append",
        required=True,
        type=_manifest_argument,
        metavar="ROLE=PATH",
        help="owner-only pristine frozen manifest; repeat once per role",
    )
    parser.add_argument("--ground-truth", required=True, type=Path)
    parser.add_argument("--methodology", required=True, type=Path)
    parser.add_argument("--expected-count", required=True, type=_expected_count)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def _load_manifests(values: list[tuple[str, Path]]) -> dict[str, dict[str, Any]]:
    manifests: dict[str, dict[str, Any]] = {}
    for role, path in values:
        if role in manifests:
            raise CohortEvidenceSealError(f"duplicate manifest role: {role}")
        manifests[role] = load_private_manifest(path)
    return manifests


def seal_evidence(
    manifest_values: list[tuple[str, Path]],
    ground_truth_path: Path,
    methodology_path: Path,
    output_path: Path,
    *,
    expected_count: int,
) -> dict[str, Any]:
    private_policy = PrivateInputPolicy(
        maximum_bytes=MAX_INPUT_BYTES,
        error=CohortEvidenceSealError,
    )
    draft, _source_sha256 = load_private_json(
        ground_truth_path, "independent ground truth", private_policy
    )
    methodology = private_regular_file(
        methodology_path, "independent methodology", private_policy
    )
    if methodology.stat().st_size == 0:
        raise CohortEvidenceSealError("independent methodology is empty")
    seal = build_evidence_seal(
        draft,
        _load_manifests(manifest_values),
        methodology_sha256=file_sha256(methodology),
        expected_count=expected_count,
        policy=_policy(),
    )
    _adjudication_service().validate_evidence_seal(
        seal, expected_count=expected_count
    )
    write_private_json(
        output_path,
        seal,
        maximum_bytes=MAX_INPUT_BYTES,
        replace=False,
        error=CohortEvidenceSealError,
    )
    return seal


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        seal = seal_evidence(
            args.manifest,
            args.ground_truth,
            args.methodology,
            args.output,
            expected_count=args.expected_count,
        )
    except (CohortEvidenceSealError, CohortError) as exc:
        print(f"evidence sealing failed: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "schema": seal["schema"],
                "experiment_id": seal["experiment_id"],
                "expected_count": seal["expected_count"],
                "sealed_at": seal["sealed_at"],
                "seal_sha256": seal["seal_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
