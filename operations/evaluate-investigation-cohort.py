#!/usr/bin/env python3
"""Grade frozen SOC Analyst and Incident Responder harness cohorts offline.

This executable is intentionally a thin CLI over cohort_evaluation_service.
The service owns sealed input validation, execution-proof admission, scoring,
workflow composition, and bounded output behavior.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

OPERATIONS_DIR = Path(__file__).resolve().parent
if str(OPERATIONS_DIR) not in sys.path:
    sys.path.insert(0, str(OPERATIONS_DIR))

import cohort_evaluation_service as _service
import cohort_adjudication as _adjudication
from cohort_evaluation_contracts import (
    EXPECTED_ROLE_COUNT,
    MAX_GRADED_ROLE_COUNT,
    MIN_GRADED_ROLE_COUNT,
    SUPPORTED_ROLES,
)

CohortEvaluationError = _service.CohortEvaluationError
evaluate_cohorts = _service.evaluate_cohorts
render_markdown = _service.render_markdown
write_private_bytes = _service.write_private_bytes
write_private_json = _service.write_private_json


def __getattr__(name: str):
    """Preserve the legacy import surface during the modular migration."""
    if hasattr(_service, name):
        return getattr(_service, name)
    return getattr(_adjudication, name)


def _parse_result_argument(value: str) -> tuple[str, Path]:
    role, separator, raw_path = str(value or "").partition("=")
    role = role.strip().lower()
    if not separator or role not in SUPPORTED_ROLES or not raw_path.strip():
        raise argparse.ArgumentTypeError(
            "--result must be ROLE=PATH where ROLE is incident-responder "
            "or soc-analyst"
        )
    return role, Path(raw_path.strip())


def _parse_expected_count(value: str) -> int:
    try:
        expected_count = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(
            "--expected-count must be an integer"
        ) from exc
    if not MIN_GRADED_ROLE_COUNT <= expected_count <= MAX_GRADED_ROLE_COUNT:
        raise argparse.ArgumentTypeError(
            "--expected-count must be between "
            f"{MIN_GRADED_ROLE_COUNT} and {MAX_GRADED_ROLE_COUNT} per role"
        )
    return expected_count


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--result",
        action="append",
        required=True,
        type=_parse_result_argument,
        metavar="ROLE=PATH",
        help="metadata-only cohort export; repeat once per evaluated role",
    )
    parser.add_argument("--adjudication", required=True, type=Path)
    parser.add_argument(
        "--expected-count",
        type=_parse_expected_count,
        default=EXPECTED_ROLE_COUNT,
        metavar="COUNT",
        help=(
            "cases per role to grade (1-20; default 20, the minimum "
            "production-promotion cohort size)"
        ),
    )
    parser.add_argument(
        "--required-evaluation-profile",
        default="",
        help=(
            "optional exact campaign profile that both result exports must "
            "declare"
        ),
    )
    parser.add_argument("--json-out", required=True, type=Path)
    parser.add_argument("--markdown-out", required=True, type=Path)
    parser.add_argument(
        "--replace",
        action="store_true",
        help="replace existing explicit output files",
    )
    parser.add_argument(
        "--fail-on-gate",
        action="store_true",
        help="exit 1 when any evaluated role misses the diagnostic shadow gate",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result_paths: dict[str, Path] = {}
    for role, path in args.result:
        if role in result_paths:
            raise SystemExit(f"duplicate --result role: {role}")
        result_paths[role] = path
    try:
        report = evaluate_cohorts(
            result_paths=result_paths,
            adjudication_path=args.adjudication,
            expected_count=args.expected_count,
            required_evaluation_profile=args.required_evaluation_profile,
        )
        write_private_json(
            args.json_out, report, replace=bool(args.replace)
        )
        write_private_bytes(
            args.markdown_out,
            render_markdown(report).encode("utf-8"),
            replace=bool(args.replace),
        )
    except CohortEvaluationError as exc:
        print(f"evaluation failed: {exc}", file=sys.stderr)
        return 2
    summary = {
        role: {
            "completed": details["aggregate"]["completed_count"],
            "pass": details["aggregate"]["classification_counts"]["pass"],
            "needs_review": details["aggregate"]["classification_counts"][
                "needs_review"
            ],
            "fail": details["aggregate"]["classification_counts"]["fail"],
            "effective_mean": details["aggregate"]["score"]["effective_mean"],
            "exact_verdict_rate": details["aggregate"]["exact_verdict_rate"],
            "shadow_gate": details["aggregate"]["shadow_acceptance_gate"][
                "passed"
            ],
        }
        for role, details in report["roles"].items()
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.fail_on_gate and not all(
        details["aggregate"]["shadow_acceptance_gate"]["passed"]
        for details in report["roles"].values()
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
