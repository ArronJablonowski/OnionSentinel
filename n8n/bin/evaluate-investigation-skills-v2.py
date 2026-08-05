#!/usr/bin/env python3
"""Offline replay and field-mapping validation for inactive v2 skill packs.

This utility never runs a Security Onion query and never changes a candidate
manifest on disk.  It temporarily satisfies lifecycle attestations in memory
so the production identity-only resolver can be exercised before independent
query review and human approval occur.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys
from typing import Any

import investigation_skills_v2 as skills


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CANDIDATE_DIR = ROOT / "config" / "investigation-skills-v2-candidates"
DEFAULT_FIXTURES = DEFAULT_CANDIDATE_DIR / "offline-replay-fixtures.json"


def simulated_shadow(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return a digest-bound in-memory copy usable only by this evaluator."""
    value = copy.deepcopy(manifest)
    value["maintainer"]["reviewer"] = "offline-replay-simulator"
    value["verification"] = {
        "unit_tests": True,
        "replay_cases": 1,
        "independent_query_review": True,
        "adversarial_tests": True,
        "human_approved": False,
    }
    value["artifact_digest"] = skills.artifact_digest(value)
    return value


def evaluate(candidate_dir: Path, fixture_path: Path) -> dict[str, Any]:
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    if fixture.get("schema") != "onion-sentinel-skill-offline-replay-v1":
        raise ValueError("unsupported offline replay fixture schema")
    manifests = {
        value["id"]: value
        for value in (
            skills.load_manifest(path)
            for path in sorted(candidate_dir.glob("*.candidate.json"))
        )
    }
    records = [
        {"state": "shadow", "manifest": simulated_shadow(manifest)}
        for manifest in manifests.values()
    ]
    catalog = fixture.get("field_catalog")
    if not isinstance(catalog, dict):
        raise ValueError("field_catalog must be an object")

    results: list[dict[str, Any]] = []
    passed = 0
    for case in fixture.get("cases", []):
        if not isinstance(case, dict):
            raise ValueError("replay case must be an object")
        expected = sorted(case.get("expected_selected", []))
        selection = skills.resolve_manifests(
            records,
            case.get("context", {}),
            str(case.get("role") or ""),
            case.get("permitted_capabilities", []),
            allow_shadow=True,
        )
        actual = sorted(item["id"] for item in selection["selected"])
        mapping_gaps: list[dict[str, Any]] = []
        for skill_id in actual:
            manifest = manifests[skill_id]
            for template in manifest["query_templates"]:
                available = set(catalog.get(template["backend"], []))
                missing = sorted(set(template["expected_fields"]) - available)
                if missing:
                    mapping_gaps.append({
                        "skill_id": skill_id,
                        "template_id": template["id"],
                        "backend": template["backend"],
                        "missing_fields": missing,
                    })
        ok = actual == expected and not mapping_gaps
        passed += int(ok)
        results.append({
            "id": str(case.get("id") or ""),
            "passed": ok,
            "expected_selected": expected,
            "actual_selected": actual,
            "mapping_gaps": mapping_gaps,
        })

    return {
        "schema": "onion-sentinel-skill-offline-replay-result-v1",
        "simulation_only": True,
        "query_execution": False,
        "candidate_activation": False,
        "candidate_count": len(manifests),
        "case_count": len(results),
        "passed_count": passed,
        "failed_count": len(results) - passed,
        "passed": passed == len(results) and len(results) > 0,
        "results": results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", type=Path, default=DEFAULT_CANDIDATE_DIR)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = evaluate(args.candidate_dir, args.fixtures)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"offline replay validation failed: {error}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
