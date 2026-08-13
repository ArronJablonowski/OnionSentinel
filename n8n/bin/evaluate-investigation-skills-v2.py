#!/usr/bin/env python3
"""Offline replay and governed field-mapping validation for inactive v2 skills.

This utility never runs a Security Onion query and never changes a candidate
manifest on disk. It temporarily satisfies lifecycle attestations in memory
so the production identity-only resolver and the exact Security Onion wrapper
field projections can be exercised before representative replay, independent
query review, and human approval occur.
"""
from __future__ import annotations

import argparse
import copy
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

import investigation_skills_v2 as skills


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CANDIDATE_DIR = ROOT / "config" / "investigation-skills-v2-candidates"
DEFAULT_FIXTURES = DEFAULT_CANDIDATE_DIR / "offline-replay-fixtures.json"
DEFAULT_SECURITY_ONION_WRAPPER = (
    ROOT.parent / "security-onion" / "bin" / "export-incident-evidence"
)
TEMPLATE_PACKS = {
    "dns-alert-context": "dns_activity",
    "dns-zeek-context": "dns_activity",
    "http-event-context": "zeek_http",
    "http-zeek-context": "zeek_http",
    "icmp-event-context": "network_flow",
    "ssh-flow-context": "zeek_ssh",
    "ssh-zeek-context": "zeek_ssh",
    "suricata-alert-context": "alert_context",
    "suricata-flow-context": "network_flow",
    "tls-flow-context": "zeek_tls",
    "tls-zeek-context": "zeek_tls",
    "zeek-connection-anchor": "network_flow",
    "zeek-protocol-pivots": "cross_sensor_timeline",
}


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


def load_wrapper_field_catalog(wrapper_path: Path) -> dict[str, set[str]]:
    """Read the exact projected fields from the governed SO wrapper source."""
    loader = importlib.machinery.SourceFileLoader(
        "onion_sentinel_skill_field_catalog_wrapper",
        str(wrapper_path),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise ValueError("Security Onion wrapper could not be loaded")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    packs = getattr(module, "PACKS", None)
    if not isinstance(packs, dict):
        raise ValueError("Security Onion wrapper PACKS catalog is unavailable")
    catalog: dict[str, set[str]] = {}
    for name, pack in packs.items():
        fields = pack.get("fields") if isinstance(pack, dict) else None
        if not isinstance(fields, list) or any(
            not isinstance(field, str) or not field for field in fields
        ):
            raise ValueError(f"Security Onion wrapper pack {name} has invalid fields")
        catalog[str(name)] = set(fields)
    missing = sorted(set(TEMPLATE_PACKS.values()) - set(catalog))
    if missing:
        raise ValueError(
            "Security Onion wrapper is missing required packs: "
            + ", ".join(missing)
        )
    return catalog


def _load_fixture(fixture_path: Path) -> dict[str, Any]:
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    if fixture.get("schema") != "onion-sentinel-skill-offline-replay-v1":
        raise ValueError("unsupported offline replay fixture schema")
    return fixture


def _load_candidates(candidate_dir: Path) -> dict[str, dict[str, Any]]:
    return {
        value["id"]: value
        for value in (
            skills.load_manifest(path)
            for path in sorted(candidate_dir.glob("*.candidate.json"))
        )
    }


def _shadow_records(manifests: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"state": "shadow", "manifest": simulated_shadow(manifest)}
        for manifest in manifests.values()
    ]


def _field_catalogs(
    fixture: dict[str, Any],
    wrapper_path: Path,
) -> tuple[dict[str, Any], dict[str, set[str]]]:
    fixture_catalog = fixture.get("field_catalog")
    if not isinstance(fixture_catalog, dict):
        raise ValueError("field_catalog must be an object")
    return fixture_catalog, load_wrapper_field_catalog(wrapper_path)


def _template_catalog(
    template: dict[str, Any],
    fixture_catalog: dict[str, Any],
    wrapper_catalog: dict[str, set[str]],
) -> tuple[set[str], str]:
    template_id = str(template["id"])
    wrapper_pack = TEMPLATE_PACKS.get(template_id)
    if wrapper_pack:
        return (
            wrapper_catalog[wrapper_pack],
            f"security-onion-wrapper:{wrapper_pack}",
        )
    return (
        set(fixture_catalog.get(template["backend"], [])),
        f"synthetic-fixture:{template['backend']}",
    )


def _mapping_gaps(
    actual: list[str],
    manifests: dict[str, dict[str, Any]],
    fixture_catalog: dict[str, Any],
    wrapper_catalog: dict[str, set[str]],
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for skill_id in actual:
        manifest = manifests[skill_id]
        for template in manifest["query_templates"]:
            available, provenance = _template_catalog(
                template,
                fixture_catalog,
                wrapper_catalog,
            )
            missing = sorted(set(template["expected_fields"]) - available)
            if missing:
                gaps.append({
                    "skill_id": skill_id,
                    "template_id": template["id"],
                    "backend": template["backend"],
                    "catalog": provenance,
                    "missing_fields": missing,
                })
    return gaps


def _evaluate_case(
    case: Any,
    records: list[dict[str, Any]],
    manifests: dict[str, dict[str, Any]],
    fixture_catalog: dict[str, Any],
    wrapper_catalog: dict[str, set[str]],
) -> dict[str, Any]:
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
    mapping_gaps = _mapping_gaps(
        actual,
        manifests,
        fixture_catalog,
        wrapper_catalog,
    )
    return {
        "id": str(case.get("id") or ""),
        "passed": actual == expected and not mapping_gaps,
        "expected_selected": expected,
        "actual_selected": actual,
        "mapping_gaps": mapping_gaps,
    }


def _evaluate_cases(
    cases: Any,
    records: list[dict[str, Any]],
    manifests: dict[str, dict[str, Any]],
    fixture_catalog: dict[str, Any],
    wrapper_catalog: dict[str, set[str]],
) -> tuple[list[dict[str, Any]], int]:
    results: list[dict[str, Any]] = []
    passed = 0
    for case in cases:
        result = _evaluate_case(
            case,
            records,
            manifests,
            fixture_catalog,
            wrapper_catalog,
        )
        passed += int(result["passed"])
        results.append(result)
    return results, passed


def _evaluation_result(
    manifests: dict[str, dict[str, Any]],
    results: list[dict[str, Any]],
    passed: int,
) -> dict[str, Any]:
    return {
        "schema": "onion-sentinel-skill-offline-replay-result-v1",
        "simulation_only": True,
        "query_execution": False,
        "candidate_activation": False,
        "field_catalog": {
            "security_onion": "governed-wrapper-pack-projections",
            "pcap_derived": "synthetic-contract-only",
        },
        "candidate_count": len(manifests),
        "case_count": len(results),
        "passed_count": passed,
        "failed_count": len(results) - passed,
        "passed": passed == len(results) and len(results) > 0,
        "results": results,
    }


def evaluate(
    candidate_dir: Path,
    fixture_path: Path,
    wrapper_path: Path = DEFAULT_SECURITY_ONION_WRAPPER,
) -> dict[str, Any]:
    fixture = _load_fixture(fixture_path)
    manifests = _load_candidates(candidate_dir)
    records = _shadow_records(manifests)
    fixture_catalog, wrapper_catalog = _field_catalogs(fixture, wrapper_path)
    results, passed = _evaluate_cases(
        fixture.get("cases", []),
        records,
        manifests,
        fixture_catalog,
        wrapper_catalog,
    )
    return _evaluation_result(manifests, results, passed)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", type=Path, default=DEFAULT_CANDIDATE_DIR)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument(
        "--security-onion-wrapper",
        type=Path,
        default=DEFAULT_SECURITY_ONION_WRAPPER,
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = evaluate(
            args.candidate_dir,
            args.fixtures,
            args.security_onion_wrapper,
        )
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
