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
import ast
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
DEFAULT_PCAP_POLICY = ROOT / "bin" / "pcap_evidence_query_policy.py"
DEFAULT_AC_HUNTER_PROJECTION = (
    ROOT.parent / "onion-sentinel-dashboard" / "ac_hunter_collection_projection.py"
)
TEMPLATE_PACKS = {
    "alert-group-history": "alert_context",
    "alert-group-selected-anchor": "alert_context",
    "beacon-cross-sensor": "cross_sensor_timeline",
    "beacon-flow-series": "network_flow",
    "dns-alert-context": "dns_activity",
    "dns-zeek-context": "dns_activity",
    "doh-dns-baseline": "dns_activity",
    "doh-http-context": "zeek_http",
    "doh-tls-context": "zeek_tls",
    "elastic-kql-equivalent-audit": "network_flow",
    "elastic-query-dsl-audit": "alert_context",
    "flow-window-anchor": "network_flow",
    "flow-window-timeline": "cross_sensor_timeline",
    "http-event-context": "zeek_http",
    "http-zeek-context": "zeek_http",
    "icmp-event-context": "network_flow",
    "long-connection-summary": "network_flow",
    "long-connection-timeline": "cross_sensor_timeline",
    "historical-osquery-context": "osquery_history",
    "scan-alert-context": "alert_context",
    "scan-flow-summary": "network_flow",
    "ssh-flow-context": "zeek_ssh",
    "ssh-zeek-context": "zeek_ssh",
    "suricata-alert-context": "alert_context",
    "suricata-flow-context": "network_flow",
    "security-onion-oql-equivalent-audit": "cross_sensor_timeline",
    "stun-flow-context": "network_flow",
    "stun-session-context": "zeek_stun",
    "tls-flow-context": "zeek_tls",
    "tls-zeek-context": "zeek_tls",
    "zeek-connection-anchor": "network_flow",
    "zeek-protocol-pivots": "cross_sensor_timeline",
}
TEMPLATE_PCAP_OPERATIONS = {
    "derived-pcap-connections": "connections",
    "derived-pcap-coverage": "coverage",
    "derived-pcap-packet-facts": "packet_facts",
    "icmp-pcap-summary": "packet_facts",
}
TEMPLATE_AC_HUNTER_PROJECTIONS = {
    "ac-hunter-snapshot-context": "compose_collection",
}
REPOSITORY_BACKENDS = {"osquery-historical", "pcap-derived", "ac-hunter"}


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


def _load_source_module(name: str, path: Path) -> Any:
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise ValueError(f"source module could not be loaded: {path.name}")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _valid_field_set(value: Any) -> bool:
    return isinstance(value, set) and all(
        isinstance(field, str) and field for field in value
    )


def load_pcap_field_catalog(policy_path: Path) -> dict[str, set[str]]:
    """Read exact result projections from the local derived-PCAP policy."""
    module = _load_source_module(
        "onion_sentinel_skill_field_catalog_pcap",
        policy_path,
    )
    operations = getattr(module, "OUTPUT_FIELDS_BY_OPERATION", None)
    coverage = getattr(module, "COVERAGE_SCALAR_FIELDS", None)
    if not isinstance(operations, dict) or not _valid_field_set(coverage):
        raise ValueError("derived-PCAP field policy is unavailable")
    if any(not _valid_field_set(fields) for fields in operations.values()):
        raise ValueError("derived-PCAP field policy is invalid")
    catalog = {str(name): set(fields) for name, fields in operations.items()}
    catalog["coverage"] = set(coverage)
    missing = sorted(set(TEMPLATE_PCAP_OPERATIONS.values()) - set(catalog))
    if missing:
        raise ValueError("derived-PCAP policy is missing: " + ", ".join(missing))
    return catalog


def _named_function(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    return next(
        (
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ),
        None,
    )


def _returned_dict(function: ast.FunctionDef | None) -> ast.Dict | None:
    if function is None:
        return None
    value = next(
        (node.value for node in ast.walk(function) if isinstance(node, ast.Return)),
        None,
    )
    return value if isinstance(value, ast.Dict) else None


def _constant_dict_keys(value: ast.Dict | None) -> set[str] | None:
    if value is None or any(
        not isinstance(key, ast.Constant) or not isinstance(key.value, str)
        for key in value.keys
    ):
        return None
    return {str(key.value) for key in value.keys}


def load_ac_hunter_projection_catalog(projection_path: Path) -> set[str]:
    """Extract stable top-level snapshot keys without importing runtime code."""
    try:
        tree = ast.parse(projection_path.read_text(encoding="utf-8"))
    except SyntaxError as error:
        raise ValueError("AC Hunter projection could not be parsed") from error
    keys = _constant_dict_keys(
        _returned_dict(_named_function(tree, "compose_collection"))
    )
    if keys is None:
        raise ValueError("AC Hunter compose_collection projection is unavailable")
    return keys


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
) -> tuple[
    dict[str, Any], dict[str, set[str]], dict[str, set[str]], set[str]
]:
    fixture_catalog = fixture.get("field_catalog")
    if not isinstance(fixture_catalog, dict):
        raise ValueError("field_catalog must be an object")
    return (
        fixture_catalog,
        load_wrapper_field_catalog(wrapper_path),
        load_pcap_field_catalog(DEFAULT_PCAP_POLICY),
        load_ac_hunter_projection_catalog(DEFAULT_AC_HUNTER_PROJECTION),
    )


def _template_catalog(
    template: dict[str, Any],
    fixture_catalog: dict[str, Any],
    wrapper_catalog: dict[str, set[str]],
    pcap_catalog: dict[str, set[str]],
    ac_hunter_catalog: set[str],
) -> tuple[set[str], str]:
    template_id = str(template["id"])
    wrapper_pack = TEMPLATE_PACKS.get(template_id)
    if wrapper_pack:
        return (
            wrapper_catalog[wrapper_pack],
            f"security-onion-wrapper:{wrapper_pack}",
        )
    pcap_operation = TEMPLATE_PCAP_OPERATIONS.get(template_id)
    if pcap_operation:
        return (
            pcap_catalog[pcap_operation],
            f"pcap-derived-policy:{pcap_operation}",
        )
    ac_hunter_projection = TEMPLATE_AC_HUNTER_PROJECTIONS.get(template_id)
    if ac_hunter_projection:
        return (
            ac_hunter_catalog,
            f"ac-hunter-projection:{ac_hunter_projection}",
        )
    if template.get("backend") in REPOSITORY_BACKENDS:
        raise ValueError(f"unmapped repository-backed template: {template_id}")
    return (
        set(fixture_catalog.get(template["backend"], [])),
        f"synthetic-fixture:{template['backend']}",
    )


def _mapping_gaps(
    actual: list[str],
    manifests: dict[str, dict[str, Any]],
    fixture_catalog: dict[str, Any],
    wrapper_catalog: dict[str, set[str]],
    pcap_catalog: dict[str, set[str]],
    ac_hunter_catalog: set[str],
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for skill_id in actual:
        manifest = manifests[skill_id]
        for template in manifest["query_templates"]:
            available, provenance = _template_catalog(
                template,
                fixture_catalog,
                wrapper_catalog,
                pcap_catalog,
                ac_hunter_catalog,
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
    pcap_catalog: dict[str, set[str]],
    ac_hunter_catalog: set[str],
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
        pcap_catalog,
        ac_hunter_catalog,
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
    pcap_catalog: dict[str, set[str]],
    ac_hunter_catalog: set[str],
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
            pcap_catalog,
            ac_hunter_catalog,
        )
        passed += int(result["passed"])
        results.append(result)
    return results, passed


def _valid_evidence_result(result: dict[str, Any]) -> bool:
    refs = result.get("evidence_refs")
    return (
        result.get("source_supported") is True
        and result.get("mapping_compatible") is True
        and isinstance(result.get("complete"), bool)
        and isinstance(result.get("truncated"), bool)
        and isinstance(refs, list)
        and all(isinstance(ref, str) and ref for ref in refs)
        and isinstance(result.get("rows"), list)
        and result.get("claim_kind") in {"observation", "inference"}
    )


def _evidence_unavailable(result: dict[str, Any]) -> bool:
    return (
        result.get("source_supported") is False
        or result.get("mapping_compatible") is False
        or result.get("status") in {"failed", "rejected", "unavailable"}
    )


def _fact_state(result: Any) -> str:
    if not isinstance(result, dict):
        return "unverified"
    if _evidence_unavailable(result):
        return "unavailable"
    if result.get("status") != "success" or not _valid_evidence_result(result):
        return "unverified"
    if not result["complete"] or result["truncated"] or not result["evidence_refs"]:
        return "unverified"
    return "inferred" if result["claim_kind"] == "inference" else "observed"


def _negative_evidence_allowed(result: Any, fact_state: str) -> bool:
    return (
        fact_state == "observed"
        and isinstance(result, dict)
        and result.get("rows") == []
    )


def _evaluate_evidence_case(case: Any) -> dict[str, Any]:
    if not isinstance(case, dict):
        raise ValueError("evidence replay case must be an object")
    result = case.get("result")
    fact_state = _fact_state(result)
    negative_allowed = _negative_evidence_allowed(result, fact_state)
    expected_state = str(case.get("expected_fact_state") or "")
    expected_negative = case.get("expected_negative_evidence_allowed")
    return {
        "id": str(case.get("id") or ""),
        "category": str(case.get("category") or ""),
        "fact_state": fact_state,
        "negative_evidence_allowed": negative_allowed,
        "passed": (
            fact_state == expected_state
            and negative_allowed is expected_negative
        ),
    }


def _evaluate_evidence_cases(cases: Any) -> tuple[list[dict[str, Any]], int]:
    if cases is None:
        return [], 0
    if not isinstance(cases, list):
        raise ValueError("evidence_cases must be a list")
    results = [_evaluate_evidence_case(case) for case in cases]
    return results, sum(int(result["passed"]) for result in results)


def _evaluation_result(
    manifests: dict[str, dict[str, Any]],
    results: list[dict[str, Any]],
    passed: int,
    evidence_results: list[dict[str, Any]],
    evidence_passed: int,
) -> dict[str, Any]:
    return {
        "schema": "onion-sentinel-skill-offline-replay-result-v1",
        "simulation_only": True,
        "query_execution": False,
        "candidate_activation": False,
        "field_catalog": {
            "security_onion": "governed-wrapper-pack-projections",
            "pcap_derived": "repository-derived-policy-projections",
            "ac_hunter": "repository-normalized-snapshot-projection",
        },
        "candidate_count": len(manifests),
        "case_count": len(results),
        "passed_count": passed,
        "failed_count": len(results) - passed,
        "evidence_case_count": len(evidence_results),
        "evidence_passed_count": evidence_passed,
        "evidence_failed_count": len(evidence_results) - evidence_passed,
        "passed": (
            passed == len(results)
            and len(results) > 0
            and evidence_passed == len(evidence_results)
        ),
        "results": results,
        "evidence_results": evidence_results,
    }


def evaluate(
    candidate_dir: Path,
    fixture_path: Path,
    wrapper_path: Path = DEFAULT_SECURITY_ONION_WRAPPER,
) -> dict[str, Any]:
    fixture = _load_fixture(fixture_path)
    manifests = _load_candidates(candidate_dir)
    records = _shadow_records(manifests)
    fixture_catalog, wrapper_catalog, pcap_catalog, ac_hunter_catalog = (
        _field_catalogs(fixture, wrapper_path)
    )
    results, passed = _evaluate_cases(
        fixture.get("cases", []),
        records,
        manifests,
        fixture_catalog,
        wrapper_catalog,
        pcap_catalog,
        ac_hunter_catalog,
    )
    evidence_results, evidence_passed = _evaluate_evidence_cases(
        fixture.get("evidence_cases")
    )
    return _evaluation_result(
        manifests,
        results,
        passed,
        evidence_results,
        evidence_passed,
    )


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
