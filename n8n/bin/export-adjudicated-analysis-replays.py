#!/usr/bin/env python3
"""Export append-only analyst adjudications into a private replay suite.

The resulting file contains production evidence and must remain local. It is
written mode 0600 below the runtime corpus by default and is never suitable for
source control without a separate, explicit sanitization review.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
DEFAULT_PROMPT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
DEFAULT_OUT = HOME / "n8n-local" / "soc-alerts" / "evaluations" / "adjudicated-replays.json"
DEFAULT_RUNNER = Path(__file__).resolve().with_name("run-local-ai-analysis.py")
REPLAY_SCHEMA = "onion-sentinel-analysis-replays-v1"
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_PROMPT_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_REFS = 2048
MAX_EVIDENCE_REF_LENGTH = 512
FACTORED_VALUES = {
    "event_status": {"observed", "not_observed", "unknown"},
    "detection_validity": {
        "matched_intent", "logic_error", "parser_error", "intel_error",
        "not_applicable", "unknown",
    },
    "activity_disposition": {
        "malicious", "suspicious", "authorized_benign", "benign", "unknown",
    },
    "handling": {"contain", "escalate", "investigate", "monitor", "no_action"},
}
EVIDENCE_SECTION_KEYS = (
    "alert",
    "grouped_alert_context",
    "public_enrichment",
    "pcap_evidence",
    "detection_validation",
    "asset_context",
    "analyst_state",
    "prior_analyses",
    "related_alerts",
    "correlated_alert_context",
    "recent_notifications",
    "agent_memory",
    "latest_daily_rollup",
    "incident_response_evidence",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export private production-shaped replays from analyst adjudications"
    )
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--analysis-dir", type=Path, default=DEFAULT_ANALYSIS_DIR)
    parser.add_argument("--prompt-dir", type=Path, default=DEFAULT_PROMPT_DIR)
    parser.add_argument("--runner", type=Path, default=DEFAULT_RUNNER)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--since", help="Optional ISO-8601 lower bound on adjudication created_at")
    args = parser.parse_args()
    if args.limit < 1 or args.limit > 10000:
        parser.error("--limit must be between 1 and 10000")
    return args


def load_runner(path: Path):
    bin_dir = str(path.resolve().parent)
    if bin_dir not in sys.path:
        sys.path.insert(0, bin_dir)
    spec = importlib.util.spec_from_file_location("onion_sentinel_adjudication_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load analysis runner: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bounded_json(path: Path, maximum: int) -> dict[str, Any]:
    size = path.stat().st_size
    if size > maximum:
        raise ValueError(f"{path.name} exceeds its replay export byte limit")
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError(f"{path.name} grew beyond its replay export byte limit")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} JSON root must be an object")
    return payload


def confined_path(raw_path: object, allowed_root: Path) -> Path:
    candidate = Path(str(raw_path or "")).expanduser().resolve()
    root = allowed_root.expanduser().resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"artifact path is outside {root}")
    return candidate


def latest_adjudications(conn: sqlite3.Connection, since: str | None, limit: int) -> list[sqlite3.Row]:
    columns = {
        str(item["name"] if isinstance(item, sqlite3.Row) else item[1])
        for item in conn.execute("PRAGMA table_info(analyst_adjudications)").fetchall()
    }
    optional = (
        "rationale",
        "evidence_gap",
        "next_action",
        "event_status",
        "detection_validity",
        "activity_disposition",
        "handling",
        "duplicate_of",
    )
    optional_select = ",\n               ".join(
        f"a.{name}" if name in columns else f"NULL AS {name}"
        for name in optional
    )
    where = "AND a.created_at >= ?" if since else ""
    params: list[object] = [since] if since else []
    params.append(limit)
    return conn.execute(
        f"""
        SELECT a.adjudication_id, a.analysis_id, a.outcome_override,
               a.confidence AS adjudication_confidence, a.created_at,
               {optional_select},
               r.response_json, r.artifact_path, r.alert_id, r.agent_role
        FROM analyst_adjudications AS a
        JOIN ai_analysis_runs AS r ON r.analysis_id = a.analysis_id
        WHERE NOT EXISTS (
          SELECT 1
          FROM analyst_adjudications AS newer
          WHERE newer.analysis_id = a.analysis_id
            AND (
              newer.created_at > a.created_at
              OR (newer.created_at = a.created_at AND newer.rowid > a.rowid)
            )
        )
        {where}
        ORDER BY a.created_at DESC, a.rowid DESC
        LIMIT ?
        """,
        params,
    ).fetchall()


def adjudication_verdict_contradictions(
    runner: Any,
    outcome: str,
    explicit_factors: dict[str, Any],
) -> list[str]:
    """Return contradictions using the same deterministic mapping as runtime."""
    supplied = {
        key: value
        for key, value in explicit_factors.items()
        if value not in (None, "")
    }
    if not supplied:
        return []
    factors = dict(runner.legacy_verdict_factors(outcome))
    factors.update(supplied)
    derived = runner.derive_legacy_detection_outcome(factors)
    contradictions: list[str] = []
    if derived != outcome:
        contradictions.append(f"factored verdict derives {derived}, not {outcome}")
    event_status = str(factors.get("event_status") or "unknown")
    validity = str(factors.get("detection_validity") or "unknown")
    disposition = str(factors.get("activity_disposition") or "unknown")
    handling = str(factors.get("handling") or "investigate")
    duplicate_of = str(factors.get("duplicate_of") or "").strip()
    if event_status == "not_observed" and validity == "matched_intent":
        contradictions.append(
            "an unobserved event cannot be a validated detection-intent match"
        )
    if disposition == "malicious" and handling in {"monitor", "no_action"}:
        contradictions.append(
            "malicious activity cannot use monitor/no_action handling"
        )
    if disposition in {"authorized_benign", "benign"} and handling == "contain":
        contradictions.append("benign or authorized activity cannot use contain handling")
    if duplicate_of and handling in {"contain", "escalate"}:
        contradictions.append(
            "a duplicate record cannot independently authorize containment or escalation"
        )
    if outcome.startswith("false_positive_"):
        if disposition in {"malicious", "suspicious"}:
            contradictions.append(
                "a false-positive label cannot classify activity as malicious or suspicious"
            )
        if handling in {"contain", "escalate"}:
            contradictions.append(
                "a false-positive label cannot authorize containment or escalation"
            )
    return contradictions


def _add_evidence_reference(
    references: set[str], *parts: object,
) -> None:
    cleaned = [
        " ".join(("" if part is None else str(part)).strip().split())
        for part in parts
    ]
    if not cleaned or any(not part for part in cleaned):
        return
    value = ":".join(cleaned)[:MAX_EVIDENCE_REF_LENGTH]
    if value:
        references.add(value)


def _add_alert_group_references(
    prompt_package: dict[str, Any], references: set[str],
) -> None:
    alert = prompt_package.get("alert")
    if isinstance(alert, dict):
        _add_evidence_reference(references, "alert", alert.get("alert_id"))

    grouped = prompt_package.get("grouped_alert_context")
    if isinstance(grouped, dict):
        timeline = grouped.get("timeline")
        for item in timeline if isinstance(timeline, list) else []:
            if isinstance(item, dict):
                _add_evidence_reference(
                    references, "grouped_alert_context", item.get("alert_id")
                )


def _add_enrichment_pcap_references(
    prompt_package: dict[str, Any], references: set[str],
) -> None:
    enrichment = prompt_package.get("public_enrichment")
    if isinstance(enrichment, dict):
        records = enrichment.get("records")
        for item in records if isinstance(records, list) else []:
            if not isinstance(item, dict):
                continue
            _add_evidence_reference(
                references,
                "public_enrichment",
                item.get("source"),
                item.get("indicator_type"),
                item.get("indicator"),
            )

    pcap = prompt_package.get("pcap_evidence")
    if isinstance(pcap, dict):
        parsed = pcap.get("parsed_evidence")
        for item in parsed if isinstance(parsed, list) else []:
            if isinstance(item, dict):
                _add_evidence_reference(
                    references, "pcap_evidence", item.get("request_id")
                )


def _add_validation_asset_references(
    prompt_package: dict[str, Any], references: set[str],
) -> None:
    validation = prompt_package.get("detection_validation")
    if isinstance(validation, dict):
        rule = validation.get("rule")
        if isinstance(rule, dict):
            _add_evidence_reference(
                references,
                "detection_validation",
                rule.get("sid"),
                rule.get("revision"),
            )
        playbook = validation.get("playbook")
        if isinstance(playbook, dict):
            _add_evidence_reference(
                references,
                "detection_validation",
                "playbook",
                playbook.get("id"),
            )

    assets = prompt_package.get("asset_context")
    if isinstance(assets, dict):
        matched = assets.get("matched_assets")
        for item in matched if isinstance(matched, list) else []:
            if isinstance(item, dict):
                _add_evidence_reference(
                    references, "asset_context", item.get("asset_id")
                )


def _add_prior_related_references(
    prompt_package: dict[str, Any], references: set[str],
) -> None:
    prior = prompt_package.get("prior_analyses")
    for item in prior if isinstance(prior, list) else []:
        if isinstance(item, dict):
            _add_evidence_reference(
                references, "prior_analyses", item.get("analysis_id")
            )

    related = prompt_package.get("related_alerts")
    for item in related if isinstance(related, list) else []:
        if isinstance(item, dict):
            _add_evidence_reference(
                references, "related_alerts", item.get("alert_id")
            )


def _add_correlation_references(
    prompt_package: dict[str, Any], references: set[str],
) -> None:
    correlations = prompt_package.get("correlated_alert_context")
    if isinstance(correlations, dict):
        candidates = correlations.get("candidates")
        for item in candidates if isinstance(candidates, list) else []:
            if isinstance(item, dict):
                _add_evidence_reference(
                    references,
                    "correlated_alert_context",
                    item.get("group_id"),
                )


def _add_incident_references(
    prompt_package: dict[str, Any], references: set[str],
) -> None:
    incident = prompt_package.get("incident_response_evidence")
    if isinstance(incident, dict):
        response = incident.get("security_onion_response")
        if isinstance(response, dict):
            results = response.get("results")
            for item in results if isinstance(results, list) else []:
                if not isinstance(item, dict):
                    continue
                _add_evidence_reference(
                    references,
                    "incident_response_evidence",
                    item.get("pack"),
                    item.get("window_index"),
                )
            osquery_results = response.get("osquery_results")
            for item in osquery_results if isinstance(osquery_results, list) else []:
                if isinstance(item, dict):
                    _add_evidence_reference(
                        references,
                        "incident_response_evidence",
                        "osquery",
                        item.get("pack"),
                    )


def evidence_reference_catalog(prompt_package: dict[str, Any]) -> list[str]:
    """Build a bounded catalog of citeable references from supplied evidence."""
    references: set[str] = set()
    for key in EVIDENCE_SECTION_KEYS:
        if key in prompt_package and prompt_package[key] is not None:
            _add_evidence_reference(references, key)
    _add_alert_group_references(prompt_package, references)
    _add_enrichment_pcap_references(prompt_package, references)
    _add_validation_asset_references(prompt_package, references)
    _add_prior_related_references(prompt_package, references)
    _add_correlation_references(prompt_package, references)
    _add_incident_references(prompt_package, references)
    return sorted(references)[:MAX_EVIDENCE_REFS]


def _load_replay_material(
    item: sqlite3.Row,
    *,
    analysis_root: Path,
    prompt_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    artifact_path = confined_path(item["artifact_path"], analysis_root)
    artifact = bounded_json(artifact_path, MAX_ARTIFACT_BYTES)
    prompt_path = confined_path(artifact.get("prompt_package"), prompt_root)
    prompt_package = bounded_json(prompt_path, MAX_PROMPT_BYTES)
    if prompt_package.get("package_type") != "soc-ai-investigation-prompt":
        raise ValueError("unexpected prompt package type")
    response_text = str(item["response_json"] or "{}")
    if len(response_text.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise ValueError("analysis response_json exceeds its replay export byte limit")
    response = json.loads(response_text)
    if not isinstance(response, dict):
        raise ValueError("analysis response_json root must be an object")
    return prompt_package, response


def _explicit_adjudication_factors(
    item: sqlite3.Row,
) -> dict[str, Any]:
    factors: dict[str, Any] = {}
    for field, allowed in FACTORED_VALUES.items():
        value = str(item[field] or "").strip()
        if not value:
            continue
        if value not in allowed:
            raise ValueError(f"analyst adjudication has invalid {field}")
        factors[field] = value
    return factors


def _add_adjudication_duplicate(
    item: sqlite3.Row,
    expected: dict[str, Any],
    explicit_factors: dict[str, Any],
) -> None:
    duplicate_value = item["duplicate_of"]
    if duplicate_value is None:
        if "handling" in expected or "event_status" in expected:
            expected["duplicate_of"] = None
        return
    normalized_duplicate = str(duplicate_value).strip()[:256]
    if not normalized_duplicate:
        raise ValueError("analyst adjudication has an empty duplicate_of")
    expected["duplicate_of"] = normalized_duplicate
    explicit_factors["duplicate_of"] = normalized_duplicate


def _expected_adjudication(
    runner: Any,
    item: sqlite3.Row,
) -> dict[str, Any]:
    outcome = runner.normalized_detection_outcome(item["outcome_override"])
    expected: dict[str, Any] = {"detection_outcome": outcome}
    explicit_factors = _explicit_adjudication_factors(item)
    expected.update(explicit_factors)
    _add_adjudication_duplicate(item, expected, explicit_factors)
    contradictions = adjudication_verdict_contradictions(
        runner,
        outcome,
        explicit_factors,
    )
    if contradictions:
        raise ValueError(
            "analyst adjudication has contradictory authoritative labels: "
            + "; ".join(contradictions)
        )
    return expected


def _bounded_row_text(
    item: sqlite3.Row,
    key: str,
    limit: int,
) -> str:
    return str(item[key] or "")[:limit]


def _adjudication_provenance(
    item: sqlite3.Row,
    expected: dict[str, Any],
) -> dict[str, Any]:
    return {
        "adjudication_id": _bounded_row_text(item, "adjudication_id", 160),
        "analysis_id": _bounded_row_text(item, "analysis_id", 160),
        "created_at": _bounded_row_text(item, "created_at", 80),
        "confidence": _bounded_row_text(item, "adjudication_confidence", 16),
        "agent_role": _bounded_row_text(item, "agent_role", 64),
        "rationale": _bounded_row_text(item, "rationale", 4000),
        "evidence_gap": _bounded_row_text(item, "evidence_gap", 2000),
        "next_action": _bounded_row_text(item, "next_action", 2000),
        "factored_labels": [
            field for field in (*FACTORED_VALUES, "duplicate_of")
            if field in expected
        ],
    }


def _completed_reviewer_response(
    response: dict[str, Any],
) -> dict[str, Any] | None:
    second_opinion = response.get("_second_opinion")
    if (
        isinstance(second_opinion, dict)
        and second_opinion.get("status") == "completed"
        and isinstance(second_opinion.get("response"), dict)
    ):
        return second_opinion["response"]
    return None


def replay_case(
    runner: Any,
    item: sqlite3.Row,
    *,
    analysis_root: Path,
    prompt_root: Path,
) -> dict[str, Any]:
    prompt_package, response = _load_replay_material(
        item,
        analysis_root=analysis_root,
        prompt_root=prompt_root,
    )
    expected = _expected_adjudication(runner, item)
    case_id = f"adjudication-{str(item['adjudication_id'] or '')[:160]}"
    result = {
        "case_id": case_id,
        "label_source": "analyst_adjudication",
        "label_provenance": _adjudication_provenance(item, expected),
        "expected": expected,
        "allowed_evidence_refs": evidence_reference_catalog(prompt_package),
        "prompt_package": prompt_package,
        "primary_response": response,
    }
    reviewer_response = _completed_reviewer_response(response)
    if reviewer_response is not None:
        result["reviewer_response"] = reviewer_response
    return result


def atomic_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    args = parse_args()
    if not args.db.exists():
        raise SystemExit(f"alert-store database not found: {args.db}")
    runner = load_runner(args.runner)
    connection = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        items = latest_adjudications(connection, args.since, args.limit)
    except sqlite3.OperationalError as error:
        raise SystemExit(f"analyst adjudication schema is unavailable: {error}") from error
    finally:
        connection.close()
    cases = []
    skipped = []
    for item in items:
        try:
            cases.append(
                replay_case(
                    runner,
                    item,
                    analysis_root=args.analysis_dir,
                    prompt_root=args.prompt_dir,
                )
            )
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
            skipped.append(
                {
                    "adjudication_id": str(item["adjudication_id"] or "")[:160],
                    "reason": str(error)[:500],
                }
            )
    payload = {
        "schema": REPLAY_SCHEMA,
        "version": 1,
        "suite_name": "private-analyst-adjudications",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "sensitive_local_artifact": True,
        "source_database": args.db.name,
        "cases": cases,
        "skipped": skipped,
    }
    atomic_private_json(args.out, payload)
    print(
        json.dumps(
            {
                "out": str(args.out),
                "exported_cases": len(cases),
                "skipped_cases": len(skipped),
                "mode": oct(args.out.stat().st_mode & 0o777),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
