#!/usr/bin/env python3
"""Collect one policy-brokered Elastic/OQL investigation pivot batch.

Both SOC Analyst and Incident Responder use this client.  The caller supplies
an untrusted model proposal and a trusted local authorization context.  Only
the normalized, authorization-bound protocol is sent through the existing
incident-evidence forced SSH path.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from bounded_process import BoundedProcessError, run_bounded_command
from investigation_query_contract import (
    INVESTIGATION_QUERY_CONTRACT,
    InvestigationQueryContractError,
    authorize_investigation_query_request,
    canonical_digest,
    validate_investigation_query_response,
)


HOME = Path.home()
DEFAULT_CONFIG = HOME / "n8n-local" / "config" / "incident-evidence.json"
DEFAULT_OUT = HOME / "n8n-local" / "soc-alerts" / "investigation-pivots"
MAX_CONFIG_BYTES = 64 * 1024
MAX_INPUT_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_COMPACT_HITS_PER_QUERY = 20
MAX_COMPACT_SOURCE_BYTES = 12 * 1024


class InvestigationPivotClientError(RuntimeError):
    """A local policy, transport, or persistence step failed."""


def load_config(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_CONFIG_BYTES:
        raise InvestigationPivotClientError("incident evidence config exceeds its byte limit")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise InvestigationPivotClientError("incident evidence config root must be an object")
    for key in ("host", "ssh_user", "ssh_key", "known_hosts"):
        if not str(value.get(key) or "").strip():
            raise InvestigationPivotClientError(f"incident evidence config is missing {key}")
    return value


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
    ) as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    temporary.chmod(0o600)
    os.replace(temporary, path)


def _compact_source(source: object) -> dict[str, Any]:
    if not isinstance(source, dict):
        return {}
    encoded = json.dumps(source, separators=(",", ":"), sort_keys=True).encode()
    if len(encoded) <= MAX_COMPACT_SOURCE_BYTES:
        return source
    compact: dict[str, Any] = {}
    used = 0
    for key in sorted(source):
        candidate = source[key]
        candidate_encoded = json.dumps(
            {key: candidate},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        if len(candidate_encoded) > 2048 or used + len(candidate_encoded) > 8192:
            continue
        compact[key] = candidate
        used += len(candidate_encoded)
    compact["_projection"] = {
        "truncated": True,
        "full_source_bytes": len(encoded),
        "full_source_sha256": hashlib.sha256(encoded).hexdigest(),
    }
    return compact


def _model_evidence(response: dict[str, Any]) -> dict[str, Any]:
    results = []
    gaps = []
    semantic = response.get("semantic_validity")
    controls_valid = bool(
        isinstance(semantic, dict)
        and semantic.get("controls_valid") is True
    )
    if not controls_valid:
        gaps.append({
            "query_id": "broker-controls",
            "status": "invalid_response",
            "error": (
                "Security Onion positive/negative controls did not validate; "
                "all returned event bodies were withheld from model evidence"
            ),
        })
    for result in response["results"]:
        status = result["status"]
        if status != "ok":
            gaps.append({
                "query_id": result["query_id"],
                "status": status,
                "error": str(result.get("error") or "")[:1000],
            })
        compact_hits = []
        if controls_valid:
            compact_hits = [
                {
                    "id": hit["id"],
                    "index": hit["index"],
                    "source": _compact_source(hit["source"]),
                }
                for hit in result.get("hits", [])[:MAX_COMPACT_HITS_PER_QUERY]
            ]
        selected_query = (
            result["oql_equivalent"]
            if result["dialect"] == "oql"
            else result["kql_equivalent"]
        )
        results.append({
            "query_id": result["query_id"],
            "dialect": result["dialect"],
            "pack": result["pack"],
            "purpose": result["purpose"],
            "aggregation": result["aggregation"],
            "window": result["window"],
            "observables": result["observables"],
            "observable_provenance": result["observable_provenance"],
            "status": status,
            "semantic_valid": result["semantic_valid"],
            "total_hits": result["total_hits"],
            "total_hits_relation": result["total_hits_relation"],
            "returned_hits": result["returned_hits"],
            "truncated": result["truncated"],
            "model_returned_hits": len(compact_hits),
            "model_projection_truncated": len(result.get("hits", [])) > len(compact_hits),
            "query": selected_query,
            "query_digest": result["query_digest"],
            "execution_backend": result["execution_backend"],
            "execution_semantics": result["execution_semantics"],
            "hits": compact_hits,
        })
    return {
        "query_contract": INVESTIGATION_QUERY_CONTRACT,
        "batch_id": response["batch_id"],
        "complete": response["complete"],
        "partial": response["partial"],
        "read_only": True,
        "controls_valid": controls_valid,
        "results": results,
        "evidence_gaps": gaps,
    }


def _query_audit(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a bounded, presentation-ready audit without duplicating hits."""
    audits = []
    for result in response["results"]:
        audits.append({
            "query_id": result["query_id"],
            "dialect": result["dialect"],
            "pack": result["pack"],
            "purpose": result["purpose"],
            "aggregation": result["aggregation"],
            "window": result["window"],
            "observables": result["observables"],
            "observable_provenance": result["observable_provenance"],
            "requested_size": result["size"],
            "execution_backend": result["execution_backend"],
            "execution_semantics": result["execution_semantics"],
            "index_scope": result["index_scope"],
            "query_endpoint": result["query_endpoint"],
            "query_dsl": result["query_dsl"],
            "query_digest": result["query_digest"],
            "execution_digest": result["execution_digest"],
            "request_item_digest": result["request_item_digest"],
            "kql_equivalent": result["kql_equivalent"],
            "kql_digest": result["kql_digest"],
            "oql_equivalent": result["oql_equivalent"],
            "oql_digest": result["oql_digest"],
            "status": result["status"],
            "semantic_valid": result["semantic_valid"],
            "total_hits": result["total_hits"],
            "total_hits_relation": result["total_hits_relation"],
            "returned_hits": result["returned_hits"],
            "truncated": result["truncated"],
            "duration_ms": result["duration_ms"],
            "timed_out": result["timed_out"],
            "took_ms": result["took_ms"],
            "shards": result["shards"],
            "error": str(result.get("error") or "")[:1000],
        })
    return audits


def _transport(
    request: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    key = Path(os.path.expandvars(os.path.expanduser(str(config["ssh_key"]))))
    known_hosts = Path(
        os.path.expandvars(os.path.expanduser(str(config["known_hosts"])))
    )
    try:
        connect_timeout = int(config.get("connect_timeout_seconds", 20))
        timeout = float(config.get("timeout_seconds", 420))
        max_response = int(config.get("max_response_bytes", MAX_RESPONSE_BYTES))
        max_stderr = int(config.get("max_stderr_bytes", 256 * 1024))
    except (TypeError, ValueError) as exc:
        raise InvestigationPivotClientError(
            "incident evidence transport limits are invalid"
        ) from exc
    command = [
        "/usr/bin/ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-i",
        str(key),
        f"{config['ssh_user']}@{config['host']}",
    ]
    proc = run_bounded_command(
        command,
        stdin_text=json.dumps(request, separators=(",", ":"), sort_keys=True),
        timeout_seconds=timeout,
        max_stdout_bytes=min(max_response, MAX_RESPONSE_BYTES),
        max_stderr_bytes=min(max_stderr, 256 * 1024),
    )
    if proc.returncode != 0:
        raise InvestigationPivotClientError(
            "restricted investigation query transport failed "
            f"rc={proc.returncode}: {proc.stderr[:1000]}"
        )
    try:
        response = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise InvestigationPivotClientError(
            "restricted investigation query response was invalid JSON"
        ) from exc
    if not isinstance(response, dict):
        raise InvestigationPivotClientError(
            "restricted investigation query response root was not an object"
        )
    return response


def collect_investigation_pivots(
    proposal: object,
    authorization_context: object,
    *,
    config_path: Path | str | dict[str, Any] = DEFAULT_CONFIG,
    out_dir: Path | str = DEFAULT_OUT,
    persist: bool = True,
) -> dict[str, Any]:
    """Authorize, execute, validate, and optionally persist one pivot batch."""
    request = authorize_investigation_query_request(proposal, authorization_context)
    encoded_request = json.dumps(
        request,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    if len(encoded_request) > 16 * 1024:
        raise InvestigationPivotClientError(
            "authorized investigation query request exceeds the forced-command limit"
        )
    config = (
        dict(config_path)
        if isinstance(config_path, dict)
        else load_config(Path(config_path))
    )
    response = _transport(request, config)
    validated_response = validate_investigation_query_response(response, request)
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    model_evidence = _model_evidence(validated_response)
    query_audit = _query_audit(validated_response)
    audit = {
        "query_contract": INVESTIGATION_QUERY_CONTRACT,
        "authorized_request": request,
        "authorized_request_digest": canonical_digest(request),
        "authorization_context_digest": request["authorization"]["context_digest"],
        "security_onion_response": validated_response,
        "security_onion_response_digest": canonical_digest(validated_response),
        "query_audit": query_audit,
    }
    artifact: dict[str, Any] = {
        "schema": INVESTIGATION_QUERY_CONTRACT,
        "generated_at": generated_at,
        "case_id": request["authorization"]["case_id"],
        "group_id": request["authorization"]["group_id"],
        "actor_role": request["authorization"]["actor_role"],
        "batch_id": request["batch_id"],
        "complete": validated_response["complete"],
        "partial": validated_response["partial"],
        "model_evidence": model_evidence,
        "query_audit": query_audit,
        "audit": audit,
    }
    if persist:
        destination = (
            Path(out_dir)
            / request["authorization"]["case_id"]
            / f"{request['batch_id']}.json"
        )
        _atomic_json(destination, artifact)
        artifact["artifact_path"] = str(destination)
    return artifact


def _read_json(path: Path, label: str) -> object:
    raw = path.read_bytes()
    if len(raw) > MAX_INPUT_BYTES:
        raise InvestigationPivotClientError(f"{label} exceeds its byte limit")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvestigationPivotClientError(f"{label} is invalid JSON") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect a bounded policy-brokered Elastic/OQL pivot batch"
    )
    parser.add_argument("--request-file", type=Path, required=True)
    parser.add_argument("--authorization-context-file", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--no-persist", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        artifact = collect_investigation_pivots(
            _read_json(args.request_file, "investigation proposal"),
            _read_json(
                args.authorization_context_file,
                "investigation authorization context",
            ),
            config_path=args.config,
            out_dir=args.out_dir,
            persist=not args.no_persist,
        )
        print(json.dumps(artifact, separators=(",", ":"), sort_keys=True))
        return 0
    except (
        BoundedProcessError,
        InvestigationPivotClientError,
        InvestigationQueryContractError,
        OSError,
        ValueError,
    ) as exc:
        print(f"investigation pivot collection failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
