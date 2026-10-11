"""Bounded evidence dispatch owner."""
from __future__ import annotations

import datetime as dt


import hashlib


import json

import glob

import importlib.machinery

import importlib.util





import subprocess



import time


from pathlib import Path




def osquery_binary(r) -> Path | None:
    """Return the managed Elastic Agent osqueryd without accepting a caller path."""
    candidates = sorted(
        glob.glob("/opt/Elastic/Agent/data/elastic-agent-*/components/osqueryd"),
        reverse=True,
    )
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file():
            return path
    return None


def execute_osquery_pack(r, binary: Path, pack_name: str) -> dict:
    """Run one reviewed query as ephemeral osqueryi and preserve its exact audit."""
    r.AUDIT_CONTEXT["osquery_query_count"] = int(
        r.AUDIT_CONTEXT.get("osquery_query_count", 0)
    ) + 1
    query = r.OSQUERY_PACKS[pack_name]
    digest = hashlib.sha256(query.encode("utf-8")).hexdigest()
    started = time.monotonic()
    base = {
        "pack": pack_name,
        "target": "security-onion-local-host",
        "query": query,
        "query_digest": digest,
    }
    try:
        proc = subprocess.run(
            ["osqueryi", "--disable_database", "--json", query],
            executable=str(binary),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=r.OSQUERY_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            **base,
            "status": "timeout",
            "total_rows": 0,
            "returned_rows": 0,
            "truncated": False,
            "duration_ms": r.OSQUERY_TIMEOUT_SECONDS * 1000,
            "rows": [],
        }
    duration_ms = round((time.monotonic() - started) * 1000)
    if len(proc.stdout) > r.MAX_OSQUERY_OUTPUT_BYTES:
        return {
            **base,
            "status": "output_limit",
            "total_rows": 0,
            "returned_rows": 0,
            "truncated": False,
            "duration_ms": duration_ms,
            "rows": [],
        }
    if proc.returncode != 0:
        return {
            **base,
            "status": "error",
            "total_rows": 0,
            "returned_rows": 0,
            "truncated": False,
            "duration_ms": duration_ms,
            "rows": [],
            "error": proc.stderr.decode("utf-8", "replace")[:1000],
        }
    try:
        parsed = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            **base,
            "status": "invalid_response",
            "total_rows": 0,
            "returned_rows": 0,
            "truncated": False,
            "duration_ms": duration_ms,
            "rows": [],
            "error": str(exc),
        }
    if not isinstance(parsed, list) or any(not isinstance(row, dict) for row in parsed):
        return {
            **base,
            "status": "invalid_response",
            "total_rows": 0,
            "returned_rows": 0,
            "truncated": False,
            "duration_ms": duration_ms,
            "rows": [],
            "error": "osquery result root must be an array of objects",
        }
    rows = parsed[:r.MAX_OSQUERY_ROWS]
    return {
        **base,
        "status": "ok",
        "total_rows": len(parsed),
        "returned_rows": len(rows),
        "truncated": len(parsed) > len(rows),
        "duration_ms": duration_ms,
        "rows": rows,
    }


def execute_pivot_batch(r, data: dict) -> int:
    request = r.validated_pivot_request(data)
    results = [
        r.execute_pivot_query(query)
        for query in request["queries"]
    ]
    controls = r.execute_controls(request["authorization"]["anchor"])
    validity = r.pivot_semantic_validity(results, controls)
    complete = validity["semantic_valid"]
    response = {
        "ok": True,
        "complete": complete,
        "partial": not complete,
        "read_only": True,
        "query_contract": r.INVESTIGATION_QUERY_CONTRACT,
        "batch_id": request["batch_id"],
        "request_digest": r.canonical_digest(request),
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z"),
        "results": results,
        "controls": controls,
        "semantic_validity": validity,
    }
    return r.emit_response(
        response,
        output_error="bounded investigation pivot response exceeded the output contract",
    )


def execute_dhcp_discovery(r, data: dict) -> int:
    """Route the fixed DHCP contract inside the existing read-only SSH lane."""
    helper_path = Path(r.__file__).resolve().with_name("export-dhcp-observations")
    if not helper_path.is_file():
        r.fail("DHCP discovery helper is unavailable", 3)
    loader = importlib.machinery.SourceFileLoader(
        "_onion_sentinel_dhcp_discovery",
        str(helper_path),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        r.fail("DHCP discovery helper could not be loaded", 3)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    try:
        response = module.execute_request(data)
    except ValueError as exc:
        r.fail(f"invalid DHCP discovery request: {exc}")
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        r.fail(f"DHCP discovery query failed: {exc}", 3)
    r.AUDIT_CONTEXT["helper_invocation_count"] = 1
    return r.emit_response(
        response,
        maximum_bytes=4 * 1024 * 1024,
        output_error="bounded DHCP discovery response exceeded the output contract",
    )


def execute_software_inventory(r, data: dict) -> int:
    """Route the fixed software contract inside the read-only evidence lane."""
    helper_path = Path(r.__file__).resolve().with_name(
        "export-software-observations"
    )
    if not helper_path.is_file():
        r.fail("software inventory helper is unavailable", 3)
    loader = importlib.machinery.SourceFileLoader(
        "_onion_sentinel_software_inventory",
        str(helper_path),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        r.fail("software inventory helper could not be loaded", 3)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    try:
        response = module.execute_request(data)
    except ValueError as exc:
        r.fail(f"invalid software inventory request: {exc}")
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        r.fail(f"software inventory query failed: {exc}", 3)
    r.AUDIT_CONTEXT["helper_invocation_count"] = 1
    return r.emit_response(
        response,
        maximum_bytes=4 * 1024 * 1024,
        output_error="bounded software inventory response exceeded the output contract",
    )


def main(r) -> int:
    if not r.SO_QUERY.is_file():
        r.fail("Security Onion query CLI is unavailable", 3)
    request_data = r.read_request()
    if (
        request_data.get("contract") == r.DHCP_DISCOVERY_CONTRACT
        or request_data.get("operation") == r.DHCP_DISCOVERY_OPERATION
    ):
        return r.execute_dhcp_discovery(request_data)
    if (
        request_data.get("contract") == r.SOFTWARE_INVENTORY_CONTRACT
        or request_data.get("operation") == r.SOFTWARE_INVENTORY_OPERATION
    ):
        return r.execute_software_inventory(request_data)
    if (
        request_data.get("query_contract") == r.INVESTIGATION_QUERY_CONTRACT
        or request_data.get("operation") == r.INVESTIGATION_QUERY_OPERATION
    ):
        return r.execute_pivot_batch(request_data)
    binary = r.osquery_binary()
    if binary is None:
        r.fail("managed Elastic Agent osqueryd is unavailable", 3)
    packs, osquery_packs, windows, observables, size, anchor = r.validated_request(request_data)
    results = []
    for window_index, window in enumerate(windows):
        for pack_name in packs:
            result = r.execute_pack(pack_name, window, observables, size)
            result.update({
                "window_index": window_index,
                "window": window,
                "kql_equivalent": r.kql_equivalent(
                    window,
                    pack_name,
                    observables,
                ),
            })
            results.append(result)
    osquery_results = [
        r.execute_osquery_pack(binary, pack_name)
        for pack_name in osquery_packs
    ]
    controls = r.execute_controls(anchor)
    validity = r.semantic_validity(results, osquery_results, controls)
    complete = validity["semantic_valid"]
    response = {
        # A failed evidence pack is an explicit investigative gap, not a
        # transport failure. Returning a successful protocol response lets the
        # incident worker preserve all other pack results and report the gap.
        "ok": True,
        "complete": complete,
        "partial": not complete,
        "read_only": True,
        "query_contract": r.QUERY_CONTRACT,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "observables": observables,
        "results": results,
        "osquery_results": osquery_results,
        "controls": controls,
        "semantic_validity": validity,
    }
    return r.emit_response(response)
