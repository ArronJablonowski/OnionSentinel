#!/usr/bin/env python3
"""Validate the source credential catalog and secret-free lifecycle inventory."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import stat
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "operations/security/credential-governance.json"
CATALOG_SCHEMA = "onion-sentinel-credential-catalog-v1"
INVENTORY_SCHEMA = "onion-sentinel-credential-inventory-v1"
RESULT_SCHEMA = "onion-sentinel-credential-governance-result-v1"
MAX_FILE_BYTES = 1024 * 1024
ENTRY_KEYS = frozenset({
    "id", "kind", "purpose", "owner", "storage_class", "bindings",
    "allowed_actions", "required_when", "creation_evidence",
    "expiration_policy", "rotation_policy", "revocation_procedure",
    "rollback_policy",
})
INVENTORY_KEYS = frozenset({"schema", "generated_at", "records"})
RECORD_KEYS = frozenset({
    "credential_id", "generation", "state", "created_at", "expires_at",
    "rotation_due_at", "storage_class", "allowed_actions",
    "predecessor_generation",
})
BINDING_PREFIXES = ("env:", "file:", "n8n-var:", "ssh:", "field:")
IDENTIFIER_RE = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*")
SECRET_MATERIAL_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:token|password|secret)=[^<\s][^\s]{7,}",
    re.IGNORECASE,
)
SENSITIVE_SUFFIXES = (
    "_TOKEN", "_PASSWORD", "_API_KEY", "_AUTH_KEY", "_API_SECRET",
    "_CHAT_ID", "_API_ID", "_ORGANIZATION_ID",
)
SENSITIVE_EXACT = frozenset({
    "N8N_POSTGRES_USER", "ALERT_STORE_POSTGRES_USER",
    "ONION_SENTINEL_EVALUATION_TOKEN",
})
SSH_BINDINGS = frozenset({
    "ssh:relay-to-security-onion-alert-poll",
    "ssh:relay-to-security-onion-pcap",
    "ssh:relay-to-security-onion-incident-evidence",
    "ssh:relay-to-security-onion-live-osquery",
    "ssh:mac-to-relay-live-osquery",
    "ssh:mac-to-relay-incident-evidence",
    "ssh:mac-to-relay-ac-hunter",
    "ssh:relay-to-mac-alert-intake",
    "ssh:relay-to-mac-pcap-intake",
})


def _bounded_json(path: Path) -> object:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES:
        raise ValueError("JSON source is not an admissible regular file")
    with path.open("rb") as handle:
        raw = handle.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("JSON source exceeds its byte budget")
    return json.loads(raw.decode("utf-8"))


def load_catalog(path: Path) -> dict:
    payload = _bounded_json(Path(path))
    if not isinstance(payload, dict):
        raise ValueError("credential catalog must be an object")
    return payload


def _environment_names(path: Path) -> set[str]:
    names = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name = line.split("=", 1)[0].strip()
        if name in SENSITIVE_EXACT or name.endswith(SENSITIVE_SUFFIXES):
            names.add(name)
    return names


def _required_bindings(root: Path) -> set[str]:
    names = set()
    for relative in ("n8n/.env.example", "relay/config/relay.example.env"):
        names.update(_environment_names(root / relative))
    names.add("ONION_SENTINEL_EVALUATION_TOKEN")
    return {f"env:{name}" for name in names} | SSH_BINDINGS | {
        "n8n-var:RELAY_WEBHOOK_TOKEN",
        "n8n-var:PCAP_BROKER_TOKEN",
        "file:mac-admin-password-record",
        "file:mac-admin-session-token",
        "file:mac-ac-hunter-service-credential",
        "file:mac-hermes-openai-codex-auth",
        "file:security-onion-pcap-stream-signing-key",
    }


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 512


def _string_list(value: object) -> bool:
    return bool(
        isinstance(value, list)
        and value
        and all(_text(item) for item in value)
        and len(value) == len(set(value))
    )


def _entry_errors(entry: object, index: int) -> list[str]:
    prefix = f"entry[{index}]"
    if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
        return [f"{prefix}: field set is invalid"]
    return (
        _entry_scalar_errors(entry, prefix)
        + _entry_collection_errors(entry, prefix)
        + _entry_material_errors(entry, prefix)
    )


def _entry_scalar_errors(entry: dict, prefix: str) -> list[str]:
    errors = []
    if not _text(entry["id"]) or not IDENTIFIER_RE.fullmatch(entry["id"]):
        errors.append(f"{prefix}: id is invalid")
    for name in ENTRY_KEYS - {"id", "bindings", "allowed_actions"}:
        if not _text(entry[name]):
            errors.append(f"{prefix}: {name} is invalid")
    return errors


def _entry_collection_errors(entry: dict, prefix: str) -> list[str]:
    errors = []
    if not _string_list(entry["bindings"]) or not all(
        item.startswith(BINDING_PREFIXES) for item in entry["bindings"]
    ):
        errors.append(f"{prefix}: bindings are invalid")
    if not _string_list(entry["allowed_actions"]):
        errors.append(f"{prefix}: allowed_actions are invalid")
    return errors


def _entry_material_errors(entry: dict, prefix: str) -> list[str]:
    if SECRET_MATERIAL_RE.search(json.dumps(entry, sort_keys=True)):
        return [f"{prefix}: secret material is forbidden"]
    return []


def _catalog_projection(entries: list) -> tuple[list[str], list[object], list[str]]:
    errors = []
    identifiers = []
    bindings = []
    for index, entry in enumerate(entries):
        errors.extend(_entry_errors(entry, index))
        if not isinstance(entry, dict):
            continue
        identifiers.append(entry.get("id"))
        if isinstance(entry.get("bindings"), list):
            bindings.extend(entry["bindings"])
    return errors, identifiers, bindings


def _duplicate_catalog_errors(identifiers: list[object], bindings: list[str]) -> list[str]:
    errors = []
    if len(identifiers) != len(set(identifiers)):
        errors.append("catalog contains duplicate credential ids")
    if len(bindings) != len(set(bindings)):
        errors.append("catalog contains duplicate bindings")
    return errors


def _binding_coverage_errors(bindings: list[str], root: Path) -> list[str]:
    missing = sorted(_required_bindings(root) - set(bindings))
    if missing:
        return ["catalog is missing declared bindings: " + ", ".join(missing)]
    return []


def validate_catalog(catalog: object, root: Path = ROOT) -> list[str]:
    if not isinstance(catalog, dict) or set(catalog) != {"schema", "entries"}:
        return ["catalog field set is invalid"]
    if catalog.get("schema") != CATALOG_SCHEMA:
        return ["catalog schema is invalid"]
    entries = catalog.get("entries")
    if not isinstance(entries, list) or not entries:
        return ["catalog entries are invalid"]
    errors, identifiers, bindings = _catalog_projection(entries)
    return (
        errors
        + _duplicate_catalog_errors(identifiers, bindings)
        + _binding_coverage_errors(bindings, Path(root))
    )


def _timestamp(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _record_shape_errors(record: object, index: int) -> list[str]:
    prefix = f"record[{index}]"
    if not isinstance(record, dict) or set(record) != RECORD_KEYS:
        return [f"{prefix}: field set is invalid"]
    return (
        _record_identity_errors(record, prefix)
        + _record_timestamp_errors(record, prefix)
        + _record_contract_errors(record, prefix)
    )


def _record_identity_errors(record: dict, prefix: str) -> list[str]:
    errors = []
    if not _text(record["credential_id"]):
        errors.append(f"{prefix}: credential_id is invalid")
    generation = record["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        errors.append(f"{prefix}: generation is invalid")
    if record["state"] not in {"active", "rollback", "revoked"}:
        errors.append(f"{prefix}: state is invalid")
    return errors


def _record_timestamp_errors(record: dict, prefix: str) -> list[str]:
    errors = []
    if _timestamp(record["created_at"]) is None:
        errors.append(f"{prefix}: created_at is invalid")
    for name in ("expires_at", "rotation_due_at"):
        if record[name] is not None and _timestamp(record[name]) is None:
            errors.append(f"{prefix}: {name} is invalid")
    return errors


def _record_contract_errors(record: dict, prefix: str) -> list[str]:
    errors = []
    if not _text(record["storage_class"]):
        errors.append(f"{prefix}: storage_class is invalid")
    if not _string_list(record["allowed_actions"]):
        errors.append(f"{prefix}: allowed_actions are invalid")
    predecessor = record["predecessor_generation"]
    if predecessor is not None and (
        isinstance(predecessor, bool) or not isinstance(predecessor, int) or predecessor < 1
    ):
        errors.append(f"{prefix}: predecessor_generation is invalid")
    return errors


def _lifecycle_errors(record: dict, entry: dict, now: dt.datetime) -> list[str]:
    identifier = record["credential_id"]
    return (
        _lifecycle_contract_errors(record, entry, identifier)
        + _lifecycle_time_errors(record, now, identifier)
    )


def _lifecycle_contract_errors(
    record: dict, entry: dict, identifier: str
) -> list[str]:
    errors = []
    if record["storage_class"] != entry["storage_class"]:
        errors.append(f"{identifier}: storage class mismatch")
    if record["allowed_actions"] != entry["allowed_actions"]:
        errors.append(f"{identifier}: allowed actions mismatch")
    return errors


def _lifecycle_time_errors(
    record: dict, now: dt.datetime, identifier: str
) -> list[str]:
    errors = []
    expires = _timestamp(record["expires_at"])
    rotation_due = _timestamp(record["rotation_due_at"])
    if record["state"] == "active" and expires is not None and expires <= now:
        errors.append(f"{identifier}: active credential is expired")
    if record["state"] == "active" and rotation_due is not None and rotation_due <= now:
        errors.append(f"{identifier}: active credential rotation is overdue")
    if record["state"] == "rollback" and (expires is None or expires <= now):
        errors.append(f"{identifier}: rollback generation is expired")
    return errors


def _generation_errors(identifier: str, records: list[dict]) -> list[str]:
    errors = []
    active = [item for item in records if item["state"] == "active"]
    rollback = [item for item in records if item["state"] == "rollback"]
    if len(active) > 1:
        errors.append(f"{identifier}: duplicate active credential")
    if len(rollback) > 1:
        errors.append(f"{identifier}: duplicate rollback credential")
    if active and rollback:
        expected = rollback[0]["generation"]
        if active[0]["predecessor_generation"] != expected:
            errors.append(f"{identifier}: rollback lineage mismatch")
    return errors


def _admit_inventory_records(
    records: list, catalog_by_id: dict[str, dict], now: dt.datetime
) -> tuple[list[str], list[dict]]:
    errors = []
    admitted = []
    seen = set()
    for index, record in enumerate(records):
        shape_errors = _record_shape_errors(record, index)
        errors.extend(shape_errors)
        if shape_errors:
            continue
        key = (record["credential_id"], record["generation"])
        if key in seen:
            errors.append(f"{record['credential_id']}: duplicate generation")
            continue
        seen.add(key)
        entry = catalog_by_id.get(record["credential_id"])
        if entry is None:
            errors.append(f"{record['credential_id']}: unknown credential id")
            continue
        admitted.append(record)
        errors.extend(_lifecycle_errors(record, entry, now))
    return errors, admitted


def _grouped_generation_errors(records: list[dict]) -> tuple[list[str], dict]:
    by_id = {}
    for record in records:
        by_id.setdefault(record["credential_id"], []).append(record)
    errors = []
    for identifier, grouped in by_id.items():
        errors.extend(_generation_errors(identifier, grouped))
    return errors, by_id


def _required_inventory_errors(
    required_ids: set[str], catalog_by_id: dict[str, dict], by_id: dict
) -> list[str]:
    errors = []
    for identifier in sorted(required_ids):
        if identifier not in catalog_by_id:
            errors.append(f"{identifier}: required credential id is unknown")
        elif not any(item["state"] == "active" for item in by_id.get(identifier, [])):
            errors.append(f"{identifier}: required credential is missing")
    return errors


def validate_inventory(
    catalog: dict,
    inventory: object,
    now: dt.datetime,
    required_ids: set[str] | None = None,
) -> list[str]:
    if not isinstance(inventory, dict) or set(inventory) != INVENTORY_KEYS:
        return ["inventory field set is invalid"]
    if inventory.get("schema") != INVENTORY_SCHEMA:
        return ["inventory schema is invalid"]
    if _timestamp(inventory.get("generated_at")) is None:
        return ["inventory generated_at is invalid"]
    records = inventory.get("records")
    if not isinstance(records, list):
        return ["inventory records are invalid"]
    catalog_by_id = {entry["id"]: entry for entry in catalog["entries"]}
    errors, admitted = _admit_inventory_records(records, catalog_by_id, now)
    generation_errors, by_id = _grouped_generation_errors(admitted)
    return (
        errors
        + generation_errors
        + _required_inventory_errors(required_ids or set(), catalog_by_id, by_id)
    )


def load_private_inventory(path: Path, owner_id: int | None = None) -> dict:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
        expected_owner = os.geteuid() if owner_id is None else owner_id
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_FILE_BYTES
        ):
            raise ValueError("inventory metadata is unsafe")
        payload = _bounded_json(candidate)
        if not isinstance(payload, dict) or set(payload) != INVENTORY_KEYS:
            raise ValueError("inventory schema is invalid")
        return payload
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {"status": "invalid", "reason": "credential inventory is invalid"}


def _now(value: str | None) -> dt.datetime:
    parsed = _timestamp(value) if value else dt.datetime.now(dt.timezone.utc)
    if parsed is None:
        raise ValueError("--at must be a timezone-aware ISO-8601 timestamp")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate secret-free credential governance")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--required-id", action="append", default=[])
    parser.add_argument("--at")
    args = parser.parse_args()
    try:
        catalog = load_catalog(args.catalog)
        failures = validate_catalog(catalog, ROOT)
        status = "catalog_valid"
        if not failures and args.inventory:
            inventory = load_private_inventory(args.inventory)
            if inventory.get("status") == "invalid":
                failures = [inventory["reason"]]
            else:
                failures = validate_inventory(
                    catalog, inventory, _now(args.at), set(args.required_id)
                )
            status = "inventory_valid"
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        failures = [str(exc)]
        catalog = {"entries": []}
        status = "invalid"
    result = {
        "schema": RESULT_SCHEMA,
        "ok": not failures,
        "status": status if not failures else "failed",
        "catalog_entries": len(catalog.get("entries") or []),
    }
    if failures:
        result["failures"] = failures
    print(json.dumps(result, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
