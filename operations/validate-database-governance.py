#!/usr/bin/env python3
"""Validate the secret-free repository database governance catalog."""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "operations/quality/database-governance.json"
CATALOG_SCHEMA = "onion-sentinel-database-governance-catalog-v1"
RESULT_SCHEMA = "onion-sentinel-database-governance-result-v1"
MAX_FILE_BYTES = 1024 * 1024
REQUIRED_IDS = frozenset({
    "mac.alert-store-sqlite",
    "mac.investigation-harness-sqlite",
    "mac.n8n-postgresql",
    "mac.alert-store-postgresql",
    "relay.alert-delivery-sqlite",
})
ENTRY_KEYS = frozenset({
    "id", "engine", "owner", "purpose", "data_classes",
    "schema_version_contract", "schema_version_state", "migration_strategy",
    "migration_atomicity_state", "rollback_strategy", "backup_schedule",
    "backup_artifacts", "backup_encryption_state", "backup_secret_policy",
    "retention", "rpo_minutes", "rto_minutes", "integrity_checks",
    "partial_write_controls", "duplicate_controls", "orphan_controls",
    "growth_monitoring", "maintenance", "restore_validation",
    "provenance_controls", "source_anchors",
})
LIST_KEYS = ENTRY_KEYS - {
    "id", "engine", "owner", "purpose", "schema_version_contract",
    "schema_version_state", "migration_strategy", "migration_atomicity_state",
    "rollback_strategy", "backup_schedule", "backup_encryption_state",
    "backup_secret_policy", "retention", "rpo_minutes", "rto_minutes",
}
ID_RE = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*")
FORBIDDEN_MATERIAL_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:password|secret|token)\s*[=:]\s*[^<\s][^\s]{7,}",
    re.IGNORECASE,
)


def _bounded_json(path: Path) -> object:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    elif path.is_symlink():
        raise ValueError("catalog is not an admissible regular file")
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("catalog is not an admissible regular file")
        raw = handle.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("catalog exceeds its byte budget")
    return json.loads(raw.decode("utf-8"))


def load_catalog(path: Path = DEFAULT_CATALOG) -> dict[str, object]:
    payload = _bounded_json(Path(path))
    if not isinstance(payload, dict):
        raise ValueError("database governance catalog must be an object")
    return payload


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 800


def _string_list(value: object) -> bool:
    return bool(
        isinstance(value, list)
        and value
        and len(value) <= 24
        and all(_text(item) for item in value)
        and len(value) == len(set(value))
    )


def _anchor_is_valid(root: Path, value: str) -> bool:
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        return False
    root = root.resolve()
    resolved = root.joinpath(*candidate.parts)
    try:
        resolved.resolve(strict=True).relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False
    cursor = root
    for part in candidate.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            return False
    return resolved.is_file()


def _entry_scalar_errors(entry: dict[str, object], prefix: str) -> list[str]:
    errors: list[str] = []
    if not _text(entry["id"]) or not ID_RE.fullmatch(str(entry["id"])):
        errors.append(f"{prefix}: id is invalid")
    for name in ENTRY_KEYS - LIST_KEYS - {"id", "rpo_minutes", "rto_minutes"}:
        if not _text(entry[name]):
            errors.append(f"{prefix}: {name} is invalid")
    for name in ("rpo_minutes", "rto_minutes"):
        value = entry[name]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 525600:
            errors.append(f"{prefix}: {name} is invalid")
    if entry["engine"] not in {"sqlite", "postgresql"}:
        errors.append(f"{prefix}: engine is invalid")
    if entry["schema_version_state"] not in {
        "persisted", "upstream-managed", "legacy-unversioned"
    }:
        errors.append(f"{prefix}: schema_version_state is invalid")
    if entry["migration_atomicity_state"] not in {
        "transactional", "upstream-managed", "not-transactional"
    }:
        errors.append(f"{prefix}: migration_atomicity_state is invalid")
    if entry["backup_encryption_state"] not in {
        "encrypted", "owner-only-unencrypted"
    }:
        errors.append(f"{prefix}: backup_encryption_state is invalid")
    return errors


def _entry_collection_errors(
    entry: dict[str, object], prefix: str, root: Path
) -> list[str]:
    errors: list[str] = []
    for name in LIST_KEYS - {"source_anchors"}:
        value = entry[name]
        if not _string_list(value):
            errors.append(f"{prefix}: {name} is invalid")
    anchors = entry["source_anchors"]
    if not _string_list(anchors) or not all(
        _anchor_is_valid(root, str(value)) for value in anchors
    ):
        errors.append(f"{prefix}: source_anchors are invalid")
    return errors


def _entry_errors(entry: object, index: int, root: Path) -> list[str]:
    prefix = f"entry[{index}]"
    if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
        return [f"{prefix}: field set is invalid"]
    errors = _entry_scalar_errors(entry, prefix)
    errors.extend(_entry_collection_errors(entry, prefix, root))
    if FORBIDDEN_MATERIAL_RE.search(json.dumps(entry, sort_keys=True)):
        errors.append(f"{prefix}: secret material is forbidden")
    return errors


def _declared_gaps(entries: list[object]) -> list[str]:
    gaps: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or not _text(entry.get("id")):
            continue
        identifier = str(entry["id"])
        if entry.get("schema_version_state") == "legacy-unversioned":
            gaps.append(f"{identifier}: schema version is not persisted")
        if entry.get("migration_atomicity_state") == "not-transactional":
            gaps.append(f"{identifier}: schema migration is not atomic")
        if entry.get("backup_encryption_state") == "owner-only-unencrypted":
            gaps.append(f"{identifier}: backup encryption is not enforced")
    return sorted(gaps)


def validate_catalog(
    catalog: object,
    root: Path = ROOT,
    *,
    required_ids: set[str] | frozenset[str] = REQUIRED_IDS,
) -> dict[str, list[str]]:
    if not isinstance(catalog, dict) or set(catalog) != {"schema", "entries"}:
        return {"errors": ["catalog field set is invalid"], "declared_gaps": []}
    if catalog.get("schema") != CATALOG_SCHEMA:
        return {"errors": ["catalog schema is invalid"], "declared_gaps": []}
    entries = catalog.get("entries")
    if not isinstance(entries, list) or not entries:
        return {"errors": ["catalog entries are invalid"], "declared_gaps": []}
    errors = [
        error
        for index, entry in enumerate(entries)
        for error in _entry_errors(entry, index, Path(root))
    ]
    identifiers = [entry.get("id") for entry in entries if isinstance(entry, dict)]
    if len(identifiers) != len(set(identifiers)):
        errors.append("catalog contains duplicate database ids")
    missing = sorted(set(required_ids) - set(identifiers))
    if missing:
        errors.append("catalog is missing database ids: " + ", ".join(missing))
    return {"errors": errors, "declared_gaps": _declared_gaps(entries)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    args = parser.parse_args()
    try:
        catalog = load_catalog(args.catalog)
        result = validate_catalog(catalog, ROOT)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "schema": RESULT_SCHEMA,
                          "status": "invalid", "errors": [type(exc).__name__]}))
        return 2
    payload = {
        "catalog_entries": len(catalog["entries"]),
        "declared_gap_count": len(result["declared_gaps"]),
        "ok": not result["errors"],
        "schema": RESULT_SCHEMA,
        "status": (
            "invalid" if result["errors"] else
            "catalog_valid_with_declared_gaps" if result["declared_gaps"] else
            "catalog_valid"
        ),
    }
    if result["errors"]:
        payload["errors"] = result["errors"]
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
