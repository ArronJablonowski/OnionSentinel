"""Bounded target workflow and projection for endpoint software inventory."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Callable, NamedTuple


class CollectionPolicy(NamedTuple):
    schema: str
    apps_columns: str
    brew_columns: str
    max_cursor_chars: int
    error_type: type[RuntimeError]


class CollectionDependencies(NamedTuple):
    approved: Callable[[dict[str, Any], str], bool]
    query: Callable[..., list[dict[str, str]]]
    paged_rows: Callable[..., list[dict[str, str]]]
    safe_cell: Callable[[Any, int], str]
    record: Callable[..., dict[str, Any]]
    utc_now: Callable[[], Any]
    timestamp: Callable[[Any], str]


def record(
    *,
    hostname: str,
    product: str,
    version: str,
    category: str,
    path: str,
    os_type: str,
    os_version: str,
    observed_at: str,
    previous: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Project one stable, provenance-bound endpoint software observation."""
    asset_ref = hashlib.sha256(("host\0" + hostname).encode("utf-8")).hexdigest()[:24]
    identity = "\0".join(
        ("osquery_apps", asset_ref, product, version, category, path)
    )
    evidence_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    prior = previous.get(evidence_id) or {}
    first_seen = str(prior.get("first_seen") or observed_at)
    observations = min(
        int(prior.get("observation_count") or 0) + 1,
        1_000_000_000,
    )
    return {
        "evidence_id": evidence_id,
        "source": "osquery_apps",
        "source_dataset": "osquery.live.software_inventory",
        "tier": "installed",
        "confidence": "high",
        "asset_ref_type": "host",
        "asset_ref": asset_ref,
        "platform": "darwin",
        "operating_system_type": os_type,
        "operating_system_version": os_version,
        "operating_system_source": "osquery.live:os_version",
        "operating_system_confidence": "high",
        "product": product,
        "version": version,
        "category": category,
        "first_seen": first_seen,
        "last_seen": observed_at,
        "observation_count": observations,
    }


def _approved_aliases(
    config: dict[str, Any],
    dependencies: CollectionDependencies,
    policy: CollectionPolicy,
) -> list[str]:
    aliases = list(
        (config.get("scheduled_inventory_approval") or {}).get("target_aliases")
        or []
    )
    if not aliases:
        raise policy.error_type("no scheduled inventory endpoint alias is approved")
    if any(not dependencies.approved(config, alias) for alias in aliases):
        raise policy.error_type("scheduled inventory approval is incomplete")
    return aliases


def _prior_record_index(
    previous_cache: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("evidence_id") or ""): item
        for item in (previous_cache or {}).get("records", [])
        if isinstance(item, dict)
    }


def _identity_rows(
    config: dict[str, Any],
    alias: str,
    case_id: str,
    dependencies: CollectionDependencies,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    identity = dependencies.query(
        config,
        alias,
        "SELECT hostname FROM system_info LIMIT 1;",
        "Bind scheduled software inventory to the endpoint hostname",
        case_id,
    )
    os_rows = dependencies.query(
        config,
        alias,
        "SELECT name,version,build,platform,arch FROM os_version LIMIT 1;",
        "Record the endpoint operating system version",
        case_id,
    )
    return identity, os_rows


def _target_identity(
    config: dict[str, Any],
    alias: str,
    case_id: str,
    dependencies: CollectionDependencies,
    policy: CollectionPolicy,
) -> tuple[str, dict[str, str]]:
    identity, os_rows = _identity_rows(config, alias, case_id, dependencies)
    if len(identity) != 1 or len(os_rows) != 1:
        raise policy.error_type("endpoint identity or operating system is ambiguous")
    hostname = dependencies.safe_cell(
        identity[0].get("hostname"), 255
    ).lower().rstrip(".")
    if not hostname or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,254}", hostname):
        raise policy.error_type("endpoint returned an invalid hostname")
    return hostname, os_rows[0]


def _operating_system(
    os_row: dict[str, str], dependencies: CollectionDependencies,
) -> tuple[str, str]:
    os_name = dependencies.safe_cell(
        os_row.get("name") or os_row.get("platform"), 160
    )
    version = dependencies.safe_cell(os_row.get("version"), 160)
    build = dependencies.safe_cell(os_row.get("build"), 160)
    full_version = f"{os_name} {version}".strip()
    if build:
        full_version = f"{full_version} (build {build})".strip()
    return os_name, full_version


def _project_application(
    row: dict[str, str],
    *,
    hostname: str,
    os_type: str,
    os_version: str,
    observed_at: str,
    previous: dict[str, dict[str, Any]],
    dependencies: CollectionDependencies,
    policy: CollectionPolicy,
) -> dict[str, Any] | None:
    product = dependencies.safe_cell(
        row.get("name") or row.get("bundle_name") or row.get("bundle_identifier"),
        4096,
    )
    if not product:
        return None
    return dependencies.record(
        hostname=hostname,
        product=product,
        version=dependencies.safe_cell(
            row.get("bundle_short_version") or row.get("bundle_version"), 1024
        ),
        category="application",
        path=dependencies.safe_cell(row.get("path"), policy.max_cursor_chars),
        os_type=os_type,
        os_version=os_version,
        observed_at=observed_at,
        previous=previous,
    )


def _project_homebrew(
    row: dict[str, str],
    *,
    hostname: str,
    os_type: str,
    os_version: str,
    observed_at: str,
    previous: dict[str, dict[str, Any]],
    dependencies: CollectionDependencies,
    policy: CollectionPolicy,
) -> dict[str, Any] | None:
    product = dependencies.safe_cell(row.get("name"), 4096)
    if not product:
        return None
    return dependencies.record(
        hostname=hostname,
        product=product,
        version=dependencies.safe_cell(row.get("version"), 1024),
        category="package:homebrew",
        path=dependencies.safe_cell(row.get("path"), policy.max_cursor_chars),
        os_type=os_type,
        os_version=os_version,
        observed_at=observed_at,
        previous=previous,
    )


def _target_rows(
    config: dict[str, Any],
    alias: str,
    case_id: str,
    dependencies: CollectionDependencies,
    policy: CollectionPolicy,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    apps = dependencies.paged_rows(
        config, alias, "apps", policy.apps_columns, case_id
    )
    brew = dependencies.paged_rows(
        config, alias, "homebrew_packages", policy.brew_columns, case_id
    )
    return apps, brew


def _target_records(
    config: dict[str, Any],
    alias: str,
    case_id: str,
    observed_at: str,
    previous: dict[str, dict[str, Any]],
    dependencies: CollectionDependencies,
    policy: CollectionPolicy,
) -> tuple[str, list[dict[str, Any]]]:
    hostname, os_row = _target_identity(
        config, alias, case_id, dependencies, policy
    )
    os_type, os_version = _operating_system(os_row, dependencies)
    apps, brew = _target_rows(config, alias, case_id, dependencies, policy)
    shared = {
        "hostname": hostname,
        "os_type": os_type,
        "os_version": os_version,
        "observed_at": observed_at,
        "previous": previous,
        "dependencies": dependencies,
        "policy": policy,
    }
    projected = [_project_application(row, **shared) for row in apps]
    projected.extend(_project_homebrew(row, **shared) for row in brew)
    return hostname, [item for item in projected if item is not None]


def _target_receipt(
    hostname: str, observed_at: str, record_count: int,
) -> dict[str, Any]:
    return {
        "asset_ref": hashlib.sha256(
            ("host\0" + hostname).encode("utf-8")
        ).hexdigest()[:24],
        "status": "ok",
        "records": record_count,
        "observed_at": observed_at,
    }


def _normalized_records(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for item in records:
        unique[item["evidence_id"]] = item
    return sorted(
        unique.values(),
        key=lambda item: (
            item["asset_ref"], item["product"].casefold(), item["version"].casefold()
        ),
    )


def collect_inventory(
    config: dict[str, Any],
    previous_cache: dict[str, Any] | None,
    *,
    dependencies: CollectionDependencies,
    policy: CollectionPolicy,
) -> dict[str, Any]:
    """Collect approved targets while preserving exact query and projection order."""
    aliases = _approved_aliases(config, dependencies, policy)
    previous = _prior_record_index(previous_cache)
    observed_at = dependencies.timestamp(dependencies.utc_now())
    case_id = "scheduled-endpoint-software-" + observed_at[:10].replace("-", "")
    records: list[dict[str, Any]] = []
    targets: list[dict[str, Any]] = []
    for alias in aliases:
        hostname, target_records = _target_records(
            config, alias, case_id, observed_at, previous, dependencies, policy
        )
        records.extend(target_records)
        targets.append(_target_receipt(hostname, observed_at, len(target_records)))
    return {
        "schema": policy.schema,
        "version": 1,
        "updated_at": observed_at,
        "complete": True,
        "targets": targets,
        "records": _normalized_records(records),
    }
