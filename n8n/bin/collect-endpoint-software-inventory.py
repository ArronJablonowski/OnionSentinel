#!/usr/bin/env python3
"""Collect a fixed, read-only endpoint software cache through the Relay.

This scheduler is separate from model-directed investigation.  Operators must
explicitly approve each configured endpoint alias for scheduled inventory.
Queries are fixed here, validated independently at every SSH boundary, and
never accept SQL or target input from the web UI or an LLM.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

from live_osquery_client import (
    DEFAULT_CONFIG_FILE,
    LiveOsqueryClientError,
    collect_live_osquery,
    load_live_osquery_config,
    scheduled_inventory_approved,
)
from live_osquery_contract import LiveOsqueryContractError, MAX_ROWS
from endpoint_inventory_collection import (
    CollectionDependencies,
    CollectionPolicy,
    collect_inventory,
    record as project_inventory_record,
)
from security_jsonl_log import SecurityJsonlLogger


SCHEMA = "onion-sentinel-endpoint-software-cache-v1"
DEFAULT_CACHE = (
    Path.home() / "n8n-local" / "software-inventory" / "endpoint-cache.json"
)
DEFAULT_LOG = Path.home() / "n8n-local" / "logs" / "endpoint-software-inventory.jsonl"
MAX_CACHE_BYTES = 128 * 1024 * 1024
MAX_PAGES = 16
MAX_RECORDS = 100_000
MAX_CURSOR_CHARS = 1500
DEFAULT_ATTEMPTS = 2
MAX_ATTEMPTS = 3
DEFAULT_RETRY_DELAY_SECONDS = 300
MAX_RETRY_DELAY_SECONDS = 3600
LAST_GOOD_STALE_AFTER = dt.timedelta(hours=36)
RETRYABLE_FAILURE_CODES = frozenset(
    {
        "broker_timeout",
        "connect_failure",
        "transport_failure",
        "incomplete_artifact",
        "incomplete_evidence",
        "remote_timeout",
        "remote_error",
        "remote_invalid_response",
        "remote_cancelled",
    }
)
REMOTE_FAILURE_CODES = {
    "timeout": "remote_timeout",
    "error": "remote_error",
    "invalid_response": "remote_invalid_response",
    "cancelled": "remote_cancelled",
}
APPS_COLUMNS = (
    "name,path,bundle_identifier,bundle_name,bundle_short_version,"
    "bundle_version,bundle_package_type"
)
BREW_COLUMNS = "name,path,version,type"


class EndpointInventoryError(RuntimeError):
    """The scheduled endpoint inventory could not complete truthfully."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "inventory_error",
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _safe_cell(value: Any, maximum: int) -> str:
    text = str(value or "").strip()
    if len(text) > maximum or any(ord(char) < 32 for char in text):
        raise EndpointInventoryError("endpoint inventory returned an invalid value")
    return text


def _query(
    config: dict[str, Any],
    alias: str,
    sql: str,
    purpose: str,
    case_id: str,
) -> list[dict[str, str]]:
    artifact = collect_live_osquery(
        case_id=case_id,
        requests=[{"target_alias": alias, "query": sql, "purpose": purpose}],
        config=config,
        persist=False,
        approval_scope="scheduled_inventory",
    )
    results = artifact.get("results") or []
    if len(results) != 1:
        raise EndpointInventoryError(
            "scheduled endpoint query did not complete",
            reason_code="incomplete_artifact",
        )
    result = results[0]
    status = str(result.get("status") or "invalid_response").strip().lower()
    if status != "ok":
        raise EndpointInventoryError(
            "scheduled endpoint query returned a remote failure",
            reason_code=REMOTE_FAILURE_CODES.get(
                status,
                "remote_invalid_response",
            ),
        )
    if artifact.get("complete") is not True:
        raise EndpointInventoryError(
            "scheduled endpoint query did not complete",
            reason_code="incomplete_artifact",
        )
    if result.get("truncated") is True:
        raise EndpointInventoryError(
            "scheduled endpoint query returned incomplete evidence",
            reason_code="incomplete_evidence",
        )
    rows = result.get("rows")
    if not isinstance(rows, list):
        raise EndpointInventoryError(
            "scheduled endpoint query omitted its rows",
            reason_code="incomplete_artifact",
        )
    return rows


def _page_query(table: str, columns: str, cursor: str) -> str:
    if len(cursor) > MAX_CURSOR_CHARS:
        raise EndpointInventoryError("endpoint inventory pagination cursor is too long")
    escaped = cursor.replace("'", "''")
    return (
        f"SELECT {columns} FROM {table} WHERE path > '{escaped}' "
        f"ORDER BY path LIMIT {MAX_ROWS};"
    )


def _admitted_page_cursor(
    page: list[dict[str, str]],
    cursor: str,
    seen: set[str],
) -> str:
    paths = [_safe_cell(item.get("path"), MAX_CURSOR_CHARS) for item in page]
    if not paths or any(not path for path in paths):
        raise EndpointInventoryError("endpoint inventory row omitted its path")
    next_cursor = max(paths)
    if next_cursor <= cursor or next_cursor in seen:
        raise EndpointInventoryError("endpoint inventory pagination did not advance")
    seen.add(next_cursor)
    return next_cursor


def _append_inventory_page(
    rows: list[dict[str, str]],
    page: list[dict[str, str]],
) -> bool:
    rows.extend(page)
    if len(rows) > MAX_RECORDS:
        raise EndpointInventoryError("endpoint inventory exceeded its record limit")
    return len(page) < MAX_ROWS


def _paged_rows(
    config: dict[str, Any], alias: str, table: str, columns: str, case_id: str
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    cursor = ""
    seen: set[str] = set()
    for _page in range(MAX_PAGES):
        page = _query(
            config,
            alias,
            _page_query(table, columns, cursor),
            f"Scheduled read-only software inventory from {table}",
            case_id,
        )
        if not page:
            return rows
        next_cursor = _admitted_page_cursor(page, cursor, seen)
        if _append_inventory_page(rows, page):
            return rows
        cursor = next_cursor
    raise EndpointInventoryError("endpoint inventory exceeded its page limit")


def _record(
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
    return project_inventory_record(
        hostname=hostname,
        product=product,
        version=version,
        category=category,
        path=path,
        os_type=os_type,
        os_version=os_version,
        observed_at=observed_at,
        previous=previous,
    )


def collect(config: dict[str, Any], previous_cache: dict[str, Any] | None = None) -> dict[str, Any]:
    return collect_inventory(
        config,
        previous_cache,
        dependencies=CollectionDependencies(
            approved=scheduled_inventory_approved,
            query=_query,
            paged_rows=_paged_rows,
            safe_cell=_safe_cell,
            record=_record,
            utc_now=utc_now,
            timestamp=timestamp,
        ),
        policy=CollectionPolicy(
            schema=SCHEMA,
            apps_columns=APPS_COLUMNS,
            brew_columns=BREW_COLUMNS,
            max_cursor_chars=MAX_CURSOR_CHARS,
            error_type=EndpointInventoryError,
        ),
    )


def load_cache(path: Path) -> dict[str, Any] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > MAX_CACHE_BYTES
    ):
        raise EndpointInventoryError("endpoint inventory cache is not owner-controlled")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise EndpointInventoryError("endpoint inventory cache schema is invalid")
    return value


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > MAX_CACHE_BYTES:
        raise EndpointInventoryError("endpoint inventory cache exceeds its size limit")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def failure_code(exc: BaseException) -> str:
    code = str(getattr(exc, "reason_code", "") or "").strip().lower()
    if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
        return code
    if isinstance(exc, BlockingIOError):
        return "collector_already_running"
    if isinstance(exc, LiveOsqueryContractError):
        return "invalid_response"
    if isinstance(exc, OSError):
        return "local_io_error"
    if isinstance(exc, ValueError):
        return "invalid_local_data"
    return "collector_failure"


def last_good_cache_state(
    previous_cache: dict[str, Any] | None,
    *,
    now: dt.datetime | None = None,
) -> str:
    if previous_cache is None:
        return "missing"
    raw_updated_at = str(previous_cache.get("updated_at") or "").strip()
    try:
        updated_at = dt.datetime.fromisoformat(raw_updated_at.replace("Z", "+00:00"))
    except ValueError:
        return "invalid"
    if updated_at.tzinfo is None:
        return "invalid"
    current = (now or utc_now()).astimezone(dt.timezone.utc)
    age = current - updated_at.astimezone(dt.timezone.utc)
    if age < -dt.timedelta(minutes=5):
        return "invalid"
    return "stale" if age > LAST_GOOD_STALE_AFTER else "fresh"


def collect_with_retries(
    config: dict[str, Any],
    previous_cache: dict[str, Any] | None,
    *,
    attempts: int,
    retry_delay_seconds: int,
    logger: SecurityJsonlLogger,
) -> dict[str, Any]:
    cache_state = last_good_cache_state(previous_cache)
    for attempt in range(1, attempts + 1):
        try:
            return collect(config, previous_cache)
        except (
            EndpointInventoryError,
            LiveOsqueryClientError,
            LiveOsqueryContractError,
        ) as exc:
            setattr(exc, "attempts_completed", attempt)
            code = failure_code(exc)
            if code not in RETRYABLE_FAILURE_CODES or attempt >= attempts:
                raise
            logger.log(
                "warning",
                "endpoint_software_inventory.retry",
                attempt=attempt,
                attempts=attempts,
                failure_code=code,
                retry_delay_seconds=retry_delay_seconds,
                last_good_cache_state=cache_state,
            )
            time.sleep(retry_delay_seconds)
    raise AssertionError("endpoint inventory retry loop exhausted unexpectedly")


def _bounded_cli_int(label: str, minimum: int, maximum: int):
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{label} must be an integer") from exc
        if parsed < minimum or parsed > maximum:
            raise argparse.ArgumentTypeError(
                f"{label} must be between {minimum} and {maximum}"
            )
        return parsed

    return parse


def open_collector_lock(path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise EndpointInventoryError(
            "endpoint inventory collector lock is unavailable",
            reason_code="invalid_lock",
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise EndpointInventoryError(
                "endpoint inventory collector lock is not owner-controlled",
                reason_code="invalid_lock",
            )
        os.fchmod(descriptor, 0o600)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_FILE)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument(
        "--attempts",
        type=_bounded_cli_int("attempts", 1, MAX_ATTEMPTS),
        default=DEFAULT_ATTEMPTS,
    )
    parser.add_argument(
        "--retry-delay-seconds",
        type=_bounded_cli_int(
            "retry-delay-seconds",
            0,
            MAX_RETRY_DELAY_SECONDS,
        ),
        default=DEFAULT_RETRY_DELAY_SECONDS,
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    logger = SecurityJsonlLogger(args.log, service="endpoint-software-inventory")
    lock_path = args.cache.with_suffix(args.cache.suffix + ".lock")
    descriptor: int | None = None
    previous: dict[str, Any] | None = None
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = open_collector_lock(lock_path)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = load_cache(args.cache)
        result = collect_with_retries(
            load_live_osquery_config(args.config),
            previous,
            attempts=args.attempts,
            retry_delay_seconds=args.retry_delay_seconds,
            logger=logger,
        )
        atomic_write(args.cache, result)
        logger.log(
            "info",
            "endpoint_software_inventory.completed",
            records=len(result["records"]),
            targets=len(result["targets"]),
        )
        return 0
    except (
        BlockingIOError,
        OSError,
        ValueError,
        EndpointInventoryError,
        LiveOsqueryClientError,
        LiveOsqueryContractError,
    ) as exc:
        logger.log(
            "error",
            "endpoint_software_inventory.failed",
            failure_code=failure_code(exc),
            attempts=int(getattr(exc, "attempts_completed", 1)),
            attempt_limit=args.attempts,
            last_good_cache_state=last_good_cache_state(previous),
        )
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
