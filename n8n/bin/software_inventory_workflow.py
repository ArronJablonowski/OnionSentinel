"""Paginated collection, snapshot composition, failure state, and CLI workflow."""
from __future__ import annotations

from software_inventory_contract import *  # noqa: F401,F403
from software_inventory_contract import _empty_source_status  # noqa: F401
from software_inventory_normalization import *  # noqa: F401,F403
from software_inventory_normalization import (  # noqa: F401
    _source_status,
)
from software_inventory_transport import *  # noqa: F401,F403
PageFetcher = Callable[
    [
        Dict[str, Any],
        str,
        Dict[str, str],
        int,
        Optional[Dict[str, Any]],
        float,
    ],
    Dict[str, Any],
]


def collect_source(
    config: Dict[str, Any],
    source: str,
    window: Dict[str, str],
    now: dt.datetime,
    deadline: float,
    page_fetcher: PageFetcher = query_page,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    evidence_ids: Set[str] = set()
    cursors: Set[str] = set()
    after: Optional[Dict[str, Any]] = None
    pages = 0
    latest = ""
    try:
        while pages < config["max_pages_per_source"]:
            remaining = deadline - time.monotonic()
            if remaining <= 1:
                raise SoftwareInventoryError(
                    "software inventory collection exceeded its wall-clock budget"
                )
            response = page_fetcher(
                config,
                source,
                window,
                config["page_size"],
                after,
                min(float(config["timeout_seconds"]), remaining),
            )
            # An injected page fetcher used by tests must satisfy the same
            # contract as the transport adapter.
            response = validate_response(
                response,
                expected_source=source,
                expected_window=window,
                requested_page_size=config["page_size"],
                previous_after=after,
            )
            pages += 1
            for record in response["records"]:
                evidence_id = record["evidence_id"]
                if evidence_id in evidence_ids:
                    raise SoftwareInventoryError(
                        "software inventory source repeated an evidence identity"
                    )
                evidence_ids.add(evidence_id)
                records.append(record)
                if not latest or record["last_seen"] > latest:
                    latest = record["last_seen"]
            if len(records) > MAX_TOTAL_RECORDS:
                raise SoftwareInventoryError(
                    "software inventory source exceeded the record limit"
                )
            if response["complete"]:
                return records, _source_status(
                    status="ok",
                    complete=True,
                    pages=pages,
                    returned=len(records),
                    latest=latest,
                    now=now,
                )
            after = response["after"]
            cursor_token = json.dumps(
                after,
                separators=(",", ":"),
                sort_keys=True,
            )
            if cursor_token in cursors:
                raise SoftwareInventoryError(
                    "software inventory relay repeated a pagination cursor"
                )
            cursors.add(cursor_token)
        raise SoftwareInventoryError(
            "software inventory source exceeded its page limit"
        )
    except (
        BoundedProcessError,
        OSError,
        UnicodeError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
    ) as exc:
        source_status = _source_status(
            status="failed",
            complete=False,
            pages=pages,
            returned=len(records),
            latest=latest,
            now=now,
        )
        if isinstance(exc, SoftwareInventoryError):
            message = str(exc)
        else:
            message = f"{type(exc).__name__}: {exc}"
        raise SoftwareInventoryError(message, {source: source_status}) from exc


def collect_snapshot(
    config: Dict[str, Any],
    previous_state: Dict[str, Any],
    now: dt.datetime,
    page_fetcher: PageFetcher = query_page,
    endpoint_cache: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    del previous_state  # A complete collection is a replacement, not a merge.
    window = collection_window(now)
    deadline = time.monotonic() + config["max_collection_seconds"]
    statuses = {
        source: _empty_source_status()
        for source in SOURCES
    }
    records: List[Dict[str, Any]] = []
    evidence_ids: Set[str] = set()
    for source in SOURCES:
        if source == "osquery_apps" and endpoint_cache is not None:
            source_records = list(endpoint_cache["records"])
            latest = str(endpoint_cache["updated_at"])
            source_status = _source_status(
                status="ok",
                complete=True,
                pages=1,
                returned=len(source_records),
                latest=latest,
                now=now,
            )
        else:
            try:
                source_records, source_status = collect_source(
                    config,
                    source,
                    window,
                    now,
                    deadline,
                    page_fetcher=page_fetcher,
                )
            except SoftwareInventoryError as exc:
                if exc.source_statuses:
                    statuses.update(exc.source_statuses)
                raise SoftwareInventoryError(str(exc), statuses) from exc
        statuses[source] = source_status
        for record in source_records:
            if record["evidence_id"] in evidence_ids:
                raise SoftwareInventoryError(
                    "software inventory snapshot repeated an evidence identity",
                    statuses,
                )
            evidence_ids.add(record["evidence_id"])
            records.append(record)
            if len(records) > MAX_TOTAL_RECORDS:
                raise SoftwareInventoryError(
                    "software inventory snapshot exceeded the record limit",
                    statuses,
                )
    records.sort(
        key=lambda item: (
            item["asset_ref"].casefold(),
            item["product"].casefold(),
            item["version"].casefold(),
            item["source"],
            item["evidence_id"],
        )
    )
    stamp = format_timestamp(now)
    payload = {
            "schema": STATE_SCHEMA,
            "version": 1,
            "updated_at": stamp,
            "collection": {
                "status": "ok",
                "last_attempt_at": stamp,
                "last_success_at": stamp,
                "last_error": "",
                "window": window,
                "source_statuses": statuses,
                "complete": True,
            },
            "records": records,
        }
    if endpoint_cache is not None:
        payload["collection"]["osquery_ready"] = endpoint_cache["targets"]
    return validate_state(payload)


def failed_state(
    previous_state: Dict[str, Any],
    now: dt.datetime,
    error: str,
    source_statuses: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    previous = validate_state(previous_state)
    prior_collection = previous["collection"]
    has_snapshot = bool(
        previous["updated_at"]
        and prior_collection["last_success_at"]
        and previous["updated_at"] == prior_collection["last_success_at"]
        and prior_collection["window"]
    )
    statuses = {
        source: _empty_source_status()
        for source in SOURCES
    }
    if source_statuses:
        for source in SOURCES:
            if source in source_statuses:
                statuses[source] = source_statuses[source]
    stamp = format_timestamp(now)
    return validate_state(
        {
            "schema": STATE_SCHEMA,
            "version": 1,
            "updated_at": previous["updated_at"] if has_snapshot else stamp,
            "collection": {
                "status": "failed",
                "last_attempt_at": stamp,
                "last_success_at": (
                    str(prior_collection["last_success_at"])
                    if has_snapshot
                    else ""
                ),
                "last_error": " ".join(str(error).split())[:500],
                "window": (
                    dict(prior_collection["window"])
                    if has_snapshot
                    else collection_window(now)
                ),
                "source_statuses": statuses,
                "complete": False,
            },
            "records": list(previous["records"]) if has_snapshot else [],
        }
    )


def disabled_state(
    previous_state: Dict[str, Any],
    now: dt.datetime,
) -> Dict[str, Any]:
    previous = validate_state(previous_state)
    prior_collection = previous["collection"]
    has_snapshot = bool(
        previous["updated_at"]
        and prior_collection["last_success_at"]
        and previous["updated_at"] == prior_collection["last_success_at"]
        and prior_collection["window"]
    )
    stamp = format_timestamp(now)
    return validate_state(
        {
            "schema": STATE_SCHEMA,
            "version": 1,
            "updated_at": previous["updated_at"] if has_snapshot else stamp,
            "collection": {
                "status": "disabled",
                "last_attempt_at": stamp,
                "last_success_at": (
                    str(prior_collection["last_success_at"])
                    if has_snapshot
                    else ""
                ),
                "last_error": "",
                "window": (
                    dict(prior_collection["window"])
                    if has_snapshot
                    else collection_window(now)
                ),
                "source_statuses": {
                    source: _empty_source_status("disabled")
                    for source in SOURCES
                },
                "complete": False,
            },
            "records": list(previous["records"]) if has_snapshot else [],
        }
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    parser.add_argument(
        "--endpoint-cache", type=Path, default=DEFAULT_ENDPOINT_CACHE
    )
    parser.add_argument(
        "--database-api-url",
        default=DEFAULT_DATABASE_API_URL,
    )
    args = parser.parse_args(argv)
    logger = SecurityJsonlLogger(args.log, service="software-inventory")
    attempted_at = utc_now()
    previous: Optional[Dict[str, Any]] = None
    try:
        with collector_lock(args.state):
            previous = load_state(args.state)
            config = load_config(args.config)
            if not config["enabled"]:
                updated = disabled_state(previous, attempted_at)
                atomic_write_json(args.state, updated)
                logger.log(
                    "info",
                    "software_inventory.disabled",
                    retained=len(updated["records"]),
                )
                return 0
            endpoint_cache = load_endpoint_cache(args.endpoint_cache, attempted_at)
            updated = collect_snapshot(
                config,
                previous,
                attempted_at,
                endpoint_cache=endpoint_cache,
            )
            database_result = publish_database_snapshot(
                updated,
                api_url=args.database_api_url,
                token=database_write_token(args.env),
            )
            atomic_write_json(args.state, updated)
            logger.log(
                "info",
                "software_inventory.completed",
                returned=len(updated["records"]),
                storage_backend="postgresql",
                snapshot_id=database_result["snapshot_id"],
                source_statuses=updated["collection"]["source_statuses"],
            )
            return 0
    except (
        BoundedProcessError,
        OSError,
        UnicodeError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
    ) as exc:
        message = " ".join(str(exc).split())[:500]
        statuses = (
            exc.source_statuses
            if isinstance(exc, SoftwareInventoryError)
            else None
        )
        if previous is not None:
            try:
                updated = failed_state(
                    previous,
                    attempted_at,
                    message,
                    statuses,
                )
                atomic_write_json(args.state, updated)
            except (OSError, UnicodeError, ValueError, RuntimeError):
                pass
        logger.log(
            "error",
            "software_inventory.failed",
            error=message,
            retained=len(previous["records"]) if previous else 0,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
