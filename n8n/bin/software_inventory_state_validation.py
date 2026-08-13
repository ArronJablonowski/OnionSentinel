"""Pure Software Inventory collection-state normalization and validation."""
from __future__ import annotations

from software_inventory_contract import *  # noqa: F401,F403
from software_inventory_contract import _bounded_integer, _bounded_text
from software_inventory_record_normalization import normalize_record


def normalize_window(value: object, *, allow_empty: bool = False) -> Dict[str, str]:
    if allow_empty and value == {}:
        return {}
    if not isinstance(value, dict) or set(value) != {"start", "end"}:
        raise ValueError("software inventory window is invalid")
    start = parse_timestamp(value.get("start"))
    end = parse_timestamp(value.get("end"))
    if start >= end or end - start > dt.timedelta(days=31):
        raise ValueError("software inventory window is out of bounds")
    return {"start": format_timestamp(start), "end": format_timestamp(end)}


def freshness(latest: str, now: dt.datetime) -> str:
    if not latest:
        return "empty"
    age = max(
        0.0,
        (
            now.astimezone(dt.timezone.utc) - parse_timestamp(latest)
        ).total_seconds(),
    )
    if age <= FRESH_SECONDS:
        return "fresh"
    if age <= STALE_SECONDS:
        return "stale"
    return "expired"


def source_status(
    *,
    status: str,
    complete: bool,
    pages: int,
    returned: int,
    latest: str,
    now: dt.datetime,
) -> Dict[str, Any]:
    return {
        "status": status,
        "complete": complete,
        "pages": pages,
        "returned": returned,
        "freshness": freshness(latest, now) if status == "ok" else "unknown",
        "latest_observation_at": latest,
    }


def _source_status_header(
    value: object,
    source: str,
) -> Tuple[Dict[str, Any], str]:
    if not isinstance(value, dict) or set(value) != SOURCE_STATUS_KEYS:
        raise ValueError(f"software inventory {source} source status is invalid")
    status = _bounded_text(
        value.get("status"),
        field=f"software inventory {source} status",
        maximum=16,
        required=True,
    )
    if status not in {"not_run", "disabled", "ok", "failed"}:
        raise ValueError(f"software inventory {source} status is unsupported")
    if not isinstance(value.get("complete"), bool):
        raise ValueError(f"software inventory {source} completeness is invalid")
    return value, status


def _source_status_counters(
    value: Dict[str, Any],
    source: str,
) -> Tuple[int, int]:
    pages = _bounded_integer(
        value.get("pages"),
        field=f"software inventory {source} page count",
        minimum=0,
        maximum=MAX_PAGES_PER_SOURCE,
    )
    returned = _bounded_integer(
        value.get("returned"),
        field=f"software inventory {source} returned count",
        minimum=0,
        maximum=MAX_TOTAL_RECORDS,
    )
    return pages, returned


def _source_status_freshness(
    value: Dict[str, Any],
    source: str,
) -> Tuple[str, str]:
    normalized_freshness = _bounded_text(
        value.get("freshness"),
        field=f"software inventory {source} freshness",
        maximum=16,
        required=True,
    )
    if normalized_freshness not in {
        "unknown", "empty", "fresh", "stale", "expired"
    }:
        raise ValueError(f"software inventory {source} freshness is invalid")
    latest = _bounded_text(
        value.get("latest_observation_at"),
        field=f"software inventory {source} latest observation",
        maximum=40,
    )
    if latest:
        latest = format_timestamp(parse_timestamp(latest))
    return normalized_freshness, latest


def _validate_source_status_policy(
    value: Dict[str, Any],
    source: str,
    status: str,
    normalized_freshness: str,
) -> None:
    if status == "ok" and value["complete"] is not True:
        raise ValueError(f"software inventory {source} successful status is incomplete")
    if status != "ok" and normalized_freshness != "unknown":
        raise ValueError(f"software inventory {source} failed status claims freshness")


def normalize_source_status(value: object, source: str) -> Dict[str, Any]:
    normalized_value, status = _source_status_header(value, source)
    pages, returned = _source_status_counters(normalized_value, source)
    normalized_freshness, latest = _source_status_freshness(
        normalized_value,
        source,
    )
    _validate_source_status_policy(
        normalized_value,
        source,
        status,
        normalized_freshness,
    )
    return {
        "status": status,
        "complete": normalized_value["complete"],
        "pages": pages,
        "returned": returned,
        "freshness": normalized_freshness,
        "latest_observation_at": latest,
    }


def _state_header(value: object) -> Tuple[Dict[str, Any], str]:
    if not isinstance(value, dict) or set(value) != STATE_KEYS:
        raise ValueError("software inventory state has an invalid shape")
    if value.get("schema") != STATE_SCHEMA or value.get("version") != 1:
        raise ValueError("software inventory state schema is unsupported")
    updated_at = _bounded_text(
        value.get("updated_at"),
        field="software inventory state updated_at",
        maximum=40,
    )
    if updated_at:
        updated_at = format_timestamp(parse_timestamp(updated_at))
    return value, updated_at


def _collection_header(
    collection: object,
) -> Tuple[Dict[str, Any], str, Dict[str, str], str, Dict[str, str]]:
    if (
        not isinstance(collection, dict)
        or frozenset(collection) not in COLLECTION_KEY_SETS
    ):
        raise ValueError("software inventory collection metadata is invalid")
    status = _bounded_text(
        collection.get("status"),
        field="software inventory collection status",
        maximum=16,
        required=True,
    )
    if status not in {"never_run", "disabled", "ok", "failed"}:
        raise ValueError("software inventory collection status is unsupported")
    timestamps: Dict[str, str] = {}
    for key in ("last_attempt_at", "last_success_at"):
        text = _bounded_text(
            collection.get(key),
            field=f"software inventory collection {key}",
            maximum=40,
        )
        timestamps[key] = format_timestamp(parse_timestamp(text)) if text else ""
    error = _bounded_text(
        collection.get("last_error"),
        field="software inventory collection error",
        maximum=500,
    )
    window = normalize_window(collection.get("window"), allow_empty=True)
    if not isinstance(collection.get("complete"), bool):
        raise ValueError("software inventory collection completeness is invalid")
    statuses = collection.get("source_statuses")
    if not isinstance(statuses, dict) or set(statuses) != set(SOURCES):
        raise ValueError("software inventory source status roster is invalid")
    return collection, status, timestamps, error, window


def _collection_statuses(
    collection: Dict[str, Any],
    status: str,
) -> Dict[str, Dict[str, Any]]:
    statuses = collection["source_statuses"]
    normalized = {
        source: normalize_source_status(statuses[source], source)
        for source in SOURCES
    }
    if status == "ok" and (
        collection["complete"] is not True
        or any(not item["complete"] for item in normalized.values())
    ):
        raise ValueError("successful software inventory state is incomplete")
    return normalized


def _state_records(value: object) -> List[Dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_TOTAL_RECORDS:
        raise ValueError("software inventory state record list is invalid")
    normalized_records: List[Dict[str, Any]] = []
    evidence_ids: Set[str] = set()
    for raw in value:
        record = normalize_record(raw)
        if record["evidence_id"] in evidence_ids:
            raise ValueError("software inventory state contains duplicate evidence")
        evidence_ids.add(record["evidence_id"])
        normalized_records.append(record)
    return normalized_records


def _normalized_state(
    updated_at: str,
    collection: Dict[str, Any],
    status: str,
    timestamps: Dict[str, str],
    error: str,
    window: Dict[str, str],
    statuses: Dict[str, Dict[str, Any]],
    records: List[Dict[str, Any]],
) -> Dict[str, Any]:
    normalized = {
        "schema": STATE_SCHEMA,
        "version": 1,
        "updated_at": updated_at,
        "collection": {
            "status": status,
            "last_attempt_at": timestamps["last_attempt_at"],
            "last_success_at": timestamps["last_success_at"],
            "last_error": error,
            "window": window,
            "source_statuses": statuses,
            "complete": collection["complete"],
        },
        "records": records,
    }
    if "osquery_ready" in collection:
        normalized["collection"]["osquery_ready"] = _bounded_integer(
            collection["osquery_ready"],
            field="software inventory OSQuery-ready endpoint count",
            minimum=0,
            maximum=MAX_TOTAL_RECORDS,
        )
    return normalized


def validate_state(value: object) -> Dict[str, Any]:
    state, updated_at = _state_header(value)
    collection, status, timestamps, error, window = _collection_header(
        state.get("collection")
    )
    statuses = _collection_statuses(collection, status)
    records = _state_records(state.get("records"))
    return _normalized_state(
        updated_at,
        collection,
        status,
        timestamps,
        error,
        window,
        statuses,
        records,
    )
