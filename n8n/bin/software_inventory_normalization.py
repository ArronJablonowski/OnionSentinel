"""Software evidence normalization, provenance, tiers, and freshness policy."""
from __future__ import annotations

from software_inventory_contract import *  # noqa: F401,F403
from software_inventory_contract import (  # noqa: F401
    _HEX_24,
    _LAN_NETWORKS,
    _UUID,
    _bounded_integer,
    _bounded_text,
)
def _normalize_window(value: object, *, allow_empty: bool = False) -> Dict[str, str]:
    if allow_empty and value == {}:
        return {}
    if not isinstance(value, dict) or set(value) != {"start", "end"}:
        raise ValueError("software inventory window is invalid")
    start = parse_timestamp(value.get("start"))
    end = parse_timestamp(value.get("end"))
    if start >= end or end - start > dt.timedelta(days=31):
        raise ValueError("software inventory window is out of bounds")
    return {"start": format_timestamp(start), "end": format_timestamp(end)}


def _normalize_cursor(
    value: object,
    *,
    allow_none: bool,
    expected_source: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if value is None and allow_none:
        return None
    if not isinstance(value, dict) or set(value) != CURSOR_KEYS:
        raise ValueError("software inventory cursor is invalid")
    asset = _bounded_text(
        value.get("asset"),
        field="software inventory cursor asset",
        maximum=512,
        required=True,
    )
    product = _bounded_text(
        value.get("product"),
        field="software inventory cursor product",
        maximum=4096,
        required=True,
    )
    raw_version = value.get("version")
    if raw_version is None:
        version = None
    else:
        version = _bounded_text(
            raw_version,
            field="software inventory cursor version",
            maximum=1024,
        )
    if expected_source == "osquery_apps" and _UUID.fullmatch(asset):
        raise ValueError("software inventory cursor host must not be UUID-shaped")
    return {"asset": asset, "product": product, "version": version}


def _cursor_order(value: Dict[str, Any]) -> Tuple[str, str, Tuple[int, str]]:
    version = value.get("version")
    return (
        str(value["asset"]),
        str(value["product"]),
        (0, "") if version in (None, "") else (1, str(version)),
    )


def _cursor_public_identity(
    source: str,
    cursor: Dict[str, Any],
) -> Tuple[str, str, str]:
    raw_asset = str(cursor["asset"])
    if source == "osquery_apps":
        normalized_host = raw_asset.strip().rstrip(".").lower()
        public_asset = hashlib.sha256(
            ("host\0" + normalized_host).encode("utf-8")
        ).hexdigest()[:24]
    else:
        public_asset = str(ipaddress.ip_address(raw_asset))
    return (
        public_asset,
        str(cursor["product"]),
        str(cursor["version"] or ""),
    )


def _normalize_record(
    value: object,
    *,
    expected_source: Optional[str] = None,
    expected_window: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    if (
        not isinstance(value, dict)
        or frozenset(value) not in RECORD_KEY_SETS
    ):
        raise ValueError("software inventory record has an invalid shape")
    source = _bounded_text(
        value.get("source"),
        field="software inventory record source",
        maximum=32,
        required=True,
    )
    if source not in SOURCE_POLICY or (
        expected_source is not None and source != expected_source
    ):
        raise ValueError("software inventory record source is invalid")
    policy = SOURCE_POLICY[source]
    dataset = _bounded_text(
        value.get("source_dataset"),
        field="software inventory source dataset",
        maximum=100,
        required=True,
    )
    allowed_datasets = {
        policy["dataset"],
        *policy.get("additional_datasets", set()),
    }
    if dataset not in allowed_datasets:
        raise ValueError("software inventory record dataset is invalid")
    tier = _bounded_text(
        value.get("tier"),
        field="software inventory evidence tier",
        maximum=16,
        required=True,
    )
    confidence = _bounded_text(
        value.get("confidence"),
        field="software inventory confidence",
        maximum=16,
        required=True,
    )
    if tier != policy["tier"] or confidence != policy["confidence"]:
        raise ValueError("software inventory record evidence semantics are invalid")
    evidence_id = _bounded_text(
        value.get("evidence_id"),
        field="software inventory evidence identifier",
        maximum=24,
        required=True,
    )
    if not _HEX_24.fullmatch(evidence_id):
        raise ValueError("software inventory evidence identifier is invalid")
    asset_ref_type = _bounded_text(
        value.get("asset_ref_type"),
        field="software inventory asset reference type",
        maximum=8,
        required=True,
    )
    if asset_ref_type != policy["asset_ref_type"]:
        raise ValueError("software inventory asset reference type is invalid")
    asset_ref = _bounded_text(
        value.get("asset_ref"),
        field="software inventory asset reference",
        maximum=253,
        required=True,
    )
    if asset_ref_type == "ip":
        address = ipaddress.ip_address(asset_ref)
        asset_ref = str(address)
        if not any(address in network for network in _LAN_NETWORKS):
            raise ValueError("software inventory IP reference is not a LAN address")
    elif asset_ref_type == "host":
        if source != "osquery_apps" or not _HEX_24.fullmatch(asset_ref):
            raise ValueError("software inventory host reference is invalid")
    else:
        raise ValueError("software inventory asset reference type is invalid")
    platform = _bounded_text(
        value.get("platform"),
        field="software inventory platform",
        maximum=160,
    ).lower()
    required_platform = str(policy.get("platform") or "")
    if platform != required_platform:
        raise ValueError("software inventory platform conflicts with its source")
    product = _bounded_text(
        value.get("product"),
        field="software inventory product",
        maximum=4096,
        required=True,
    )
    version = _bounded_text(
        value.get("version"),
        field="software inventory version",
        maximum=1024,
    )
    if source == "http_user_agent" and version:
        raise ValueError("HTTP user-agent evidence must not invent a version")
    category = _bounded_text(
        value.get("category"),
        field="software inventory category",
        maximum=256,
    )
    operating_system_type = _bounded_text(
        value.get("operating_system_type") or "",
        field="software inventory operating system type",
        maximum=160,
    )
    operating_system_version = _bounded_text(
        value.get("operating_system_version") or "",
        field="software inventory operating system version",
        maximum=512,
    )
    operating_system_source = _bounded_text(
        value.get("operating_system_source") or "",
        field="software inventory operating system source",
        maximum=128,
    )
    operating_system_confidence = _bounded_text(
        value.get("operating_system_confidence") or "",
        field="software inventory operating system confidence",
        maximum=16,
    ).lower()
    os_present = bool(operating_system_type or operating_system_version)
    if source == "osquery_apps":
        if os_present and (
            operating_system_source
            not in policy.get("operating_system_sources", set())
            or operating_system_confidence != "high"
        ):
            raise ValueError(
                "endpoint operating system evidence has invalid provenance"
            )
        if not os_present and (
            operating_system_source or operating_system_confidence
        ):
            raise ValueError(
                "empty endpoint operating system evidence claims provenance"
            )
    elif any(
        (
            operating_system_type,
            operating_system_version,
            operating_system_source,
            operating_system_confidence,
        )
    ):
        raise ValueError(
            "passive software evidence cannot assert an exact operating system"
        )
    first_seen = parse_timestamp(value.get("first_seen"))
    last_seen = parse_timestamp(value.get("last_seen"))
    if first_seen > last_seen:
        raise ValueError("software inventory record timestamps are reversed")
    if expected_window is not None:
        start = parse_timestamp(expected_window["start"])
        end = parse_timestamp(expected_window["end"])
        if first_seen < start or last_seen >= end:
            raise ValueError("software inventory record falls outside the query window")
    observation_count = _bounded_integer(
        value.get("observation_count"),
        field="software inventory observation count",
        minimum=1,
        maximum=MAX_OBSERVATION_COUNT,
    )
    return {
        "evidence_id": evidence_id,
        "source": source,
        "source_dataset": dataset,
        "tier": tier,
        "confidence": confidence,
        "asset_ref_type": asset_ref_type,
        "asset_ref": asset_ref,
        "platform": platform,
        "operating_system_type": operating_system_type,
        "operating_system_version": operating_system_version,
        "operating_system_source": operating_system_source,
        "operating_system_confidence": operating_system_confidence,
        "product": product,
        "version": version,
        "category": category,
        "first_seen": format_timestamp(first_seen),
        "last_seen": format_timestamp(last_seen),
        "observation_count": observation_count,
    }


def _freshness(latest: str, now: dt.datetime) -> str:
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


def _source_status(
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
        "freshness": _freshness(latest, now) if status == "ok" else "unknown",
        "latest_observation_at": latest,
    }


def _normalize_source_status(value: object, source: str) -> Dict[str, Any]:
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
    freshness = _bounded_text(
        value.get("freshness"),
        field=f"software inventory {source} freshness",
        maximum=16,
        required=True,
    )
    if freshness not in {"unknown", "empty", "fresh", "stale", "expired"}:
        raise ValueError(f"software inventory {source} freshness is invalid")
    latest = _bounded_text(
        value.get("latest_observation_at"),
        field=f"software inventory {source} latest observation",
        maximum=40,
    )
    if latest:
        latest = format_timestamp(parse_timestamp(latest))
    if status == "ok" and value["complete"] is not True:
        raise ValueError(f"software inventory {source} successful status is incomplete")
    if status != "ok" and freshness != "unknown":
        raise ValueError(f"software inventory {source} failed status claims freshness")
    return {
        "status": status,
        "complete": value["complete"],
        "pages": pages,
        "returned": returned,
        "freshness": freshness,
        "latest_observation_at": latest,
    }


def validate_state(value: object) -> Dict[str, Any]:
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
    collection = value.get("collection")
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
    window = _normalize_window(collection.get("window"), allow_empty=True)
    if not isinstance(collection.get("complete"), bool):
        raise ValueError("software inventory collection completeness is invalid")
    statuses = collection.get("source_statuses")
    if not isinstance(statuses, dict) or set(statuses) != set(SOURCES):
        raise ValueError("software inventory source status roster is invalid")
    normalized_statuses = {
        source: _normalize_source_status(statuses[source], source)
        for source in SOURCES
    }
    if status == "ok" and (
        collection["complete"] is not True
        or any(not item["complete"] for item in normalized_statuses.values())
    ):
        raise ValueError("successful software inventory state is incomplete")
    records = value.get("records")
    if not isinstance(records, list) or len(records) > MAX_TOTAL_RECORDS:
        raise ValueError("software inventory state record list is invalid")
    normalized_records: List[Dict[str, Any]] = []
    evidence_ids: Set[str] = set()
    for raw in records:
        record = _normalize_record(raw)
        if record["evidence_id"] in evidence_ids:
            raise ValueError("software inventory state contains duplicate evidence")
        evidence_ids.add(record["evidence_id"])
        normalized_records.append(record)
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
            "source_statuses": normalized_statuses,
            "complete": collection["complete"],
        },
        "records": normalized_records,
    }
    if "osquery_ready" in collection:
        normalized["collection"]["osquery_ready"] = _bounded_integer(
            collection["osquery_ready"],
            field="software inventory OSQuery-ready endpoint count",
            minimum=0,
            maximum=MAX_TOTAL_RECORDS,
        )
    return normalized
