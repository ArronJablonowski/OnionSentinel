"""Pure Software Inventory record and evidence normalization."""
from __future__ import annotations

from software_inventory_contract import *  # noqa: F401,F403
from software_inventory_contract import (  # noqa: F401
    _HEX_24,
    _LAN_NETWORKS,
    _bounded_integer,
    _bounded_text,
)


def _record_source(
    value: object,
    expected_source: Optional[str],
) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
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
    return value, source, SOURCE_POLICY[source]


def _record_evidence(
    value: Dict[str, Any],
    policy: Dict[str, Any],
) -> Tuple[str, str, str, str]:
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
    return dataset, tier, confidence, evidence_id


def _record_asset(
    value: Dict[str, Any],
    source: str,
    policy: Dict[str, Any],
) -> Tuple[str, str, str]:
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
    if platform != str(policy.get("platform") or ""):
        raise ValueError("software inventory platform conflicts with its source")
    return asset_ref_type, asset_ref, platform


def _record_product(
    value: Dict[str, Any],
    source: str,
) -> Tuple[str, str, str]:
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
    return product, version, category


def _operating_system_fields(value: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (
        _bounded_text(
            value.get("operating_system_type") or "",
            field="software inventory operating system type",
            maximum=160,
        ),
        _bounded_text(
            value.get("operating_system_version") or "",
            field="software inventory operating system version",
            maximum=512,
        ),
        _bounded_text(
            value.get("operating_system_source") or "",
            field="software inventory operating system source",
            maximum=128,
        ),
        _bounded_text(
            value.get("operating_system_confidence") or "",
            field="software inventory operating system confidence",
            maximum=16,
        ).lower(),
    )


def _record_operating_system(
    value: Dict[str, Any],
    source: str,
    policy: Dict[str, Any],
) -> Tuple[str, str, str, str]:
    fields = _operating_system_fields(value)
    os_type, os_version, os_source, os_confidence = fields
    os_present = bool(os_type or os_version)
    if source == "osquery_apps":
        if os_present and (
            os_source not in policy.get("operating_system_sources", set())
            or os_confidence != "high"
        ):
            raise ValueError(
                "endpoint operating system evidence has invalid provenance"
            )
        if not os_present and (os_source or os_confidence):
            raise ValueError(
                "empty endpoint operating system evidence claims provenance"
            )
    elif any(fields):
        raise ValueError(
            "passive software evidence cannot assert an exact operating system"
        )
    return fields


def _record_observation(
    value: Dict[str, Any],
    expected_window: Optional[Dict[str, str]],
) -> Tuple[str, str, int]:
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
    return (
        format_timestamp(first_seen),
        format_timestamp(last_seen),
        observation_count,
    )


def normalize_record(
    value: object,
    *,
    expected_source: Optional[str] = None,
    expected_window: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    record, source, policy = _record_source(value, expected_source)
    dataset, tier, confidence, evidence_id = _record_evidence(record, policy)
    asset_ref_type, asset_ref, platform = _record_asset(record, source, policy)
    product, version, category = _record_product(record, source)
    os_type, os_version, os_source, os_confidence = _record_operating_system(
        record, source, policy
    )
    first_seen, last_seen, observation_count = _record_observation(
        record, expected_window
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
        "operating_system_type": os_type,
        "operating_system_version": os_version,
        "operating_system_source": os_source,
        "operating_system_confidence": os_confidence,
        "product": product,
        "version": version,
        "category": category,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "observation_count": observation_count,
    }
