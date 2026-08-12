"""Compatibility facade for Software Inventory normalization policy."""
from __future__ import annotations

from software_inventory_contract import *  # noqa: F401,F403
from software_inventory_contract import _UUID, _bounded_text
from software_inventory_record_normalization import normalize_record as _normalize_record
from software_inventory_state_validation import (  # noqa: F401
    freshness as _freshness,
    normalize_source_status as _normalize_source_status,
    normalize_window as _normalize_window,
    source_status as _source_status,
    validate_state,
)


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
