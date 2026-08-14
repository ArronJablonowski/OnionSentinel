"""Runtime composition for bounded alert-store transport and portal writes."""
from __future__ import annotations

from typing import Any


def asset_store_write_token(r: Any) -> str:
    return r.load_asset_store_write_token(
        r.os.environ.get("ASSET_STORE_WRITE_TOKEN"), r.Path(r.ASSET_STORE_ENV_FILE)
    )


def asset_store_post_json(
    r: Any, path: str, payload: dict, timeout: float = 10.0
) -> dict:
    return r.AssetStoreClient(
        base_url=r.SOC_ALERT_STORE_API_URL,
        maximum_response_bytes=r.SOC_ALERT_STORE_RESPONSE_MAX_BYTES,
        token=r.asset_store_write_token,
        read_json=r.read_bounded_json,
    ).post(path, payload, timeout)


def _alert_store_http_error(r: Any, exc: Any) -> Exception:
    try:
        error_payload = r.read_bounded_json(
            exc, max_bytes=r.SOC_ALERT_STORE_RESPONSE_MAX_BYTES
        )
        detail = str(
            error_payload.get("reason") or error_payload.get("error") or exc.reason
        )
    except (OSError, r.BoundedResponseError):
        detail = str(exc.reason)
    return r.AlertStoreRequestError(detail, int(exc.code or 503))


def alert_store_post_json(
    r: Any, path: str, payload: dict, timeout: float = 5.0
) -> dict:
    encoded = r.json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "Content-Length": str(len(encoded))}
    if r.SOC_ALERT_STORE_EVALUATION_TOKEN:
        headers["X-Onion-Sentinel-Evaluation-Token"] = r.SOC_ALERT_STORE_EVALUATION_TOKEN
    req = r.urllib_request.Request(
        f"{r.SOC_ALERT_STORE_API_URL}{path}", data=encoded,
        method="POST", headers=headers,
    )
    try:
        with r.urllib_request.urlopen(req, timeout=timeout) as response:
            result = r.read_bounded_json(
                response, max_bytes=r.SOC_ALERT_STORE_RESPONSE_MAX_BYTES
            )
    except r.urllib_error.HTTPError as exc:
        raise _alert_store_http_error(r, exc) from exc
    except (OSError, r.urllib_error.URLError, r.json.JSONDecodeError) as exc:
        raise r.AlertStoreRequestError(str(exc), 503) from exc
    if not isinstance(result, dict) or not result.get("ok"):
        raise r.AlertStoreRequestError(
            str(result.get("reason") or result.get("error") or "alert-store rejected request"), 400
        )
    return result


def normalized_asset_review_payload(r: Any, payload: object, *, action: str) -> dict:
    return r.normalize_asset_review_payload(payload, action=action)


def clear_asset_inventory_cache(r: Any) -> None:
    with r.ASSET_INVENTORY_CACHE_LOCK:
        r.ASSET_INVENTORY_CACHE.clear()
        r.ASSET_INVENTORY_CACHE.update(
            {"signature": None, "inventory": None, "expires_at": 0.0}
        )


def _asset_review_mutation(
    r: Any, payload: object, *, action: str, path: str, success_status: int
) -> tuple[int, dict]:
    return r.execute_asset_mutation(
        payload,
        normalizer=lambda value: r._normalized_asset_review_payload(value, action=action),
        path=path, success_status=success_status,
        write=r.asset_store_post_json, clear_cache=r._clear_asset_inventory_cache,
    )


def asset_dhcp_promotion_response(r: Any, payload: object) -> tuple[int, dict]:
    return _asset_review_mutation(
        r, payload, action="promote", path="/assets/promote-dhcp",
        success_status=r.HTTPStatus.CREATED,
    )


def asset_dhcp_ip_change_response(r: Any, payload: object) -> tuple[int, dict]:
    return _asset_review_mutation(
        r, payload, action="ip_change", path="/assets/approve-dhcp-ip-change",
        success_status=r.HTTPStatus.CREATED,
    )


def normalized_asset_mutation_payload(r: Any, payload: object, *, action: str) -> dict:
    return r.normalize_asset_mutation_payload(
        payload, action=action, parse_timestamp=r.parse_iso_timestamp
    )


def _asset_mutation(
    r: Any, payload: object, *, action: str, path: str
) -> tuple[int, dict]:
    return r.execute_asset_mutation(
        payload,
        normalizer=lambda value: r._normalized_asset_mutation_payload(value, action=action),
        path=path, success_status=r.HTTPStatus.OK,
        write=r.asset_store_post_json, clear_cache=r._clear_asset_inventory_cache,
    )


def asset_update_response(r: Any, payload: object) -> tuple[int, dict]:
    return _asset_mutation(r, payload, action="edit", path="/assets/update")


def asset_demote_response(r: Any, payload: object) -> tuple[int, dict]:
    return _asset_mutation(r, payload, action="demote", path="/assets/demote")


def dispatch_asset_write(r: Any, path: str, payload: object) -> tuple[int, dict]:
    callbacks = {
        "/api/assets/promote-dhcp": r.asset_dhcp_promotion_response,
        "/api/assets/approve-dhcp-ip-change": r.asset_dhcp_ip_change_response,
        "/api/assets/update": r.asset_update_response,
        "/api/assets/demote": r.asset_demote_response,
    }
    callback = callbacks.get(path)
    if callback is None:
        return r.HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"}
    return callback(payload)


def portal_cti_program_callbacks(r: Any, audit: Any) -> Any:
    return r.CtiProgramCallbacks(
        load=r.cti_program.load_program, save=r.cti_program.save_program,
        public_response=r.cti_program.public_response, audit=audit,
        conflict_error=r.cti_program.CTIProgramConflict,
        program_error=r.cti_program.CTIProgramError,
    )


def alert_store_get_json(r: Any, path: str, timeout: float = 5.0) -> dict:
    if not r.SOC_ALERT_STORE_API_URL:
        raise RuntimeError("alert-store API URL is not configured")
    try:
        req = r.urllib_request.Request(f"{r.SOC_ALERT_STORE_API_URL}{path}", method="GET")
    except ValueError as exc:
        raise RuntimeError(f"invalid alert-store API URL: {exc}") from exc
    try:
        with r.urllib_request.urlopen(req, timeout=timeout) as response:
            result = r.read_bounded_json(
                response, max_bytes=r.SOC_ALERT_STORE_RESPONSE_MAX_BYTES
            )
    except r.urllib_error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}: {exc.reason}") from exc
    except (OSError, r.urllib_error.URLError, r.json.JSONDecodeError) as exc:
        raise RuntimeError(str(exc)) from exc
    if not isinstance(result, dict) or not result.get("ok"):
        raise RuntimeError(
            str(result.get("reason") or result.get("error") or "alert-store returned invalid metrics")
        )
    return result
