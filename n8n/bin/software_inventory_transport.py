"""Private state persistence and bounded read-only relay collection."""
from __future__ import annotations

from software_inventory_contract import *  # noqa: F401,F403
from software_inventory_contract import (  # noqa: F401
    _CORRELATION_ID,
    _HEX_24,
    _HEX_64,
    _bounded_integer,
    _owner_file,
    _read_json_file,
)
from software_inventory_normalization import *  # noqa: F401,F403
from software_inventory_normalization import (  # noqa: F401
    _cursor_order,
    _cursor_public_identity,
    _normalize_cursor,
    _normalize_record,
    _normalize_window,
)

def database_write_token(path: Path) -> str:
    metadata = path.lstat()
    if (
        not path.is_file()
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 1024 * 1024
    ):
        raise ValueError("runtime environment file is not owner-controlled")
    values: Dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    token = values.get("ASSET_STORE_WRITE_TOKEN") or values.get(
        "N8N_POST_COMMIT_TOKEN"
    )
    if not token or len(token) < 32:
        raise ValueError("software inventory database write token is missing")
    return token


def _database_post(
    api_url: str,
    token: str,
    route: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    encoded = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    request = urllib_request.Request(
        f"{api_url.rstrip('/')}{route}",
        data=encoded,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(encoded)),
            "X-Onion-Sentinel-Asset-Token": token,
        },
    )
    try:
        with urllib_request.urlopen(request, timeout=60) as response:
            body = response.read(1024 * 1024 + 1)
    except urllib_error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        raise RuntimeError(
            f"software inventory database returned HTTP {exc.code}: "
            f"{' '.join(detail.split())[:300]}"
        ) from exc
    except (OSError, urllib_error.URLError) as exc:
        raise RuntimeError(
            f"software inventory database is unavailable: {exc}"
        ) from exc
    if len(body) > 1024 * 1024:
        raise RuntimeError("software inventory database response is too large")
    result = json.loads(body)
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise RuntimeError("software inventory database rejected the request")
    return result


def publish_database_snapshot(
    state: Dict[str, Any],
    *,
    api_url: str,
    token: str,
) -> Dict[str, Any]:
    normalized = validate_state(state)
    canonical = json.dumps(
        normalized,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    snapshot_id = hashlib.sha256(canonical).hexdigest()
    start = _database_post(
        api_url,
        token,
        "/software-inventory/import/start",
        {
            "snapshot_id": snapshot_id,
            "updated_at": normalized["updated_at"],
            "collection": normalized["collection"],
            "expected_records": len(normalized["records"]),
        },
    )
    if start.get("already_active") is not True:
        records = normalized["records"]
        for offset in range(0, len(records), DATABASE_CHUNK_SIZE):
            _database_post(
                api_url,
                token,
                "/software-inventory/import/chunk",
                {
                    "snapshot_id": snapshot_id,
                    "records": records[offset : offset + DATABASE_CHUNK_SIZE],
                },
            )
        _database_post(
            api_url,
            token,
            "/software-inventory/import/commit",
            {"snapshot_id": snapshot_id},
        )
    return {
        "ok": True,
        "snapshot_id": snapshot_id,
        "records": len(normalized["records"]),
        "already_active": start.get("already_active") is True,
    }

def load_state(path: Path) -> Dict[str, Any]:
    try:
        value = _read_json_file(path, MAX_STATE_BYTES, exact_mode=0o600)
    except FileNotFoundError:
        return empty_state()
    return validate_state(value)


def load_endpoint_cache(
    path: Path,
    now: dt.datetime,
    *,
    maximum_age: dt.timedelta = dt.timedelta(hours=36),
) -> Optional[Dict[str, Any]]:
    """Return one complete, fresh, owner-controlled endpoint cache."""
    try:
        value = _read_json_file(path, MAX_STATE_BYTES, exact_mode=0o600)
    except FileNotFoundError:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema", "version", "updated_at", "complete", "targets", "records"
        }
        or value.get("schema") != "onion-sentinel-endpoint-software-cache-v1"
        or value.get("version") != 1
        or value.get("complete") is not True
    ):
        raise ValueError("endpoint software inventory cache is invalid")
    updated = parse_timestamp(value.get("updated_at"))
    current = now.astimezone(dt.timezone.utc)
    if updated > current + dt.timedelta(minutes=5) or current - updated > maximum_age:
        return None
    targets = value.get("targets")
    records = value.get("records")
    if (
        not isinstance(targets, list)
        or not targets
        or len(targets) > 64
        or not isinstance(records, list)
        or len(records) > MAX_TOTAL_RECORDS
    ):
        raise ValueError("endpoint software inventory cache is out of bounds")
    assets: Set[str] = set()
    for target in targets:
        if (
            not isinstance(target, dict)
            or set(target) != {"asset_ref", "status", "records", "observed_at"}
            or target.get("status") != "ok"
            or not _HEX_24.fullmatch(str(target.get("asset_ref") or ""))
        ):
            raise ValueError("endpoint software inventory target status is invalid")
        assets.add(str(target["asset_ref"]))
    normalized = [
        _normalize_record(record, expected_source="osquery_apps")
        for record in records
    ]
    if any(record["asset_ref"] not in assets for record in normalized):
        raise ValueError("endpoint software inventory record has no target coverage")
    return {
        "updated_at": format_timestamp(updated),
        "targets": len(assets),
        "records": normalized,
    }


def _prepare_private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(parents=True, exist_ok=False, mode=0o700)
        except FileExistsError:
            # Another same-UID collector may have created it between lstat and
            # mkdir; the ownership/type checks below still decide trust.
            pass
        info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
    ):
        raise ValueError(
            "software inventory state directory is not owner-controlled"
        )
    os.chmod(path, 0o700)


def atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    normalized = validate_state(payload)
    encoded = (
        json.dumps(normalized, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        raise ValueError("software inventory state exceeds its byte limit")
    _prepare_private_directory(path.parent)
    if path.exists() or path.is_symlink():
        _owner_file(path, maximum_bytes=MAX_STATE_BYTES, exact_mode=0o600)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=str(path.parent),
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(str(temporary), str(path))
        os.chmod(path, 0o600)
        directory_descriptor = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@contextlib.contextmanager
def collector_lock(state_path: Path) -> Iterator[None]:
    _prepare_private_directory(state_path.parent)
    lock_path = state_path.parent / ".collector.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(lock_path), flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError("software inventory collector lock is invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SoftwareInventoryError(
                "software inventory collection is already running"
            ) from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def build_request(
    source: str,
    window: Dict[str, str],
    page_size: int,
    after: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if source not in SOURCE_POLICY:
        raise ValueError("software inventory source is unsupported")
    normalized_window = _normalize_window(window)
    bounded_page_size = _bounded_integer(
        page_size,
        field="software inventory page size",
        minimum=1,
        maximum=MAX_PAGE_SIZE,
    )
    cursor = _normalize_cursor(
        after,
        allow_none=True,
        expected_source=source,
    )
    return {
        "contract": CONTRACT,
        "operation": OPERATION,
        "source": source,
        "window": normalized_window,
        "page_size": bounded_page_size,
        "after": cursor,
    }


def relay_failure_diagnostic(stdout: object, stderr: object) -> str:
    messages: List[str] = []
    try:
        payload = json.loads(str(stdout or ""))
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        for key in (
            "error",
            "detail",
            "upstream_error",
            "upstream_detail",
            "transport_detail",
        ):
            raw = payload.get(key)
            if not isinstance(raw, str):
                continue
            text = " ".join(
                "".join(
                    character if character.isprintable() else " "
                    for character in raw
                ).split()
            )
            if text:
                messages.append(text[:300])
    stderr_text = " ".join(
        "".join(
            character if character.isprintable() else " "
            for character in str(stderr or "")
        ).split()
    )
    if stderr_text:
        messages.append(stderr_text[:300])
    return "; ".join(messages)[:700]


def validate_response(
    value: object,
    *,
    expected_source: str,
    expected_window: Dict[str, str],
    requested_page_size: int,
    previous_after: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) not in RESPONSE_KEY_SETS:
        raise ValueError("relay response has an invalid software inventory shape")
    if (
        value.get("ok") is not True
        or value.get("contract") != CONTRACT
        or value.get("read_only") is not True
        or value.get("source") != expected_source
    ):
        raise ValueError("relay response failed the software inventory contract")
    window = _normalize_window(value.get("window"))
    if window != _normalize_window(expected_window):
        raise ValueError("relay response window does not match the request")
    receipt = value.get("audit_receipt")
    if receipt is not None:
        response_without_receipt = {
            key: item for key, item in value.items() if key != "audit_receipt"
        }
        expected_request = build_request(
            expected_source,
            expected_window,
            requested_page_size,
            previous_after,
        )
        if (
            not isinstance(receipt, dict)
            or set(receipt) != AUDIT_RECEIPT_KEYS
            or receipt.get("receipt_contract") != TRANSPORT_RECEIPT_CONTRACT
            or not _CORRELATION_ID.fullmatch(
                str(receipt.get("correlation_id") or "")
            )
            or receipt.get("request_digest")
            != hashlib.sha256(
                json.dumps(
                    expected_request,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
            or receipt.get("response_payload_digest")
            != hashlib.sha256(
                json.dumps(
                    response_without_receipt,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
            or receipt.get("read_only") is not True
            or receipt.get("terminal_status")
            != ("complete" if value.get("complete") is True else "partial")
            or any(
                isinstance(receipt.get(field), bool)
                or not isinstance(receipt.get(field), int)
                for field in (
                    "elastic_search_count",
                    "osquery_query_count",
                    "helper_invocation_count",
                )
            )
            or (
                receipt.get("elastic_search_count"),
                receipt.get("osquery_query_count"),
                receipt.get("helper_invocation_count"),
            ) != (0, 0, 1)
        ):
            raise ValueError(
                "relay response audit receipt failed validation"
            )
    records = value.get("records")
    returned = value.get("returned")
    if (
        not isinstance(records, list)
        or isinstance(returned, bool)
        or not isinstance(returned, int)
        or returned != len(records)
        or returned > requested_page_size
    ):
        raise ValueError("relay response result accounting is invalid")
    complete = value.get("complete")
    truncated = value.get("truncated")
    if not isinstance(complete, bool) or not isinstance(truncated, bool):
        raise ValueError("relay response pagination state is invalid")
    after = _normalize_cursor(
        value.get("after"),
        allow_none=True,
        expected_source=expected_source,
    )
    if complete:
        if truncated or after is not None:
            raise ValueError("terminal software inventory page is inconsistent")
    elif (
        not truncated
        or after is None
        or returned != requested_page_size
        or returned == 0
    ):
        raise ValueError("non-terminal software inventory page is inconsistent")
    audit = value.get("query_audit")
    policy = SOURCE_POLICY[expected_source]
    if (
        not isinstance(audit, dict)
        or set(audit) != QUERY_AUDIT_KEYS
        or audit.get("index") != policy["index"]
        or audit.get("dataset") != policy["dataset"]
        or not _HEX_64.fullmatch(str(audit.get("query_digest") or ""))
    ):
        raise ValueError("relay response fixed-query audit is invalid")
    normalized_records: List[Dict[str, Any]] = []
    previous_cursor = (
        _normalize_cursor(
            previous_after,
            allow_none=False,
            expected_source=expected_source,
        )
        if previous_after is not None
        else None
    )
    for raw in records:
        record = _normalize_record(
            raw,
            expected_source=expected_source,
            expected_window=window,
        )
        normalized_records.append(record)
    if after is not None:
        # OSQuery cursors contain the indexed hostname, while the public
        # records intentionally contain only a hostname digest.  Therefore a
        # cursor must never be derived from or compared with a public record.
        # It is validated solely as a strictly advancing, transient token.
        if previous_cursor is not None and (
            _cursor_order(after) <= _cursor_order(previous_cursor)
        ):
            raise ValueError("software inventory cursor did not advance")
        if not normalized_records or _cursor_public_identity(
            expected_source,
            after,
        ) != (
            normalized_records[-1]["asset_ref"],
            normalized_records[-1]["product"],
            normalized_records[-1]["version"],
        ):
            raise ValueError(
                "software inventory cursor does not identify the last public record"
            )
    normalized = dict(value)
    normalized["window"] = window
    normalized["after"] = after
    normalized["records"] = normalized_records
    normalized["query_audit"] = {
        "index": policy["index"],
        "dataset": policy["dataset"],
        "query_digest": str(audit["query_digest"]),
    }
    return normalized


def query_page(
    config: Dict[str, Any],
    source: str,
    window: Dict[str, str],
    page_size: int,
    after: Optional[Dict[str, Any]],
    timeout_seconds: float,
) -> Dict[str, Any]:
    """Read one fixed aggregation page through the forced SSH command."""
    request = build_request(source, window, page_size, after)
    command = [
        "/usr/bin/ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={config['known_hosts']}",
        "-o",
        f"ConnectTimeout={config['connect_timeout_seconds']}",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-i",
        str(config["ssh_key"]),
        "-p",
        str(config["port"]),
        f"{config['ssh_user']}@{config['host']}",
    ]
    completed = run_bounded_command(
        command,
        stdin_text=json.dumps(request, separators=(",", ":"), sort_keys=True),
        timeout_seconds=max(1.0, float(timeout_seconds)),
        max_stdout_bytes=config["max_response_bytes"],
        max_stderr_bytes=config["max_stderr_bytes"],
    )
    if completed.returncode != 0:
        detail = relay_failure_diagnostic(completed.stdout, completed.stderr)
        raise SoftwareInventoryError(
            f"software inventory relay returned {completed.returncode}: "
            f"{detail or 'no bounded diagnostic'}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SoftwareInventoryError(
            "software inventory relay returned invalid JSON"
        ) from exc
    return validate_response(
        payload,
        expected_source=source,
        expected_window=request["window"],
        requested_page_size=page_size,
        previous_after=after,
    )
