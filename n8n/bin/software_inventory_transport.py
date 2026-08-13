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
import software_inventory_validation as _validation


def _require_owner_controlled_environment(path: Path) -> None:
    metadata = path.lstat()
    if (
        not path.is_file()
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 1024 * 1024
    ):
        raise ValueError("runtime environment file is not owner-controlled")


def _environment_values(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _database_token(values: Dict[str, str]) -> str:
    token = values.get("ASSET_STORE_WRITE_TOKEN") or values.get(
        "N8N_POST_COMMIT_TOKEN"
    )
    if not token or len(token) < 32:
        raise ValueError("software inventory database write token is missing")
    return token


def database_write_token(path: Path) -> str:
    _require_owner_controlled_environment(path)
    return _database_token(_environment_values(path))


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
    return _validation.validated_endpoint_cache(value, now, maximum_age)


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


def _diagnostic_text(value: object) -> str:
    return " ".join(
        "".join(
            character if character.isprintable() else " "
            for character in str(value or "")
        ).split()
    )


def _relay_payload_messages(payload: object) -> List[str]:
    if not isinstance(payload, dict):
        return []
    messages: List[str] = []
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
        text = _diagnostic_text(raw)
        if text:
            messages.append(text[:300])
    return messages


def relay_failure_diagnostic(stdout: object, stderr: object) -> str:
    try:
        payload = json.loads(str(stdout or ""))
    except json.JSONDecodeError:
        payload = None
    messages = _relay_payload_messages(payload)
    stderr_text = _diagnostic_text(stderr)
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
    return _validation.validate_relay_response(
        value,
        expected_source=expected_source,
        expected_window=expected_window,
        requested_page_size=requested_page_size,
        previous_after=previous_after,
        build_request=build_request,
    )


def _relay_ssh_command(config: Dict[str, Any]) -> List[str]:
    return [
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
    completed = run_bounded_command(
        _relay_ssh_command(config),
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
