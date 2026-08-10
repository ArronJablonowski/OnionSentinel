"""Relay collection, private cache lifecycle, and review service composition."""
from __future__ import annotations

from ac_hunter_config import *  # noqa: F401,F403
from ac_hunter_config import (  # noqa: F401
    _parse_timestamp,
    _safe_error,
    _secure_file_bytes,
    _utc_iso,
)
from ac_hunter_transport import *  # noqa: F401,F403
from ac_hunter_normalization import *  # noqa: F401,F403
from ac_hunter_scoring import *  # noqa: F401,F403
from ac_hunter_collection import *  # noqa: F401,F403
def collect(client: AcHunterApiClient, clock: Callable[[], float]) -> Dict[str, Any]:
    raw: Dict[str, object] = {}
    statuses: Dict[str, Dict[str, object]] = {}
    successes = 0
    for operation, params, optional in COLLECTION_OPERATIONS:
        api_operation = (
            "useragent_count"
            if operation in {"useragent_count_false", "useragent_count_true"}
            else operation
        )
        try:
            raw[operation] = client.get(api_operation, params)
            statuses[operation] = {"status": "ok", "http_status": 200, "error": ""}
            successes += 1
        except AcHunterError as exc:
            statuses[operation] = {
                "status": "unavailable" if optional else "failed",
                "http_status": 0,
                "error": _safe_error(exc),
            }
    if successes == 0:
        raise AcHunterTransportError("all AC Hunter collection operations failed")
    return normalize_collection(
        raw,
        pulled_at=_utc_iso(clock()),
        source_statuses=statuses,
    )


def collect_from_relay(
    config_path: Path = DEFAULT_CONFIG,
    *,
    clock: Callable[[], float] = time.time,
) -> Dict[str, Any]:
    """Run one scheduled, normalized collection through the fixed Relay path."""

    config = load_config(config_path)
    if config.get("enabled") is not True:
        raise AcHunterConfigurationError("AC Hunter Deep Review is disabled")
    transport = RelayTransport(config)
    client = AcHunterApiClient(
        transport,
        lambda: load_credentials(Path(config["credentials_file"])),
        clock=clock,
    )
    return validate_cache(collect(client, clock))


def _validate_cache_tree(value: object, depth: int = 0) -> None:
    if depth > 12:
        raise AcHunterConfigurationError("AC Hunter cache nesting is invalid")
    if isinstance(value, dict):
        if len(value) > 1000:
            raise AcHunterConfigurationError("AC Hunter cache object is too large")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise AcHunterConfigurationError("AC Hunter cache key is invalid")
            if key.lower() in FORBIDDEN_CACHE_KEYS:
                raise AcHunterConfigurationError(
                    "AC Hunter cache contains authentication material"
                )
            _validate_cache_tree(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 5000:
            raise AcHunterConfigurationError("AC Hunter cache list is too large")
        for item in value:
            _validate_cache_tree(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > 8192 or any(
            ord(character) < 9
            or 13 < ord(character) < 32
            for character in value
        ):
            raise AcHunterConfigurationError("AC Hunter cache text is invalid")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise AcHunterConfigurationError("AC Hunter cache value is invalid")


def validate_cache(payload: object) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise AcHunterConfigurationError("AC Hunter cache must be an object")
    if (
        payload.get("schema") != REVIEW_SCHEMA
        or payload.get("version") != REVIEW_VERSION
        or payload.get("ok") is not True
        or not isinstance(payload.get("modules"), dict)
        or not isinstance(payload.get("metadata"), dict)
        or not isinstance(payload.get("cache"), dict)
    ):
        raise AcHunterConfigurationError("AC Hunter cache schema is unsupported")
    metadata = payload["metadata"]
    if metadata.get("dataset") != FIXED_DATASET:
        raise AcHunterConfigurationError("AC Hunter cache dataset is invalid")
    if _parse_timestamp(payload.get("last_pulled_at")) is None:
        raise AcHunterConfigurationError("AC Hunter cache timestamp is invalid")
    _validate_cache_tree(payload)
    return copy.deepcopy(payload)


def _prepare_private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise AcHunterConfigurationError(
            "AC Hunter cache directory is not owner-controlled"
        )


def load_cache(path: Path) -> Optional[Dict[str, Any]]:
    if Path(os.path.abspath(str(path))) != Path(
        os.path.abspath(str(DEFAULT_CACHE))
    ):
        raise AcHunterConfigurationError(
            "AC Hunter cache path is outside the fixed runtime location"
        )
    try:
        raw = _secure_file_bytes(path, maximum_bytes=MAX_CACHE_BYTES)
    except AcHunterConfigurationError:
        if not path.exists() and not path.is_symlink():
            return None
        raise
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcHunterConfigurationError("AC Hunter cache JSON is invalid") from exc
    return validate_cache(payload)


def atomic_write_cache(path: Path, payload: Mapping[str, Any]) -> None:
    if Path(os.path.abspath(str(path))) != Path(
        os.path.abspath(str(DEFAULT_CACHE))
    ):
        raise AcHunterConfigurationError(
            "AC Hunter cache path is outside the fixed runtime location"
        )
    normalized = validate_cache(dict(payload))
    encoded = (
        json.dumps(normalized, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_CACHE_BYTES:
        raise AcHunterConfigurationError("AC Hunter normalized cache is too large")
    _prepare_private_directory(path.parent)
    if path.exists() or path.is_symlink():
        _secure_file_bytes(path, maximum_bytes=MAX_CACHE_BYTES)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(path.parent)
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
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _cache_age(payload: Mapping[str, Any], now: float) -> float:
    refreshed = _parse_timestamp(payload.get("last_pulled_at"))
    if refreshed is None:
        return float("inf")
    return max(0.0, now - refreshed)


def _cache_view(
    payload: Mapping[str, Any],
    *,
    now: float,
    ttl: int,
    stale: bool,
    error: str = "",
) -> Dict[str, Any]:
    value = copy.deepcopy(dict(payload))
    age = int(_cache_age(value, now))
    status = "stale" if stale else "fresh"
    value["cache"] = {
        "status": status,
        "stale": stale,
        "refreshed_at": value.get("last_pulled_at", ""),
        "age_seconds": age,
        "ttl_seconds": ttl,
        "last_error": _safe_error(error, "") if error else "",
    }
    metadata = value.setdefault("metadata", {})
    metadata["stale"] = stale
    if error:
        metadata["collection_error"] = _safe_error(error)
    else:
        metadata.pop("collection_error", None)
    return value


class AcHunterReviewService:
    """Single-flight collection with normalized fresh/stale cache semantics."""

    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        client: Optional[AcHunterApiClient] = None,
        clock: Callable[[], float] = time.time,
        collector: Callable[[AcHunterApiClient, Callable[[], float]], Dict[str, Any]] = collect,
    ) -> None:
        self.config = dict(config)
        self.clock = clock
        self.collector = collector
        self._lock = threading.RLock()
        self._memory_cache: Optional[Dict[str, Any]] = None
        if client is None and self.config.get("enabled") is True:
            transport = RelayTransport(self.config)
            credentials_path = Path(self.config["credentials_file"])
            client = AcHunterApiClient(
                transport,
                lambda: load_credentials(credentials_path),
                clock=clock,
            )
        self.client = client

    @classmethod
    def from_config_path(
        cls, path: Path = DEFAULT_CONFIG
    ) -> "AcHunterReviewService":
        return cls(load_config(path))

    def _cached(self) -> Optional[Dict[str, Any]]:
        if self._memory_cache is not None:
            return copy.deepcopy(self._memory_cache)
        value = load_cache(Path(self.config["cache_file"]))
        if value is not None:
            self._memory_cache = value
            return copy.deepcopy(value)
        return None

    def response(self, force_refresh: bool = False) -> Tuple[int, Dict[str, Any]]:
        with self._lock:
            if self.config.get("enabled") is not True:
                return 503, _error_payload(
                    "AC Hunter Deep Review is disabled", stale=False
                )
            if self.client is None:
                return 503, _error_payload(
                    "AC Hunter client is unavailable", stale=False
                )
            now = self.clock()
            ttl = int(self.config["cache_ttl_seconds"])
            try:
                cached = self._cached()
            except AcHunterError:
                cached = None
            if (
                cached is not None
                and _cache_age(cached, now) <= ttl
                and (
                    not force_refresh
                    or _cache_age(cached, now)
                    < MIN_FORCE_REFRESH_INTERVAL_SECONDS
                )
            ):
                view = _cache_view(
                    cached, now=now, ttl=ttl, stale=False
                )
                if force_refresh:
                    view["cache"]["refresh_limited"] = True
                    view["cache"]["refresh_available_in_seconds"] = max(
                        0,
                        MIN_FORCE_REFRESH_INTERVAL_SECONDS
                        - int(_cache_age(cached, now)),
                    )
                return 200, view
            try:
                fresh = self.collector(self.client, self.clock)
                fresh = validate_cache(fresh)
                atomic_write_cache(Path(self.config["cache_file"]), fresh)
                self._memory_cache = fresh
                return 200, _cache_view(
                    fresh, now=self.clock(), ttl=ttl, stale=False
                )
            except Exception as exc:
                safe = (
                    _safe_error(exc)
                    if isinstance(exc, AcHunterError)
                    else "AC Hunter normalized collection failed"
                )
                if cached is not None:
                    return 200, _cache_view(
                        cached,
                        now=self.clock(),
                        ttl=ttl,
                        stale=True,
                        error=safe,
                    )
                return 503, _error_payload(safe, stale=False)


def _error_payload(error: str, *, stale: bool) -> Dict[str, Any]:
    return {
        "schema": REVIEW_SCHEMA,
        "version": REVIEW_VERSION,
        "ok": False,
        "last_pulled_at": "",
        "metadata": {
            "dataset": FIXED_DATASET,
            "source": "AC Hunter behavioral triage via the Onion Sentinel Relay",
            "transport_path": "Onion Sentinel → Relay → AC Hunter",
            "complete": False,
            "stale": stale,
            "collection_error": _safe_error(error),
        },
        "dataset": {"name": FIXED_DATASET, "time_range": {"start": "", "end": ""}},
        "time_range": {"start": "", "end": ""},
        "cache": {
            "status": "unavailable",
            "stale": stale,
            "refreshed_at": "",
            "age_seconds": 0,
            "ttl_seconds": 0,
            "last_error": _safe_error(error),
        },
        "verdict_counts": {name: 0 for name in VERDICT_ORDER},
        "top_hosts": [],
        "top_risky_internal_hosts": [],
        "correlated_hosts": [],
        "modules": {
            key: {
                "count": 0,
                "status": "unavailable",
                "error": "",
                "findings": [],
            }
            for key in MODULE_KEYS
        },
        "analyst_notes": [],
        "counts": {},
        "disclaimer": (
            "AC Hunter is a behavioral triage source. Scores and correlations "
            "do not by themselves establish malware or compromise."
        ),
    }


def database_review_response(
    api_url: str = DEFAULT_DATABASE_API_URL,
    *,
    timeout: float = 10.0,
) -> Tuple[int, Dict[str, Any]]:
    """Read one bounded normalized snapshot from loopback PostgreSQL storage."""

    if api_url != DEFAULT_DATABASE_API_URL:
        return 503, _error_payload(
            "AC Hunter database endpoint is outside the fixed allowlist",
            stale=False,
        )
    request = urllib.request.Request(
        api_url,
        method="GET",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_CACHE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        message = (
            "AC Hunter has not completed a scheduled database collection yet"
            if exc.code == 404
            else "AC Hunter PostgreSQL cache is unavailable"
        )
        return 503, _error_payload(message, stale=False)
    except (OSError, urllib.error.URLError, TimeoutError):
        return 503, _error_payload(
            "AC Hunter PostgreSQL cache is unavailable", stale=False
        )
    if len(raw) > MAX_CACHE_BYTES:
        return 503, _error_payload(
            "AC Hunter PostgreSQL response exceeds its size boundary",
            stale=False,
        )
    try:
        payload = validate_cache(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, AcHunterError):
        return 503, _error_payload(
            "AC Hunter PostgreSQL returned an invalid snapshot", stale=False
        )
    return 200, payload


def deep_review_response(
    force_refresh: bool = False,
) -> Tuple[int, Dict[str, object]]:
    """Read the database cache; web requests never trigger AC Hunter pulls."""

    del force_refresh
    return database_review_response()
