"""Secure configuration and persistence boundary for access observation."""
from __future__ import annotations

from collections.abc import Callable, Mapping
import os
from pathlib import Path
import re
import stat
import threading

from portal_access_enforcement import (
    MODE_ADMIN_ENFORCE,
    MODE_LEGACY,
    MODE_OBSERVE,
    MODE_RBAC_ENFORCE,
    parse_mode,
)
from portal_access_observer import (
    AccessObservation,
    begin_observation,
    finalize_observation,
    precommit_observation,
)
from portal_admin_audit_store import (
    append_verified_event,
    load_verified_events,
)
from portal_request_routes import PostRoute
from portal_session_principal import HumanPrincipal


ACCESS_MODE_ENV = "ONION_SENTINEL_ACCESS_MODE"
KEY_FILENAME = "onion-sentinel-admin-audit-signing.key"
LEDGER_FILENAME = "onion-sentinel-admin-audit.jsonl"
HEX_KEY_RE = re.compile(r"^[a-f0-9]{64}$")


class AccessObserverConfigurationError(RuntimeError):
    """Raised when observe-mode custody or mode admission is unsafe."""


def audit_signing_key_path(home: Path) -> Path:
    return Path(home) / "n8n-local" / "config" / KEY_FILENAME


def audit_ledger_path(home: Path) -> Path:
    return Path(home) / "n8n-local" / "logs" / LEDGER_FILENAME


def _owner_private_file(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AccessObserverConfigurationError(
            "access audit signing key is unavailable"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size < 1
            or metadata.st_size > maximum_bytes
        ):
            raise AccessObserverConfigurationError(
                "access audit signing key must be an owner-only regular file"
            )
        payload = os.read(descriptor, maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if len(payload) > maximum_bytes:
        raise AccessObserverConfigurationError(
            "access audit signing key exceeds its size limit"
        )
    return payload


def _load_signing_key(path: Path) -> bytes:
    payload = _owner_private_file(path, 65)
    try:
        value = payload.decode("ascii").removesuffix("\n")
    except UnicodeDecodeError as exc:
        raise AccessObserverConfigurationError(
            "access audit signing key has an invalid format"
        ) from exc
    if not HEX_KEY_RE.fullmatch(value):
        raise AccessObserverConfigurationError(
            "access audit signing key has an invalid format"
        )
    return bytes.fromhex(value)


class AccessObserverRuntime:
    """Audit phased write decisions and precommit enforced mutations."""

    def __init__(
        self,
        *,
        mode: str,
        signing_key: bytes | None,
        ledger_path: Path,
        append_event: Callable[..., object] = append_verified_event,
        failure_sink: Callable[[str], object] | None = None,
        initial_event_count: int = 0,
    ) -> None:
        self.mode = parse_mode(mode)
        if self.mode not in {
            MODE_LEGACY,
            MODE_OBSERVE,
            MODE_ADMIN_ENFORCE,
            MODE_RBAC_ENFORCE,
        }:
            raise AccessObserverConfigurationError(
                "configured access enforcement mode is not qualified"
            )
        if self.mode != MODE_LEGACY and (
            not isinstance(signing_key, bytes) or len(signing_key) < 32
        ):
            raise AccessObserverConfigurationError(
                "enabled access mode requires an access audit signing key"
            )
        self._signing_key = signing_key
        self._ledger_path = Path(ledger_path)
        self._append_event = append_event
        self._failure_sink = failure_sink
        self._lock = threading.Lock()
        self._event_count = initial_event_count
        self._failure_count = 0
        self._last_failure_type = ""

    @property
    def enabled(self) -> bool:
        return self.mode != MODE_LEGACY

    @property
    def enforcing(self) -> bool:
        return self.mode in {MODE_ADMIN_ENFORCE, MODE_RBAC_ENFORCE}

    def begin(
        self,
        route: PostRoute,
        *,
        principal: HumanPrincipal | None,
        same_origin_authorized: bool,
        csrf_authorized: bool,
        request_id: str,
    ) -> AccessObservation | None:
        if not self.enabled:
            return None
        return begin_observation(
            route,
            mode=self.mode,
            principal=principal,
            same_origin_authorized=same_origin_authorized,
            csrf_authorized=csrf_authorized,
            request_id=request_id,
            signing_key=self._signing_key,
        )

    def _record_failure(self, error_type: str) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_type = error_type
        if self._failure_sink is not None:
            try:
                self._failure_sink(error_type)
            except Exception:
                pass

    def record_boundary_failure(self, error_type: str) -> None:
        """Record a safe failure type without accepting exception detail."""
        self._record_failure(error_type)

    def finalize(
        self,
        observation: AccessObservation | None,
        *,
        http_status: int,
        occurred_at: str,
    ) -> bool:
        if observation is None:
            return True
        fields = finalize_observation(
            observation,
            http_status=http_status,
            occurred_at=occurred_at,
        )
        try:
            self._append_event(
                self._ledger_path,
                fields,
                signing_key=self._signing_key,
            )
        except Exception as exc:
            self._record_failure(type(exc).__name__)
            return False
        with self._lock:
            self._event_count += 1
        return True

    def precommit(
        self,
        observation: AccessObservation | None,
        *,
        occurred_at: str,
    ) -> bool:
        if observation is None or not self.enforcing:
            return True
        try:
            fields = precommit_observation(
                observation,
                occurred_at=occurred_at,
            )
            self._append_event(
                self._ledger_path,
                fields=fields,
                signing_key=self._signing_key,
            )
        except Exception as exc:
            self._record_failure(type(exc).__name__)
            return False
        with self._lock:
            self._event_count += 1
        return True

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "mode": self.mode,
                "enabled": self.enabled,
                "enforcing": self.enforcing,
                "audit_event_count": self._event_count,
                "audit_failure_count": self._failure_count,
                "last_failure_type": self._last_failure_type,
            }


def load_access_observer_runtime(
    *,
    environ: Mapping[str, str],
    home: Path,
    failure_sink: Callable[[str], object] | None = None,
) -> AccessObserverRuntime:
    mode = parse_mode(str(environ.get(ACCESS_MODE_ENV) or MODE_LEGACY))
    ledger_path = audit_ledger_path(home)
    if mode == MODE_LEGACY:
        return AccessObserverRuntime(
            mode=mode,
            signing_key=None,
            ledger_path=ledger_path,
            failure_sink=failure_sink,
        )
    if mode not in {
        MODE_OBSERVE,
        MODE_ADMIN_ENFORCE,
        MODE_RBAC_ENFORCE,
    }:
        raise AccessObserverConfigurationError(
            "configured access enforcement mode is not qualified"
        )
    key = _load_signing_key(audit_signing_key_path(home))
    try:
        events = load_verified_events(ledger_path, signing_key=key)
    except Exception as exc:
        raise AccessObserverConfigurationError(
            "access audit ledger verification failed"
        ) from exc
    return AccessObserverRuntime(
        mode=mode,
        signing_key=key,
        ledger_path=ledger_path,
        failure_sink=failure_sink,
        initial_event_count=len(events),
    )


__all__ = (
    "ACCESS_MODE_ENV",
    "AccessObserverConfigurationError",
    "AccessObserverRuntime",
    "audit_ledger_path",
    "audit_signing_key_path",
    "load_access_observer_runtime",
)
