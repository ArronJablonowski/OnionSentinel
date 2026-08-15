"""Strict owner-managed Viewer and Analyst credential admission."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat

from portal_access_policy import HUMAN_PRINCIPAL_KIND
from portal_admin_session_store import (
    validate_password_record,
    verify_admin_password,
)
from portal_session_principal import HumanPrincipal, PRINCIPAL_ID_RE


STORE_SCHEMA = "onion-sentinel-human-identities-v1"
STORE_FIELDS = frozenset({"schema", "generation", "identities"})
IDENTITY_FIELDS = frozenset({
    "username", "principal_id", "role", "password",
})
DELEGATED_ROLES = frozenset({"viewer", "analyst"})
RESERVED_ADMINISTRATOR_ID = "local-administrator"
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
MAXIMUM_STORE_BYTES = 256 * 1024
MAXIMUM_IDENTITIES = 64
MAXIMUM_GENERATION = 1_000_000
DUMMY_PASSWORD_RECORD = {
    "algorithm": "pbkdf2_sha256",
    "iterations": 200_000,
    "salt": "00" * 16,
    "hash": "00" * 32,
}


class HumanIdentityConfigurationError(RuntimeError):
    """Raised when an owner-managed identity store is unsafe or ambiguous."""


@dataclass(frozen=True)
class HumanIdentity:
    username: str
    principal_id: str
    role: str
    password_record: dict[str, object]


@dataclass(frozen=True)
class HumanIdentityStore:
    generation: int
    identities: dict[str, HumanIdentity]


def empty_human_identity_store() -> HumanIdentityStore:
    return HumanIdentityStore(0, {})


def _validate_parent(path: Path) -> None:
    try:
        metadata = path.parent.lstat()
    except OSError as exc:
        raise HumanIdentityConfigurationError(
            "human identity directory is unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise HumanIdentityConfigurationError(
            "human identity directory must be owner-only"
        )


def _owner_private_payload(path: Path) -> bytes | None:
    _validate_parent(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise HumanIdentityConfigurationError(
            "human identity store is unavailable"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 1 <= metadata.st_size <= MAXIMUM_STORE_BYTES
        ):
            raise HumanIdentityConfigurationError(
                "human identity store must be a bounded owner-only regular file"
            )
        payload = os.read(descriptor, MAXIMUM_STORE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) > MAXIMUM_STORE_BYTES:
        raise HumanIdentityConfigurationError(
            "human identity store must be a bounded owner-only regular file"
        )
    return payload


def _password_record(value: object) -> dict[str, object]:
    try:
        return validate_password_record(value)
    except Exception as exc:
        raise HumanIdentityConfigurationError(
            "human identity store has an invalid format"
        ) from exc


def _identity(value: object) -> HumanIdentity:
    if not isinstance(value, dict) or set(value) != IDENTITY_FIELDS:
        raise HumanIdentityConfigurationError(
            "human identity store has an invalid format"
        )
    username = value.get("username")
    principal_id = value.get("principal_id")
    role = value.get("role")
    if (
        not isinstance(username, str)
        or not USERNAME_RE.fullmatch(username)
        or username == RESERVED_ADMINISTRATOR_ID
        or not isinstance(principal_id, str)
        or not PRINCIPAL_ID_RE.fullmatch(principal_id)
        or principal_id == RESERVED_ADMINISTRATOR_ID
        or role not in DELEGATED_ROLES
    ):
        raise HumanIdentityConfigurationError(
            "human identity store has an invalid format"
        )
    return HumanIdentity(
        username=username,
        principal_id=principal_id,
        role=str(role),
        password_record=_password_record(value.get("password")),
    )


def _store_envelope(payload: bytes) -> tuple[int, list[object]]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HumanIdentityConfigurationError(
            "human identity store has an invalid format"
        ) from exc
    if (
        not isinstance(value, dict)
        or set(value) != STORE_FIELDS
        or value.get("schema") != STORE_SCHEMA
    ):
        raise HumanIdentityConfigurationError(
            "human identity store has an invalid format"
        )
    generation = value.get("generation")
    records = value.get("identities")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or not 1 <= generation <= MAXIMUM_GENERATION
        or not isinstance(records, list)
        or not 0 <= len(records) <= MAXIMUM_IDENTITIES
    ):
        raise HumanIdentityConfigurationError(
            "human identity store has an invalid format"
        )
    return generation, records


def _identity_map(records: list[object]) -> dict[str, HumanIdentity]:
    identities: dict[str, HumanIdentity] = {}
    principals: set[str] = set()
    for record in records:
        identity = _identity(record)
        if identity.username in identities or identity.principal_id in principals:
            raise HumanIdentityConfigurationError(
                "human identity store has ambiguous identities"
            )
        identities[identity.username] = identity
        principals.add(identity.principal_id)
    return identities


def _validated_store(payload: bytes) -> HumanIdentityStore:
    generation, records = _store_envelope(payload)
    return HumanIdentityStore(generation, _identity_map(records))


def load_enforcement_human_identity_store(path: Path) -> HumanIdentityStore:
    """Pin one optional owner-only delegated identity store at startup."""
    payload = _owner_private_payload(Path(path))
    if payload is None:
        return empty_human_identity_store()
    return _validated_store(payload)


def serialize_human_identity_store(store: HumanIdentityStore) -> bytes:
    """Return a canonical validated payload without projecting secrets."""
    payload = json.dumps(
        {
            "schema": STORE_SCHEMA,
            "generation": store.generation,
            "identities": [
                {
                    "username": identity.username,
                    "principal_id": identity.principal_id,
                    "role": identity.role,
                    "password": identity.password_record,
                }
                for identity in sorted(
                    store.identities.values(), key=lambda item: item.username
                )
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    _validated_store(payload)
    return payload


def authenticate_human_identity(
    username: object,
    password: object,
    store: HumanIdentityStore,
) -> HumanPrincipal | None:
    """Authenticate one exact server-configured delegated identity."""
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    identity = store.identities.get(username)
    record = (
        identity.password_record
        if identity is not None
        else DUMMY_PASSWORD_RECORD
    )
    if not verify_admin_password(password, record) or identity is None:
        return None
    return HumanPrincipal(
        HUMAN_PRINCIPAL_KIND,
        identity.principal_id,
        identity.role,
    )


__all__ = (
    "HumanIdentity",
    "HumanIdentityConfigurationError",
    "HumanIdentityStore",
    "STORE_SCHEMA",
    "authenticate_human_identity",
    "empty_human_identity_store",
    "load_enforcement_human_identity_store",
    "serialize_human_identity_store",
)
