"""Owner-controlled credential and bounded loopback Asset Store client."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from typing import Callable
from urllib import error as urllib_error
from urllib import request as urllib_request

from http_runtime import BoundedResponseError


ASSET_MUTATION_PATHS = frozenset({
    "/assets/promote-dhcp",
    "/assets/approve-dhcp-ip-change",
    "/assets/update",
    "/assets/demote",
})


class AlertStoreRequestError(RuntimeError):
    """Preserve an alert-store HTTP status without exposing response bodies."""

    def __init__(self, detail: str, status_code: int = 503):
        super().__init__(detail)
        self.status_code = int(status_code)


def _owner_controlled_environment(path: Path, owner_id: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuntimeError("asset-store write credential is unavailable") from exc
    unsafe = (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_id
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 1024 * 1024
    )
    if unsafe:
        raise RuntimeError("asset-store environment file is not owner-controlled")


def _environment_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RuntimeError("asset-store write credential is unavailable") from exc
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        cleaned = value.strip()
        if (
            len(cleaned) >= 2
            and cleaned[0] == cleaned[-1]
            and cleaned[0] in {"'", '"'}
        ):
            cleaned = cleaned[1:-1]
        values[key.strip()] = cleaned
    return values


def load_asset_store_write_token(
    configured: object,
    environment_path: Path,
    *,
    owner_id: int | None = None,
) -> str:
    """Load one write token without returning other environment values."""
    direct = str(configured or "").strip()
    if direct:
        if len(direct) < 32:
            raise RuntimeError("asset-store write credential is invalid")
        return direct
    _owner_controlled_environment(
        environment_path,
        os.geteuid() if owner_id is None else owner_id,
    )
    values = _environment_values(environment_path)
    token = values.get("ASSET_STORE_WRITE_TOKEN") or values.get(
        "N8N_POST_COMMIT_TOKEN", "",
    )
    if len(token) < 32:
        raise RuntimeError("asset-store write credential is invalid")
    return token


@dataclass(frozen=True)
class AssetStoreClient:
    base_url: str
    maximum_response_bytes: int
    token: Callable[[], str]
    read_json: Callable[..., object]
    urlopen: Callable[..., object] = urllib_request.urlopen

    def _error_detail(self, error: urllib_error.HTTPError) -> str:
        try:
            payload = self.read_json(error, max_bytes=self.maximum_response_bytes)
            if not isinstance(payload, dict):
                return str(error.reason)
            return str(payload.get("reason") or payload.get("error") or error.reason)
        except (OSError, BoundedResponseError, json.JSONDecodeError):
            return str(error.reason)

    def post(self, path: str, payload: dict, timeout: float = 10.0) -> dict:
        """Send one authenticated mutation to an allowlisted Asset route."""
        if path not in ASSET_MUTATION_PATHS:
            raise ValueError("asset-store mutation path is not allowlisted")
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        request = urllib_request.Request(
            f"{self.base_url}{path}",
            data=encoded,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(encoded)),
                "X-Onion-Sentinel-Asset-Token": self.token(),
            },
        )
        try:
            with self.urlopen(request, timeout=timeout) as response:
                result = self.read_json(
                    response, max_bytes=self.maximum_response_bytes,
                )
        except urllib_error.HTTPError as exc:
            raise AlertStoreRequestError(
                self._error_detail(exc)[:500], int(exc.code or 503),
            ) from exc
        except (OSError, urllib_error.URLError, json.JSONDecodeError) as exc:
            raise AlertStoreRequestError(str(exc)[:500], 503) from exc
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise AlertStoreRequestError("asset-store rejected request", 400)
        return result
