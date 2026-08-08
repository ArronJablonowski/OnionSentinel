"""Validated PostgreSQL and disaster-recovery repositories for Asset data."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Callable


JsonReader = Callable[..., dict]
InventoryValidator = Callable[[object], dict]
InventoryFileLoader = Callable[[Path], dict]


def missing_asset_inventory() -> dict:
    return {
        "schema": "onion-sentinel-asset-inventory-v1",
        "version": 0,
        "generated_at": "",
        "assets": [],
        "inventory_status": "missing",
    }


def invalid_asset_inventory(status: str = "invalid") -> dict:
    return {"assets": [], "inventory_status": status}


@dataclass
class AssetInventoryRepository:
    database_enabled: bool
    cache: dict[str, object]
    cache_lock: object
    epoch_seconds: Callable[[], float]
    fetch_json: JsonReader
    validate_inventory: InventoryValidator
    load_inventory_file: InventoryFileLoader
    inventory_path: Path
    maximum_bytes: int

    def load(self) -> tuple[dict, str]:
        if self.database_enabled:
            return self._load_database()
        return self._load_file()

    def _cached_database(self) -> dict | None:
        with self.cache_lock:
            inventory = self.cache.get("inventory")
            if (
                float(self.cache.get("expires_at") or 0) > self.epoch_seconds()
                and isinstance(inventory, dict)
            ):
                return dict(inventory)
        return None

    def _load_database(self) -> tuple[dict, str]:
        cached = self._cached_database()
        if cached is not None:
            return cached, ""
        try:
            result = self.fetch_json("/assets/snapshot", timeout=5.0)
            inventory = self.validate_inventory(result.get("inventory"))
            inventory["inventory_status"] = "database"
        except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return invalid_asset_inventory("unavailable"), (
                f"PostgreSQL asset inventory unavailable: {exc}"
            )
        with self.cache_lock:
            self.cache.update({
                "signature": "postgresql",
                "inventory": inventory,
                "expires_at": self.epoch_seconds() + 5.0,
            })
        return dict(inventory), ""

    def _file_signature(self) -> tuple[str, int, int]:
        metadata = self.inventory_path.stat()
        if (
            not self.inventory_path.is_file()
            or metadata.st_size > self.maximum_bytes
        ):
            raise ValueError("asset inventory is not a bounded regular file")
        return (
            str(self.inventory_path.resolve()),
            metadata.st_mtime_ns,
            metadata.st_size,
        )

    def _load_file(self) -> tuple[dict, str]:
        try:
            signature = self._file_signature()
        except FileNotFoundError:
            return missing_asset_inventory(), ""
        except (OSError, ValueError) as exc:
            return invalid_asset_inventory(), str(exc)
        with self.cache_lock:
            cached = self.cache.get("inventory")
            if self.cache.get("signature") == signature and isinstance(cached, dict):
                return dict(cached), ""
            try:
                inventory = self.load_inventory_file(self.inventory_path)
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                return invalid_asset_inventory(), str(exc)
            self.cache.update({"signature": signature, "inventory": inventory})
            return dict(inventory), ""


def validate_dhcp_state(
    state: object,
    *,
    maximum_observations: int,
    error_message: str,
) -> dict:
    if not isinstance(state, dict):
        raise ValueError(error_message)
    if state.get("schema") != "onion-sentinel-dhcp-asset-observations-v1":
        raise ValueError(error_message)
    if not isinstance(state.get("collection"), dict):
        raise ValueError(error_message)
    observations = state.get("observations")
    if not isinstance(observations, list) or len(observations) > maximum_observations:
        raise ValueError(error_message)
    return state


def missing_dhcp_state() -> dict:
    return {
        "updated_at": "",
        "collection": {
            "status": "never_run",
            "last_attempt_at": "",
            "last_success_at": "",
            "last_error": "",
        },
        "observations": [],
    }


def invalid_dhcp_state(status: str) -> dict:
    return {"collection": {"status": status}, "observations": []}


@dataclass(frozen=True)
class DhcpStateRepository:
    database_enabled: bool
    fetch_json: JsonReader
    state_path: Path
    maximum_bytes: int

    def load(self) -> tuple[dict, str]:
        if self.database_enabled:
            return self._load_database()
        return self._load_file()

    def _load_database(self) -> tuple[dict, str]:
        try:
            result = self.fetch_json("/assets/dhcp-state", timeout=5.0)
            state = validate_dhcp_state(
                result.get("state"),
                maximum_observations=100_000,
                error_message="database DHCP state failed validation",
            )
            return state, ""
        except (RuntimeError, TypeError, ValueError) as exc:
            return invalid_dhcp_state("unavailable"), (
                f"PostgreSQL DHCP state unavailable: {exc}"
            )

    def _read_file(self) -> dict:
        metadata = self.state_path.stat()
        if not self.state_path.is_file() or metadata.st_size > self.maximum_bytes:
            raise ValueError("DHCP observation state is not a bounded regular file")
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        return validate_dhcp_state(
            state,
            maximum_observations=5000,
            error_message="DHCP observation state failed schema validation",
        )

    def _load_file(self) -> tuple[dict, str]:
        try:
            return self._read_file(), ""
        except FileNotFoundError:
            return missing_dhcp_state(), ""
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            return invalid_dhcp_state("invalid"), str(exc)
