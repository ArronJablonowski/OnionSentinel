"""Authenticated alert delivery transports for the Raspberry Pi relay.

The preferred transport sends bounded batches through a dedicated SSH key whose
Mac-side authorized_keys entry forces the Onion Sentinel intake command.  The
relay receives one acknowledgement per message, so a lost connection is safe
to replay and one malformed alert cannot block unrelated alerts behind it.
"""
from __future__ import annotations

import json
import importlib.util
import sys
from pathlib import Path
from typing import Iterable

try:
    import process_io
except ModuleNotFoundError:
    _process_spec = importlib.util.spec_from_file_location(
        "process_io", Path(__file__).with_name("process_io.py")
    )
    if _process_spec is None or _process_spec.loader is None:
        raise
    process_io = importlib.util.module_from_spec(_process_spec)
    sys.modules.setdefault("process_io", process_io)
    _process_spec.loader.exec_module(process_io)


PROTOCOL = "onion-sentinel-alert-batch/v1"
DEFAULT_BATCH_ITEMS = 100
DEFAULT_BATCH_BYTES = 8 * 1024 * 1024


class AlertDeliveryError(RuntimeError):
    """Transport or protocol failure that makes the whole submitted batch retryable."""


def _positive_int(value: object, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(parsed, maximum))


def delivery_mode(config: dict) -> str:
    ingest = config.get("alert_ingest", {})
    configured = str(ingest.get("mode") or "").strip().lower()
    if configured:
        return configured
    return str(config.get("webhook", {}).get("transport") or "http").strip().lower()


def delivery_enabled(config: dict) -> bool:
    ingest = config.get("alert_ingest", {})
    if "enabled" in ingest:
        return bool(ingest.get("enabled"))
    return bool(config.get("webhook", {}).get("enabled"))


def _ssh_command(config: dict) -> tuple[list[str], int]:
    ingest = config.get("alert_ingest", {})
    host = str(ingest.get("host") or "").strip()
    user = str(ingest.get("user") or "").strip()
    key_value = str(ingest.get("ssh_key") or "").strip()
    if not host or not user or not key_value:
        raise AlertDeliveryError("SSH alert intake requires host, user, and ssh_key")
    key = Path(key_value).expanduser()
    if not key.is_file():
        raise AlertDeliveryError(f"SSH alert intake key does not exist: {key}")
    known_hosts_value = str(
        ingest.get("known_hosts") or "/opt/so-alert-relay/keys/macstudio_known_hosts"
    ).strip()
    if not known_hosts_value:
        raise AlertDeliveryError("SSH alert intake requires a pinned known_hosts file")
    known_hosts = Path(known_hosts_value).expanduser()
    if not known_hosts.is_file():
        raise AlertDeliveryError(
            f"SSH alert intake known_hosts file does not exist: {known_hosts}"
        )
    connect_timeout = _positive_int(ingest.get("connect_timeout_seconds"), 20, 120)
    command = str(ingest.get("remote_command") or "onion-sentinel-alert-intake batch").strip()
    if command != "onion-sentinel-alert-intake batch":
        raise AlertDeliveryError("unsupported SSH alert intake command")
    return [
        "ssh",
        "-i",
        str(key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-T",
        f"{user}@{host}",
        command,
    ], connect_timeout


def _encoded_batch(messages: list[dict]) -> bytes:
    return (
        json.dumps({"protocol": PROTOCOL, "messages": messages}, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def split_batches(config: dict, messages: Iterable[dict]) -> list[list[dict]]:
    """Bound each SSH process by item count and encoded bytes."""
    ingest = config.get("alert_ingest", {})
    max_items = _positive_int(ingest.get("batch_max_items"), DEFAULT_BATCH_ITEMS, 1000)
    max_bytes = _positive_int(ingest.get("batch_max_bytes"), DEFAULT_BATCH_BYTES, 32 * 1024 * 1024)
    batches: list[list[dict]] = []
    current: list[dict] = []
    empty_batch_bytes = len(_encoded_batch([]))
    current_bytes = empty_batch_bytes
    for message in messages:
        encoded_item_bytes = len(
            json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        item_batch_bytes = empty_batch_bytes + encoded_item_bytes
        if item_batch_bytes > max_bytes:
            delivery_id = str(message.get("delivery_id") or "unknown")
            raise AlertDeliveryError(f"alert intake item {delivery_id} exceeds batch_max_bytes")
        candidate_bytes = current_bytes + encoded_item_bytes + (1 if current else 0)
        if current and (len(current) >= max_items or candidate_bytes > max_bytes):
            batches.append(current)
            current = [message]
            current_bytes = item_batch_bytes
        else:
            current.append(message)
            current_bytes = candidate_bytes
    if current:
        batches.append(current)
    return batches


def _last_json_object(text: str) -> dict:
    for line in reversed((text or "").splitlines()):
        candidate = line.strip()
        if not (candidate.startswith("{") and candidate.endswith("}")):
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise AlertDeliveryError("SSH alert intake returned no JSON acknowledgement")


def deliver_ssh_batch(config: dict, messages: list[dict]) -> dict:
    command, connect_timeout = _ssh_command(config)
    ingest = config.get("alert_ingest", {})
    process_timeout = _positive_int(ingest.get("request_timeout_seconds"), 180, 1800)
    payload = _encoded_batch(messages)
    result = process_io.run_bounded_command(
        command,
        input_bytes=payload,
        timeout_seconds=max(process_timeout, connect_timeout + 10),
        max_stdout_bytes=2 * 1024 * 1024,
        max_stderr_bytes=256 * 1024,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[-500:]
        raise AlertDeliveryError(
            f"SSH alert intake exited {result.returncode}: {detail or 'no error detail'}"
        )
    response = _last_json_object(result.stdout.decode("utf-8", errors="replace"))
    if response.get("protocol") != PROTOCOL or not isinstance(response.get("results"), list):
        raise AlertDeliveryError("SSH alert intake returned an invalid protocol response")
    expected = {str(item.get("delivery_id") or "") for item in messages}
    received = {str(item.get("delivery_id") or "") for item in response["results"] if isinstance(item, dict)}
    missing = sorted(expected - received)
    if missing:
        raise AlertDeliveryError(f"SSH alert intake omitted {len(missing)} acknowledgement(s)")
    return response


def deliver_ssh_messages(config: dict, messages: Iterable[dict]) -> list[dict]:
    results: list[dict] = []
    for batch in split_batches(config, messages):
        response = deliver_ssh_batch(config, batch)
        results.extend(item for item in response["results"] if isinstance(item, dict))
    return results
