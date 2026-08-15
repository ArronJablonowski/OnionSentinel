#!/usr/bin/env python3
"""PCAP delivery to the Mac Studio and broker completion/retry operations."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path

from relay_pcap_transport import *  # noqa: F401,F403


DEFAULT_MAC_KNOWN_HOSTS = "/opt/so-alert-relay/keys/macstudio_known_hosts"


def remote_shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def remote_artifact_dir(config: dict, request_id: str) -> str:
    transfer = mac_transfer_config(config)
    base_dir = str(transfer.get("artifact_dir") or "n8n-local/pcap-evidence/artifacts").strip().rstrip("/")
    if not base_dir or base_dir.startswith("/") or ".." in Path(base_dir).parts:
        raise RuntimeError("mac_transfer.artifact_dir must be a relative safe path")
    return f"{base_dir}/{safe_transfer_id(request_id)}"


def mac_ssh_base(config: dict) -> list[str]:
    transfer = mac_transfer_config(config)
    host = str(transfer.get("host") or "").strip()
    user = str(transfer.get("user") or "").strip()
    key = str(transfer.get("ssh_key") or "").strip()
    known_hosts = str(
        transfer.get("known_hosts") or DEFAULT_MAC_KNOWN_HOSTS
    ).strip()
    if not host or not user or not key or not known_hosts:
        raise RuntimeError(
            "mac_transfer requires host, user, ssh_key, and known_hosts"
        )
    return [
        "ssh",
        "-i",
        str(resolve_path(key)),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={resolve_path(known_hosts)}",
        "-o",
        f"ConnectTimeout={int(transfer.get('connect_timeout_seconds') or 20)}",
        f"{user}@{host}",
    ]


def run_mac_ssh(config: dict, command: str, timeout: int = 60) -> subprocess.CompletedProcess:
    proc = process_io.run_bounded_command(
        [*mac_ssh_base(config), command],
        timeout_seconds=timeout,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=256 * 1024,
    )
    return subprocess.CompletedProcess(
        proc.args,
        proc.returncode,
        proc.stdout.decode("utf-8", errors="replace"),
        proc.stderr.decode("utf-8", errors="replace"),
    )


def verify_remote_artifact(config: dict, remote_path: str, expected_size: int, expected_sha256: str) -> None:
    request_id = safe_transfer_id(Path(remote_path).parent.name)
    filename = Path(remote_path).name
    command = " ".join([
        "onion-sentinel-pcap-intake", "verify", request_id, filename,
        str(expected_size), expected_sha256,
    ])
    proc = run_mac_ssh(config, command, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"remote artifact verification exited {proc.returncode}")
    payload = parse_last_json_object(proc.stdout)
    if int(payload.get("size") or -1) != expected_size:
        raise RuntimeError("Mac artifact size did not match Security Onion metadata")
    if str(payload.get("sha256") or "").lower() != expected_sha256:
        raise RuntimeError("Mac artifact sha256 did not match Security Onion metadata")


def cleanup_remote_artifact(config: dict, request_id: str) -> None:
    """Delete exactly one Mac intake request through the restricted SSH wrapper."""
    request_id = safe_transfer_id(request_id)
    proc = run_mac_ssh(
        config,
        f"onion-sentinel-pcap-intake cleanup {request_id}",
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"remote artifact cleanup exited {proc.returncode}")
    payload = parse_last_json_object(proc.stdout)
    if payload.get("status") != "cleaned" or payload.get("request_id") != request_id:
        raise RuntimeError("Mac artifact cleanup returned an invalid response")


def _relay_spool_metadata(
    pcap_request: dict,
    export_result: dict,
) -> tuple[str, int, str, str]:
    request_id = safe_transfer_id(
        export_result.get("request_id") or pcap_request.get("request_id")
    )
    expected_size = int(export_result.get("artifact_size_bytes") or 0)
    expected_sha256 = str(export_result.get("artifact_sha256") or "").lower()
    relay_spool_path = str(export_result.get("relay_spool_path") or "").strip()
    return request_id, expected_size, expected_sha256, relay_spool_path


def _validated_relay_spool_artifact(
    config: dict,
    pcap_request: dict,
    export_result: dict,
) -> tuple[str, int, str, Path]:
    request_id, expected_size, expected_sha256, relay_spool_path = (
        _relay_spool_metadata(pcap_request, export_result)
    )
    if not relay_spool_path:
        raise RuntimeError(
            "read-only streamed PCAP result is missing its relay spool path"
        )
    artifact_path = Path(relay_spool_path).resolve(strict=False)
    spool_root = pcap_spool_dir(config).resolve(strict=False)
    if artifact_path.parent != spool_root or artifact_path.name != f"{request_id}.tar":
        raise RuntimeError("relay stream artifact escaped the configured spool")
    if not artifact_path.is_file() or artifact_path.stat().st_size != expected_size:
        raise RuntimeError("relay stream artifact is missing or incomplete")
    if sha256_file(artifact_path) != expected_sha256:
        raise RuntimeError(
            "relay stream artifact sha256 did not match its checkpoint"
        )
    return request_id, expected_size, expected_sha256, artifact_path


def _rsync_delivery_plan(
    config: dict,
    request_id: str,
    export_result: dict,
    artifact_path: Path,
    expected_size: int,
) -> tuple[str, str, list[str], int, int]:
    transfer = mac_transfer_config(config)
    remote_dir = remote_artifact_dir(config, request_id)
    remote_name = Path(
        str(export_result.get("artifact_path") or artifact_path.name)
    ).name
    remote_path = f"{remote_dir}/{remote_name}"
    rsync_ssh = " ".join(
        remote_shell_quote(part) for part in mac_ssh_base(config)[:-1]
    )
    # remote_dir is already restricted to safe relative path segments. Avoid
    # shell quoting inside the rsync target because rsync passes it through to
    # the remote server and some implementations treat quotes as path bytes.
    target = (
        f"{str(transfer.get('user')).strip()}@"
        f"{str(transfer.get('host')).strip()}:{remote_dir}/"
    )
    maximum_bps = rsync_max_bytes_per_second(config)
    # rsync expresses --bwlimit in KiB/s. Throttle the sending process on the
    # relay so cached artifacts cannot burst at line rate across a mirrored
    # VLAN and oversubscribe Security Onion's capture destination.
    bwlimit_kib = max(1, maximum_bps // 1024)
    command = [
        "rsync",
        "-av",
        "--checksum",
        "--partial",
        "--append-verify",
        f"--bwlimit={bwlimit_kib}",
        "-e",
        rsync_ssh,
        str(artifact_path),
        target,
    ]
    return (
        remote_dir,
        remote_path,
        command,
        transfer_timeout(config, expected_size),
        maximum_bps,
    )


def _run_rsync_transfer_attempt(
    config: dict,
    request_id: str,
    expected_size: int,
    remote_dir: str,
    command: list[str],
    timeout: int,
    progress: PcapProgressReporter | None,
) -> None:
    mkdir_proc = run_mac_ssh(
        config,
        f"onion-sentinel-pcap-intake prepare {request_id} {expected_size}",
        timeout=60,
    )
    if mkdir_proc.returncode != 0:
        raise RuntimeError(
            mkdir_proc.stderr.strip()
            or f"failed to create Mac artifact dir {remote_dir}"
        )
    if progress:
        progress.update("relay_to_mac", expected_size)
    raw_proc = process_io.run_bounded_command(
        command,
        timeout_seconds=timeout,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=1024 * 1024,
    )
    stdout = raw_proc.stdout.decode("utf-8", errors="replace")
    stderr = raw_proc.stderr.decode("utf-8", errors="replace")
    if raw_proc.returncode != 0:
        raise RuntimeError(
            stderr.strip() or stdout.strip() or f"rsync exited {raw_proc.returncode}"
        )
    if progress:
        progress.update("verifying", expected_size, lambda: expected_size)


def _cleanup_rejected_mac_artifact(
    config: dict,
    request_id: str,
    verify_error: RuntimeError,
) -> None:
    try:
        cleanup_remote_artifact(config, request_id)
    except RuntimeError as cleanup_error:
        raise RuntimeError(
            f"{verify_error}; failed to clean rejected Mac artifact: {cleanup_error}"
        ) from verify_error


def _require_unchanged_relay_artifact(
    artifact_path: Path,
    expected_size: int,
    expected_sha256: str,
    verify_error: RuntimeError,
) -> None:
    if (
        artifact_path.stat().st_size != expected_size
        or sha256_file(artifact_path) != expected_sha256
    ):
        raise RuntimeError(
            "relay artifact changed after Mac verification failure"
        ) from verify_error


def upload_pcap_artifact_via_rsync(
    config: dict,
    pcap_request: dict,
    export_result: dict,
    progress: PcapProgressReporter | None = None,
) -> dict:
    request_id, expected_size, expected_sha256, artifact_path = (
        _validated_relay_spool_artifact(config, pcap_request, export_result)
    )
    remote_dir, remote_path, command, timeout, maximum_bps = _rsync_delivery_plan(
        config,
        request_id,
        export_result,
        artifact_path,
        expected_size,
    )
    for attempt in range(2):
        _run_rsync_transfer_attempt(
            config,
            request_id,
            expected_size,
            remote_dir,
            command,
            timeout,
            progress,
        )
        try:
            verify_remote_artifact(config, remote_path, expected_size, expected_sha256)
            break
        except RuntimeError as verify_error:
            _cleanup_rejected_mac_artifact(config, request_id, verify_error)
            if attempt:
                raise
            _require_unchanged_relay_artifact(
                artifact_path,
                expected_size,
                expected_sha256,
                verify_error,
            )
    return {
        "ok": True,
        "status": "artifact_rsynced",
        "path": remote_path,
        "artifact_size_bytes": expected_size,
        "artifact_sha256": expected_sha256,
        "max_bytes_per_second": maximum_bps,
    }


def cleanup_relay_spool_artifact(config: dict, request_id: str) -> bool:
    """Delete only a committed request's relay-side resumable artifacts."""
    if not config.get("pcap_broker", {}).get("artifact_spool_delete_after_upload", True):
        return True
    request_id = safe_transfer_id(request_id)
    try:
        spool_root = pcap_spool_dir(config).resolve(strict=False)
        artifact = (spool_root / f"{request_id}.tar").resolve(strict=False)
        if artifact.parent != spool_root:
            raise RuntimeError("relay spool cleanup escaped the configured spool")
        artifact.unlink(missing_ok=True)
        artifact.with_suffix(".stream.json").unlink(missing_ok=True)
        request_dir = (spool_root / request_id).resolve(strict=False)
        if request_dir.parent == spool_root and request_dir.is_dir():
            shutil.rmtree(request_dir)
        return True
    except Exception as exc:
        print(
            json.dumps(
                {"event": "pcap_relay_spool_cleanup_failed", "request_id": request_id, "error": str(exc)[:500]},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return False


def complete_pcap_request(config: dict, request_id: str, status: str, payload: dict) -> bool:
    broker = config.get("pcap_broker", {})
    attempts = max(1, min(5, int(broker.get("completion_retry_attempts", 3) or 3)))
    delay_seconds = max(0.0, min(30.0, float(broker.get("completion_retry_delay_seconds", 2) or 0)))
    completion = {"request_id": request_id, "status": status, "relay_host": socket.gethostname(), **payload}
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            broker_request(config, "POST", broker_path(config, "complete", "/pcap/complete"), completion)
            return True
        except Exception as exc:
            last_error = exc
            if attempt < attempts and delay_seconds:
                time.sleep(delay_seconds)
    # Completion callbacks are bookkeeping. Losing one should be loud in
    # journald but should not stop the relay from servicing other requests.
    print(
        json.dumps(
            {
                "event": "pcap_complete_failed",
                "request_id": request_id,
                "status": status,
                "attempts": attempts,
                "error": str(last_error)[:500] if last_error else "unknown completion failure",
            },
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return False


def pcap_retry_delay_seconds(config: dict, attempt_count: int) -> int:
    broker = config.get("pcap_broker", {})
    base = max(1, min(600, int(broker.get("transfer_retry_base_seconds", 30) or 30)))
    maximum = max(base, min(6 * 3600, int(broker.get("transfer_retry_max_seconds", 1800) or 1800)))
    exponent = max(0, min(10, int(attempt_count or 1) - 1))
    return min(maximum, base * (2 ** exponent))


def retry_pcap_request(
    config: dict,
    request_id: str,
    stage: str,
    error: object,
    attempt_count: int,
    diagnostics: dict | None = None,
) -> dict:
    """Persist a bounded retry without discarding resumable transfer state."""
    payload = {
        "request_id": request_id,
        "stage": stage,
        "error": str(error)[:1000],
        "retry_after_seconds": pcap_retry_delay_seconds(config, attempt_count),
    }
    if diagnostics:
        payload["diagnostics"] = diagnostics
    return broker_request(
        config,
        "POST",
        broker_path(config, "retry", "/pcap-retry"),
        payload,
    )


_PCAP_OUTCOME_RULES = (
    ("no_packets_available", ("no matching packet",), ()),
    ("expired", (), ("retention", "expired")),
    ("oversize", ("exceed",), ("size", "artifact")),
    ("timeout", (), ("timeout", "timed out")),
    ("checksum_failed", (), ("sha256", "checksum")),
    ("rejected", (), ("unsupported", "has been removed", "rejected")),
    (
        "transport_failed",
        (),
        ("rsync", "artifact upload", "connection", "ssh", "spool filesystem"),
    ),
)


def _pcap_outcome_rule_matches(
    detail: str,
    required_terms: tuple[str, ...],
    alternative_terms: tuple[str, ...],
) -> bool:
    return all(term in detail for term in required_terms) and (
        not alternative_terms or any(term in detail for term in alternative_terms)
    )


def pcap_outcome_from_error(error: object) -> str:
    detail = str(error or "").lower()
    for outcome, required_terms, alternative_terms in _PCAP_OUTCOME_RULES:
        if _pcap_outcome_rule_matches(detail, required_terms, alternative_terms):
            return outcome
    return "failed"
