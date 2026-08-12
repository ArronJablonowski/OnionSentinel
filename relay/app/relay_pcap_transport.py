#!/usr/bin/env python3
"""PCAP broker transport, bounded streaming, and spool policy."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path
from urllib import request

from relay_core import *  # noqa: F401,F403

def mac_transfer_config(config: dict) -> dict:
    broker = config.get("pcap_broker", {})
    transfer = broker.get("mac_transfer") if isinstance(broker.get("mac_transfer"), dict) else {}
    return transfer


def broker_path(config: dict, name: str, default_path: str) -> str:
    paths = config.get("pcap_broker", {}).get("paths", {})
    path = paths.get(name, default_path) if isinstance(paths, dict) else default_path
    return "/" + str(path or default_path).lstrip("/")


def broker_headers(config: dict) -> dict:
    token = config.get("pcap_broker", {}).get("token", "")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "so-alert-relay-dev/0.1",
    }
    if token:
        headers["X-Relay-Token"] = token
    return headers


def broker_request(config: dict, method: str, path: str, payload_data: dict | None = None) -> dict:
    broker = config.get("pcap_broker", {})
    base_url = str(broker.get("url") or "").rstrip("/")
    if not base_url:
        raise RuntimeError("pcap_broker.url is empty")
    timeout = broker.get("timeout_seconds", 20)
    data = None if payload_data is None else json.dumps(payload_data, sort_keys=True).encode("utf-8")
    req = request.Request(
        f"{base_url}{path}",
        data=data,
        headers=broker_headers(config),
        method=method,
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            body = read_bounded_http_body(
                response,
                webhook_int(broker, "response_max_bytes", 1024 * 1024),
            ).decode("utf-8")
    except HTTPError as exc:
        raise RuntimeError(f"PCAP broker returned HTTP {exc.code}: {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"PCAP broker request failed: {exc.reason}") from exc
    try:
        parsed = json.loads(body or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"PCAP broker returned invalid JSON: {exc}") from exc
    if not parsed.get("ok"):
        raise RuntimeError(parsed.get("reason") or parsed.get("error") or "PCAP broker rejected request")
    return parsed


class PcapProgressReporter:
    """Renew a PCAP claim while a long export or transfer is demonstrably active.

    Progress reporting is advisory: an unavailable health callback must never
    interrupt resumable evidence transfer. The broker's transfer timeout still
    bounds a process that is alive but no longer useful.
    """

    def __init__(self, config: dict, request_id: str):
        self.config = config
        self.request_id = safe_transfer_id(request_id)
        broker = config.get("pcap_broker", {})
        self.interval = max(10.0, float(broker.get("progress_interval_seconds", 30) or 30))
        self.stage = "claimed"
        self.total_bytes = 0
        self._probe = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def update(self, stage: str, total_bytes: int = 0, probe=None) -> None:
        self.stage = stage
        self.total_bytes = max(0, int(total_bytes or 0))
        self._probe = probe
        self.report()

    def report(self) -> None:
        transferred = 0
        try:
            if self._probe is not None:
                transferred = max(0, int(self._probe() or 0))
            broker_request(
                self.config,
                "POST",
                broker_path(self.config, "progress", "/pcap/progress"),
                {
                    "request_id": self.request_id,
                    "stage": self.stage,
                    "transferred_bytes": transferred,
                    "total_bytes": self.total_bytes,
                },
            )
        except Exception as exc:
            print(
                json.dumps(
                    {"event": "pcap_progress_report_failed", "request_id": self.request_id, "error": str(exc)[:300]},
                    sort_keys=True,
                ),
                file=sys.stderr,
            )

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.report()

    def __enter__(self):
        self.report()
        self._thread = threading.Thread(target=self._run, name=f"pcap-progress-{self.request_id}", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=min(5.0, self.interval))


def upload_pcap_artifact(
    config: dict,
    pcap_request: dict,
    export_result: dict,
    progress: PcapProgressReporter | None = None,
) -> dict | None:
    broker = config.get("pcap_broker", {})
    upload_mode = str(broker.get("artifact_upload_mode") or "streamed_chunks").strip().lower()
    if upload_mode in {"streamed_chunks", "streaming", "relay_stream"}:
        return upload_pcap_artifact_via_rsync(config, pcap_request, export_result, progress)
    raise RuntimeError(
        f"unsupported PCAP artifact_upload_mode {upload_mode!r}; "
        "Security Onion PCAP transfer must use read-only streamed_chunks"
    )


def completed_artifact_path(export_result: dict, upload_result: dict | None) -> str | None:
    """Prefer Mac-side artifact metadata when the upload path provides it."""
    if upload_result:
        for key in ("path", "artifact_file"):
            value = upload_result.get(key)
            if value:
                return str(value)
    value = export_result.get("artifact_path")
    return str(value) if value else None


def pcap_spool_dir(config: dict) -> Path:
    broker = config.get("pcap_broker", {})
    raw_path = str(broker.get("artifact_spool_dir") or "/mnt/onion-sentinel-pcap-spool/pcap")
    path = Path(raw_path)
    if not path.is_absolute():
        raise RuntimeError("pcap_broker.artifact_spool_dir must be an absolute path")
    return path


def spool_mount_ready(config: dict) -> bool:
    broker = config.get("pcap_broker", {})
    if not bool(broker.get("artifact_spool_require_mount", False)):
        return True
    spool_dir = pcap_spool_dir(config)
    # The configured directory is intentionally one level below the filesystem
    # root. Requiring that parent to be a mount prevents an absent USB disk from
    # silently redirecting multi-gigabyte writes onto the Pi SD card.
    return os.path.ismount(spool_dir.parent)


def require_spool_capacity(config: dict, artifact_size: int) -> None:
    broker = config.get("pcap_broker", {})
    max_bytes = int(broker.get("artifact_spool_max_bytes", 32 * 1024 * 1024 * 1024) or 0)
    min_free_bytes = int(broker.get("artifact_spool_min_free_bytes", 100 * 1024 * 1024 * 1024) or 0)
    max_used_percent = max(1.0, min(75.0, float(broker.get("artifact_spool_max_used_percent", 75) or 75)))
    if max_bytes > 0 and artifact_size > max_bytes:
        raise RuntimeError(f"PCAP artifact exceeds relay spool limit: {artifact_size} > {max_bytes}")
    spool_dir = pcap_spool_dir(config)
    if not spool_dir.exists() or not spool_dir.is_dir():
        raise RuntimeError(f"relay PCAP spool directory is unavailable: {spool_dir}")
    if not spool_mount_ready(config):
        raise RuntimeError(f"relay PCAP spool filesystem is not mounted: {spool_dir.parent}")
    usage = shutil.disk_usage(spool_dir)
    required = artifact_size + max(0, min_free_bytes)
    if usage.free < required:
        raise RuntimeError(f"relay PCAP spool has insufficient free space: free={usage.free} required={required}")
    projected_percent = ((usage.used + artifact_size) / usage.total) * 100 if usage.total else 100.0
    if projected_percent > max_used_percent:
        raise RuntimeError(
            f"relay PCAP spool high watermark exceeded: projected={projected_percent:.1f}% limit={max_used_percent:.1f}%"
        )


def spool_usage(config: dict) -> dict:
    spool_dir = pcap_spool_dir(config)
    if not spool_dir.exists():
        return {"available": False, "path": str(spool_dir)}
    if not spool_mount_ready(config):
        return {"available": False, "path": str(spool_dir), "reason": "spool filesystem is not mounted"}
    usage = shutil.disk_usage(spool_dir)
    return {
        "available": True,
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "used_percent": round((usage.used / usage.total) * 100, 1) if usage.total else 100.0,
    }


def cleanup_stale_spool_partials(config: dict) -> int:
    """Remove interrupted relay-spool transfer fragments older than the configured TTL."""
    broker = config.get("pcap_broker", {})
    ttl_seconds = int(broker.get("artifact_spool_partial_ttl_seconds", 0) or 0)
    if ttl_seconds < 0:
        return 0
    try:
        spool_dir = pcap_spool_dir(config)
    except Exception:
        return 0
    if not spool_dir.exists() or not spool_dir.is_dir():
        return 0
    cutoff = time.time() - ttl_seconds
    removed = 0
    for path in spool_dir.rglob("*.part"):
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def cleanup_stale_spool_artifacts(config: dict) -> int:
    """Remove completed relay artifacts after their bounded retry window.

    This runs while the broker lock is held, so a matching rsync upload cannot
    be active. Security Onion keeps its independently retained export as the
    recovery source if a request is retried after this relay-side TTL.
    """
    broker = config.get("pcap_broker", {})
    ttl_seconds = int(broker.get("artifact_spool_completed_ttl_seconds", 3600) or 0)
    if ttl_seconds < 0:
        return 0
    try:
        spool_dir = pcap_spool_dir(config)
    except Exception:
        return 0
    if not spool_dir.exists() or not spool_dir.is_dir():
        return 0
    cutoff = time.time() - ttl_seconds
    removed = 0
    for path in spool_dir.glob("*.tar"):
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
                path.with_suffix(".stream.json").unlink(missing_ok=True)
                removed += 1
        except OSError:
            continue
    for path in spool_dir.iterdir():
        try:
            if path.is_dir() and path.stat().st_mtime < cutoff:
                shutil.rmtree(path)
                removed += 1
        except OSError:
            continue
    return removed


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json_write(path: Path, payload: dict) -> None:
    """Persist a relay checkpoint without exposing a partially-written file."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def load_json_file(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def streamed_chunk_mode(config: dict) -> bool:
    mode = str(config.get("pcap_broker", {}).get("artifact_upload_mode") or "streamed_chunks").strip().lower()
    if mode not in {"streamed_chunks", "streaming", "relay_stream"}:
        raise RuntimeError(
            "Security Onion PCAP transfer must use read-only streamed_chunks; "
            "Security Onion staging modes have been removed"
        )
    return True


def security_onion_storage_status(config: dict) -> dict:
    """Read non-blocking `/nsm` telemetry through the restricted wrapper."""
    payload = run_ssh_pcap_export(config, {"mode": "storage_status"})
    if payload.get("status") != "storage_status":
        raise RuntimeError("Security Onion PCAP wrapper returned invalid storage status")
    return payload


def capture_protection_decision(
    config: dict,
    status: dict | None,
    *,
    capture_loss_threshold_percent: object | None = None,
) -> dict:
    """Decide whether the relay may start another Security Onion PCAP read.

    The restricted wrapper always permits valid read-only requests. Scheduling
    policy lives on the relay so capture telemetry can pause background evidence
    work without changing or blocking Security Onion's native retention logic.
    """
    broker = config.get("pcap_broker", {})
    if not bool(broker.get("capture_protection_enabled", True)):
        return {"deferred": False, "reason": "disabled"}
    require_telemetry = bool(broker.get("capture_protection_require_telemetry", True))
    configured_threshold = (
        broker.get("capture_loss_threshold_percent", 5.0)
        if capture_loss_threshold_percent is None
        else capture_loss_threshold_percent
    )
    try:
        threshold = float(configured_threshold)
    except (TypeError, ValueError):
        threshold = 5.0
    threshold = max(0.1, min(100.0, threshold))
    packet_loss_threshold = max(
        0.0,
        min(100.0, float(broker.get("sensor_packet_loss_threshold_percent", 0.1) or 0.1)),
    )
    freshness = max(60, min(3600, int(broker.get("capture_loss_freshness_seconds", 900) or 900)))
    if not isinstance(status, dict) or not status.get("zeek_capture_loss_available"):
        return {
            "deferred": require_telemetry,
            "reason": "Zeek capture-loss telemetry is unavailable",
            "threshold_percent": threshold,
        }
    age = max(0, int(status.get("zeek_capture_loss_age_seconds") or 0))
    maximum = max(0.0, float(status.get("zeek_capture_loss_max_percent") or 0.0))
    if age > freshness:
        return {
            "deferred": require_telemetry,
            "reason": f"Zeek capture-loss telemetry is stale ({age}s)",
            "observed_percent": maximum,
            "threshold_percent": threshold,
            "age_seconds": age,
        }
    for prefix, label in (("zeek", "Zeek"), ("suricata", "Suricata")):
        available = bool(status.get(f"{prefix}_packet_loss_available"))
        packet_age = max(0, int(status.get(f"{prefix}_packet_loss_age_seconds") or 0))
        packet_loss = max(0.0, float(status.get(f"{prefix}_packet_loss_percent") or 0.0))
        if available and packet_age <= freshness and packet_loss > packet_loss_threshold:
            return {
                "deferred": True,
                "reason": (
                    f"{label} packet loss {packet_loss:.4f}% exceeds "
                    f"{packet_loss_threshold:.4f}%"
                ),
                "observed_percent": packet_loss,
                "threshold_percent": packet_loss_threshold,
                "age_seconds": packet_age,
                "metric": f"{prefix}_packet_loss",
            }
    if maximum > threshold:
        return {
            "deferred": True,
            "reason": f"Zeek capture loss {maximum:.4f}% exceeds {threshold:.4f}%",
            "observed_percent": maximum,
            "threshold_percent": threshold,
            "age_seconds": age,
        }
    return {
        "deferred": False,
        "reason": "capture telemetry is healthy",
        "observed_percent": maximum,
        "threshold_percent": threshold,
        "age_seconds": age,
    }


def require_capture_safe(config: dict, status: dict | None = None) -> dict:
    """Raise a retryable deferral when live-capture telemetry is unhealthy."""
    current = status if isinstance(status, dict) else security_onion_storage_status(config)
    decision = capture_protection_decision(config, current)
    if decision.get("deferred"):
        raise PcapCaptureProtectionDeferred(str(decision.get("reason")), decision)
    return current


def stream_chunk_idle_timeout(config: dict) -> int:
    """Return the no-progress timeout without limiting total read duration."""
    broker = config.get("pcap_broker", {})
    configured = int(broker.get("stream_chunk_idle_timeout_seconds", 300) or 300)
    return max(60, min(3600, configured))


def wait_for_stream_progress(proc: subprocess.Popen, temporary: Path, idle_timeout: int) -> bytes:
    """Wait while bytes advance, terminating only a genuinely idle stream.

    A fixed total timeout can truncate a healthy large read. The destination
    file is the authoritative progress signal because stdout is written there
    directly without buffering packet data in relay memory.
    """
    last_size = -1
    last_progress = time.monotonic()
    while proc.poll() is None:
        try:
            current_size = temporary.stat().st_size
        except OSError:
            current_size = 0
        now = time.monotonic()
        if current_size != last_size:
            last_size = current_size
            last_progress = now
        elif now - last_progress >= idle_timeout:
            proc.kill()
            proc.wait()
            raise RuntimeError(
                f"Security Onion PCAP chunk stream made no progress for {idle_timeout} seconds"
            )
        time.sleep(1)
    return proc.stderr.read() if proc.stderr is not None else b""


def transfer_timeout(config: dict, artifact_size: int) -> int:
    transfer = mac_transfer_config(config)
    floor = max(300, int(transfer.get("rsync_timeout_seconds") or 1800))
    minimum_bps = max(256 * 1024, int(transfer.get("minimum_bytes_per_second", 2 * 1024 * 1024) or 1))
    # The relay-to-Mac leg crosses the monitored LAN. Its bandwidth ceiling is
    # deliberately part of timeout sizing so a safe low-rate transfer is not
    # mistaken for a stalled job merely because the artifact is large.
    maximum_bps = rsync_max_bytes_per_second(config)
    estimate_bps = min(minimum_bps, maximum_bps)
    estimate = int(artifact_size / estimate_bps) + 600
    return min(12 * 3600, max(floor, estimate))


def rsync_max_bytes_per_second(config: dict) -> int:
    """Return the enforced relay-to-Mac ceiling for monitored LAN traffic."""
    transfer = mac_transfer_config(config)
    configured = int(transfer.get("max_bytes_per_second", 4 * 1024 * 1024) or 1)
    return max(1024 * 1024, min(8 * 1024 * 1024, configured))


def stream_one_security_onion_chunk(
    config: dict,
    request_payload: dict,
    destination: Path,
    source_size: int,
) -> int:
    """Stream one filtered capture directly from Security Onion to relay SSD."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    temporary.unlink(missing_ok=True)
    command = pcap_ssh_command(config)
    encoded = json.dumps(request_payload, sort_keys=True).encode("utf-8")
    try:
        with temporary.open("wb") as handle:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=handle,
                stderr=subprocess.PIPE,
            )
            if proc.stdin is None:
                proc.kill()
                proc.wait()
                raise RuntimeError("Security Onion PCAP chunk stream stdin is unavailable")
            proc.stdin.write(encoded)
            proc.stdin.close()
            stderr = wait_for_stream_progress(proc, temporary, stream_chunk_idle_timeout(config))
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    if proc.returncode != 0:
        temporary.unlink(missing_ok=True)
        detail = (stderr or b"").decode("utf-8", errors="replace")[-500:].strip()
        raise RuntimeError(detail or f"Security Onion PCAP chunk stream exited {proc.returncode}")
    size = temporary.stat().st_size
    # tcpdump writes a 24-byte global header even when the filter matches no
    # packets. Empty variants are expected because VLAN encapsulation differs.
    if size <= 24:
        temporary.unlink(missing_ok=True)
        return 0
    maximum = source_size + (16 * 1024 * 1024)
    if size > maximum:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f"Security Onion PCAP chunk exceeded source ceiling: {size} > {maximum}")
    temporary.replace(destination)
    destination.chmod(0o600)
    return size


def streamed_spool_artifact(
    config: dict,
    pcap_request: dict,
    progress: PcapProgressReporter | None = None,
) -> dict:
    """Build a resumable tar on relay SSD from stateless Security Onion streams.

    Security Onion never creates an Onion Sentinel PCAP file in this mode. The
    only durable state is under the externally mounted relay spool.
    """
    request_id = safe_transfer_id(pcap_request.get("request_id"))
    spool_dir = pcap_spool_dir(config)
    spool_dir.mkdir(parents=True, exist_ok=True)
    artifact = spool_dir / f"{request_id}.tar"
    sidecar = spool_dir / f"{request_id}.stream.json"
    prior = load_json_file(sidecar)
    if artifact.is_file() and prior.get("artifact_sha256") and prior.get("artifact_size_bytes") == artifact.stat().st_size:
        if sha256_file(artifact) == str(prior["artifact_sha256"]):
            return {
                "ok": True,
                "status": "relay_stream_artifact",
                "request_id": request_id,
                "relay_spool_path": str(artifact),
                "artifact_path": f"{request_id}.tar",
                "artifact_sha256": prior["artifact_sha256"],
                "artifact_size_bytes": artifact.stat().st_size,
                "part_count": int(prior.get("part_count") or 0),
                "source_mode": "streamed_chunks",
                "security_onion_staging_bytes": 0,
                "reused_existing_artifact": True,
            }

    manifest_request = {**pcap_request, "mode": "stream_manifest"}
    manifest = run_ssh_pcap_export(config, manifest_request)
    require_capture_safe(config, manifest.get("storage_status"))
    chunks = manifest.get("chunks") if isinstance(manifest.get("chunks"), list) else []
    if not chunks:
        raise PcapExportError("no matching packet capture files found", {"candidate_count": 0, "streamed": True})
    request_dir = spool_dir / request_id
    request_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    checkpoint_path = request_dir / "checkpoint.json"
    checkpoint = load_json_file(checkpoint_path)
    if checkpoint.get("manifest_id") != manifest.get("manifest_id"):
        for path in request_dir.glob("part-*.pcap*"):
            if path.is_file():
                path.unlink()
        checkpoint = {"manifest_id": manifest.get("manifest_id"), "completed": {}}
        atomic_json_write(checkpoint_path, checkpoint)
    completed = checkpoint.setdefault("completed", {})
    source_upper_bound = sum(max(0, int(item.get("source_size_bytes") or 0)) for item in chunks)
    if progress:
        progress.update(
            "security_onion_to_relay",
            source_upper_bound,
            lambda: sum(path.stat().st_size for path in request_dir.glob("part-*.pcap") if path.is_file()),
        )

    part_paths: list[Path] = []
    total_bytes = 0
    for chunk_index, item in enumerate(chunks):
        if chunk_index:
            # Re-check between bounded source rotations. A transfer already on
            # the relay SSD is resumable, so pausing here does not discard work.
            require_capture_safe(config)
        chunk_id = safe_transfer_id(item.get("chunk_id"))
        source_size = int(item.get("source_ceiling_bytes") or item.get("source_size_bytes") or 0)
        if source_size <= 0:
            continue
        part = request_dir / f"part-{chunk_id}.pcap"
        recorded = completed.get(chunk_id) if isinstance(completed.get(chunk_id), dict) else {}
        if recorded.get("empty") is True:
            continue
        if part.is_file() and recorded.get("size") == part.stat().st_size and recorded.get("sha256") == sha256_file(part):
            part_paths.append(part)
            total_bytes += part.stat().st_size
            continue
        part.unlink(missing_ok=True)
        require_spool_capacity(config, source_size)
        stream_request = {
            **pcap_request,
            "mode": "stream_chunk",
            "manifest_id": manifest.get("manifest_id"),
            "chunk_id": chunk_id,
            "capture_ref": item.get("capture_ref"),
            "source_size_bytes": item.get("source_size_bytes"),
            "source_device": item.get("source_device"),
            "source_inode": item.get("source_inode"),
            "bpf_variant": item.get("bpf_variant"),
        }
        size = stream_one_security_onion_chunk(config, stream_request, part, source_size)
        if not size:
            completed[chunk_id] = {"empty": True, "size": 0}
        else:
            digest = sha256_file(part)
            completed[chunk_id] = {"size": size, "sha256": digest}
            part_paths.append(part)
            total_bytes += size
        atomic_json_write(checkpoint_path, checkpoint)

    if not part_paths:
        raise PcapExportError(
            "no matching packets found",
            {"candidate_count": len(chunks), "search_strategy": "stateless-streamed-rotation-chunks"},
        )
    require_spool_capacity(config, total_bytes)
    temporary_tar = artifact.with_suffix(".tar.part")
    temporary_tar.unlink(missing_ok=True)
    try:
        with tarfile.open(temporary_tar, "w") as archive:
            for part in sorted(part_paths):
                archive.add(part, arcname=part.name, recursive=False)
        temporary_tar.replace(artifact)
        artifact.chmod(0o600)
    except Exception:
        temporary_tar.unlink(missing_ok=True)
        raise
    digest = sha256_file(artifact)
    metadata = {
        "manifest_id": manifest.get("manifest_id"),
        "artifact_sha256": digest,
        "artifact_size_bytes": artifact.stat().st_size,
        "part_count": len(part_paths),
        "source_chunk_count": len(chunks),
    }
    atomic_json_write(sidecar, metadata)
    shutil.rmtree(request_dir, ignore_errors=True)
    return {
        "ok": True,
        "status": "relay_stream_artifact",
        "request_id": request_id,
        "relay_spool_path": str(artifact),
        "artifact_path": f"{request_id}.tar",
        "artifact_sha256": digest,
        "artifact_size_bytes": artifact.stat().st_size,
        "part_count": len(part_paths),
        "source_mode": "streamed_chunks",
        "security_onion_staging_bytes": 0,
    }
