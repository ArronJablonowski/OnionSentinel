#!/usr/bin/env python3
"""Bounded Security Onion PCAP streaming and relay-spool assembly."""
from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

from relay_core import (
    PcapExportError,
    pcap_ssh_command,
    run_ssh_pcap_export,
    safe_transfer_id,
)
from relay_pcap_capture_policy import require_capture_safe
from relay_pcap_spool_policy import (
    atomic_json_write,
    load_json_file,
    pcap_spool_dir,
    require_spool_capacity,
    sha256_file,
)

def stream_chunk_idle_timeout(config: dict) -> int:
    """Return the no-progress timeout without limiting total read duration."""
    broker = config.get("pcap_broker", {})
    configured = int(broker.get("stream_chunk_idle_timeout_seconds", 300) or 300)
    return max(60, min(3600, configured))


def wait_for_stream_progress(
    proc: subprocess.Popen,
    temporary: Path,
    idle_timeout: int,
) -> bytes:
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


def _run_security_onion_chunk_stream(
    config: dict,
    request_payload: dict,
    temporary: Path,
) -> tuple[subprocess.Popen, bytes]:
    command = pcap_ssh_command(config)
    encoded = json.dumps(request_payload, sort_keys=True).encode("utf-8")
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
        stderr = wait_for_stream_progress(
            proc,
            temporary,
            stream_chunk_idle_timeout(config),
        )
    return proc, stderr


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
    try:
        proc, stderr = _run_security_onion_chunk_stream(
            config,
            request_payload,
            temporary,
        )
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    if proc.returncode != 0:
        temporary.unlink(missing_ok=True)
        detail = (stderr or b"").decode("utf-8", errors="replace")[-500:].strip()
        raise RuntimeError(
            detail
            or f"Security Onion PCAP chunk stream exited {proc.returncode}"
        )
    size = temporary.stat().st_size
    # tcpdump writes a 24-byte global header even when the filter matches no
    # packets. Empty variants are expected because VLAN encapsulation differs.
    if size <= 24:
        temporary.unlink(missing_ok=True)
        return 0
    maximum = source_size + (16 * 1024 * 1024)
    if size > maximum:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(
            f"Security Onion PCAP chunk exceeded source ceiling: {size} > {maximum}"
        )
    temporary.replace(destination)
    destination.chmod(0o600)
    return size


def _verified_existing_artifact(
    request_id: str,
    artifact: Path,
    prior: dict,
) -> dict | None:
    if not (
        artifact.is_file()
        and prior.get("artifact_sha256")
        and prior.get("artifact_size_bytes") == artifact.stat().st_size
        and sha256_file(artifact) == str(prior["artifact_sha256"])
    ):
        return None
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


def _load_stream_manifest(config: dict, pcap_request: dict) -> tuple[dict, list]:
    manifest_request = {**pcap_request, "mode": "stream_manifest"}
    manifest = run_ssh_pcap_export(config, manifest_request)
    require_capture_safe(config, manifest.get("storage_status"))
    chunks = manifest.get("chunks") if isinstance(manifest.get("chunks"), list) else []
    if not chunks:
        raise PcapExportError(
            "no matching packet capture files found",
            {"candidate_count": 0, "streamed": True},
        )
    return manifest, chunks


def _load_stream_checkpoint(request_dir: Path, manifest: dict) -> tuple[Path, dict]:
    checkpoint_path = request_dir / "checkpoint.json"
    checkpoint = load_json_file(checkpoint_path)
    if checkpoint.get("manifest_id") != manifest.get("manifest_id"):
        for path in request_dir.glob("part-*.pcap*"):
            if path.is_file():
                path.unlink()
        checkpoint = {"manifest_id": manifest.get("manifest_id"), "completed": {}}
        atomic_json_write(checkpoint_path, checkpoint)
    return checkpoint_path, checkpoint


def _stream_request_payload(
    pcap_request: dict,
    manifest: dict,
    item: dict,
    chunk_id: str,
) -> dict:
    return {
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


def _recorded_part_matches(part: Path, recorded: dict) -> bool:
    return (
        part.is_file()
        and recorded.get("size") == part.stat().st_size
        and recorded.get("sha256") == sha256_file(part)
    )


def _stream_manifest_part(
    config: dict,
    pcap_request: dict,
    manifest: dict,
    item: dict,
    chunk_index: int,
    request_dir: Path,
    checkpoint_path: Path,
    checkpoint: dict,
) -> tuple[Path | None, int]:
    completed = checkpoint.setdefault("completed", {})
    if chunk_index:
        # Re-check between bounded source rotations. A transfer already on the
        # relay SSD is resumable, so pausing here does not discard work.
        require_capture_safe(config)
    chunk_id = safe_transfer_id(item.get("chunk_id"))
    source_size = int(
        item.get("source_ceiling_bytes") or item.get("source_size_bytes") or 0
    )
    if source_size <= 0:
        return None, 0
    part = request_dir / f"part-{chunk_id}.pcap"
    recorded = (
        completed.get(chunk_id)
        if isinstance(completed.get(chunk_id), dict)
        else {}
    )
    if recorded.get("empty") is True:
        return None, 0
    if _recorded_part_matches(part, recorded):
        return part, part.stat().st_size
    part.unlink(missing_ok=True)
    require_spool_capacity(config, source_size)
    size = stream_one_security_onion_chunk(
        config,
        _stream_request_payload(pcap_request, manifest, item, chunk_id),
        part,
        source_size,
    )
    if not size:
        completed[chunk_id] = {"empty": True, "size": 0}
    else:
        completed[chunk_id] = {"size": size, "sha256": sha256_file(part)}
    atomic_json_write(checkpoint_path, checkpoint)
    return (part, size) if size else (None, 0)


def _stream_manifest_parts(
    config: dict,
    pcap_request: dict,
    manifest: dict,
    chunks: list,
    request_dir: Path,
    checkpoint_path: Path,
    checkpoint: dict,
) -> tuple[list[Path], int]:
    part_paths: list[Path] = []
    total_bytes = 0
    for chunk_index, item in enumerate(chunks):
        part, size = _stream_manifest_part(
            config,
            pcap_request,
            manifest,
            item,
            chunk_index,
            request_dir,
            checkpoint_path,
            checkpoint,
        )
        if part is not None:
            part_paths.append(part)
            total_bytes += size
    return part_paths, total_bytes


def _publish_stream_artifact(artifact: Path, part_paths: list[Path]) -> str:
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
    return sha256_file(artifact)


def _report_stream_progress(
    progress: PcapProgressReporter | None,
    chunks: list,
    request_dir: Path,
) -> None:
    if not progress:
        return
    source_upper_bound = sum(
        max(0, int(item.get("source_size_bytes") or 0)) for item in chunks
    )
    progress.update(
        "security_onion_to_relay",
        source_upper_bound,
        lambda: sum(
            path.stat().st_size
            for path in request_dir.glob("part-*.pcap")
            if path.is_file()
        ),
    )


def _complete_stream_artifact(
    request_id: str,
    artifact: Path,
    sidecar: Path,
    request_dir: Path,
    manifest: dict,
    chunks: list,
    part_paths: list[Path],
) -> dict:
    digest = _publish_stream_artifact(artifact, part_paths)
    atomic_json_write(
        sidecar,
        {
            "manifest_id": manifest.get("manifest_id"),
            "artifact_sha256": digest,
            "artifact_size_bytes": artifact.stat().st_size,
            "part_count": len(part_paths),
            "source_chunk_count": len(chunks),
        },
    )
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


def streamed_spool_artifact(
    config: dict,
    pcap_request: dict,
    progress: PcapProgressReporter | None = None,
) -> dict:
    """Build a resumable relay-spool tar from stateless Security Onion streams."""
    request_id = safe_transfer_id(pcap_request.get("request_id"))
    spool_dir = pcap_spool_dir(config)
    spool_dir.mkdir(parents=True, exist_ok=True)
    artifact = spool_dir / f"{request_id}.tar"
    sidecar = spool_dir / f"{request_id}.stream.json"
    prior = load_json_file(sidecar)
    existing = _verified_existing_artifact(request_id, artifact, prior)
    if existing is not None:
        return existing

    manifest, chunks = _load_stream_manifest(config, pcap_request)
    request_dir = spool_dir / request_id
    request_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    checkpoint_path, checkpoint = _load_stream_checkpoint(request_dir, manifest)
    _report_stream_progress(progress, chunks, request_dir)
    part_paths, total_bytes = _stream_manifest_parts(
        config,
        pcap_request,
        manifest,
        chunks,
        request_dir,
        checkpoint_path,
        checkpoint,
    )
    if not part_paths:
        raise PcapExportError(
            "no matching packets found",
            {
                "candidate_count": len(chunks),
                "search_strategy": "stateless-streamed-rotation-chunks",
            },
        )
    require_spool_capacity(config, total_bytes)
    return _complete_stream_artifact(
        request_id,
        artifact,
        sidecar,
        request_dir,
        manifest,
        chunks,
        part_paths,
    )
