"""Path-confined PCAP artifact transfer, archive, and materialization policy."""
from __future__ import annotations

from pathlib import Path
from typing import Any


def analysis_json_path(out_dir: Path, request_id: str, safe_filename: Any) -> Path:
    return out_dir / f"{safe_filename(request_id)}-pcap-analysis.json"


def candidate_artifact_paths(
    request: dict[str, Any],
    artifact_dir: Path,
    safe_filename: Any,
) -> list[Path]:
    request_id = safe_filename(request.get("request_id"))
    remote_name = Path(str(request.get("artifact_path") or "capture.pcap")).name
    request_dir = artifact_dir / request_id
    candidates = [request_dir / remote_name]
    for pattern in ("*.pcap", "*.pcapng", "*.tar", "*.tar.gz", "*.tgz"):
        candidates.extend(sorted(request_dir.glob(pattern)))
    return list(dict.fromkeys(candidates))


def local_artifact_path(
    request: dict[str, Any],
    artifact_dir: Path,
    safe_filename: Any,
) -> Path:
    request_id = safe_filename(request.get("request_id"))
    remote_name = Path(str(request.get("artifact_path") or "capture.pcap")).name
    return artifact_dir / request_id / remote_name


def _expected_size(request: dict[str, Any], maximum: int) -> tuple[int | None, str]:
    raw = request.get("artifact_size_bytes")
    try:
        value = int(raw) if raw not in (None, "") else None
    except (TypeError, ValueError):
        return None, "remote artifact size metadata is invalid"
    if value is not None and (value < 0 or value > maximum):
        return None, "remote artifact exceeds the configured transfer ceiling"
    return value, ""


def _remote_path_error(artifact_path: str, re_module: Any) -> str:
    if not re_module.fullmatch(
        r"/nsm/pcapout/onion-sentinel/[A-Za-z0-9._/-]+", artifact_path
    ):
        return "remote artifact path is outside the Onion Sentinel PCAP output directory"
    if ".." in Path(artifact_path).parts:
        return "remote artifact path contains traversal components"
    return ""


def _validate_download(
    temp_path: Path,
    expected_size: int | None,
    expected_sha256: str,
    sha256_file: Any,
) -> str:
    if expected_size is not None and temp_path.stat().st_size != expected_size:
        return "downloaded artifact size did not match broker metadata"
    if expected_sha256 and sha256_file(temp_path) != expected_sha256:
        return "downloaded artifact sha256 did not match broker metadata"
    return ""


def _perform_transfer(
    command: list[str],
    temp_path: Path,
    ceiling: int,
    dependencies: dict[str, Any],
) -> tuple[Any | None, str]:
    try:
        process = dependencies["run_bounded_command_to_file"](
            command,
            temp_path,
            timeout_seconds=dependencies["remote_fetch_timeout_seconds"],
            max_stdout_bytes=max(1, ceiling),
            max_stderr_bytes=dependencies["max_tool_stderr_bytes"],
        )
    except (dependencies["BoundedProcessError"], OSError) as caught:
        return None, str(caught)[:240]
    if process.returncode != 0:
        return None, process.stderr[:240] or f"ssh exited {process.returncode}"
    return process, ""


def fetch_remote_artifact(
    request: dict[str, Any],
    artifact_dir: Path,
    ssh_target: str,
    ssh_bin: str,
    dependencies: dict[str, Any],
) -> dict[str, Any]:
    artifact_path = str(request.get("artifact_path") or "")
    expected_sha256 = str(request.get("artifact_sha256") or "")
    if not artifact_path or not ssh_target:
        return {"ok": False, "reason": "remote fetch not configured"}
    error = _remote_path_error(artifact_path, dependencies["re"])
    if error:
        return {"ok": False, "reason": error}
    expected_size, error = _expected_size(
        request, dependencies["max_remote_artifact_bytes"]
    )
    if error:
        return {"ok": False, "reason": error}
    destination = dependencies["local_artifact_path"](request, artifact_dir)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destination.with_suffix(destination.suffix + ".tmp")
    command = [
        ssh_bin, "-o", "BatchMode=yes", "-T", ssh_target,
        "sudo", "-n", "cat", artifact_path,
    ]
    ceiling = expected_size if expected_size is not None else dependencies[
        "max_remote_artifact_bytes"
    ]
    dependencies["require_runtime_capacity"](
        destination.parent, max(1, ceiling), label="remote PCAP artifact fetch"
    )
    _, error = _perform_transfer(command, temp_path, ceiling, dependencies)
    if error:
        temp_path.unlink(missing_ok=True)
        return {"ok": False, "reason": error}
    error = _validate_download(
        temp_path, expected_size, expected_sha256, dependencies["sha256_file"]
    )
    if error:
        temp_path.unlink(missing_ok=True)
        return {"ok": False, "reason": error}
    temp_path.replace(destination)
    destination.chmod(0o600)
    return {"ok": True, "path": str(destination)}


def safe_extract_tar(
    path: Path,
    destination: Path,
    dependencies: dict[str, Any],
) -> None:
    with dependencies["tarfile"].open(path) as archive:
        members = archive.getmembers()
        expanded = _archive_size(members, dependencies)
        dependencies["require_runtime_capacity"](
            destination, expanded, label="PCAP archive extraction"
        )
        _validate_archive_members(members, destination)
        archive.extractall(destination, members=members)


def _archive_size(members: list[Any], dependencies: dict[str, Any]) -> int:
    if len(members) > dependencies["max_archive_members"]:
        raise ValueError(
            f"archive has too many members: {len(members)} > "
            f"{dependencies['max_archive_members']}"
        )
    expanded = sum(
        max(0, int(member.size or 0)) for member in members if member.isfile()
    )
    if expanded > dependencies["max_extracted_bytes"]:
        raise ValueError(
            f"archive expands beyond limit: {expanded} > "
            f"{dependencies['max_extracted_bytes']}"
        )
    return expanded


def _validate_archive_members(members: list[Any], destination: Path) -> None:
    root = destination.resolve()
    for member in members:
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise ValueError(f"unsupported archive member type: {member.name}")
        target = (destination / member.name).resolve()
        if target != root and root not in target.parents:
            raise ValueError(f"unsafe tar member path: {member.name}")


def _direct_pcaps(
    candidates: list[Path],
    suffixes: set[str],
    maximum: int,
) -> list[Path]:
    pcaps = list(
        dict.fromkeys(
            candidate
            for candidate in candidates
            if candidate.exists() and candidate.suffix.lower() in suffixes
        )
    )
    if len(pcaps) > maximum:
        raise ValueError(
            f"artifact directory contains too many PCAP files: {len(pcaps)} > {maximum}"
        )
    return sorted(pcaps)


def _archive_pcaps(
    candidates: list[Path],
    work_dir: Path,
    dependencies: dict[str, Any],
) -> list[Path]:
    for candidate in candidates:
        if not candidate.exists():
            continue
        if candidate.suffix.lower() != ".tar" and not candidate.name.endswith(
            (".tar.gz", ".tgz")
        ):
            continue
        extract_dir = work_dir / "extract"
        extract_dir.mkdir(parents=True, exist_ok=True)
        dependencies["safe_extract_tar"](candidate, extract_dir)
        pcaps = [
            path
            for path in extract_dir.rglob("*")
            if path.is_file() and path.suffix.lower() in dependencies["pcap_suffixes"]
        ]
        if len(pcaps) > dependencies["max_pcap_files"]:
            raise ValueError(
                f"archive contains too many PCAP files: {len(pcaps)} > "
                f"{dependencies['max_pcap_files']}"
            )
        return sorted(pcaps)
    return []


def materialize_pcap_files(
    request: dict[str, Any],
    args: Any,
    work_dir: Path,
    direct_pcap: Path | None,
    dependencies: dict[str, Any],
) -> tuple[list[Path], str]:
    if direct_pcap:
        return [direct_pcap], "direct"
    candidates = dependencies["candidate_artifact_paths"](request, args.artifact_dir)
    if getattr(args, "fetch_remote", False) and not any(
        path.exists() for path in candidates
    ):
        fetched = dependencies["fetch_remote_artifact"](
            request,
            args.artifact_dir,
            getattr(args, "ssh_target", ""),
            getattr(args, "ssh_bin", "ssh"),
        )
        if not fetched.get("ok"):
            return [], f"artifact-fetch-failed: {fetched.get('reason')}"
        candidates = dependencies["candidate_artifact_paths"](
            request, args.artifact_dir
        )
    direct = _direct_pcaps(
        candidates, dependencies["pcap_suffixes"], dependencies["max_pcap_files"]
    )
    if direct:
        return direct, "copied-artifact"
    extracted = _archive_pcaps(candidates, work_dir, dependencies)
    if extracted:
        return extracted, "extracted-artifact"
    return [], "artifact-not-copied-to-mac"
