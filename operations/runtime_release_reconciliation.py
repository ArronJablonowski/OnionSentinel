#!/usr/bin/env python3
"""Build and evaluate a read-only repository-to-runtime release manifest."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable
import urllib.request


INSTALLER_PATH = "n8n/bin/install-macstudio-stack.zsh"
MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_RUNTIME_FILE_BYTES = 64 * 1024 * 1024
MAX_HEALTH_BYTES = 64 * 1024
DIRECT_COPY_RE = re.compile(
    r'^\s*cp(?:\s+-R)?\s+"\$REPO_DIR/([^"$]+)"\s+'
    r'"\$(STACK_DIR|DASHBOARD_RUNTIME_DIR)/([^"$]+)"\s*$'
)
EXCLUDED_RUNTIME_PREFIXES = (
    ".env",
    "alert_store/config/",
    "config/",
    "soc-alerts/agent-memory/",
)
TREE_MAPPINGS = (
    ("n8n/onion_sentinel", "onion_sentinel"),
    ("onion-sentinel-dashboard/assets", "onion-sentinel-dashboard/assets"),
)
ALERT_STORE_TREES = ("lib", "routes", "services", "repositories", "jobs", "composition")
QUERY_RUNTIME_INSTALLER = "n8n/bin/install-investigation-query-runtime.py"
V1_QUERY_PREFIX = "n8n/compat/investigation-pivots-v1"
V2_QUERY_PREFIX = "n8n/bin"
VERSIONED_QUERY_FILES = (
    "investigation_query_contract.py",
    "collect-investigation-pivots.py",
)
V2_QUERY_DEPENDENCIES = (
    "investigation_query_schema.py",
    "investigation_query_normalization_primitives.py",
    "investigation_query_observable_normalization.py",
    "investigation_query_event_tuple_normalization.py",
    "investigation_query_authorization_normalization.py",
    "investigation_query_normalization.py",
    "investigation_query_authorization_proposal.py",
    "investigation_query_authorization_manifest.py",
    "investigation_query_authorization_request.py",
    "investigation_query_authorization_adapter.py",
    "investigation_query_authorization.py",
    "investigation_query_rendering.py",
    "investigation_query_response_source.py",
    "investigation_query_response_result.py",
    "investigation_query_response_control.py",
    "investigation_query_response.py",
)
REQUIRED_INSTALLER_MARKERS = (
    'for tree in lib routes services repositories jobs composition; do',
    '"$REPO_DIR/n8n/bin/install-ai-runtime-package.py"',
    '"$REPO_DIR/n8n/onion_sentinel"',
    '"$REPO_DIR/onion-sentinel-dashboard/assets/."',
    '"$STACK_DIR/bin/install-investigation-query-runtime.py"',
)
ALLOWED_DYNAMIC_COPY_FRAGMENTS = (
    'cp "$REPO_DIR/n8n/config/$reviewer_prompt"',
    'cp "$REPO_DIR/n8n/agent-memory/$memory_file"',
)
ALLOWED_REPOSITORY_ONLY_FRAGMENTS = (
    '"$REPO_DIR/n8n/bin/set-runtime-release-id.py"',
    'local source="$REPO_DIR/n8n/alert_store/$tree"',
    '"$REPO_DIR/n8n/bin"  "$REPO_DIR/onion-sentinel-dashboard"',
)
CREDENTIAL_GOVERNANCE_PREFLIGHT_RE = re.compile(
    r'^\s*PYTHONDONTWRITEBYTECODE=1\s+/usr/bin/python3\s+'
    r'"\$REPO_DIR/operations/validate-credential-governance\.py"\s+--catalog\s+'
    r'"\$REPO_DIR/operations/security/credential-governance\.json"\s+>/dev/null\s*$'
)


class ReconciliationError(RuntimeError):
    """The source plan or runtime could not be safely reconciled."""


@dataclass(frozen=True, order=True)
class Mapping:
    source: str
    runtime: str


def _git(repo_root: Path, *args: str, maximum: int = MAX_GIT_OUTPUT_BYTES) -> bytes:
    completed = subprocess.run(
        ("git", "-C", str(repo_root), *args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", "replace").strip()[:512]
        raise ReconciliationError(f"Git source lookup failed: {detail}")
    if len(completed.stdout) > maximum:
        raise ReconciliationError("Git source lookup exceeded its byte limit")
    return completed.stdout


def resolve_revision(repo_root: Path, revision: str) -> str:
    value = _git(repo_root, "rev-parse", "--verify", f"{revision}^{{commit}}", maximum=256)
    commit = value.decode("ascii", "strict").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReconciliationError("source revision did not resolve to a commit")
    return commit


def git_file(repo_root: Path, revision: str, path: str) -> bytes:
    return _git(repo_root, "show", f"{revision}:{path}")


def git_tree_files(
    repo_root: Path,
    revision: str,
    prefix: str,
    *,
    required: bool = True,
) -> tuple[str, ...]:
    raw = _git(repo_root, "ls-tree", "-r", "-z", "--name-only", revision, "--", prefix)
    files = tuple(item.decode("utf-8") for item in raw.split(b"\0") if item)
    if required and not files:
        raise ReconciliationError(f"deployment source tree is empty: {prefix}")
    return files


def _logical_lines(source: str) -> tuple[str, ...]:
    return tuple(re.sub(r"\\\n\s*", " ", source).splitlines())


def _excluded(runtime: str) -> bool:
    return any(
        runtime == prefix or runtime.startswith(prefix)
        for prefix in EXCLUDED_RUNTIME_PREFIXES
    )


def _safe_relative(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ReconciliationError(f"unsafe {label} path in deployment plan")
    return str(path)


def validate_installer_coverage(installer: str) -> None:
    for marker in REQUIRED_INSTALLER_MARKERS:
        if marker not in installer:
            raise ReconciliationError("installer deployment contract marker is missing")
    _validate_copy_operations(installer)
    _validate_repository_runtime_operations(installer)
    _validate_repository_only_references(installer)


def _validate_copy_operations(installer: str) -> None:
    for line in _logical_lines(installer):
        if not re.search(r"\bcp(?:\s+-R)?\s+.*\$REPO_DIR/", line):
            continue
        if DIRECT_COPY_RE.match(line):
            continue
        if any(fragment in line for fragment in ALLOWED_DYNAMIC_COPY_FRAGMENTS):
            continue
        raise ReconciliationError(
            "installer contains an unclassified repository copy operation"
        )


def _known_non_copy_operation(line: str) -> bool:
    excluded_sources = (
        "$REPO_DIR/n8n/.env.example",
        "$REPO_DIR/n8n/config/",
        "$REPO_DIR/n8n/agent-memory/",
        "$REPO_DIR/n8n/launchd/",
    )
    return (
        any(fragment in line for fragment in ALLOWED_DYNAMIC_COPY_FRAGMENTS)
        or any(source in line for source in excluded_sources)
        or "install-ai-runtime-package.py" in line
        or "install-investigation-query-runtime.py" in line
    )


def _validate_repository_runtime_operations(installer: str) -> None:
    for line in _logical_lines(installer):
        if "$REPO_DIR/" not in line or not any(
            root in line
            for root in ("$STACK_DIR", "$DASHBOARD_RUNTIME_DIR", "$LAUNCHD_DIR")
        ):
            continue
        if DIRECT_COPY_RE.match(line):
            continue
        if _known_non_copy_operation(line):
            continue
        raise ReconciliationError(
            "installer contains an unclassified repository-to-runtime operation"
        )


def _repository_only_reference_allowed(line: str) -> bool:
    return (
        any(fragment in line for fragment in ALLOWED_REPOSITORY_ONLY_FRAGMENTS)
        or CREDENTIAL_GOVERNANCE_PREFLIGHT_RE.fullmatch(line) is not None
    )


def _validate_repository_only_references(installer: str) -> None:
    runtime_roots = ("$STACK_DIR", "$DASHBOARD_RUNTIME_DIR", "$LAUNCHD_DIR")
    for line in _logical_lines(installer):
        if "$REPO_DIR/" not in line or any(root in line for root in runtime_roots):
            continue
        if _repository_only_reference_allowed(line):
            continue
        raise ReconciliationError("installer contains an unclassified repository reference")


def _direct_mappings(installer: str) -> Iterable[Mapping]:
    for line in _logical_lines(installer):
        match = DIRECT_COPY_RE.match(line)
        if not match:
            continue
        source, destination_root, destination = match.groups()
        if source.endswith("/."):
            continue
        runtime = (
            destination
            if destination_root == "STACK_DIR"
            else f"onion-sentinel-dashboard/{destination}"
        )
        source = _safe_relative(source, "source")
        runtime = _safe_relative(runtime, "runtime")
        if not _excluded(runtime):
            yield Mapping(source, runtime)


def build_mappings(repo_root: Path, revision: str) -> tuple[Mapping, ...]:
    installer = git_file(repo_root, revision, INSTALLER_PATH).decode("utf-8")
    validate_installer_coverage(installer)
    mappings = set(_direct_mappings(installer))
    tree_mappings = list(TREE_MAPPINGS)
    for tree in ALERT_STORE_TREES:
        source_prefix = f"n8n/alert_store/{tree}"
        if git_tree_files(repo_root, revision, source_prefix, required=False):
            tree_mappings.append((source_prefix, f"alert_store/{tree}"))
    for source_prefix, runtime_prefix in tree_mappings:
        for source in git_tree_files(repo_root, revision, source_prefix):
            relative = PurePosixPath(source).relative_to(source_prefix)
            runtime = str(PurePosixPath(runtime_prefix) / relative)
            if not _excluded(runtime):
                mappings.add(Mapping(source, runtime))
    return tuple(sorted(mappings, key=lambda item: (item.runtime, item.source)))


def read_live_release_id(health_url: str) -> str:
    request = urllib.request.Request(health_url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        raw = response.read(MAX_HEALTH_BYTES + 1)
    if len(raw) > MAX_HEALTH_BYTES:
        raise ReconciliationError("health response exceeded its byte limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReconciliationError("health response is not valid JSON") from exc
    release_id = value.get("release_id") if isinstance(value, dict) else None
    if not isinstance(release_id, str) or not release_id:
        raise ReconciliationError("health response has no release identity")
    return release_id


def _open_runtime_file(root: Path, relative: str) -> list[int]:
    parts = PurePosixPath(relative).parts
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    descriptors: list[int] = []
    try:
        descriptors.append(os.open(root, directory_flags))
        for part in parts[:-1]:
            descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
        file_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        descriptor = os.open(parts[-1], file_flags, dir_fd=descriptors[-1])
        descriptors.append(descriptor)
        return descriptors
    except FileNotFoundError:
        for opened in reversed(descriptors):
            os.close(opened)
        raise
    except OSError as exc:
        for opened in reversed(descriptors):
            os.close(opened)
        raise ReconciliationError("runtime path is not a safe regular file") from exc


def _digest_descriptor(descriptor: int) -> tuple[str, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise ReconciliationError("runtime path is not a safe regular file")
    if metadata.st_size > MAX_RUNTIME_FILE_BYTES:
        raise ReconciliationError("runtime file exceeded its byte limit")
    digest = hashlib.sha256()
    consumed = 0
    while True:
        chunk = os.read(
            descriptor,
            min(1024 * 1024, MAX_RUNTIME_FILE_BYTES + 1 - consumed),
        )
        if not chunk:
            break
        consumed += len(chunk)
        if consumed > MAX_RUNTIME_FILE_BYTES:
            raise ReconciliationError("runtime file exceeded its byte limit")
        digest.update(chunk)
    return digest.hexdigest(), consumed


def _hash_runtime_file(root: Path, relative: str) -> tuple[str, int]:
    descriptors = _open_runtime_file(root, relative)
    try:
        return _digest_descriptor(descriptors[-1])
    finally:
        for opened in reversed(descriptors):
            os.close(opened)


def _git_path_exists(repo_root: Path, revision: str, path: str) -> bool:
    completed = subprocess.run(
        ("git", "-C", str(repo_root), "cat-file", "-e", f"{revision}:{path}"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode == 0


def _query_runtime_mappings(
    repo_root: Path,
    revision: str,
    stack_dir: Path,
) -> tuple[str, tuple[Mapping, ...]]:
    if not _git_path_exists(repo_root, revision, QUERY_RUNTIME_INSTALLER):
        return "not_present", ()
    classification, selected_for_mapping = _selected_query_contract(
        repo_root,
        revision,
        stack_dir,
    )
    prefix = V1_QUERY_PREFIX if selected_for_mapping == "v1" else V2_QUERY_PREFIX
    names = list(VERSIONED_QUERY_FILES)
    if selected_for_mapping == "v2":
        names.extend(V2_QUERY_DEPENDENCIES)
    mappings = tuple(
        Mapping(f"{prefix}/{name}", f"bin/{name}")
        for name in names
        if _git_path_exists(repo_root, revision, f"{prefix}/{name}")
    )
    return classification, mappings


def _selected_query_contract(
    repo_root: Path,
    revision: str,
    stack_dir: Path,
) -> tuple[str, str]:
    candidates = {
        "v1": f"{V1_QUERY_PREFIX}/investigation_query_contract.py",
        "v2": f"{V2_QUERY_PREFIX}/investigation_query_contract.py",
    }
    selected: str | None = None
    try:
        runtime_digest, _size = _hash_runtime_file(
            stack_dir,
            "bin/investigation_query_contract.py",
        )
    except (FileNotFoundError, ReconciliationError):
        runtime_digest = None
    for contract, source in candidates.items():
        if not _git_path_exists(repo_root, revision, source):
            continue
        if hashlib.sha256(git_file(repo_root, revision, source)).hexdigest() == runtime_digest:
            selected = contract
            break
    classification = selected or ("missing" if runtime_digest is None else "unrecognized")
    return classification, selected or "v1"


def _reconcile_mapping(
    repo_root: Path,
    stack_dir: Path,
    revision: str,
    mapping: Mapping,
) -> dict[str, object]:
    source_data = git_file(repo_root, revision, mapping.source)
    source_digest = hashlib.sha256(source_data).hexdigest()
    try:
        runtime_digest, runtime_size = _hash_runtime_file(stack_dir, mapping.runtime)
    except FileNotFoundError:
        status_name, runtime_digest, runtime_size = "missing", None, None
    except ReconciliationError:
        status_name, runtime_digest, runtime_size = "unsafe", None, None
    else:
        status_name = "match" if runtime_digest == source_digest else "mismatch"
    return {
        "runtime": mapping.runtime,
        "source": mapping.source,
        "source_sha256": source_digest,
        "source_size": len(source_data),
        "runtime_sha256": runtime_digest,
        "runtime_size": runtime_size,
        "status": status_name,
    }


def reconcile(
    *,
    repo_root: Path,
    stack_dir: Path,
    revision: str,
    expected_release_id: str,
    live_release_id: str,
) -> dict[str, object]:
    commit = resolve_revision(repo_root, revision)
    if expected_release_id != commit:
        raise ReconciliationError("expected release identity does not match source revision")
    if live_release_id != expected_release_id:
        raise ReconciliationError("live release identity does not match expected release")
    if stack_dir.is_symlink() or not stack_dir.is_dir():
        raise ReconciliationError("runtime root must be a regular directory")
    query_contract, query_mappings = _query_runtime_mappings(
        repo_root,
        commit,
        stack_dir,
    )
    mappings = set(build_mappings(repo_root, commit))
    mappings.update(query_mappings)
    entries = [
        _reconcile_mapping(repo_root, stack_dir, commit, mapping)
        for mapping in sorted(mappings, key=lambda item: (item.runtime, item.source))
    ]
    counts = {
        name: sum(entry["status"] == name for entry in entries)
        for name in ("match", "mismatch", "missing", "unsafe")
    }
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema_version": 1,
        "source_of_truth": INSTALLER_PATH,
        "source_revision": commit,
        "expected_release_id": expected_release_id,
        "live_release_id": live_release_id,
        "investigation_query_contract": query_contract,
        "excluded_runtime_prefixes": list(EXCLUDED_RUNTIME_PREFIXES),
        "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
        "counts": counts,
        "ok": counts["mismatch"] == counts["missing"] == counts["unsafe"] == 0,
        "entries": entries,
    }
