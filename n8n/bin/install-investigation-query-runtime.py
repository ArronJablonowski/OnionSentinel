#!/usr/bin/env python3
"""Install the Mac-side investigation pivot stack without wire-version drift.

The Security Onion forced-command wrapper has no unauthenticated capability
negotiation endpoint.  The operator-selected contract in the local,
permission-restricted incident-evidence config is therefore authoritative.
An absent setting means v1.  V2 is installed only after an explicit exact-ID
opt in, which must happen together with the Security Onion v2 wrapper cutover.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


V1 = "onion-sentinel-investigation-pivots-v1"
V2 = "onion-sentinel-investigation-pivots-v2"
SUPPORTED_CONTRACTS = frozenset({V1, V2})
VERSIONED_QUERY_FILES = (
    "investigation_query_contract.py",
    "collect-investigation-pivots.py",
)
HARDENED_BUILDER = "build-ai-investigation-prompt.py"
HARDENED_BUILDER_DEPENDENCIES = (
    "prompt_builder_cli.py",
    "prompt_correlation_context.py",
    "prompt_correlation_facts.py",
    "prompt_incident_evidence_projection.py",
    "prompt_incident_grounding.py",
    "prompt_investigation_query_context.py",
    "prompt_package_compactor.py",
)
MAX_CONFIG_BYTES = 64 * 1024
MAX_RUNTIME_FILE_BYTES = 2 * 1024 * 1024


class QueryRuntimeInstallError(RuntimeError):
    """A configured wire contract or runtime bundle failed closed."""


def _read_regular_file(path: Path, *, maximum_bytes: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise QueryRuntimeInstallError(f"required regular file is unavailable: {path}")
    data = path.read_bytes()
    if len(data) > maximum_bytes:
        raise QueryRuntimeInstallError(f"file exceeds its byte limit: {path}")
    return data


def configured_contract(config_path: Path) -> str:
    raw = _read_regular_file(config_path, maximum_bytes=MAX_CONFIG_BYTES)
    try:
        config = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryRuntimeInstallError(
            "incident-evidence config is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(config, dict):
        raise QueryRuntimeInstallError("incident-evidence config root must be an object")
    selected = str(config.get("investigation_query_contract") or V1).strip()
    if selected not in SUPPORTED_CONTRACTS:
        raise QueryRuntimeInstallError(
            "incident-evidence investigation_query_contract must be exactly "
            f"{V1!r} or {V2!r}"
        )
    return selected


def _module_tree(path: Path) -> ast.Module:
    raw = _read_regular_file(path, maximum_bytes=MAX_RUNTIME_FILE_BYTES)
    try:
        return ast.parse(raw.decode("utf-8"), filename=str(path))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise QueryRuntimeInstallError(f"runtime Python is invalid: {path}") from exc


def _assigned_contract(path: Path) -> str | None:
    for node in _module_tree(path).body:
        value: ast.expr | None = None
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            value = node.value
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            value = node.value
            targets = [node.target]
        if (
            isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and any(
                isinstance(target, ast.Name)
                and target.id == "INVESTIGATION_QUERY_CONTRACT"
                for target in targets
            )
        ):
            return value.value
    return None


def _imports_contract_authority(path: Path, required: set[str]) -> bool:
    for node in _module_tree(path).body:
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.module != "investigation_query_contract":
            continue
        imported = {alias.name for alias in node.names}
        if required.issubset(imported):
            return True
    return False


def validate_versioned_runtime(directory: Path, expected_contract: str) -> None:
    contract_path = directory / "investigation_query_contract.py"
    collector_path = directory / "collect-investigation-pivots.py"
    if _assigned_contract(contract_path) != expected_contract:
        raise QueryRuntimeInstallError(
            f"query contract module does not embed {expected_contract}"
        )
    if not _imports_contract_authority(
        collector_path,
        {
            "INVESTIGATION_QUERY_CONTRACT",
            "authorize_investigation_query_request",
            "validate_investigation_query_response",
        },
    ):
        raise QueryRuntimeInstallError(
            "pivot collector does not import the adjacent contract authority"
        )


def validate_hardened_builder(path: Path) -> None:
    tree = _module_tree(path)
    imports_module = any(
        isinstance(node, ast.Import)
        and any(
            alias.name == "investigation_query_contract"
            and alias.asname == "INVESTIGATION_CONTRACT"
            for alias in node.names
        )
        for node in tree.body
    )
    if not imports_module:
        raise QueryRuntimeInstallError(
            "hardened prompt builder does not import the adjacent contract authority"
        )
    imported_dependencies = {
        node.module
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and isinstance(node.module, str)
    }
    required_dependencies = {
        Path(name).stem for name in HARDENED_BUILDER_DEPENDENCIES
    }
    if not required_dependencies.issubset(imported_dependencies):
        raise QueryRuntimeInstallError(
            "hardened prompt builder does not import its adjacent modules"
        )
    for name in HARDENED_BUILDER_DEPENDENCIES:
        _module_tree(path.parent / name)
    builder_source = _read_regular_file(
        path,
        maximum_bytes=MAX_RUNTIME_FILE_BYTES,
    ).decode("utf-8")
    cli_source = _read_regular_file(
        path.parent / "prompt_builder_cli.py",
        maximum_bytes=MAX_RUNTIME_FILE_BYTES,
    ).decode("utf-8")
    if (
        "--blind-reanalysis" not in cli_source
        or "blind_model_authored_context" not in builder_source
    ):
        raise QueryRuntimeInstallError(
            "prompt builder is missing blind-reanalysis hardening"
        )


def validate_runtime(directory: Path, expected_contract: str) -> None:
    validate_versioned_runtime(directory, expected_contract)
    validate_hardened_builder(directory / HARDENED_BUILDER)


def _load_v1_manifest(bundle: Path) -> dict[str, str]:
    raw = _read_regular_file(bundle / "manifest.json", maximum_bytes=64 * 1024)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryRuntimeInstallError("v1 compatibility manifest is invalid") from exc
    if (
        not isinstance(value, dict)
        or value.get("query_contract") != V1
        or not isinstance(value.get("files"), dict)
    ):
        raise QueryRuntimeInstallError("v1 compatibility manifest is malformed")
    files: dict[str, str] = {}
    for name in VERSIONED_QUERY_FILES:
        digest = str(value["files"].get(name) or "")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise QueryRuntimeInstallError(
                f"v1 compatibility manifest has no valid digest for {name}"
            )
        files[name] = digest
    return files


def validate_v1_bundle(bundle: Path) -> None:
    expected = _load_v1_manifest(bundle)
    validate_versioned_runtime(bundle, V1)
    for name, digest in expected.items():
        data = _read_regular_file(
            bundle / name,
            maximum_bytes=MAX_RUNTIME_FILE_BYTES,
        )
        if hashlib.sha256(data).hexdigest() != digest:
            raise QueryRuntimeInstallError(
                f"v1 compatibility file digest changed: {name}"
            )


def _atomic_install(source: Path, destination: Path) -> None:
    data = _read_regular_file(source, maximum_bytes=MAX_RUNTIME_FILE_BYTES)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with tempfile.NamedTemporaryFile(
        "wb",
        dir=destination.parent,
        prefix=f".{destination.name}.",
        delete=False,
    ) as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.chmod(temporary, 0o755)
    os.replace(temporary, destination)


def install_query_runtime(
    *,
    repo_root: Path,
    runtime_bin: Path,
    config_path: Path,
) -> dict[str, Any]:
    selected = configured_contract(config_path)
    v1_bundle = repo_root / "n8n" / "compat" / "investigation-pivots-v1"
    current_source = repo_root / "n8n" / "bin"

    if selected == V1:
        validate_v1_bundle(v1_bundle)
        for name in VERSIONED_QUERY_FILES:
            _atomic_install(v1_bundle / name, runtime_bin / name)
        action = "installed_bundled_v1"
    else:
        validate_versioned_runtime(current_source, V2)
        for name in VERSIONED_QUERY_FILES:
            _atomic_install(current_source / name, runtime_bin / name)
        action = "installed_explicit_v2"

    validate_hardened_builder(current_source / HARDENED_BUILDER)
    for name in HARDENED_BUILDER_DEPENDENCIES:
        _atomic_install(current_source / name, runtime_bin / name)
    _atomic_install(
        current_source / HARDENED_BUILDER,
        runtime_bin / HARDENED_BUILDER,
    )
    validate_runtime(runtime_bin, selected)
    return {
        "contract": selected,
        "action": action,
        "runtime_bin": str(runtime_bin),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--runtime-bin", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        outcome = install_query_runtime(
            repo_root=args.repo_root.resolve(),
            runtime_bin=args.runtime_bin.resolve(),
            config_path=args.config.resolve(),
        )
    except (OSError, QueryRuntimeInstallError) as exc:
        raise SystemExit(f"investigation query runtime install refused: {exc}")
    print(json.dumps(outcome, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
