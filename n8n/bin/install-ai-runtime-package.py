#!/usr/bin/env python3
"""Validate and atomically install the complete Onion Sentinel Python package."""
from __future__ import annotations

import argparse
import compileall
import importlib
import os
from pathlib import Path
import shutil
import sys
import tempfile


REQUIRED_MODULES = (
    "onion_sentinel",
    "onion_sentinel.analysis.providers.cli_common",
    "onion_sentinel.analysis.providers.codex",
    "onion_sentinel.analysis.providers.hermes",
    "onion_sentinel.analysis.providers.ollama",
    "onion_sentinel.analysis.providers.openclaw",
    "onion_sentinel.analysis.providers.registry",
    "onion_sentinel.analysis.providers.routing",
    "onion_sentinel.analysis.persistence.analysis_index",
    "onion_sentinel.analysis.persistence.memory_journal",
    "onion_sentinel.analysis.conclusions.verdict",
    "onion_sentinel.analysis.conclusions.confidence",
    "onion_sentinel.analysis.conclusions.authorization",
    "onion_sentinel.analysis.conclusions.authorization_evidence",
    "onion_sentinel.analysis.conclusions.evidence_guard",
    "onion_sentinel.analysis.conclusions.tuning",
    "onion_sentinel.analysis.conclusions.incident_report",
    "onion_sentinel.analysis.conclusions.incident_completeness",
    "onion_sentinel.analysis.review.comparison",
    "onion_sentinel.analysis.review.adjudication",
    "onion_sentinel.analysis.review.authorization",
    "onion_sentinel.analysis.review.disagreement",
    "onion_sentinel.analysis.review.gates",
    "onion_sentinel.analysis.review.contracts",
    "onion_sentinel.analysis.review.package",
    "onion_sentinel.analysis.review.projection",
    "onion_sentinel.analysis.review.text",
    "onion_sentinel.analysis.review.validation",
    "onion_sentinel.analysis.review.supplemental",
    "onion_sentinel.analysis.reporting.incident",
    "onion_sentinel.analysis.reporting.markdown",
    "onion_sentinel.analysis.reporting.publication",
    "onion_sentinel.composition",
    "onion_sentinel.contracts.errors",
    "onion_sentinel.contracts.models",
    "onion_sentinel.contracts.ports",
    "onion_sentinel.runtime",
)


def validate_source(source: Path) -> Path:
    resolved = source.resolve(strict=True)
    if source.is_symlink() or not resolved.is_dir():
        raise RuntimeError("AI runtime package source must be a regular directory")
    if resolved.name != "onion_sentinel" or not (resolved / "__init__.py").is_file():
        raise RuntimeError("AI runtime package source is incomplete")
    for path in resolved.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("AI runtime package source cannot contain symlinks")
    return resolved


def validate_staged_package(package: Path) -> None:
    if not compileall.compile_dir(str(package), quiet=1, force=True):
        raise RuntimeError("AI runtime package compilation failed")
    parent = str(package.parent)
    original_path = list(sys.path)
    existing = {
        name: sys.modules.pop(name)
        for name in list(sys.modules)
        if name == "onion_sentinel" or name.startswith("onion_sentinel.")
    }
    try:
        sys.path.insert(0, parent)
        importlib.invalidate_caches()
        for module_name in REQUIRED_MODULES:
            importlib.import_module(module_name)
    except Exception as exc:
        raise RuntimeError(
            f"AI runtime package import validation failed: {type(exc).__name__}"
        ) from exc
    finally:
        for name in list(sys.modules):
            if name == "onion_sentinel" or name.startswith("onion_sentinel."):
                sys.modules.pop(name, None)
        sys.modules.update(existing)
        sys.path[:] = original_path


def remove_validation_bytecode(package: Path) -> None:
    """Do not publish host-version-specific validation caches."""
    for cache in sorted(package.rglob("__pycache__"), reverse=True):
        shutil.rmtree(cache)


def install_package(source: Path, destination: Path) -> None:
    source = validate_source(source)
    destination = destination.expanduser()
    if destination.name != "onion_sentinel" or destination.is_symlink():
        raise RuntimeError("AI runtime package destination is invalid")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(
        tempfile.mkdtemp(prefix=".onion-sentinel-package.", dir=destination.parent)
    )
    staged = staging_root / "onion_sentinel"
    backup = destination.parent / f".onion-sentinel-package-backup.{os.getpid()}"
    installed = False
    try:
        shutil.copytree(source, staged)
        validate_staged_package(staged)
        remove_validation_bytecode(staged)
        if backup.exists():
            raise RuntimeError("AI runtime package backup path already exists")
        if destination.exists():
            destination.rename(backup)
        try:
            staged.rename(destination)
            installed = True
        except Exception:
            if backup.exists() and not destination.exists():
                backup.rename(destination)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)
        if not installed and backup.exists() and not destination.exists():
            backup.rename(destination)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    install_package(args.source, args.destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
