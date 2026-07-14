#!/usr/bin/env python3
"""Create an atomic, verified local disaster-recovery bundle."""

from __future__ import annotations

import argparse
from contextlib import closing
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def backup_sqlite(source: Path, destination: Path) -> int:
    # sqlite3.Connection's context manager commits or rolls back but does not
    # close the handle. Explicit closing keeps repeated backup jobs bounded.
    with closing(sqlite3.connect(source)) as src, closing(sqlite3.connect(destination)) as dst:
        with src, dst:
            src.backup(dst)
    with closing(sqlite3.connect(destination)) as check:
        result = check.execute("PRAGMA quick_check").fetchone()[0]
        rows = check.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    if result != "ok":
        raise RuntimeError(f"SQLite backup failed quick_check: {result}")
    return int(rows)


def postgres_dump(docker: str, destination: Path) -> None:
    command = [
        docker, "exec", "n8n-postgres", "sh", "-ec",
        'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc',
    ]
    with destination.open("wb") as stream:
        subprocess.run(command, stdout=stream, check=True, timeout=1800)
    if destination.stat().st_size == 0:
        raise RuntimeError("PostgreSQL dump is empty")
    with destination.open("rb") as stream:
        subprocess.run(
            [docker, "exec", "-i", "n8n-postgres", "pg_restore", "--list"],
            stdin=stream,
            stdout=subprocess.DEVNULL,
            check=True,
            timeout=300,
        )


def archive_runtime_secrets(stack_dir: Path, destination: Path) -> list[str]:
    candidates = [Path(".env"), Path("n8n_data/config"), Path("config"), Path("soc-alerts/agent-memory")]
    included: list[str] = []
    with tarfile.open(destination, "w:gz") as archive:
        for relative in candidates:
            source = stack_dir / relative
            if source.exists():
                archive.add(source, arcname=str(relative), recursive=True)
                included.append(str(relative))
    return included


def create_bundle(stack_dir: Path, backup_root: Path, docker: str) -> Path:
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    staging = backup_root / f".staging-{stamp}"
    final = backup_root / stamp
    staging.mkdir(mode=0o700, parents=True)
    try:
        alert_rows = backup_sqlite(stack_dir / "alert_store_data/alerts.sqlite3", staging / "alerts.sqlite3")
        postgres_dump(docker, staging / "n8n-postgres.dump")
        included = archive_runtime_secrets(stack_dir, staging / "runtime-secrets.tar.gz")
        files = {}
        for path in sorted(staging.iterdir()):
            if path.is_file():
                os.chmod(path, 0o600)
                files[path.name] = {"bytes": path.stat().st_size, "sha256": sha256_file(path)}
        manifest = {
            "created_at": dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  "),
            "alert_rows": alert_rows,
            "runtime_paths": included,
            "files": files,
        }
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        os.chmod(staging / "manifest.json", 0o600)
        staging.rename(final)
        return final
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def prune(backup_root: Path, keep: int) -> None:
    bundles = sorted((path for path in backup_root.iterdir() if path.is_dir() and not path.name.startswith(".")), reverse=True)
    for path in bundles[keep:]:
        shutil.rmtree(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-dir", type=Path, default=Path.home() / "n8n-local")
    parser.add_argument("--backup-root", type=Path)
    parser.add_argument("--docker", default="/usr/local/bin/docker")
    parser.add_argument("--keep", type=int, default=7)
    args = parser.parse_args()
    backup_root = args.backup_root or args.stack_dir / "recovery_backups"
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(backup_root, 0o700)
    with (backup_root / ".backup.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        bundle = create_bundle(args.stack_dir, backup_root, args.docker)
        prune(backup_root, max(2, args.keep))
    print(f"backup_ok path={bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
