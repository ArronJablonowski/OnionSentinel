#!/usr/bin/env python3
"""Restore the newest runtime bundle into isolated temporary resources."""

from __future__ import annotations

import argparse
from contextlib import closing
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def newest_bundle(root: Path) -> Path:
    bundles = sorted(path for path in root.iterdir() if path.is_dir() and not path.name.startswith("."))
    if not bundles:
        raise RuntimeError("no recovery bundle exists")
    return bundles[-1]


def verify_bundle(bundle: Path) -> dict[str, object]:
    manifest = json.loads((bundle / "manifest.json").read_text())
    for name, metadata in dict(manifest.get("files") or {}).items():
        path = bundle / name
        if not path.is_file() or sha256_file(path) != metadata.get("sha256"):
            raise RuntimeError(f"bundle hash validation failed for {name}")
    required = {"alerts.sqlite3", "n8n-postgres.dump", "runtime-secrets.tar.gz"}
    if not required.issubset(set(dict(manifest.get("files") or {}))):
        raise RuntimeError("recovery bundle is missing required files")
    return manifest


def validate_runtime_archive(path: Path) -> dict[str, object]:
    with tarfile.open(path) as archive:
        members = archive.getmembers()
    names = [member.name for member in members]
    for name in names:
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts:
            raise RuntimeError("unsafe path in runtime recovery archive")
    required_prefixes = {".env", "n8n_data/config"}
    missing = [prefix for prefix in required_prefixes if not any(name == prefix or name.startswith(prefix + "/") for name in names)]
    if missing:
        raise RuntimeError("runtime recovery archive lacks required configuration")
    return {"member_count": len(names), "required_paths": sorted(required_prefixes)}


def validate_sqlite(source: Path, temp_dir: Path) -> dict[str, object]:
    restored = temp_dir / "alerts-restored.sqlite3"
    shutil.copy2(source, restored)
    with closing(sqlite3.connect(f"file:{restored}?mode=ro", uri=True)) as conn:
        quick_check = conn.execute("PRAGMA quick_check").fetchone()[0]
        alerts = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
        groups = int(conn.execute("SELECT COUNT(*) FROM alert_group_summary").fetchone()[0])
    if quick_check != "ok":
        raise RuntimeError(f"restored SQLite quick_check failed: {quick_check}")
    return {"quick_check": quick_check, "alert_rows": alerts, "group_rows": groups}


def docker_output(docker: str, args: list[str], **kwargs) -> str:
    result = subprocess.run([docker, *args], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    return result.stdout.strip()


def restore_postgres(docker: str, dump: Path) -> dict[str, object]:
    image = docker_output(docker, ["inspect", "-f", "{{.Config.Image}}", "n8n-postgres"])
    name = f"onion-sentinel-restore-drill-{secrets.token_hex(5)}"
    docker_output(docker, [
        "run", "--detach", "--rm", "--name", name, "--network", "none",
        "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=4g",
        "-e", "POSTGRES_HOST_AUTH_METHOD=trust", image,
    ])
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            probe = subprocess.run([docker, "exec", name, "pg_isready", "-U", "postgres"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("temporary PostgreSQL did not become ready")
        docker_output(docker, ["exec", name, "createdb", "-U", "postgres", "n8n_restore_drill"])
        with dump.open("rb") as stream:
            subprocess.run(
                [docker, "exec", "-i", name, "pg_restore", "-U", "postgres", "--no-owner", "--no-privileges", "-d", "n8n_restore_drill"],
                stdin=stream, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=1800,
            )
        table_count = int(docker_output(docker, ["exec", name, "psql", "-U", "postgres", "-d", "n8n_restore_drill", "-Atc", "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';"]))
        workflow_count = int(docker_output(docker, ["exec", name, "psql", "-U", "postgres", "-d", "n8n_restore_drill", "-Atc", "SELECT CASE WHEN to_regclass('public.workflow_entity') IS NULL THEN -1 ELSE (SELECT COUNT(*) FROM workflow_entity) END;"]))
        if table_count <= 0 or workflow_count < 0:
            raise RuntimeError("restored PostgreSQL is missing n8n schema")
        return {"image": image, "table_count": table_count, "workflow_count": workflow_count, "network": "none"}
    finally:
        subprocess.run([docker, "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-dir", type=Path, default=Path.home() / "n8n-local")
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--docker", default="/usr/local/bin/docker")
    args = parser.parse_args()
    started = time.monotonic()
    bundle = args.bundle or newest_bundle(args.stack_dir / "recovery_backups")
    report: dict[str, object] = {
        "started_at": dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  "),
        "bundle": bundle.name,
        "status": "running",
    }
    output_dir = args.stack_dir / "logs/restore-drills"
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    output = output_dir / f"restore-drill-{stamp}.json"
    try:
        manifest = verify_bundle(bundle)
        with tempfile.TemporaryDirectory(prefix="onion-sentinel-restore-") as temp:
            report["sqlite"] = validate_sqlite(bundle / "alerts.sqlite3", Path(temp))
        if int(report["sqlite"]["alert_rows"]) != int(manifest.get("alert_rows") or -1):
            raise RuntimeError("restored SQLite row count does not match bundle manifest")
        report["runtime_archive"] = validate_runtime_archive(bundle / "runtime-secrets.tar.gz")
        report["postgres"] = restore_postgres(args.docker, bundle / "n8n-postgres.dump")
        report["manifest_alert_rows"] = int(manifest.get("alert_rows") or 0)
        report["status"] = "passed"
        return_code = 0
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        return_code = 2
    finally:
        report["runtime_seconds"] = round(time.monotonic() - started, 3)
        report["completed_at"] = dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        os.chmod(output, 0o600)
        print(json.dumps({"ok": report["status"] == "passed", "report": str(output), **report}, sort_keys=True))
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
