#!/usr/bin/env python3
"""Restore the newest runtime bundle into isolated temporary resources."""

from __future__ import annotations

import argparse
from contextlib import closing
import datetime as dt
import getpass
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
import sys


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from recovery_encryption import (
    ENCRYPTION_SCHEME,
    PBKDF2_ITERATIONS,
    RecoveryEncryption,
)
from recovery_bundle import (
    decrypt_bundle_files,
    newest_bundle,
    sha256_file,
    verify_bundle,
)


CURRENT_HARNESS_SCHEMA_VERSION = 5


def __runtime_archive_member_state(
    members: list[tarfile.TarInfo],
) -> tuple[list[str], bool]:
    names: list[str] = []
    audit_name = "logs/onion-sentinel-admin-audit.jsonl"
    audit_chain_present = False
    for member in members:
        name = member.name
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts:
            raise RuntimeError("unsafe path in runtime recovery archive")
        if pure.parts and pure.parts[0] == "admin-state":
            raise RuntimeError(
                "runtime recovery archive must not contain active session state"
            )
        if name == audit_name:
            if not member.isfile():
                raise RuntimeError(
                    "runtime recovery archive audit chain is not a regular file"
                )
            audit_chain_present = True
        names.append(name)
    return names, audit_chain_present


def validate_runtime_archive(path: Path) -> dict[str, object]:
    with tarfile.open(path) as archive:
        members = archive.getmembers()
    names, audit_chain_present = __runtime_archive_member_state(members)
    required_prefixes = {".env", "n8n_data/config"}
    missing = [prefix for prefix in required_prefixes if not any(name == prefix or name.startswith(prefix + "/") for name in names)]
    if missing:
        raise RuntimeError("runtime recovery archive lacks required configuration")
    return {
        "member_count": len(names),
        "required_paths": sorted(required_prefixes),
        "audit_chain_present": audit_chain_present,
    }


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


def __harness_database_state(conn: sqlite3.Connection) -> dict[str, object]:
    conn.execute("PRAGMA query_only = ON")
    state: dict[str, object] = {
        "quick_check": str(conn.execute("PRAGMA quick_check").fetchone()[0]),
        "foreign_key_errors": len(conn.execute("PRAGMA foreign_key_check").fetchall()),
    }
    tables = {
        str(row[0])
        for row in conn.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
    }
    required = {
        "harness_metadata", "harness_runs", "harness_events", "harness_evidence",
        "harness_hypotheses", "harness_decisions", "harness_model_calls",
        "harness_tool_calls", "harness_budget_reservations",
    }
    missing = sorted(required.difference(tables))
    if missing:
        raise RuntimeError("restored harness SQLite is missing table(s): " + ", ".join(missing))
    state["runs"] = int(conn.execute("SELECT COUNT(*) FROM harness_runs").fetchone()[0])
    state["schema_row"] = conn.execute(
        """
        SELECT value FROM harness_metadata
        WHERE key = 'schema_version'
        """
    ).fetchone()
    return state


def __validated_harness_summary(state: dict[str, object]) -> dict[str, object]:
    quick_check = str(state["quick_check"])
    foreign_key_errors = int(state["foreign_key_errors"])
    schema_row = state["schema_row"]
    if quick_check != "ok":
        raise RuntimeError(f"restored harness SQLite quick_check failed: {quick_check}")
    if foreign_key_errors:
        raise RuntimeError(
            "restored harness SQLite foreign_key_check failed: "
            f"{foreign_key_errors} row(s)"
        )
    if schema_row is None or not str(schema_row[0]).isdigit():
        raise RuntimeError("restored harness SQLite schema version is invalid")
    schema_version = int(schema_row[0])
    if schema_version < 1 or schema_version > CURRENT_HARNESS_SCHEMA_VERSION:
        raise RuntimeError("restored harness SQLite schema version is unsupported")
    return {
        "quick_check": quick_check,
        "foreign_key_check_rows": foreign_key_errors,
        "run_rows": int(state["runs"]),
        "schema_version": schema_version,
    }


def validate_harness_sqlite(source: Path, temp_dir: Path) -> dict[str, object]:
    """Restore and validate the optional investigation trace database."""
    restored = temp_dir / "investigation-harness-restored.sqlite3"
    shutil.copy2(source, restored)
    with closing(sqlite3.connect(f"file:{restored}?mode=ro", uri=True)) as conn:
        state = __harness_database_state(conn)
    return __validated_harness_summary(state)


def docker_output(docker: str, args: list[str], **kwargs) -> str:
    result = subprocess.run([docker, *args], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    return result.stdout.strip()


def __start_restore_postgres(docker: str, source_container: str) -> tuple[str, str]:
    image = docker_output(
        docker,
        ["inspect", "-f", "{{.Config.Image}}", source_container],
    )
    name = f"onion-sentinel-restore-drill-{secrets.token_hex(5)}"
    docker_output(docker, [
        "run", "--detach", "--rm", "--name", name, "--network", "none",
        "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=4g",
        "-e", "POSTGRES_HOST_AUTH_METHOD=trust", image,
    ])
    return image, name


def __wait_for_restore_postgres(docker: str, name: str) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        probe = subprocess.run(
            [docker, "exec", name, "pg_isready", "-U", "postgres"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if probe.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("temporary PostgreSQL did not become ready")


def __load_restore_dump(docker: str, name: str, dump: Path) -> None:
    docker_output(docker, ["exec", name, "createdb", "-U", "postgres", "n8n_restore_drill"])
    with dump.open("rb") as stream:
        subprocess.run(
            [docker, "exec", "-i", name, "pg_restore", "-U", "postgres", "--no-owner", "--no-privileges", "-d", "n8n_restore_drill"],
            stdin=stream, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            check=True, timeout=1800,
        )


def __psql_count(docker: str, name: str, query: str) -> int:
    return int(docker_output(
        docker,
        ["exec", name, "psql", "-U", "postgres", "-d", "n8n_restore_drill", "-Atc", query],
    ))


def __shadow_restore_summary(docker: str, name: str, image: str) -> dict[str, object]:
    schema_versions = __psql_count(
        docker, name,
        "SELECT CASE WHEN to_regclass('onion_sentinel_queue.schema_version') IS NULL THEN -1 ELSE (SELECT COUNT(*) FROM onion_sentinel_queue.schema_version) END;",
    )
    durable_jobs = __psql_count(
        docker, name,
        "SELECT CASE WHEN to_regclass('onion_sentinel_queue.shadow_durable_jobs') IS NULL THEN -1 ELSE (SELECT COUNT(*) FROM onion_sentinel_queue.shadow_durable_jobs) END;",
    )
    if schema_versions < 1 or durable_jobs < 0:
        raise RuntimeError("restored PostgreSQL is missing alert-store shadow schema")
    return {
        "image": image, "schema_version_rows": schema_versions,
        "durable_job_rows": durable_jobs, "network": "none",
    }


def __n8n_restore_summary(docker: str, name: str, image: str) -> dict[str, object]:
    table_count = __psql_count(
        docker, name,
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';",
    )
    workflow_count = __psql_count(
        docker, name,
        "SELECT CASE WHEN to_regclass('public.workflow_entity') IS NULL THEN -1 ELSE (SELECT COUNT(*) FROM workflow_entity) END;",
    )
    if table_count <= 0 or workflow_count < 0:
        raise RuntimeError("restored PostgreSQL is missing n8n schema")
    return {"image": image, "table_count": table_count, "workflow_count": workflow_count, "network": "none"}


def restore_postgres(
    docker: str,
    dump: Path,
    *,
    source_container: str = "n8n-postgres",
    schema_kind: str = "n8n",
) -> dict[str, object]:
    image, name = __start_restore_postgres(docker, source_container)
    try:
        __wait_for_restore_postgres(docker, name)
        __load_restore_dump(docker, name, dump)
        if schema_kind == "alert-store-shadow":
            return __shadow_restore_summary(docker, name, image)
        return __n8n_restore_summary(docker, name, image)
    finally:
        subprocess.run([docker, "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def __parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-dir", type=Path, default=Path.home() / "n8n-local")
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--docker", default="/usr/local/bin/docker")
    parser.add_argument(
        "--keychain-service",
        default="com.arron.onion-sentinel.runtime-backup",
    )
    parser.add_argument("--keychain-account", default=getpass.getuser())
    parser.add_argument("--security", default="/usr/bin/security")
    parser.add_argument("--openssl", default="/usr/bin/openssl")
    return parser.parse_args()


def __initial_report(bundle: Path) -> dict[str, object]:
    return {
        "started_at": dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  "),
        "bundle": bundle.name,
        "status": "running",
    }


def __report_destination(stack_dir: Path) -> Path:
    output_dir = stack_dir / "logs/restore-drills"
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    return output_dir / f"restore-drill-{stamp}.json"


def __validate_sqlite_backups(
    payloads: dict[str, Path],
    manifest: dict[str, object],
    report: dict[str, object],
) -> None:
    with tempfile.TemporaryDirectory(prefix="onion-sentinel-restore-") as temp:
        temp_dir = Path(temp)
        report["sqlite"] = validate_sqlite(payloads["alerts.sqlite3"], temp_dir)
        harness_path = payloads.get("investigation-harness.sqlite3")
        report["investigation_harness"] = (
            validate_harness_sqlite(harness_path, temp_dir)
            if harness_path is not None
            else {"present": False}
        )
    if int(report["sqlite"]["alert_rows"]) != int(manifest.get("alert_rows") or -1):
        raise RuntimeError("restored SQLite row count does not match bundle manifest")
    if "investigation-harness.sqlite3" in payloads:
        if int(report["investigation_harness"]["run_rows"]) != int(manifest.get("harness_runs", -1)):
            raise RuntimeError("restored harness SQLite run count does not match bundle manifest")
        report["investigation_harness"]["present"] = True


def __restore_postgres_backups(
    args: argparse.Namespace,
    payloads: dict[str, Path],
    report: dict[str, object],
) -> None:
    report["postgres"] = restore_postgres(
        args.docker,
        payloads["n8n-postgres.dump"],
    )
    shadow_dump = payloads.get("alert-store-postgres.dump")
    report["alert_store_postgres_shadow"] = (
        restore_postgres(
            args.docker, shadow_dump,
            source_container="onion-sentinel-alert-store-postgres",
            schema_kind="alert-store-shadow",
        )
        if shadow_dump is not None
        else {"present": False}
    )
    if shadow_dump is not None:
        report["alert_store_postgres_shadow"]["present"] = True


def __execute_restore_drill(
    args: argparse.Namespace, bundle: Path, report: dict[str, object],
) -> None:
    manifest = verify_bundle(bundle)
    encryption = RecoveryEncryption.from_keychain(
        service=getattr(
            args,
            "keychain_service",
            "com.arron.onion-sentinel.runtime-backup",
        ),
        account=getattr(args, "keychain_account", getpass.getuser()),
        security=getattr(args, "security", "/usr/bin/security"),
        openssl=getattr(args, "openssl", "/usr/bin/openssl"),
    )
    with tempfile.TemporaryDirectory(
        prefix="onion-sentinel-recovery-plaintext-"
    ) as plaintext_temp:
        plaintext_root = Path(plaintext_temp)
        payloads = decrypt_bundle_files(
            bundle,
            manifest,
            plaintext_root,
            encryption,
        )
        __validate_sqlite_backups(payloads, manifest, report)
        report["runtime_archive"] = validate_runtime_archive(
            payloads["runtime-secrets.tar.gz"]
        )
        __restore_postgres_backups(args, payloads, report)
    report["manifest_alert_rows"] = int(manifest.get("alert_rows") or 0)
    report["encryption"] = dict(manifest["encryption"])
    report["status"] = "passed"


def __publish_report(
    report: dict[str, object], output: Path, started: float,
) -> None:
    report["runtime_seconds"] = round(time.monotonic() - started, 3)
    report["completed_at"] = dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(output, 0o600)
    print(json.dumps({"ok": report["status"] == "passed", "report": str(output), **report}, sort_keys=True))


def main() -> int:
    args = __parse_args()
    started = time.monotonic()
    bundle = args.bundle or newest_bundle(args.stack_dir / "recovery_backups")
    report = __initial_report(bundle)
    output = __report_destination(args.stack_dir)
    try:
        __execute_restore_drill(args, bundle, report)
        return_code = 0
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        return_code = 2
    finally:
        __publish_report(report, output, started)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
