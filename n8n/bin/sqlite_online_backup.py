#!/usr/bin/env python3
"""Copy an online SQLite database with bounded busy retries and small steps."""
from __future__ import annotations

import argparse
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import time


def backup(source: Path, destination: Path, *, timeout: float = 60.0) -> None:
    """Create an owner-only snapshot; never publish a partial copy as success."""
    if not 0 < timeout <= 3600:
        raise ValueError("backup timeout must be between zero and 3600 seconds")
    if source.is_symlink() or not source.is_file():
        raise ValueError("backup source must be a regular, non-symlinked database")
    if source.resolve() == destination.resolve():
        raise ValueError("backup destination must differ from source")
    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    deadline = time.monotonic() + timeout

    def progress(status: int, remaining: int, total: int) -> None:
        if time.monotonic() >= deadline:
            raise TimeoutError("SQLite online backup exceeded its bounded deadline")

    try:
        with closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True,
                                     timeout=min(timeout, 0.25))) as reader:
            # Pin a read snapshot so concurrent WAL commits cannot restart every
            # incremental copy step. Writers remain online in WAL mode.
            reader.execute("BEGIN")
            while True:
                try:
                    reader.execute("SELECT count(*) FROM sqlite_schema").fetchone()
                    break
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                        raise
                    progress(0, 0, 0)
                    time.sleep(0.05)
            with closing(sqlite3.connect(destination, timeout=min(timeout, 0.25))) as writer:
                reader.backup(writer, pages=256, progress=progress, sleep=0.05)
        with destination.open("rb") as snapshot:
            os.fsync(snapshot.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    args = parser.parse_args()
    try:
        backup(args.source, args.destination, timeout=args.timeout_seconds)
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f"online backup failed: {type(exc).__name__}: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
