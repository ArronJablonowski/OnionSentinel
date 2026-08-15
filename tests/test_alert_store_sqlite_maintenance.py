from __future__ import annotations

from contextlib import closing
import gc
import os
from pathlib import Path
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n" / "bin" / "maintain-alert-store-sqlite.zsh"


SCHEMA = """
CREATE TABLE alerts (
    suppression_key TEXT,
    triage_level TEXT,
    rule_name TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    filter_status TEXT
);
CREATE TABLE alert_group_summary (
    group_key TEXT,
    filter_status TEXT
);
"""


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


@unittest.skipUnless(
    sys.platform == "darwin" and Path("/bin/zsh").is_file(),
    "Mac Studio SQLite maintenance requires macOS zsh and ACL semantics",
)
class AlertStoreSqliteMaintenancePermissionsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.stack = self.root / "stack"
        self.database_dir = self.stack / "alert_store_data"
        self.database_dir.mkdir(parents=True)
        self.database = self.database_dir / "alerts.sqlite3"
        self.backup_dir = self.stack / "alert_store_backups"
        self.log_dir = self.stack / "logs"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def environment(self, *, path: str | None = None) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "STACK_DIR": str(self.stack),
                "ALERT_STORE_DB_PATH": str(self.database),
                "ALERT_STORE_BACKUP_DIR": str(self.backup_dir),
                "ALERT_STORE_MAINTENANCE_LOG_DIR": str(self.log_dir),
                "ALERT_STORE_BACKUP_KEEP": "10",
                "ALERT_STORE_AUTO_RECOVER": "0",
            }
        )
        if path is not None:
            env["PATH"] = path
        return env

    def run_maintenance(
        self, *, path: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/zsh", str(SCRIPT)],
            env=self.environment(path=path),
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def create_valid_database(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.executescript(SCHEMA)

    def test_database_fixture_closes_its_connection(self) -> None:
        gc.collect()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            self.create_valid_database()
            gc.collect()
        unclosed = [
            warning
            for warning in caught
            if "unclosed database" in str(warning.message)
        ]
        self.assertEqual(unclosed, [])

    def assert_owner_only_regular_files(self, directory: Path) -> None:
        for child in directory.iterdir():
            if child.is_file() and not child.is_symlink():
                self.assertEqual(mode(child), 0o600, child)

    def test_successful_backup_and_retained_files_are_owner_only(self) -> None:
        self.create_valid_database()
        self.backup_dir.mkdir(mode=0o755)
        subprocess.run(
            ["chmod", "+a", "everyone allow read", str(self.backup_dir)],
            check=True,
            capture_output=True,
            text=True,
        )
        retained = self.backup_dir / "alerts.sqlite3.retained.backup"
        retained.write_bytes(b"retained")
        retained.chmod(0o644)
        subprocess.run(
            ["chmod", "+a", "everyone allow read", str(retained)],
            check=True,
            capture_output=True,
            text=True,
        )
        external = self.root / "external-evidence"
        external.write_bytes(b"external")
        external.chmod(0o644)
        (self.backup_dir / "do-not-follow.backup").symlink_to(external)

        completed = self.run_maintenance()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(mode(self.backup_dir), 0o700)
        directory_acl = subprocess.run(
            ["ls", "-lde", str(self.backup_dir)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertNotIn("everyone allow read", directory_acl)
        backups = sorted(self.backup_dir.glob("alerts.sqlite3.*.backup"))
        self.assertGreaterEqual(len(backups), 2)
        self.assert_owner_only_regular_files(self.backup_dir)
        retained_acl = subprocess.run(
            ["ls", "-lde", str(retained)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertNotIn("everyone allow read", retained_acl)
        self.assertEqual(mode(external), 0o644)

    def test_recovery_artifacts_are_owner_only(self) -> None:
        self.database.write_bytes(b"malformed database")
        self.database.chmod(0o644)
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        sqlite_executable = shutil.which("sqlite3")
        self.assertIsNotNone(sqlite_executable)
        wrapper = fake_bin / "sqlite3"
        wrapper.write_text(
            "#!/bin/sh\n"
            "last=\n"
            "for argument do last=$argument; done\n"
            "if [ \"$last\" = .recover ]; then\n"
            f"  printf '%s\\n' {shlex.quote(SCHEMA)}\n"
            "  exit 0\n"
            "fi\n"
            "if [ \"$last\" = 'PRAGMA quick_check;' ]; then\n"
            "  case \"$*\" in\n"
            "    *.recovered*) ;;\n"
            "    *) printf '%s\\n' malformed; exit 0 ;;\n"
            "  esac\n"
            "fi\n"
            f"exec {shlex.quote(sqlite_executable)} \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        runtime_path = f"{fake_bin}:{os.environ.get('PATH', '')}"

        completed = self.run_maintenance(path=runtime_path)

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(mode(self.backup_dir), 0o700)
        expected_suffixes = (".corrupt", ".recover.sql", ".recover.err", ".recovered")
        for suffix in expected_suffixes:
            matches = list(self.backup_dir.glob(f"*{suffix}"))
            self.assertEqual(
                len(matches),
                1,
                f"{suffix}: stdout={completed.stdout!r} stderr={completed.stderr!r} "
                f"files={sorted(path.name for path in self.backup_dir.iterdir())!r}",
            )
            self.assertEqual(mode(matches[0]), 0o600, matches[0])
        self.assert_owner_only_regular_files(self.backup_dir)

    def test_symlinked_backup_directory_is_rejected_without_writing(self) -> None:
        self.create_valid_database()
        external = self.root / "external"
        external.mkdir()
        self.backup_dir.symlink_to(external, target_is_directory=True)

        completed = self.run_maintenance()

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("symbolic link", completed.stdout + completed.stderr)
        state = self.log_dir / "alert-store-sqlite-maintenance-state.json"
        self.assertTrue(state.is_file())
        self.assertIn('"status": "failed"', state.read_text(encoding="utf-8"))
        self.assertEqual(list(external.iterdir()), [])

    def test_temporary_and_auto_recovery_artifacts_are_secured_in_order(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        temporary_create = source.index(
            'sqlite3 -cmd ".timeout $SQLITE_BUSY_TIMEOUT_MS" "$DB_PATH" '
            '".backup \'$backup_tmp\'"'
        )
        temporary_secure = source.index(
            'secure_regular_file "$backup_tmp"', temporary_create
        )
        temporary_check = source.index(
            'backup_check="$(quick_check "$backup_tmp")"', temporary_secure
        )
        self.assertLess(temporary_create, temporary_secure)
        self.assertLess(temporary_secure, temporary_check)

        swap = source.index(
            'mv "$DB_PATH" "$BACKUP_DIR/alerts.sqlite3.$STAMP.malformed-swapped-out"'
        )
        swap_secure = source.index(
            'secure_regular_file '
            '"$BACKUP_DIR/alerts.sqlite3.$STAMP.malformed-swapped-out"',
            swap,
        )
        live_copy = source.index('cp -p "$recovered" "$DB_PATH"', swap_secure)
        live_secure = source.index('secure_regular_file "$DB_PATH"', live_copy)
        self.assertLess(swap, swap_secure)
        self.assertLess(swap_secure, live_copy)
        self.assertLess(live_copy, live_secure)

    def test_verified_backup_is_encrypted_before_plaintext_cleanup_and_commit(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        create = source.index('"$SNAPSHOT_TOOL" create')
        plaintext_cleanup = source.index('rm -f "$backup_tmp"', create)
        commit_log = source.index('log "backup_ok path=$backup"', plaintext_cleanup)
        self.assertIn('backup="$BACKUP_DIR/alerts.sqlite3.$STAMP.backup.enc"', source)
        self.assertIn(
            'metadata="$BACKUP_DIR/alerts.sqlite3.$STAMP.backup.json"',
            source,
        )
        self.assertIn("trap 'cleanup_backup_plaintext' EXIT INT TERM", source)
        self.assertLess(create, plaintext_cleanup)
        self.assertLess(plaintext_cleanup, commit_log)
        self.assertNotIn('mv "$backup_tmp" "$backup"', source)

    def test_retention_and_stale_cleanup_manage_encrypted_snapshot_pairs(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("-name 'alerts.sqlite3.*.backup.json'", source)
        self.assertIn('encrypted="${old_metadata%.json}.enc"', source)
        self.assertIn('rm -f "$old_metadata" "$encrypted"', source)
        self.assertIn("-name 'alerts.sqlite3.*.backup.enc'", source)


if __name__ == "__main__":
    unittest.main()
