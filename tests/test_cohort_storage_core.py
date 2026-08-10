from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "operations"
if str(OPERATIONS) not in sys.path:
    sys.path.insert(0, str(OPERATIONS))

import cohort_storage_core as storage


class CohortStorageCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp.name) / "alerts.sqlite3"
        self.database_path.touch()
        self.policy = storage.CohortStoragePolicy(
            error=RuntimeError,
            sha256_value=lambda value: str(value),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_connect_read_only_closes_owned_connection_when_setup_fails(self) -> None:
        connection = mock.Mock()
        connection.execute.side_effect = storage.sqlite3.OperationalError(
            "query-only setup failed"
        )
        with (
            mock.patch.object(
                storage.sqlite3,
                "connect",
                return_value=connection,
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "could not open alert database read-only",
            ),
        ):
            storage.connect_read_only(self.database_path, self.policy)

        connection.close.assert_called_once_with()

    def test_connect_read_only_returns_successful_connection_to_caller(self) -> None:
        query_only = mock.Mock()
        query_only.fetchone.return_value = (1,)
        connection = mock.Mock()
        connection.execute.side_effect = [mock.Mock(), mock.Mock(), query_only]
        with mock.patch.object(
            storage.sqlite3,
            "connect",
            return_value=connection,
        ):
            returned = storage.connect_read_only(self.database_path, self.policy)

        self.assertIs(returned, connection)
        connection.close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
