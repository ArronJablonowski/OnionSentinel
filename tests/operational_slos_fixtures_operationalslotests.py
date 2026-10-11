from __future__ import annotations

from operational_slos_fixtures import (
    Path,
    ROOT,
    closing,
    dt,
    importlib,
    io,
    json,
    load_module,
    mock,
    shutil,
    sqlite3,
    subprocess,
    sys,
    tempfile,
    unittest,
)

class OperationalSloTestsFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.slo = load_module("operational_slos", ROOT / "n8n/bin/evaluate-operational-slos.py")
        cls.backup = load_module("runtime_backup", ROOT / "n8n/bin/backup-onion-sentinel-runtime.py")


