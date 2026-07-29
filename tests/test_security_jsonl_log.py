import json
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "security_jsonl_log",
    ROOT / "n8n/bin/security_jsonl_log.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SecurityJsonlLogger = MODULE.SecurityJsonlLogger


class SecurityJsonlLoggerTest(unittest.TestCase):
    def test_timestamp_redaction_and_owner_only_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            logger = SecurityJsonlLogger(path, service="test")
            logger.log(
                "error",
                "request.failed",
                run_id="run-1",
                token="do-not-log",
                message="password=also-secret failed",
            )
            record = json.loads(path.read_text())
            self.assertRegex(record["timestamp"], r"^\d{4}-\d{2}-\d{2}T")
            self.assertGreater(record["timestamp_epoch_ms"], 0)
            self.assertEqual(record["token"], "[REDACTED]")
            self.assertNotIn("do-not-log", json.dumps(record))
            self.assertNotIn("also-secret", json.dumps(record))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
