import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / "n8n" / "alert_store" / "test" / "http_runtime.test.js"


class AlertStoreHttpRuntimeTests(unittest.TestCase):
    def test_node_http_runtime_contract(self):
        result = subprocess.run(
            ["node", "--test", str(TEST)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
