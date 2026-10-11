"""Production credential admission must precede any service mutation."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerCredentialPreflightTests(unittest.TestCase):
    def test_missing_inventory_refuses_before_creating_runtime_files(self):
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, STACK_DIR=directory,
                       ONION_SENTINEL_RELEASE_ID="58fac8c58d39a7c00db9edd4269d963c86d1db6c",
                       ONION_SENTINEL_VALIDATE_ONLY="0")
            result = subprocess.run(
                ["zsh", str(ROOT / "n8n/bin/install-macstudio-stack.zsh")],
                env=env, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 78, result.stderr)
            self.assertIn("before service changes", result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
