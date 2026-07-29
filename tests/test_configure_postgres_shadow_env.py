from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/configure-postgres-shadow-env.py"


class ConfigurePostgresShadowEnvTest(unittest.TestCase):
    def test_configures_disabled_shadow_without_replacing_other_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            env_file = Path(temporary) / ".env"
            env_file.write_text("CHAT_ID=123\nALERT_STORE_POSTGRES_PORT=9999\n")
            result = subprocess.run(
                ["/usr/bin/python3", str(SCRIPT), "--env-file", str(env_file)],
                input=b"a" * 64 + b"\n",
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            content = env_file.read_text()
            self.assertIn("CHAT_ID=123", content)
            self.assertIn("ALERT_STORE_POSTGRES_SHADOW_ENABLED=0", content)
            self.assertIn("ALERT_STORE_POSTGRES_PORT=5433", content)
            self.assertIn("ALERT_STORE_POSTGRES_PASSWORD=" + "a" * 64, content)
            self.assertEqual(content.count("ALERT_STORE_POSTGRES_PORT="), 1)
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)

    def test_rejects_short_password_without_modifying_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            env_file = Path(temporary) / ".env"
            env_file.write_text("CHAT_ID=123\n")
            before = env_file.read_bytes()
            result = subprocess.run(
                ["/usr/bin/python3", str(SCRIPT), "--env-file", str(env_file)],
                input=b"short\n",
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(env_file.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
