import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/send-telegram-notification.py"
SPEC = importlib.util.spec_from_file_location("telegram_notification", SCRIPT)
assert SPEC and SPEC.loader
TELEGRAM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TELEGRAM)


class TelegramNotificationTests(unittest.TestCase):
    def test_parser_ignores_unrelated_malformed_values(self):
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / ".env"
            env_path.write_text(
                "URLSCAN_API_KEY=not shell safe value\n"
                "TELEGRAM_BOT_TOKEN='token-placeholder'\n"
                'TELEGRAM_CHAT_ID="chat-placeholder"\n'
            )
            self.assertEqual(
                TELEGRAM.read_credentials(env_path),
                ("token-placeholder", "chat-placeholder"),
            )

    @mock.patch.object(TELEGRAM.time, "sleep")
    @mock.patch.object(TELEGRAM.urllib.request, "urlopen", side_effect=TimeoutError("timed out"))
    def test_timeout_retries_without_raising(self, urlopen, sleep):
        ok, detail = TELEGRAM.send_message(
            "token-placeholder",
            "chat-placeholder",
            "test",
            attempts=3,
            timeout=0.01,
        )
        self.assertFalse(ok)
        self.assertEqual(detail, "network_timeout")
        self.assertEqual(urlopen.call_count, 3)
        self.assertEqual(sleep.call_count, 2)


if __name__ == "__main__":
    unittest.main()
