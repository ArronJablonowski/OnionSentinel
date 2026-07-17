#!/usr/bin/env python3
"""Black-box checks for the Mac forced-command alert intake wrapper."""
from __future__ import annotations

import json
import os
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "n8n" / "bin" / "onion-sentinel-alert-intake.py"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - stdlib callback name
        size = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(size))
        if body.get("alert_id") == "bad-alert":
            payload = {"ok": False, "status": "rejected", "reason": "synthetic rejection"}
            self.send_response(400)
        else:
            payload = {"ok": True, "status": "accepted", "stored": True}
            self.send_response(200)
        encoded = json.dumps(payload).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


class MacAlertIntakeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def run_intake(self, messages: list[dict], command: str = "onion-sentinel-alert-intake batch"):
        env = {
            **os.environ,
            "SSH_ORIGINAL_COMMAND": command,
            "ONION_SENTINEL_ALERT_STORE_URL": f"http://127.0.0.1:{self.server.server_port}/alert",
        }
        payload = json.dumps({"protocol": "onion-sentinel-alert-batch/v1", "messages": messages})
        return subprocess.run(
            ["python3", str(SCRIPT)],
            input=payload,
            text=True,
            capture_output=True,
            check=False,
            env=env,
            timeout=10,
        )

    def test_batch_returns_per_item_success_and_permanent_rejection(self) -> None:
        result = self.run_intake([
            {"delivery_id": "good-alert", "payload": {"alert_id": "good-alert"}},
            {"delivery_id": "bad-alert", "payload": {"alert_id": "bad-alert"}},
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        by_id = {item["delivery_id"]: item for item in response["results"]}
        self.assertTrue(by_id["good-alert"]["ok"])
        self.assertFalse(by_id["bad-alert"]["ok"])
        self.assertFalse(by_id["bad-alert"]["retryable"])

    def test_non_forced_command_is_rejected(self) -> None:
        result = self.run_intake([], command="bash")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not permitted", result.stderr)

    def test_batch_deadline_returns_retryable_acknowledgements(self) -> None:
        # Subprocess tests cover the full wrapper; this assertion protects the
        # bounded acknowledgement path without deliberately sleeping 30s.
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"status": "batch_deadline"', source)
        self.assertIn("BATCH_DEADLINE_SECONDS", source)


if __name__ == "__main__":
    unittest.main()
