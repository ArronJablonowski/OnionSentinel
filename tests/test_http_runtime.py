import http.client
import importlib.util
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "onion-sentinel-dashboard" / "http_runtime.py"
SPEC = importlib.util.spec_from_file_location("dashboard_http_runtime", MODULE)
assert SPEC and SPEC.loader
RUNTIME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNTIME)


class BlockingHandler(BaseHTTPRequestHandler):
    entered = threading.Event()
    release = threading.Event()

    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        if self.path == "/hold":
            self.entered.set()
            self.release.wait(timeout=3)
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class BoundedHttpRuntimeTests(unittest.TestCase):
    def setUp(self):
        BlockingHandler.entered.clear()
        BlockingHandler.release.clear()
        self.server = RUNTIME.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            BlockingHandler,
            max_active_requests=1,
            request_timeout_seconds=2,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        BlockingHandler.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def test_excess_request_receives_503_without_an_unbounded_wait_queue(self):
        first_result = {}

        def first_request():
            connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
            connection.request("GET", "/hold")
            response = connection.getresponse()
            first_result["status"] = response.status
            response.read()
            connection.close()

        first = threading.Thread(target=first_request)
        first.start()
        self.assertTrue(BlockingHandler.entered.wait(timeout=2))

        second = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        second.request("GET", "/")
        response = second.getresponse()
        self.assertEqual(response.status, 503)
        self.assertEqual(response.getheader("Retry-After"), "1")
        response.read()
        second.close()

        snapshot = self.server.runtime_snapshot()
        self.assertEqual(snapshot["active_requests"], 1)
        self.assertEqual(snapshot["rejected_requests"], 1)
        BlockingHandler.release.set()
        first.join(timeout=3)
        self.assertEqual(first_result.get("status"), 200)


if __name__ == "__main__":
    unittest.main()
