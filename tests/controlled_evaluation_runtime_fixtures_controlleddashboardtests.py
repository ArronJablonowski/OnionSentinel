from __future__ import annotations

from controlled_evaluation_runtime_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    BIN_DIR,
    BaseHTTPRequestHandler,
    CONTROLLED_CREDENTIAL_KEYS,
    CONTROLLED_ROUTE_FIELDS,
    DASHBOARD_SERVER,
    EVALUATION_TOKEN,
    INSTALLER_PATH,
    PIPELINE_ADAPTER_PATH,
    PRIMARY_ROUTE,
    Path,
    RELEASE_ID,
    REPLACEMENT_RELEASE_ID,
    REVIEWER_ROUTE,
    ROOT,
    RUNNER_PATH,
    SCHEDULER_PATH,
    SCORING_RULES,
    SimpleNamespace,
    ThreadingHTTPServer,
    available_port,
    closing,
    dt,
    hashlib,
    importlib,
    io,
    json,
    load_python_module,
    mock,
    os,
    process_output,
    raw_request_status,
    request_json,
    request_json_bytes,
    request_status,
    sanitized_environment,
    shutil,
    socket,
    sqlite3,
    startup_failure_diagnostic,
    stop_process,
    subprocess,
    sys,
    tempfile,
    threading,
    time,
    unittest,
    urllib,
    write_controlled_route_fixture,
)

class ControlledDashboardTestsFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-controlled-dashboard-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "home"
        self.dashboard_root = self.root / "runtime-dashboard"
        self.alert_db = (
            self.home
            / "n8n-local"
            / "alert_store_data"
            / "alerts.sqlite3"
        )
        self.alert_db.parent.mkdir(parents=True, mode=0o700)
        self.alert_db.write_bytes(b"controlled-dashboard-health-sentinel")
        self.alert_db.chmod(0o600)
        self.dashboard_root.mkdir(mode=0o700)
        (self.dashboard_root / "index.html").write_text(
            "<!doctype html><title>controlled evaluation</title>",
            encoding="utf-8",
        )
        (self.dashboard_root / "index.html").chmod(0o600)
        self.port = available_port()
        self.alert_store_health_available = True
        self.alert_store_post_count = 0
        self.alert_store_health = {
            "ok": True,
            "status": "healthy",
            "service": "onion-sentinel-alert-store",
            "controlled_evaluation": True,
            "runtime_mode": "controlled-evaluation",
            "release_id": RELEASE_ID,
            "listen_host": "127.0.0.1",
            "listen_port": 0,
            "accepting_requests": True,
        }
        fixture = self

        class FakeControlledAlertStoreHandler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *args: object) -> None:
                """Keep readiness polling out of the test output."""

            def _send_json(self, status: int, payload: dict) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header(
                    "Content-Type",
                    "application/json; charset=utf-8",
                )
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if (
                    self.path != "/health"
                    or not fixture.alert_store_health_available
                ):
                    self._send_json(503, {"ok": False})
                    return
                self._send_json(200, fixture.alert_store_health)

            def do_POST(self) -> None:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if length > 0:
                    self.rfile.read(length)
                fixture.alert_store_post_count += 1
                self._send_json(
                    503,
                    {
                        "ok": False,
                        "status": "synthetic_downstream_unavailable",
                    },
                )

        self.alert_store_server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            FakeControlledAlertStoreHandler,
        )
        self.alert_store_server.daemon_threads = True
        self.alert_store_port = int(
            self.alert_store_server.server_address[1]
        )
        self.alert_store_health["listen_port"] = self.alert_store_port
        self.alert_store_thread = threading.Thread(
            target=self.alert_store_server.serve_forever,
            name="controlled-dashboard-fake-alert-store",
            daemon=True,
        )
        self.alert_store_thread.start()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.log_file = tempfile.TemporaryFile(
            mode="w+t",
            encoding="utf-8",
        )
        environment = {
            **sanitized_environment(),
            "HOME": str(self.home),
            "ONION_SENTINEL_EVALUATION_MODE": "1",
            "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
            "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
            "SOC_ALERT_STORE_API_URL": (
                f"http://127.0.0.1:{self.alert_store_port}"
            ),
        }
        self.process = subprocess.Popen(
            [
                sys.executable,
                str(DASHBOARD_SERVER),
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--dashboard-root",
                str(self.dashboard_root),
            ],
            cwd=DASHBOARD_SERVER.parent,
            env=environment,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 10
        last_probe = "not attempted"
        while time.monotonic() < deadline:
            returncode = self.process.poll()
            if returncode is not None:
                last_probe = (
                    "child exited before readiness: "
                    f"returncode={returncode}"
                )
                break
            try:
                status, health = request_json(f"{self.base_url}/healthz")
                last_probe = (
                    f"http_status={status}; "
                    f"ok={bool(health.get('ok'))}; "
                    "dashboard_ready="
                    f"{bool(health.get('dashboard_ready'))}; "
                    "alert_store_ready="
                    f"{bool(health.get('alert_store_ready'))}"
                )
                if status == 200:
                    return
            except (OSError, urllib.error.URLError) as exc:
                last_probe = f"{type(exc).__name__}: {exc}"
                time.sleep(0.05)
        self.fail(
            "controlled dashboard did not become healthy: "
            + startup_failure_diagnostic(
                self.process,
                self.log_file,
                last_probe=last_probe,
            )
        )


    def tearDown(self) -> None:
        stop_process(self.process, graceful=False)
        self.alert_store_server.shutdown()
        self.alert_store_server.server_close()
        self.alert_store_thread.join(timeout=5)
        self.log_file.close()
        self.temporary.cleanup()


