from __future__ import annotations

from onion_sentinel_server_fixtures import (
    DASHBOARD_DIR,
    Message,
    Path,
    ROOT,
    SimpleNamespace,
    hashlib,
    identity_module,
    importlib,
    json,
    mock,
    observer_runtime_module,
    os,
    principal_module,
    server,
    subprocess,
    sys,
    tempfile,
    unittest,
)

class OnionSentinelServerTestsFixtures(unittest.TestCase):
    def _assert_isolated_enforcement_startup(self, home: Path, mode: str):
        stack = home / "n8n-local"
        config = stack / "config"
        state = stack / "admin-state"
        config.mkdir(parents=True, mode=0o700)
        state.mkdir(mode=0o700)
        os.chmod(config, 0o700)
        os.chmod(state, 0o700)
        key = config / "onion-sentinel-admin-audit-signing.key"
        key.write_text("ab" * 32 + "\n", encoding="ascii")
        os.chmod(key, 0o600)
        password = config / "onion-sentinel-admin-password.json"
        password.write_text(
            json.dumps({
                "algorithm": "pbkdf2_sha256",
                "iterations": 200_000,
                "salt": "00" * 16,
                "hash": "00" * 32,
            }),
            encoding="utf-8",
        )
        os.chmod(password, 0o600)
        command = (
            "import sys; "
            f"sys.path.insert(0, {str(DASHBOARD_DIR)!r}); "
            "import onion_sentinel_server as server; "
            "assert server.ACCESS_RUNTIME.observer.enforcing; "
            "assert server.ACCESS_RUNTIME.session_required; "
            "assert server.ACCESS_RUNTIME.password_configured()"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", command],
            env={
                "HOME": str(home),
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "ONION_SENTINEL_ACCESS_MODE": mode,
                "ONION_SENTINEL_APPLICATION_LOG": str(
                    stack / "logs/application.jsonl"
                ),
            },
            cwd=home,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
