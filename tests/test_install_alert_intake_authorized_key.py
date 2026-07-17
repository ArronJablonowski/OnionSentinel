import base64
import stat
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "n8n" / "bin" / "install-alert-intake-authorized-key.py"


def public_key(label: str) -> str:
    encoded = base64.b64encode(f"synthetic-{label}".encode()).decode()
    return f"ssh-ed25519 {encoded} {label}@test\n"


def run_installer(tmp_path: Path, stdin: str) -> subprocess.CompletedProcess:
    wrapper = tmp_path / "onion-sentinel-alert-intake.py"
    wrapper.write_text("#!/usr/bin/env python3\n")
    wrapper.chmod(0o700)
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--authorized-keys",
            str(tmp_path / "authorized_keys"),
            "--wrapper",
            str(wrapper),
        ],
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
    )


def test_installer_preserves_admin_keys_and_writes_real_newlines(tmp_path: Path):
    authorized_keys = tmp_path / "authorized_keys"
    admin = public_key("admin").strip()
    authorized_keys.write_text(admin + "\n")

    result = run_installer(tmp_path, public_key("relay"))

    assert result.returncode == 0, result.stderr
    text = authorized_keys.read_text()
    assert text.endswith("\n")
    assert "\\n" not in text
    assert text.splitlines()[0] == admin
    assert len(text.splitlines()) == 2
    assert text.count("onion-sentinel-alert-intake@relay") == 1
    assert 'from="10.88.8.8"' in text
    assert "no-port-forwarding" in text
    assert stat.S_IMODE(authorized_keys.stat().st_mode) == 0o600
    assert list(tmp_path.glob("authorized_keys.pre-alert-intake.*"))


def test_installer_replaces_managed_entry_idempotently(tmp_path: Path):
    authorized_keys = tmp_path / "authorized_keys"
    authorized_keys.write_text(public_key("admin"))
    assert run_installer(tmp_path, public_key("relay-one")).returncode == 0

    result = run_installer(tmp_path, public_key("relay-two"))

    assert result.returncode == 0, result.stderr
    text = authorized_keys.read_text()
    assert len(text.splitlines()) == 2
    assert text.count("onion-sentinel-alert-intake@relay") == 1
    assert base64.b64encode(b"synthetic-relay-two").decode() in text
    assert base64.b64encode(b"synthetic-relay-one").decode() not in text


def test_installer_refuses_literal_newline_corruption(tmp_path: Path):
    authorized_keys = tmp_path / "authorized_keys"
    malformed = public_key("admin").strip() + "\\n" + public_key("relay").strip()
    authorized_keys.write_text(malformed)

    result = run_installer(tmp_path, public_key("replacement"))

    assert result.returncode != 0
    assert "literal" in result.stderr
    assert authorized_keys.read_text() == malformed


def test_installer_requires_exactly_one_public_key(tmp_path: Path):
    result = run_installer(tmp_path, public_key("one") + public_key("two"))

    assert result.returncode != 0
    assert "exactly one" in result.stderr
    assert not (tmp_path / "authorized_keys").exists()
