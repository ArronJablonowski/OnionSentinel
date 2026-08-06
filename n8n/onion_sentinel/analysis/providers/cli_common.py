"""Shared secret-minimizing primitives for operator-approved CLI adapters."""
from __future__ import annotations

import os
from pathlib import Path


ALLOWED_ENVIRONMENT_KEYS = (
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)


def sanitized_environment(
    executable: str,
    *,
    extra: dict[str, str] | None = None,
    environ: dict[str, str] | None = None,
    user_home: Path | None = None,
) -> dict[str, str]:
    """Return a minimal environment without inheriting provider secrets."""
    source = os.environ if environ is None else environ
    home = Path.home() if user_home is None else user_home
    env = {
        key: value
        for key in ALLOWED_ENVIRONMENT_KEYS
        if (value := source.get(key))
    }
    path_parts = [
        str(Path(executable).parent),
        str(home / ".local" / "bin"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ]
    env["PATH"] = ":".join(dict.fromkeys(path_parts))
    env["NO_COLOR"] = "1"
    if extra:
        env.update(extra)
    return env


def summarize_harness_failure(label: str, stderr: str, returncode: int) -> str:
    """Classify a failure without retaining prompt-bearing output."""
    lowered = str(stderr or "").lower()
    if "context window" in lowered or "maximum context" in lowered:
        return "model context window exhausted"
    if any(
        token in lowered
        for token in ("rate limit", "usage limit", "too many requests")
    ):
        return "provider rate or usage limit reached"
    if any(
        token in lowered
        for token in (
            "authentication",
            "unauthorized",
            "login required",
            "invalid api key",
        )
    ):
        return "provider authentication failed"
    if any(
        token in lowered
        for token in (
            "model not found",
            "unknown model",
            "does not exist",
            "model unavailable",
        )
    ):
        return "configured model is unavailable or unauthorized"
    return f"{label} exited with code {returncode}"
