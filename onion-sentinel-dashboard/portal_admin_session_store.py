"""Administration token, password, and session persistence policy."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable
from pathlib import Path


def ensure_admin_token(
    path: Path,
    *,
    random_bytes: Callable[[int], bytes],
) -> str:
    try:
        token = path.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[a-f0-9]{64}", token):
            return token
    except Exception:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    token = random_bytes(32).hex()
    path.write_text(token, encoding="utf-8")
    try:
        path.chmod(0o600)
    except Exception:
        pass
    return token


def load_admin_password_record(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("algorithm") == "pbkdf2_sha256":
            return data
    except Exception:
        pass
    return None


def verify_admin_password(password: str, record: dict | None) -> bool:
    if not record or not password:
        return False
    try:
        iterations = int(record.get("iterations", 0))
        salt = bytes.fromhex(str(record.get("salt", "")))
        expected = bytes.fromhex(str(record.get("hash", "")))
        if iterations < 200_000 or not salt or not expected:
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def admin_session_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def load_admin_sessions(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_admin_sessions(state_dir: Path, path: Path, sessions: dict) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sessions, indent=2, sort_keys=True), encoding="utf-8")
    try:
        path.chmod(0o600)
    except Exception:
        pass


def prune_admin_sessions(
    sessions: dict,
    *,
    now_timestamp: int,
    save_sessions: Callable[[dict], None],
) -> dict:
    pruned = {
        sid_hash: meta
        for sid_hash, meta in sessions.items()
        if isinstance(meta, dict)
        and int(meta.get("expires_at", 0) or 0) > now_timestamp
    }
    if pruned != sessions:
        save_sessions(pruned)
    return pruned


def create_admin_session(
    client_ip: str,
    *,
    now_timestamp: int,
    ttl_seconds: int,
    new_session_id: Callable[[], str],
    load_pruned_sessions: Callable[[], dict],
    save_sessions: Callable[[dict], None],
) -> str:
    session_id = new_session_id()
    sessions = load_pruned_sessions()
    sessions[admin_session_hash(session_id)] = {
        "created_at": now_timestamp,
        "expires_at": now_timestamp + ttl_seconds,
        "client_ip": client_ip,
    }
    save_sessions(sessions)
    return session_id


def destroy_admin_session(
    session_id: str,
    *,
    load_sessions: Callable[[], dict],
    save_sessions: Callable[[dict], None],
) -> None:
    if not session_id:
        return
    sessions = load_sessions()
    sessions.pop(admin_session_hash(session_id), None)
    save_sessions(sessions)


def parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def admin_session_cookie_header(
    cookie_name: str,
    session_id: str,
    max_age: int,
) -> str:
    return f"{cookie_name}={session_id}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict"


def expired_admin_session_cookie_header(cookie_name: str) -> str:
    return f"{cookie_name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
