#!/usr/bin/env python3
"""Persistent LAN report portal for Arron's local HTML reports/projects."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import html
import json
import mimetypes
import os
import re
import shutil
import secrets
import shlex
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

HOME = Path.home()
DEFAULT_PORT = 8765
DEFAULT_HOST = "0.0.0.0"
EXCLUDE_DIR_NAMES = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "Library", "Applications", "Music", "Movies", "Pictures", "Public", ".Trash",
    "backups", "backup", "templates",
}
SCAN_ROOTS = [
    # LaunchAgent-safe source: mirrored by ~/.hermes/scripts/sync_report_portal.py.
    # This avoids macOS privacy/TCC edge cases where launchd services can see a Documents
    # directory but not enumerate files inside it.
    HOME / "report_portal" / "library",
]
LAST_UPDATED_FILE = HOME / "report_portal" / ".last_updated"
MACOS_UPDATE_STATUS_FILE = HOME / "report_portal" / ".macos_update_status.json"
SOC_ALERT_STATUS_FILE = HOME / "report_portal" / ".soc_alert_status.json"
SOC_ALERT_STORE_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
SOC_ALERT_DASHBOARD_DIR = HOME / "report_portal" / "library" / "Cybersecurity" / "SOC Alerts"
SOC_ALERT_DETAIL_DIR = SOC_ALERT_DASHBOARD_DIR / "details"
SOC_ALERT_STATIC_STATUS_FILE = SOC_ALERT_DASHBOARD_DIR / "soc-alerts-status.json"
SOC_ALERT_N8N_BEACON_FILE = SOC_ALERT_DASHBOARD_DIR / "n8n-beacon.json"
SOC_ANALYST_PROMPT_FILE = HOME / "n8n-local" / "config" / "soc_analyst_system_prompt.md"
SIEM_ENGINEER_PROMPT_FILE = HOME / "n8n-local" / "config" / "siem_engineer_system_prompt.md"
SOC_AI_SETTINGS_FILE = HOME / "n8n-local" / "config" / "ai_model_settings.json"
SOC_ANALYST_PROMPT_MAX_BYTES = 20000
SOC_ALERT_API_MAX_LIMIT = 500
SOC_ALERT_LEVEL_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
    "unknown": 0,
}
HERMES_DR_BACKUP_DIR = HOME / "Hermes_DR_Backups"
HERMES_DR_REMOTE_DEST = "aj_lab@10.77.7.222"
HERMES_DR_REMOTE_DIR = "/Users/aj_lab/Hermes_DR_Backups"
CRON_JOBS_FILE = HOME / ".hermes" / "cron" / "jobs.json"
CRON_OUTPUT_DIR = HOME / ".hermes" / "cron" / "output"
RESOURCE_LIBRARY_SOURCES = [
    ("Books", HOME / "Documents" / "Books"),
    ("Talks", HOME / "Documents" / "Talks"),
    ("Posters", HOME / "Documents" / "CheatSheets" / "SANS_Posters"),
    ("CheatSheets", HOME / "Documents" / "CheatSheets"),
    ("LinkedIn", HOME / "Documents" / "LinkedIn"),
    ("Tools", HOME / "Documents" / "Tools"),
    ("Certificates", HOME / "Documents" / "Certs"),
]
RESOURCE_LIBRARY_REMOVAL_DIR = HOME / "Documents" / "removal"
RESOURCE_LIBRARY_BUILDER = HOME / ".hermes" / "scripts" / "build_pdf_library_dashboard.py"
RESOURCE_LIBRARY_SYNC = HOME / ".hermes" / "scripts" / "sync_report_portal.py"
RESOURCE_LIBRARY_MUTATION_WORKER = HOME / ".hermes" / "scripts" / "process_resource_library_removals.py"
RESOURCE_LIBRARY_REMOVAL_QUEUE = HOME / "report_portal" / ".resource_removal_queue" / "requests.jsonl"
RESOURCE_LIBRARY_METADATA_FILE = HOME / "report_portal" / "resource_library_metadata.json"
RESOURCE_LIBRARY_ACTION_STATUS_DIR = HOME / "report_portal" / ".resource_removal_queue" / "status"
RESOURCE_LIBRARY_MUTATION_CRON_ID = "a246853c325f"
ADMIN_STATE_DIR = HOME / "report_portal" / ".admin_actions"
ADMIN_TOKEN_FILE = HOME / "report_portal" / ".admin_token"
ADMIN_PASSWORD_FILE = HOME / "report_portal" / ".admin_password.json"
ADMIN_SESSIONS_FILE = ADMIN_STATE_DIR / ".admin_sessions.json"
ADMIN_SESSION_COOKIE = "lan_portal_admin"
ADMIN_SESSION_TTL_SECONDS = 8 * 60 * 60
ADMIN_LOCK_FILE = ADMIN_STATE_DIR / ".admin_action.lock"
N8N_CONTAINER_NAME = "n8n"
N8N_HEALTH_URL = "http://127.0.0.1:5678/healthz"
ADMIN_COMMAND_ENV = {
    **os.environ,
    "PATH": f"/opt/homebrew/bin:{HOME / '.hermes' / 'hermes-agent' / 'venv' / 'bin'}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    "HOMEBREW_NO_AUTO_UPDATE": "0",
}
HERMES_BIN = str(HOME / ".hermes" / "hermes-agent" / "venv" / "bin" / "hermes")
CODEX_CLI_BIN = str(HOME / ".local" / "bin" / "codex")
ADMIN_ACTIONS = {
    "hermes-update": {
        "label": "Hermes Agent update",
        "summary": "Runs hermes update from the installed Hermes CLI.",
        "command": [HERMES_BIN, "update"],
        "accent": "#23d3ee",
    },
    "brew-update": {
        "label": "Homebrew update + upgrade",
        "summary": "Runs brew update, then brew upgrade for installed formulae/casks.",
        "command": ["/bin/bash", "-lc", "/opt/homebrew/bin/brew update && /opt/homebrew/bin/brew upgrade"],
        "accent": "#f8c76a",
    },
    "macos-update": {
        "label": "macOS software updates",
        "summary": "Runs softwareupdate --install --all --agree-to-license. Some macOS updates may still require admin authorization or a restart.",
        "command": ["/usr/sbin/softwareupdate", "--install", "--all", "--agree-to-license"],
        "accent": "#a78bfa",
    },
    "reboot": {
        "label": "Reboot system",
        "summary": "Reboots the Mac with passwordless sudo after typed confirmation. Requires the LAN Portal sudoers drop-in that allows only the exact reboot command.",
        "command": [
            "/usr/bin/sudo",
            "-n",
            "/sbin/shutdown",
            "-r",
            "now",
        ],
        "accent": "#ff7a90",
        "requires_confirmation": "REBOOT",
    },
}
STANDALONE_HTML: list[Path] = []
ISO_DATE_TIME_SEPARATOR_RE = re.compile(r"(\d{4}-\d{2}-\d{2})(?:T|\s+)(?=\d{2}:\d{2}:\d{2})")

@dataclass(frozen=True)
class Report:
    rid: str
    title: str
    path: Path
    rel: str
    category: str
    size: int
    mtime: float
    is_index: bool


@dataclass(frozen=True)
class CronJobSummary:
    jid: str
    name: str
    schedule: str
    next_run: str
    enabled: bool
    state: str
    last_status: str
    sort_key: str


def format_iso_timestamp(value: dt.datetime, *, timespec: str = "seconds", utc_z: bool = False) -> str:
    """Render project timestamps as ISO 8601 with the T separator replaced by two spaces."""
    if value.tzinfo is None:
        value = value.astimezone()
    if utc_z:
        value = value.astimezone(dt.timezone.utc)
    rendered = value.isoformat(timespec=timespec).replace("T", "  ")
    return rendered.replace("+00:00", "Z") if utc_z else rendered


def now_iso_local() -> str:
    return format_iso_timestamp(dt.datetime.now().astimezone())


def now_iso_utc() -> str:
    return format_iso_timestamp(dt.datetime.now(dt.timezone.utc), utc_z=True)


def parse_iso_timestamp(value: object) -> dt.datetime:
    """Parse current and historical ISO timestamp separators."""
    cleaned = str(value).strip()
    cleaned = ISO_DATE_TIME_SEPARATOR_RE.sub(r"\1T", cleaned).replace("Z", "+00:00")
    return dt.datetime.fromisoformat(cleaned)


def format_timestamp_text(value: object, *, fallback: str = "unknown time") -> str:
    if not value:
        return fallback
    try:
        parsed = value if isinstance(value, dt.datetime) else parse_iso_timestamp(value)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return format_iso_timestamp(parsed.astimezone())
    except Exception:
        text = str(value).strip()
        return ISO_DATE_TIME_SEPARATOR_RE.sub(r"\1  ", text) if text else fallback


def ensure_admin_token() -> str:
    """Return a persistent CSRF token for admin POST actions."""
    try:
        token = ADMIN_TOKEN_FILE.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[a-f0-9]{64}", token):
            return token
    except Exception:
        pass
    ADMIN_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    token = os.urandom(32).hex()
    ADMIN_TOKEN_FILE.write_text(token, encoding="utf-8")
    try:
        ADMIN_TOKEN_FILE.chmod(0o600)
    except Exception:
        pass
    return token


def load_admin_password_record() -> dict | None:
    """Load the local admin password hash record, if configured."""
    try:
        data = json.loads(ADMIN_PASSWORD_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("algorithm") == "pbkdf2_sha256":
            return data
    except Exception:
        pass
    return None


def admin_password_configured() -> bool:
    return load_admin_password_record() is not None


def verify_admin_password(password: str) -> bool:
    record = load_admin_password_record()
    if not record or not password:
        return False
    try:
        iterations = int(record.get("iterations", 0))
        salt = bytes.fromhex(str(record.get("salt", "")))
        expected = bytes.fromhex(str(record.get("hash", "")))
        if iterations < 200_000 or not salt or not expected:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def admin_session_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def load_admin_sessions() -> dict:
    try:
        data = json.loads(ADMIN_SESSIONS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_admin_sessions(sessions: dict) -> None:
    ADMIN_STATE_DIR.mkdir(parents=True, exist_ok=True)
    ADMIN_SESSIONS_FILE.write_text(json.dumps(sessions, indent=2, sort_keys=True), encoding="utf-8")
    try:
        ADMIN_SESSIONS_FILE.chmod(0o600)
    except Exception:
        pass


def prune_admin_sessions(sessions: dict | None = None) -> dict:
    sessions = load_admin_sessions() if sessions is None else sessions
    now_ts = int(dt.datetime.now().timestamp())
    pruned = {
        sid_hash: meta
        for sid_hash, meta in sessions.items()
        if isinstance(meta, dict) and int(meta.get("expires_at", 0) or 0) > now_ts
    }
    if pruned != sessions:
        save_admin_sessions(pruned)
    return pruned


def create_admin_session(client_ip: str) -> str:
    now_ts = int(dt.datetime.now().timestamp())
    session_id = secrets.token_urlsafe(32)
    sessions = prune_admin_sessions()
    sessions[admin_session_hash(session_id)] = {
        "created_at": now_ts,
        "expires_at": now_ts + ADMIN_SESSION_TTL_SECONDS,
        "client_ip": client_ip,
    }
    save_admin_sessions(sessions)
    return session_id


def destroy_admin_session(session_id: str) -> None:
    if not session_id:
        return
    sessions = load_admin_sessions()
    sessions.pop(admin_session_hash(session_id), None)
    save_admin_sessions(sessions)


def resource_library_id_for(path: Path) -> str:
    return hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:12]


def find_resource_library_pdf(resource_id: str, source_path: str = "") -> tuple[Path, str, Path] | None:
    if not re.fullmatch(r"[a-f0-9]{12}", resource_id or ""):
        return None

    # Preferred path: the static Resource Library card posts its exact source path.
    # This avoids macOS launchd/TCC cases where the portal process can access a
    # specific file path but cannot enumerate ~/Documents recursively.
    if source_path:
        try:
            candidate = Path(source_path).expanduser().resolve()
        except Exception:
            candidate = None
        if candidate and candidate.suffix.lower() == ".pdf" and candidate.name and not candidate.name.startswith("._"):
            for category, root in RESOURCE_LIBRARY_SOURCES:
                try:
                    rel = candidate.relative_to(root.resolve())
                except ValueError:
                    continue
                if resource_library_id_for(candidate) == resource_id and candidate.is_file():
                    return candidate, category, rel

    # Fallback for interactive/local runs where recursive Documents access works.
    for category, root in RESOURCE_LIBRARY_SOURCES:
        if not root.exists():
            continue
        for src in root.rglob("*.pdf"):
            if any(part == "__MACOSX" for part in src.parts) or src.name.startswith("._") or not src.is_file():
                continue
            rel = src.relative_to(root)
            if category == "CheatSheets" and rel.parts and rel.parts[0] == "SANS_Posters":
                continue
            if resource_library_id_for(src) == resource_id:
                return src, category, rel
    return None


def unique_destination(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for i in range(1, 1000):
        candidate = path.with_name(f"{stem} ({i}){suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not find unique removal destination for {path.name}")


def refresh_resource_library() -> None:
    env = {**os.environ, "PATH": ADMIN_COMMAND_ENV.get("PATH", os.environ.get("PATH", ""))}
    subprocess.run([sys.executable, str(RESOURCE_LIBRARY_BUILDER)], check=True, timeout=180, env=env, capture_output=True, text=True)
    subprocess.run([sys.executable, str(RESOURCE_LIBRARY_SYNC)], check=True, timeout=180, env=env, capture_output=True, text=True)


def load_resource_library_metadata() -> dict:
    try:
        data = json.loads(RESOURCE_LIBRARY_METADATA_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_resource_library_metadata(data: dict) -> None:
    RESOURCE_LIBRARY_METADATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = RESOURCE_LIBRARY_METADATA_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(RESOURCE_LIBRARY_METADATA_FILE)


def clean_resource_tags(values) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    if isinstance(values, str):
        values = re.split(r"[,;\n]+", values)
    if not isinstance(values, list):
        return []
    for value in values:
        tag = re.sub(r"\s+", " ", str(value)).strip()[:40]
        if not tag:
            continue
        key = tag.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(tag)
    return out[:12]


def sanitize_resource_filename(name: str, original_suffix: str) -> str:
    """Return a safe basename while preserving the source file extension.

    Users rename the visible title in the web UI; the actual file on disk must
    keep its original extension. If they type another extension, strip it and
    restore the original suffix instead of producing names like `.txt.pdf`.
    """
    suffix = original_suffix if original_suffix.startswith(".") else f".{original_suffix}"
    suffix = suffix or ".pdf"
    cleaned = re.sub(r"[/:\\]+", "-", name).strip().strip(".")
    cleaned = re.sub(r"\s+", " ", cleaned)[:120].strip()
    if not cleaned:
        raise ValueError("New filename is empty")
    if Path(cleaned).suffix:
        cleaned = cleaned[: -len(Path(cleaned).suffix)].rstrip(" .")
    if not cleaned:
        raise ValueError("New filename is empty")
    cleaned = f"{cleaned}{suffix}"
    if cleaned.startswith("._") or cleaned in {".", ".."}:
        raise ValueError("Invalid filename")
    return cleaned


def queue_resource_action(record: dict) -> dict:
    RESOURCE_LIBRARY_REMOVAL_QUEUE.parent.mkdir(parents=True, exist_ok=True)
    action_id = str(record.get("action_id") or uuid.uuid4())
    payload = {**record, "action_id": action_id, "queued_at": now_iso_local()}
    with RESOURCE_LIBRARY_REMOVAL_QUEUE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True) + "\n")
    return {"ok": True, "queued": True, "action_id": action_id, "message": "Resource Library action queued for the Hermes worker."}


def trigger_resource_library_worker() -> None:
    hermes = HOME / ".hermes" / "hermes-agent" / "venv" / "bin" / "hermes"
    cmd = [str(hermes if hermes.exists() else "hermes"), "cron", "run", RESOURCE_LIBRARY_MUTATION_CRON_ID]
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        pass


def resource_favorites() -> list[str]:
    data = load_resource_library_metadata()
    favs = data.get("_favorites", [])
    if not isinstance(favs, list):
        return []
    return sorted({str(x) for x in favs if re.fullmatch(r"[a-f0-9]{12}", str(x))})


def set_resource_favorite(resource_id: str, favorite: bool) -> tuple[bool, dict]:
    if not re.fullmatch(r"[a-f0-9]{12}", resource_id or ""):
        return False, {"ok": False, "error": "Invalid resource id"}
    data = load_resource_library_metadata()
    favs = set(resource_favorites())
    if favorite:
        favs.add(resource_id)
    else:
        favs.discard(resource_id)
    data["_favorites"] = sorted(favs)
    save_resource_library_metadata(data)
    queue_resource_action({"action": "refresh", "reason": "favorite", "id": resource_id})
    trigger_resource_library_worker()
    return True, {"ok": True, "favorite": favorite, "favorites": sorted(favs)}


def set_resource_tags(resource_id: str, tags) -> tuple[bool, dict]:
    if not re.fullmatch(r"[a-f0-9]{12}", resource_id or ""):
        return False, {"ok": False, "error": "Invalid resource id"}
    cleaned = clean_resource_tags(tags)
    data = load_resource_library_metadata()
    entry = data.get(resource_id, {}) if isinstance(data.get(resource_id, {}), dict) else {}
    entry["custom_tags"] = cleaned
    data[resource_id] = entry
    save_resource_library_metadata(data)
    queue_resource_action({"action": "refresh", "reason": "tags", "id": resource_id})
    trigger_resource_library_worker()
    return True, {"ok": True, "tags": cleaned, "queued": True}


def rename_resource_file(resource_id: str, source_path: str, new_name: str) -> tuple[bool, dict]:
    found = find_resource_library_pdf(resource_id, source_path)
    if not found:
        return False, {"ok": False, "error": "Resource not found"}
    src, _category, _rel = found
    try:
        safe_name = sanitize_resource_filename(new_name, src.suffix)
    except ValueError as exc:
        return False, {"ok": False, "error": str(exc)}
    dest = src.with_name(safe_name)
    if dest.resolve() == src.resolve():
        return False, {"ok": False, "error": f"Rename aborted: the file is already named '{dest.name}'. No files were changed."}
    if dest.exists():
        return False, {"ok": False, "error": f"Rename aborted: a file named '{dest.name}' already exists. No files were changed."}
    display_title = re.sub(r"[_-]+", " ", dest.stem).strip() or dest.stem
    try:
        shutil.move(str(src), str(dest))
    except PermissionError as exc:
        data = queue_resource_action({"action": "rename", "id": resource_id, "source": str(src), "new_name": safe_name, "portal_error": str(exc)})
        trigger_resource_library_worker()
        data.update({"display_title": display_title, "source": str(src), "target_source": str(dest), "refresh_after_ms": 65000})
        return True, data
    except Exception as exc:
        return False, {"ok": False, "error": f"Rename failed: {exc}"}
    # Preserve metadata across the source-path-derived ID change.
    data = load_resource_library_metadata()
    old_entry = data.pop(resource_id, None)
    new_id = resource_library_id_for(dest)
    if isinstance(old_entry, dict):
        data[new_id] = old_entry
    favs = data.get("_favorites", [])
    if isinstance(favs, list) and resource_id in favs:
        data["_favorites"] = sorted({new_id if x == resource_id else str(x) for x in favs})
    save_resource_library_metadata(data)
    try:
        refresh_resource_library()
    except Exception as exc:
        return True, {"ok": True, "warning": f"Renamed file on disk, but Resource Library refresh failed: {exc}", "new_id": new_id, "source": str(dest), "display_title": display_title, "renamed_on_disk": True}
    return True, {"ok": True, "new_id": new_id, "source": str(dest), "display_title": display_title, "renamed_on_disk": True, "refresh_after_ms": 1200}


def queue_resource_removal(resource_id: str, source_path: str, error: str) -> dict:
    data = queue_resource_action({"action": "remove", "id": resource_id, "source": source_path, "portal_error": error})
    trigger_resource_library_worker()
    data.update({"message": "Removal queued for the Hermes Resource Library worker.", "source": source_path})
    return data


def move_resource_to_removal(resource_id: str, source_path: str = "") -> tuple[bool, dict]:
    found = find_resource_library_pdf(resource_id, source_path)
    if not found:
        return False, {"ok": False, "error": "Resource not found"}
    src, category, rel = found
    dest = unique_destination(RESOURCE_LIBRARY_REMOVAL_DIR / category / rel)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.move(str(src), str(dest))
    except PermissionError as exc:
        return True, queue_resource_removal(resource_id, str(src), str(exc))
    except Exception as exc:
        return False, {"ok": False, "error": f"Move failed: {exc}"}
    try:
        refresh_resource_library()
    except Exception as exc:
        return True, {
            "ok": True,
            "warning": f"Moved file, but Resource Library refresh failed: {exc}",
            "moved_to": str(dest),
            "title": src.name,
        }
    return True, {"ok": True, "moved_to": str(dest), "title": src.name}


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


def admin_session_cookie_header(session_id: str, max_age: int | None = None) -> str:
    max_age = ADMIN_SESSION_TTL_SECONDS if max_age is None else max_age
    return f"{ADMIN_SESSION_COOKIE}={session_id}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict"


def expired_admin_session_cookie_header() -> str:
    return f"{ADMIN_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"


def read_soc_analyst_prompt() -> dict:
    """Return the current SOC Analyst system prompt shown on the Settings page."""
    try:
        prompt = SOC_ANALYST_PROMPT_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        prompt = ""
    except Exception as exc:
        return {"ok": False, "error": f"Could not read SOC Analyst prompt: {exc}", "path": str(SOC_ANALYST_PROMPT_FILE)}
    return {"ok": True, "prompt": prompt, "path": str(SOC_ANALYST_PROMPT_FILE)}


def read_siem_engineer_prompt() -> dict:
    """Return the current SIEM Engineer system prompt shown on the Settings page."""
    try:
        prompt = SIEM_ENGINEER_PROMPT_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        prompt = ""
    except Exception as exc:
        return {"ok": False, "error": f"Could not read SIEM Engineer prompt: {exc}", "path": str(SIEM_ENGINEER_PROMPT_FILE)}
    return {"ok": True, "prompt": prompt, "path": str(SIEM_ENGINEER_PROMPT_FILE)}


def save_prompt_file(prompt: object, path: Path, label: str) -> tuple[bool, dict]:
    """Atomically save an editable SOC settings prompt."""
    normalized = str(prompt or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized:
        return False, {"ok": False, "error": f"{label} prompt cannot be empty.", "path": str(path)}
    if len(normalized.encode("utf-8")) > SOC_ANALYST_PROMPT_MAX_BYTES:
        return False, {"ok": False, "error": f"{label} prompt exceeds {SOC_ANALYST_PROMPT_MAX_BYTES} bytes.", "path": str(path)}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(normalized + "\n", encoding="utf-8")
        try:
            tmp.chmod(0o600)
        except Exception:
            pass
        tmp.replace(path)
    except Exception as exc:
        return False, {"ok": False, "error": f"Could not save {label} prompt: {exc}", "path": str(path)}
    return True, {"ok": True, "message": f"{label} prompt saved.", "path": str(path), "bytes": len((normalized + "\n").encode("utf-8"))}


def save_soc_analyst_prompt(prompt: object) -> tuple[bool, dict]:
    """Atomically save the editable SOC Analyst system prompt."""
    return save_prompt_file(prompt, SOC_ANALYST_PROMPT_FILE, "SOC Analyst")


def save_siem_engineer_prompt(prompt: object) -> tuple[bool, dict]:
    """Atomically save the editable SIEM Engineer system prompt."""
    return save_prompt_file(prompt, SIEM_ENGINEER_PROMPT_FILE, "SIEM Engineer")


def default_soc_ai_settings() -> dict:
    """Return safe AI analysis routing defaults for the Settings page and runner."""
    return {
        "mode": "ollama",
        "ollama_model": os.environ.get("SOC_AI_MODEL") or "devstral:latest",
        "ollama_url": os.environ.get("OLLAMA_URL") or "http://127.0.0.1:11434",
        "cloud_provider": "gpt-cli",
        "cloud_model": "",
        "cloud_command": "",
        "hybrid_policy": "cloud_for_critical_high_or_recommended",
    }


def normalize_soc_ai_settings(payload: dict | None) -> tuple[bool, dict]:
    """Validate and normalize editable SOC AI model routing settings."""
    payload = payload if isinstance(payload, dict) else {}
    settings = default_soc_ai_settings()
    for key in settings:
        if key in payload:
            settings[key] = str(payload.get(key) or "").strip()
    if settings["mode"] not in {"ollama", "cloud", "hybrid"}:
        return False, {"ok": False, "error": "Mode must be ollama, cloud, or hybrid."}
    if settings["hybrid_policy"] not in {"cloud_for_critical_high_or_recommended", "cloud_when_recommended_only"}:
        return False, {"ok": False, "error": "Hybrid policy is invalid."}
    if not settings["ollama_model"]:
        return False, {"ok": False, "error": "Ollama model cannot be empty."}
    if not settings["ollama_url"].startswith(("http://", "https://")):
        return False, {"ok": False, "error": "Ollama URL must start with http:// or https://."}
    if settings["mode"] in {"cloud", "hybrid"} and not settings["cloud_command"]:
        return False, {"ok": False, "error": "Cloud or hybrid mode requires a cloud CLI command."}
    for key in ("ollama_model", "ollama_url", "cloud_provider", "cloud_model", "cloud_command"):
        settings[key] = settings[key][:240]
    return True, settings


def read_soc_ai_settings() -> dict:
    """Return the current SOC AI model-routing settings."""
    try:
        raw = json.loads(SOC_AI_SETTINGS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raw = {}
    except Exception as exc:
        return {"ok": False, "error": f"Could not read SOC AI settings: {exc}", "path": str(SOC_AI_SETTINGS_FILE)}
    ok, normalized = normalize_soc_ai_settings(raw)
    if not ok:
        normalized = default_soc_ai_settings()
    return {"ok": True, "settings": normalized, "path": str(SOC_AI_SETTINGS_FILE)}


def list_ollama_models() -> list[str]:
    """Return locally installed Ollama model names from `ollama ls`."""
    commands = [
        ["/opt/homebrew/bin/ollama", "ls"],
        ["/usr/local/bin/ollama", "ls"],
        ["ollama", "ls"],
    ]
    output = ""
    for command in commands:
        try:
            proc = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                env=ADMIN_COMMAND_ENV,
            )
        except Exception:
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            output = proc.stdout
            break
    models: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("name"):
            continue
        name = stripped.split()[0].strip()
        if name and name not in models:
            models.append(name)
    return models


def ollama_models_response() -> dict:
    settings = read_soc_ai_settings().get("settings") or default_soc_ai_settings()
    models = list_ollama_models()
    current = str(settings.get("ollama_model") or "").strip()
    if current and current not in models:
        models.insert(0, current)
    return {
        "ok": True,
        "models": models,
        "selected": current,
        "command": "ollama ls",
    }


def save_soc_ai_settings(payload: object) -> tuple[bool, dict]:
    """Atomically save SOC AI model-routing settings."""
    ok, normalized = normalize_soc_ai_settings(payload if isinstance(payload, dict) else {})
    if not ok:
        return False, normalized
    try:
        SOC_AI_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = SOC_AI_SETTINGS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            tmp.chmod(0o600)
        except Exception:
            pass
        tmp.replace(SOC_AI_SETTINGS_FILE)
    except Exception as exc:
        return False, {"ok": False, "error": f"Could not save SOC AI settings: {exc}", "path": str(SOC_AI_SETTINGS_FILE)}
    return True, {"ok": True, "message": "SOC AI model settings saved.", "settings": normalized, "path": str(SOC_AI_SETTINGS_FILE)}


def admin_status_path(action_id: str) -> Path:
    return ADMIN_STATE_DIR / f"{action_id}.json"


def admin_log_path(action_id: str) -> Path:
    return ADMIN_STATE_DIR / f"{action_id}.log"


def process_is_running(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_admin_action_status(action_id: str) -> dict:
    action = ADMIN_ACTIONS.get(action_id, {})
    current_command = " ".join(str(part) for part in action.get("command", []))
    status = {
        "id": action_id,
        "label": action.get("label", action_id),
        "summary": action.get("summary", ""),
        "command": current_command,
        "started_at": None,
        "pid": None,
        "state": "idle",
        "returncode": None,
        "message": "Not run yet.",
        "updated_at": None,
    }
    path = admin_status_path(action_id)
    loaded_has_command = False
    try:
        if path.exists():
            loaded_status = json.loads(path.read_text(encoding="utf-8"))
            loaded_has_command = "command" in loaded_status
            status.update(loaded_status)
    except Exception as exc:
        status.update({"state": "error", "message": f"Could not read status: {exc}"})
    if action_id == "reboot" and status.get("started_at") and ((not loaded_has_command) or status.get("command") != current_command):
        status.update({
            "command": current_command,
            "message": "Last reboot run was recorded before the current reboot command path changed; the timestamp is retained for audit history.",
        })
    if status.get("state") == "running" and not process_is_running(status.get("pid")):
        status["state"] = "unknown"
        status["message"] = "Process is no longer visible; check the log for completion details."
    return status


def write_admin_action_status(action_id: str, status: dict) -> None:
    ADMIN_STATE_DIR.mkdir(parents=True, exist_ok=True)
    status["updated_at"] = now_iso_local()
    admin_status_path(action_id).write_text(json.dumps(status, indent=2), encoding="utf-8")


def _parse_admin_status_time(value: object) -> dt.datetime | None:
    if not value:
        return None
    try:
        return parse_iso_timestamp(value)
    except Exception:
        return None


def latest_admin_action_outcome() -> dict | None:
    """Return the newest non-running admin action outcome for status banner rendering."""
    newest: dict | None = None
    newest_time: dt.datetime | None = None
    for action_id, action in ADMIN_ACTIONS.items():
        status = read_admin_action_status(action_id)
        state = str(status.get("state") or "idle")
        if state in {"idle", "running"}:
            continue
        when = (
            _parse_admin_status_time(status.get("finished_at"))
            or _parse_admin_status_time(status.get("updated_at"))
            or _parse_admin_status_time(status.get("started_at"))
        )
        if not when:
            continue
        if newest_time is None or when > newest_time:
            newest_time = when
            newest = {
                "id": action_id,
                "label": status.get("label") or action.get("label", action_id),
                "state": state,
                "returncode": status.get("returncode"),
                "message": status.get("message") or "No completion message recorded.",
                "when": format_iso_timestamp(when),
            }
    return newest


def read_admin_lock() -> dict | None:
    try:
        return json.loads(ADMIN_LOCK_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def running_admin_action() -> dict | None:
    """Return the currently running admin action, clearing stale locks when safe."""
    lock = read_admin_lock()
    if lock:
        pid = lock.get("pid")
        if process_is_running(pid):
            return lock
        try:
            ADMIN_LOCK_FILE.unlink()
        except FileNotFoundError:
            pass
        except Exception:
            return lock
    for action_id in ADMIN_ACTIONS:
        status = read_admin_action_status(action_id)
        if status.get("state") == "running" and process_is_running(status.get("pid")):
            return {
                "id": action_id,
                "label": status.get("label") or ADMIN_ACTIONS[action_id]["label"],
                "pid": status.get("pid"),
                "started_at": status.get("started_at"),
            }
    return None


def claim_admin_action_lock(action_id: str, label: str, started_at: str) -> tuple[bool, str]:
    """Atomically claim the singleton admin-action lock."""
    ADMIN_STATE_DIR.mkdir(parents=True, exist_ok=True)
    running = running_admin_action()
    if running:
        return False, f"{running.get('label', 'Another admin action')} is still running as PID {running.get('pid', 'unknown')}. Wait for it to complete before starting another update or reboot."
    payload = {"id": action_id, "label": label, "pid": None, "started_at": started_at}
    try:
        fd = os.open(str(ADMIN_LOCK_FILE), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        return True, "Lock acquired."
    except FileExistsError:
        running = running_admin_action()
        if running:
            return False, f"{running.get('label', 'Another admin action')} is still running as PID {running.get('pid', 'unknown')}. Wait for it to complete before starting another update or reboot."
        return claim_admin_action_lock(action_id, label, started_at)
    except Exception as exc:
        return False, f"Could not acquire admin action lock: {exc}"


def update_admin_action_lock_pid(action_id: str, pid: int) -> None:
    lock = read_admin_lock() or {}
    if lock.get("id") == action_id:
        lock["pid"] = pid
        ADMIN_LOCK_FILE.write_text(json.dumps(lock, indent=2), encoding="utf-8")


def release_admin_action_lock(action_id: str) -> None:
    lock = read_admin_lock() or {}
    if not lock or lock.get("id") == action_id:
        try:
            ADMIN_LOCK_FILE.unlink()
        except FileNotFoundError:
            pass


def start_admin_action(action_id: str, confirmation: str = "") -> tuple[bool, str]:
    action = ADMIN_ACTIONS.get(action_id)
    if not action:
        return False, "Unknown admin action."
    required = action.get("requires_confirmation")
    if required and confirmation != required:
        return False, f"Confirmation failed. Type {required!r} to run this action."
    running = running_admin_action()
    if running:
        return False, f"{running.get('label', 'Another admin action')} is still running as PID {running.get('pid', 'unknown')}. Wait for it to complete before starting another update or reboot."
    current = read_admin_action_status(action_id)
    if current.get("state") == "running" and process_is_running(current.get("pid")):
        return False, f"{action['label']} is already running."
    available, availability_message = check_admin_action_available(action_id)
    if not available:
        return False, availability_message
    ADMIN_STATE_DIR.mkdir(parents=True, exist_ok=True)
    log_path = admin_log_path(action_id)
    started_at = now_iso_local()
    lock_ok, lock_message = claim_admin_action_lock(action_id, str(action["label"]), started_at)
    if not lock_ok:
        return False, lock_message
    command = [str(part) for part in action["command"]]
    with log_path.open("ab") as log:
        log.write(f"\n===== {started_at} START {action['label']} =====\n".encode("utf-8"))
        log.write(("Command: " + " ".join(command) + "\n").encode("utf-8"))
        log.flush()
    initial_status = {
        "id": action_id,
        "label": action["label"],
        "summary": action.get("summary", ""),
        "command": " ".join(command),
        "started_at": started_at,
        "pid": None,
        "state": "running",
        "returncode": None,
        "message": f"Starting {action['label']}.",
    }
    write_admin_action_status(action_id, initial_status)
    status_path = admin_status_path(action_id)
    lock_path = ADMIN_LOCK_FILE
    finish_py = (
        "import datetime,json,pathlib,subprocess,sys; "
        f"p=pathlib.Path({str(status_path)!r}); "
        f"lp=pathlib.Path({str(lock_path)!r}); "
        f"aid={action_id!r}; "
        "d=json.loads(p.read_text()); "
        "rc=int(sys.argv[1]); "
        "label=d.get('label') or aid; "
        "d.update({'state':'ok' if rc == 0 else 'failed', 'returncode':rc, "
        "'message':(f'{label} completed successfully.' if rc == 0 else f'{label} failed with exit code {rc}.'), "
        "'finished_at':datetime.datetime.now().astimezone().isoformat(timespec='seconds').replace('T','  '), "
        "'updated_at':datetime.datetime.now().astimezone().isoformat(timespec='seconds').replace('T','  ')}); "
        "p.write_text(json.dumps(d, indent=2)); "
        f"checker=pathlib.Path({str(HOME / '.hermes' / 'scripts' / 'check_macos_updates.py')!r}); "
        "\ntry:\n subprocess.run([str(checker)], timeout=300) if (rc == 0 and aid == 'macos-update' and checker.exists()) else None\n"
        "except Exception: pass\n"
        "try:\n l=json.loads(lp.read_text()) if lp.exists() else {};\n"
        " lp.unlink() if (not l or l.get('id') == aid) else None\n"
        "except Exception: pass"
    )
    shell_command = " ".join(shlex.quote(part) for part in command)
    wrapped_command = (
        f"{shell_command}; rc=$?; "
        f"printf '\\n===== %s END {shlex.quote(action['label'])} rc=%s =====\\n' \"$(date -u '+%Y-%m-%d  %H:%M:%SZ')\" \"$rc\"; "
        f"/usr/bin/python3 -c {shlex.quote(finish_py)} \"$rc\"; exit $rc"
    )
    with log_path.open("ab") as log:
        try:
            proc = subprocess.Popen(
                ["/bin/bash", "-lc", wrapped_command],
                stdout=log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=str(HOME),
                env=ADMIN_COMMAND_ENV,
                start_new_session=True,
            )
        except Exception as exc:
            release_admin_action_lock(action_id)
            write_admin_action_status(action_id, {
                **initial_status,
                "state": "failed",
                "returncode": None,
                "message": f"Failed to start {action['label']}: {exc}",
            })
            return False, f"Failed to start {action['label']}: {exc}"
    initial_status["pid"] = proc.pid
    initial_status["message"] = f"Started {action['label']} as PID {proc.pid}."
    update_admin_action_lock_pid(action_id, proc.pid)
    write_admin_action_status(action_id, initial_status)
    return True, f"Started {action['label']}."


def tail_file(path: Path, max_chars: int = 7000) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return "No log output yet."
    if len(data) > max_chars:
        data = data[-max_chars:]
    return data.decode("utf-8", errors="replace")


def _parse_cron_time(value: object) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = parse_iso_timestamp(value)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return parsed.astimezone()
    except Exception:
        return None


def _cron_failure_status(status: str) -> bool:
    status = status.lower().strip()
    if not status:
        return False
    return any(marker in status for marker in ("fail", "error", "timeout", "exception"))


def _cron_job_index() -> dict[str, dict]:
    try:
        data = json.loads(CRON_JOBS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    jobs: dict[str, dict] = {}
    for job in data.get("jobs", []):
        jid = str(job.get("id") or job.get("job_id") or "").strip()
        if jid:
            jobs[jid] = job
    return jobs


def cron_failure_records(limit: int = 12) -> list[dict]:
    """Collect recent failed Hermes cron runs from jobs.json and cron output files."""
    records: list[dict] = []
    seen: set[tuple[str, str]] = set()
    jobs = _cron_job_index()

    def add_record(job_id: str, name: str, status: str, when: dt.datetime | None, detail: str, source: Path | None) -> None:
        detail = redact_sensitive_text(detail.strip()) if detail else "No failure detail recorded."
        source_key = str(source) if source else str(when or "jobs.json")
        key = (job_id, source_key)
        if key in seen:
            return
        seen.add(key)
        records.append({
            "job_id": job_id or "unknown",
            "name": name or jobs.get(job_id, {}).get("name") or "Unnamed cron",
            "status": status or "error",
            "when": when,
            "detail": detail,
            "source": source,
        })

    # Output files preserve complete run-level failure logs, including tracebacks.
    try:
        output_files = sorted(
            [p for p in CRON_OUTPUT_DIR.rglob("*.md") if p.is_file()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:300]
    except Exception:
        output_files = []
    for path in output_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        status_match = re.search(r"^\*\*Status:\*\*\s*(.+)$", text, re.MULTILINE)
        status = status_match.group(1).strip() if status_match else ""
        if not _cron_failure_status(status):
            continue
        name_match = re.search(r"^#\s+Cron Job:\s*(.+)$", text, re.MULTILINE)
        id_match = re.search(r"^\*\*Job ID:\*\*\s*(.+)$", text, re.MULTILINE)
        run_match = re.search(r"^\*\*Run Time:\*\*\s*(.+)$", text, re.MULTILINE)
        job_id = id_match.group(1).strip() if id_match else path.parent.name
        name = name_match.group(1).strip() if name_match else str(jobs.get(job_id, {}).get("name") or "Unnamed cron")
        when = _parse_cron_time(run_match.group(1).strip()) if run_match else dt.datetime.fromtimestamp(path.stat().st_mtime).astimezone()
        add_record(job_id, name, status, when, text, path)

    # jobs.json carries the latest error even when an output artifact is missing.
    for job_id, job in jobs.items():
        last_status = str(job.get("last_status") or "")
        last_error = str(job.get("last_error") or "")
        if not last_error and not _cron_failure_status(last_status):
            continue
        when = _parse_cron_time(job.get("last_run_at") or job.get("updated_at") or job.get("created_at"))
        if when and any(
            row.get("job_id") == job_id
            and isinstance(row.get("when"), dt.datetime)
            and abs((row["when"] - when).total_seconds()) <= 5
            for row in records
        ):
            continue
        detail = last_error or f"Last status: {last_status}"
        add_record(job_id, str(job.get("name") or "Unnamed cron"), last_status or "error", when, detail, None)

    records.sort(key=lambda row: row.get("when") or dt.datetime.fromtimestamp(0).astimezone(), reverse=True)
    return records[:limit]


def render_cron_failure_log_section() -> str:
    records = cron_failure_records()
    if not records:
        body = '<p>No failed Hermes cron runs found in <code>{}</code> or <code>{}</code>.</p>'.format(
            html.escape(str(CRON_JOBS_FILE)),
            html.escape(str(CRON_OUTPUT_DIR)),
        )
    else:
        table_rows = []
        detail_blocks = []
        for idx, row in enumerate(records, 1):
            when = row.get("when")
            when_label = format_iso_timestamp(when.astimezone()) if isinstance(when, dt.datetime) else "unknown time"
            source = row.get("source")
            source_label = str(source) if source else str(CRON_JOBS_FILE)
            detail = str(row.get("detail") or "No failure detail recorded.")
            if len(detail) > 9000:
                detail = detail[-9000:]
            table_rows.append(
                f"<tr><td>{idx}</td><td>{html.escape(str(row.get('name') or 'Unnamed cron'))}<br><code>{html.escape(str(row.get('job_id') or 'unknown'))}</code></td>"
                f"<td><span class=\"badge warn\">{html.escape(str(row.get('status') or 'error'))}</span></td>"
                f"<td>{html.escape(when_label)}</td><td><code>{html.escape(source_label)}</code></td></tr>"
            )
            detail_blocks.append(
                f"<details class=\"cron-failure-detail\" {'open' if idx == 1 else ''}>"
                f"<summary>{html.escape(str(row.get('name') or 'Unnamed cron'))} · {html.escape(str(row.get('status') or 'error'))} · {html.escape(when_label)}</summary>"
                f"<pre>{html.escape(detail)}</pre></details>"
            )
        body = f'''
<p>Recent failed Hermes cron runs from <code>{html.escape(str(CRON_JOBS_FILE))}</code> and <code>{html.escape(str(CRON_OUTPUT_DIR))}</code>.</p>
<table><thead><tr><th>#</th><th>Job</th><th>Status</th><th>Run time</th><th>Source</th></tr></thead><tbody>{''.join(table_rows)}</tbody></table>
{''.join(detail_blocks)}'''
    return f'<section class="section cron-failure-log"><h2>Cron failure log</h2>{body}</section>'



def _run_admin_version_command(command: list[str], timeout: int = 12) -> tuple[int | None, str]:
    """Run a bounded version/discovery command for Admin card metadata."""
    try:
        proc = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=ADMIN_COMMAND_ENV,
        )
        return proc.returncode, proc.stdout.strip()
    except Exception as exc:
        return None, f"Unable to run {' '.join(command)}: {exc}"


def _json_outdated_entries(data: dict) -> list[dict]:
    """Normalize Homebrew outdated --json=v2 formula/cask entries."""
    entries: list[dict] = []
    for section in ("formulae", "casks"):
        raw_items = data.get(section) if isinstance(data, dict) else []
        if not isinstance(raw_items, list):
            continue
        for item in raw_items:
            if isinstance(item, dict):
                copied = dict(item)
                copied["kind"] = "cask" if section == "casks" else "formula"
                entries.append(copied)
    return entries


def _brew_entry_versions(item: dict) -> tuple[str, str, str]:
    """Return name/current/latest display strings from a Homebrew JSON entry."""
    name = str(item.get("name") or item.get("token") or item.get("full_name") or "unknown")
    installed_raw = item.get("installed_versions") or item.get("installed_version") or item.get("installed") or []
    if isinstance(installed_raw, list):
        installed = ", ".join(str(x) for x in installed_raw if x) or "installed"
    else:
        installed = str(installed_raw or "installed")
    current_raw = item.get("current_version") or item.get("current_versions") or item.get("latest_version") or item.get("latest") or "available"
    if isinstance(current_raw, list):
        current = ", ".join(str(x) for x in current_raw if x) or "available"
    else:
        current = str(current_raw or "available")
    return name, installed, current


def _shorten(value: str, max_len: int = 96) -> str:
    value = " ".join(str(value).split())
    if len(value) <= max_len:
        return value
    return value[: max_len - 1].rstrip() + "…"


def admin_action_version_info(action_id: str) -> dict[str, str]:
    """Return current/latest version metadata for an Administration update card."""
    if action_id == "macos-update":
        _rc, sw = _run_admin_version_command(["/usr/bin/sw_vers"], timeout=6)
        fields: dict[str, str] = {}
        for line in sw.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip()] = value.strip()
        version = fields.get("ProductVersion") or "Unknown"
        build = fields.get("BuildVersion")
        current = f"macOS {version}" + (f" ({build})" if build else "")
        data = read_macos_update_status()
        updates = data.get("updates") if isinstance(data.get("updates"), list) else []
        if updates:
            latest = _shorten(str(updates[0]), 120)
            detail = f"{len(updates)} cached macOS update(s) available from softwareupdate check at {data.get('checked_at') or 'unknown time'}."
        elif int(data.get("count", 0) or 0) == 0:
            latest = "Current"
            detail = f"No cached macOS updates available. Last checked {data.get('checked_at') or 'unknown time'}."
        else:
            latest = "Unknown"
            detail = f"macOS update availability is unknown. Last check: {data.get('status') or 'not checked'}."
        return {"current": current, "latest": latest, "detail": detail}

    if action_id == "brew-update":
        _rc, version_out = _run_admin_version_command(["/opt/homebrew/bin/brew", "--version"], timeout=8)
        current = version_out.splitlines()[0].strip() if version_out.splitlines() else "Homebrew version unknown"
        rc, outdated_out = _run_admin_version_command(["/opt/homebrew/bin/brew", "outdated", "--json=v2"], timeout=25)
        entries: list[dict] = []
        if rc == 0:
            try:
                json_start = outdated_out.find("{")
                payload = outdated_out[json_start:] if json_start >= 0 else outdated_out
                entries = _json_outdated_entries(json.loads(payload))
            except Exception:
                entries = []
        if entries:
            version_bits = []
            detail_bits = []
            for item in entries[:6]:
                name, installed, latest_version = _brew_entry_versions(item)
                version_bits.append(f"{name} {latest_version}")
                detail_bits.append(f"{name}: {installed} → {latest_version}")
            suffix = "" if len(entries) <= 6 else f" +{len(entries) - 6} more"
            latest = _shorten(", ".join(version_bits) + suffix, 140)
            detail = f"{len(entries)} Homebrew package(s) outdated: " + "; ".join(detail_bits) + ("." if len(entries) <= 6 else f"; plus {len(entries) - 6} more.")
        elif rc == 0:
            latest = "Current"
            detail = "No Homebrew formulae or casks are outdated."
        else:
            latest = "Unknown"
            detail = _shorten(outdated_out or "Could not determine Homebrew outdated versions.", 260)
        return {"current": current, "latest": latest, "detail": detail}

    if action_id == "hermes-update":
        _rc, version_out = _run_admin_version_command([HERMES_BIN, "--version"], timeout=25)
        current_line = version_out.splitlines()[0].strip() if version_out.splitlines() else "Hermes Agent version unknown"
        project = HOME / ".hermes" / "hermes-agent"
        _lrc, local_hash = _run_admin_version_command(["/usr/bin/git", "-C", str(project), "rev-parse", "--short", "HEAD"], timeout=8)
        _orc, origin_hash = _run_admin_version_command(["/usr/bin/git", "-C", str(project), "rev-parse", "--short", "origin/main"], timeout=8)
        _src, subject = _run_admin_version_command(["/usr/bin/git", "-C", str(project), "log", "origin/main", "-1", "--pretty=%s"], timeout=8)
        _vrc, origin_init = _run_admin_version_command(["/usr/bin/git", "-C", str(project), "show", "origin/main:hermes_cli/__init__.py"], timeout=8)
        version_match = re.search(r"Hermes Agent\s+(v\S+)", current_line)
        version_label = version_match.group(1) if version_match else current_line
        origin_version_match = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", origin_init)
        origin_release_match = re.search(r"__release_date__\s*=\s*['\"]([^'\"]+)['\"]", origin_init)
        origin_version_label = f"v{origin_version_match.group(1)}" if origin_version_match else "latest"
        origin_release_label = f" ({origin_release_match.group(1)})" if origin_release_match else ""
        current = _shorten(f"Hermes Agent {version_label}" + (f" · {local_hash}" if local_hash else ""), 110)
        update_available = local_hash and origin_hash and local_hash != origin_hash
        if update_available:
            latest = _shorten(f"Hermes Agent {origin_version_label}{origin_release_label} · {origin_hash}", 110)
            detail = _shorten(f"Current Hermes version {version_label} at commit {local_hash}; latest available is Hermes Agent {origin_version_label}{origin_release_label} at {origin_hash}. {subject}", 260)
        elif "Update available" in version_out:
            latest = "Available"
            detail = _shorten("Hermes reports an update is available: " + " ".join(version_out.splitlines()[-2:]), 220)
        else:
            latest = "Current"
            detail = _shorten(f"Current commit {local_hash or 'unknown'} matches origin/main." if local_hash else "No Hermes update version detail available.", 220)
        return {"current": current, "latest": latest, "detail": detail}

    return {"current": "Not applicable", "latest": "Not applicable", "detail": "This action does not have update-version metadata."}

def check_admin_action_available(action_id: str, skip_expensive: bool = False) -> tuple[bool, str]:
    """Return whether an admin action can be started because relevant updates exist."""
    if action_id == "reboot":
        return True, "Reboot is available when no other admin action is running and typed confirmation is provided."
    if skip_expensive:
        return True, "Availability check skipped while another admin action is running."
    if action_id == "macos-update":
        data = read_macos_update_status()
        try:
            count = int(data.get("count", -1))
        except Exception:
            count = -1
        checked_at = str(data.get("checked_at") or "unknown time")
        if count > 0:
            return True, f"{count} macOS update(s) available. Last checked {checked_at}."
        if count == 0:
            return False, f"No macOS updates available. Last checked {checked_at}."
        return False, f"macOS update availability is unknown. Refresh the update check first. Last checked {checked_at}."
    if action_id == "brew-update":
        try:
            proc = subprocess.run(
                ["/opt/homebrew/bin/brew", "outdated", "--quiet"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                env=ADMIN_COMMAND_ENV,
            )
            outdated = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            if outdated:
                preview = ", ".join(outdated[:5])
                suffix = "" if len(outdated) <= 5 else f" and {len(outdated) - 5} more"
                return True, f"{len(outdated)} Homebrew package(s) outdated: {preview}{suffix}."
            if proc.returncode == 0:
                return False, "No Homebrew updates available."
            return False, f"Could not determine Homebrew update availability: {proc.stderr.strip() or 'brew outdated failed'}."
        except Exception as exc:
            return False, f"Could not determine Homebrew update availability: {exc}"
    if action_id == "hermes-update":
        try:
            proc = subprocess.run(
                [HERMES_BIN, "update", "--check"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=45,
                env=ADMIN_COMMAND_ENV,
            )
            output = proc.stdout.strip()
            lower = output.lower()
            if "update available" in lower or "commit behind" in lower:
                return True, "Hermes Agent update is available."
            if "up to date" in lower or "already up" in lower or "no update" in lower:
                return False, "No Hermes Agent update available."
            if proc.returncode == 0:
                return False, f"No Hermes Agent update detected. Check output: {output[-240:] or 'empty output'}."
            return False, f"Could not determine Hermes Agent update availability: {output[-240:] or 'hermes update --check failed'}."
        except Exception as exc:
            return False, f"Could not determine Hermes Agent update availability: {exc}"
    return True, "No update availability rule is configured for this action."


def local_ip() -> str:
    candidates = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        candidates.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        candidates.append(socket.gethostbyname(hostname))
    except Exception:
        pass
    for ip in candidates:
        if ip and not ip.startswith("127."):
            return ip
    return "127.0.0.1"


def title_from_html(path: Path) -> str:
    name_title = path.stem.replace("_", " ").strip()
    try:
        data = path.read_text(errors="ignore")[:20000]
        import re
        m = re.search(r"<title[^>]*>(.*?)</title>", data, flags=re.I | re.S)
        if m:
            t = html.unescape(re.sub(r"\s+", " ", m.group(1)).strip())
            if t:
                return t
        h = re.search(r"<h1[^>]*>(.*?)</h1>", data, flags=re.I | re.S)
        if h:
            t = html.unescape(re.sub(r"<[^>]+>", "", h.group(1))).strip()
            if t:
                return t
    except Exception:
        pass
    return name_title or path.name


def category_for(path: Path) -> str:
    sp = str(path)
    if "/report_portal/library/Threat Intel/" in sp or "Daily Threat Intel Briefs" in sp:
        return "Threat Intel"
    if "/report_portal/library/Threat Hunting/" in sp or "/ThreatHunting/ATHF/" in sp:
        return "Threat Hunting"
    if "/report_portal/library/Product Research/" in sp or "entrepreneurial_product_research_reports" in sp or "entrepreneurial_research" in sp:
        return "Product Research"
    if "/report_portal/library/Projects/" in sp:
        try:
            rel = path.relative_to(HOME / "report_portal" / "library" / "Projects")
            return f"Project: {rel.parts[0]}" if rel.parts else "Projects"
        except Exception:
            return "Projects"
    if "/gitProjects/" in sp:
        try:
            rel = path.relative_to(HOME / "gitProjects")
            return f"Project: {rel.parts[0]}" if rel.parts else "Projects"
        except Exception:
            return "Projects"
    if "/report_portal/library/Cybersecurity Library/" in sp or "Cybersecurity Library Web" in sp:
        return "Cybersecurity"
    if "/report_portal/library/Cybersecurity/" in sp or "Sigma Learning Web" in sp:
        return "Cybersecurity"
    if "/report_portal/library/Resource Library/" in sp or "Resource Library Web" in sp:
        return "Cybersecurity"
    if "/report_portal/library/Portal Operations/" in sp or "LAN Portal Web Server Architecture" in path.name:
        return "Portal Operations"
    if "/report_portal/library/Web App Projects/" in sp or "Web App Projects Web" in sp:
        return "Web App Projects"
    if "/report_portal/library/Prototype Web App/" in sp or "forest_room" in path.name.lower():
        return "Prototype: Web app"
    if "/report_portal/library/Local AI/" in sp or "Local LLM Benchmark Dashboard" in path.name:
        return "Local AI"
    return "Reports"


def should_skip_dir(path: Path) -> bool:
    return path.name in EXCLUDE_DIR_NAMES or path.name.startswith(".")


def report_id(path: Path) -> str:
    return hashlib.sha1(str(path).encode()).hexdigest()[:16]


def scan_reports() -> list[Report]:
    paths: list[Path] = []
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        if root.is_file() and root.suffix.lower() in (".html", ".htm"):
            paths.append(root)
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not should_skip_dir(Path(dirpath) / d)]
            for filename in filenames:
                if filename.lower().endswith((".html", ".htm")):
                    paths.append(Path(dirpath) / filename)
    for f in STANDALONE_HTML:
        if f.exists():
            paths.append(f)
    seen = set()
    reports = []
    for p in paths:
        try:
            p = p.resolve()
            if p in seen or not p.is_file():
                continue
            seen.add(p)
            st = p.stat()
            try:
                rel = str(p.relative_to(HOME))
            except Exception:
                rel = str(p)
            reports.append(Report(
                rid=report_id(p),
                title=title_from_html(p),
                path=p,
                rel=rel,
                category=category_for(p),
                size=st.st_size,
                mtime=st.st_mtime,
                is_index=p.name.lower() in ("index.html", "index.htm"),
            ))
        except Exception:
            continue
    return sorted(reports, key=lambda r: (r.mtime, r.title.lower()), reverse=True)


def latest_threat_report(reports: list[Report]) -> Report | None:
    """Return the newest real threat-intel brief, excluding the index/latest redirect shim."""
    candidates = [r for r in reports if r.category == "Threat Intel" and not r.is_index]
    return max(candidates, key=lambda r: (r.mtime, r.title.lower()), default=None)


def soc_alerts_report(reports: list[Report]) -> Report | None:
    """Return the SOC Alerts dashboard report used as the LAN Portal default page."""
    return next((r for r in reports if r.title == "SOC Alerts" or "Cybersecurity/SOC Alerts/index.html" in r.rel), None)


def soc_alerts_default_path(reports: list[Report]) -> str | None:
    report = soc_alerts_report(reports)
    return f"/view/{report.rid}/" if report else None


def is_daily_threat_brief_file(report: Report) -> bool:
    """Return True for individual daily brief HTML files now grouped under the dashboard."""
    return (
        report.category == "Threat Intel"
        and not report.is_index
        and report.path.name.endswith(" - Daily Threat Intel Brief.html")
    )


def human_size(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} TB"


def artifact_library_disk_usage() -> int:
    """Return disk usage for mirrored HTML artifacts plus supporting files.

    This intentionally measures the whole configured portal library, not just
    `.html` files, so PDFs, images, JS/CSS assets, SQLite/db files, and other
    supporting artifacts count toward the dashboard metric. Use allocated disk
    blocks when the platform exposes them; fall back to logical file size.
    """
    total = 0
    seen: set[Path] = set()
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        try:
            root = root.resolve()
        except Exception:
            continue
        if root.is_file():
            files = [root]
        else:
            files = []
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if not should_skip_dir(Path(dirpath) / d)]
                for filename in filenames:
                    files.append(Path(dirpath) / filename)
        for path in files:
            try:
                p = path.resolve()
                if p in seen or not p.is_file():
                    continue
                seen.add(p)
                st = p.stat()
                total += int(getattr(st, "st_blocks", 0) or 0) * 512 or st.st_size
            except Exception:
                continue
    return total


def process_matches(matchers: list[str], exclude: list[str] | None = None) -> list[str]:
    """Return ps output lines whose command text matches any supplied substring."""
    exclude = exclude or []
    proc = subprocess.run(
        ["/bin/ps", "axww", "-o", "pid=,args="],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=True,
    )
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return [
        line for line in lines
        if any(matcher in line for matcher in matchers)
        and not any(blocked in line for blocked in exclude)
    ]


def macs_fan_control_status() -> tuple[bool, str]:
    """Return whether Macs Fan Control is currently running plus detail text."""
    try:
        matches = process_matches([
            "Macs Fan Control.app/Contents/MacOS/Macs Fan Control",
            "com.crystalidea.macsfancontrol",
            "MacsFanControl",
        ], exclude=["grep"])
        if matches:
            preview = " | ".join(matches[:2])
            return True, f"Macs Fan Control is running: {preview}"
        return False, "WARNING: Macs Fan Control is not currently running on this system."
    except Exception as exc:
        return False, f"WARNING: Unable to verify Macs Fan Control process state: {exc}"


def codex_app_status() -> tuple[bool, str]:
    """Return whether the Codex desktop app is currently running plus detail text."""
    try:
        matches = process_matches([
            "/Applications/Codex.app/Contents/MacOS/Codex",
            "/Applications/Codex.app/Contents/Resources/codex app-server",
        ], exclude=["grep"])
        if matches:
            preview = " | ".join(matches[:2])
            return True, f"Codex app is running: {preview}"
        return False, "WARNING: Codex app is not currently running on this system."
    except Exception as exc:
        return False, f"WARNING: Unable to verify Codex app process state: {exc}"


def codex_cli_status() -> tuple[bool, str]:
    """Return whether the Codex command-line interface is currently running."""
    try:
        proc = subprocess.run(
            ["/bin/ps", "axww", "-o", "pid=,args="],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=True,
        )
        matches: list[str] = []
        exclude_bits = [
            "/Applications/Codex.app/",
            "Codex Computer Use.app/",
            "Codex for Chrome",
            "com.openai.codex",
            "Sparkle/Launcher",
            "browser_crashpad_handler",
            "grep",
        ]
        cli_patterns = [
            re.compile(r"(^|/)codex(\s|$)", re.IGNORECASE),
            re.compile(r"(^|\s)codex\s+(exec|run|login|resume|mcp|sandbox|apply|--)", re.IGNORECASE),
            re.compile(r"openai[-_]codex", re.IGNORECASE),
        ]
        for raw_line in proc.stdout.splitlines():
            line = raw_line.strip()
            if not line or any(bit in line for bit in exclude_bits):
                continue
            if any(pattern.search(line) for pattern in cli_patterns):
                matches.append(line)
        if matches:
            preview = " | ".join(matches[:3])
            suffix = "" if len(matches) <= 3 else f" | +{len(matches) - 3} more"
            return True, f"Codex CLI is running: {preview}{suffix}"
        return False, "Codex CLI is not currently running."
    except Exception as exc:
        return False, f"WARNING: Unable to verify Codex CLI process state: {exc}"


def docker_status() -> tuple[bool, str]:
    """Return whether Docker is currently running plus detail text."""
    docker_bin = shutil.which("docker") or "/usr/local/bin/docker"
    try:
        info_proc = subprocess.run(
            [docker_bin, "info", "--format", "{{.ServerVersion}}"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
            check=False,
            env={**os.environ, "PATH": ADMIN_COMMAND_ENV.get("PATH", os.environ.get("PATH", ""))},
        )
        if info_proc.returncode == 0 and info_proc.stdout.strip():
            version = info_proc.stdout.strip().splitlines()[0]
            return True, f"Docker daemon is running. Server version: {version}."
        desktop_matches = process_matches([
            "/Applications/Docker.app/Contents/MacOS/Docker",
            "com.docker.backend",
            "com.docker.hyperkit",
            "com.docker.virtualization",
            "docker desktop",
        ], exclude=["grep"])
        if desktop_matches:
            preview = " | ".join(desktop_matches[:2])
            return True, f"Docker Desktop process is running, but docker info did not return daemon details: {preview}"
        helper_matches = process_matches(["com.docker.vmnetd"], exclude=["grep"])
        helper_note = ""
        if helper_matches:
            helper_note = f" Docker helper is present but the daemon is unavailable: {' | '.join(helper_matches[:1])}."
        stderr = (info_proc.stderr or "").strip().splitlines()
        reason = stderr[-1] if stderr else "docker info did not report a running daemon"
        return False, f"WARNING: Docker is not currently running or the daemon is unavailable: {reason}.{helper_note}"
    except Exception as exc:
        return False, f"WARNING: Unable to verify Docker state: {exc}"


def n8n_container_status() -> dict[str, object]:
    """Return compact n8n container/app health without exposing container config."""
    now = dt.datetime.now().astimezone()
    checked_at = format_iso_timestamp(now)
    checked_label = format_iso_timestamp(now)
    docker_bin = shutil.which("docker") or "/usr/local/bin/docker"
    env = {**os.environ, "PATH": ADMIN_COMMAND_ENV.get("PATH", os.environ.get("PATH", ""))}
    base: dict[str, object] = {
        "id": "n8n",
        "label": "n8n container",
        "startable": False,
        "checked_at": checked_at,
    }
    try:
        inspect_proc = subprocess.run(
            [docker_bin, "inspect", N8N_CONTAINER_NAME],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
            env=env,
        )
    except Exception as exc:
        return {
            **base,
            "running": False,
            "level": "alert",
            "value": "Docker unavailable",
            "detail": f"WARNING: unable to inspect {N8N_CONTAINER_NAME}: {exc} · checked {checked_label}",
        }
    if inspect_proc.returncode != 0:
        stderr = (inspect_proc.stderr or inspect_proc.stdout or "docker inspect failed").strip().splitlines()
        reason = stderr[-1] if stderr else "docker inspect failed"
        lower_reason = reason.lower()
        value = "Missing" if "no such object" in lower_reason or "no such container" in lower_reason else "Docker unavailable"
        return {
            **base,
            "running": False,
            "level": "alert",
            "value": value,
            "detail": f"WARNING: {N8N_CONTAINER_NAME} status unavailable: {reason} · healthz not checked · checked {checked_label}",
        }
    try:
        inspect_data = json.loads(inspect_proc.stdout)
        container = inspect_data[0] if isinstance(inspect_data, list) and inspect_data else {}
    except Exception as exc:
        return {
            **base,
            "running": False,
            "level": "alert",
            "value": "Unknown",
            "detail": f"WARNING: unable to parse docker inspect output for {N8N_CONTAINER_NAME}: {exc} · checked {checked_label}",
        }
    state_obj = (container.get("State") or {}) if isinstance(container, dict) else {}
    host_config = (container.get("HostConfig") or {}) if isinstance(container, dict) else {}
    restart_obj = host_config.get("RestartPolicy") or {}
    state = str(state_obj.get("Status") or "unknown")
    started_at = str(state_obj.get("StartedAt") or "unknown")
    restart_policy = str(restart_obj.get("Name") or "none")
    health_ok = False
    health_detail = "not checked"
    if state == "running":
        try:
            health_proc = subprocess.run(
                ["/usr/bin/curl", "-fsS", "--max-time", "5", N8N_HEALTH_URL],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=7,
                check=False,
            )
            body = health_proc.stdout.strip()
            if health_proc.returncode == 0:
                try:
                    payload = json.loads(body)
                    health_ok = payload.get("status") == "ok"
                except Exception:
                    health_ok = body == '{"status":"ok"}'
                health_detail = "ok" if health_ok else f"unexpected response: {body[:120] or 'empty body'}"
            else:
                err = (health_proc.stderr or body or "curl failed").strip().splitlines()
                health_detail = err[-1] if err else "curl failed"
        except Exception as exc:
            health_detail = f"health check error: {exc}"
    if state != "running":
        level = "alert"
        value = state if state != "unknown" else "Unknown"
    elif not health_ok:
        level = "warn"
        value = "Health warning"
    elif restart_policy != "unless-stopped":
        level = "warn"
        value = "Policy warning"
    else:
        level = "ok"
        value = "Healthy"
    detail = (
        f"state={state} · healthz={health_detail} · restart={restart_policy} "
        f"· started={started_at} · checked {checked_label}"
    )
    return {
        **base,
        "running": level == "ok",
        "level": level,
        "value": value,
        "detail": detail,
        "container_state": state,
        "healthz": health_detail,
        "restart_policy": restart_policy,
        "started_at": started_at,
    }


ADMIN_SERVICE_LABELS = {
    "macs-fan-control": "Macs Fan Control",
    "codex": "Codex app",
    "codex-cli": "Codex CLI",
    "docker": "Docker",
    "n8n": "n8n container",
}


def admin_service_statuses() -> dict[str, dict[str, object]]:
    """Return current process/service status records for Administration status cards."""
    checks = {
        "macs-fan-control": macs_fan_control_status,
        "codex": codex_app_status,
        "codex-cli": codex_cli_status,
        "docker": docker_status,
    }
    statuses: dict[str, dict[str, object]] = {}
    for service_id, checker in checks.items():
        running, detail = checker()
        statuses[service_id] = {
            "id": service_id,
            "label": ADMIN_SERVICE_LABELS[service_id],
            "running": running,
            "level": "ok" if running else "warn",
            "startable": True,
            "value": "Running" if running else "Not running",
            "detail": detail,
        }
    statuses["n8n"] = n8n_container_status()
    return statuses


def start_admin_service(service_id: str) -> tuple[bool, str, dict[str, object] | None]:
    """Start one allowed Administration service/app without repeating the request on refresh."""
    start_commands = {
        "macs-fan-control": ["/usr/bin/open", "-a", "Macs Fan Control"],
        "codex": ["/usr/bin/open", "-a", "Codex"],
        "codex-cli": ["/usr/bin/osascript", "-e", f'tell application "Terminal" to do script "{CODEX_CLI_BIN}"', "-e", 'tell application "Terminal" to activate'],
        "docker": ["/usr/bin/open", "-a", "Docker"],
    }
    if service_id not in start_commands:
        return False, "Unknown service.", None
    status = admin_service_statuses().get(service_id)
    if status and status.get("running"):
        return True, f"{ADMIN_SERVICE_LABELS[service_id]} is already running.", status
    try:
        subprocess.Popen(
            start_commands[service_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        status = admin_service_statuses().get(service_id)
        return True, f"Started {ADMIN_SERVICE_LABELS[service_id]}. The card will update when it reports running.", status
    except Exception as exc:
        status = admin_service_statuses().get(service_id)
        return False, f"Unable to start {ADMIN_SERVICE_LABELS[service_id]}: {exc}", status


def defang_admin_service_json(statuses: dict[str, dict[str, object]]) -> dict[str, object]:
    return {"ok": True, "services": statuses, "time": now_iso_local()}


def system_uptime_metric() -> tuple[str, str, bool]:
    """Return compact system uptime/detail and warning state using macOS boot time plus fan-control status."""
    fan_running, fan_detail = macs_fan_control_status()
    try:
        proc = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "kern.boottime"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2,
            check=True,
        )
        match = re.search(r"sec\s*=\s*(\d+)", proc.stdout)
        if not match:
            raise ValueError(proc.stdout.strip() or "Unable to parse kern.boottime")
        boot_epoch = int(match.group(1))
        boot_dt = dt.datetime.fromtimestamp(boot_epoch).astimezone()
        now = dt.datetime.now().astimezone()
        total_seconds = max(0, int((now - boot_dt).total_seconds()))
        days, rem = divmod(total_seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes = rem // 60
        if days:
            uptime_value = f"{days}d {hours}h"
        elif hours:
            uptime_value = f"{hours}h {minutes}m"
        else:
            uptime_value = f"{minutes}m"
        uptime_detail = f"Booted {format_iso_timestamp(boot_dt)} · uptime {days} days, {hours} hours, {minutes} minutes"
        if not fan_running:
            return "⚠ Fan Ctrl", f"{fan_detail} · {uptime_detail}", True
        return uptime_value, f"{uptime_detail} · {fan_detail}", False
    except Exception as exc:
        if not fan_running:
            return "⚠ Fan Ctrl", f"{fan_detail} · Unable to determine system uptime: {exc}", True
        return "Unknown", f"Unable to determine system uptime: {exc} · {fan_detail}", True


def local_disk_usage_metric() -> tuple[int, int, float]:
    """Return free bytes, total bytes, and percent free for the user's home volume."""
    try:
        usage = shutil.disk_usage(HOME)
        percent_free = (usage.free / usage.total * 100) if usage.total else 0.0
        return int(usage.free), int(usage.total), percent_free
    except Exception:
        return 0, 0, 0.0


DISK_INVENTORY_CACHE: dict[str, object] = {"generated": 0.0, "dirs": [], "files": [], "warnings": []}


def _parse_size_path_lines(output: str, multiplier: int = 1) -> list[dict]:
    rows: list[dict] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        try:
            size = int(parts[0]) * multiplier
        except Exception:
            continue
        rows.append({"size": size, "path": parts[1]})
    return rows


def _parse_file_stat_lines(output: str) -> list[dict]:
    rows: list[dict] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        try:
            allocated = int(parts[0]) * 512
            logical = int(parts[1])
        except Exception:
            continue
        rows.append({"size": allocated, "logical_size": logical, "path": parts[2]})
    return rows


def local_disk_inventory(limit: int = 10, cache_seconds: int = 600) -> tuple[list[dict], list[dict], list[str], dt.datetime]:
    """Return cached largest directories/files under HOME for the Local Disk detail page."""
    now = dt.datetime.now().astimezone()
    cached_at = float(DISK_INVENTORY_CACHE.get("generated") or 0.0)
    if cached_at and (now.timestamp() - cached_at) < cache_seconds:
        generated = dt.datetime.fromtimestamp(cached_at).astimezone()
        return (
            list(DISK_INVENTORY_CACHE.get("dirs") or []),
            list(DISK_INVENTORY_CACHE.get("files") or []),
            list(DISK_INVENTORY_CACHE.get("warnings") or []),
            generated,
        )

    warnings: list[str] = []
    top_dirs: list[dict] = []
    top_files: list[dict] = []
    try:
        proc = subprocess.run(
            ["/usr/bin/du", "-k", "-x", "-d", "4", str(HOME)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        dir_rows = [row for row in _parse_size_path_lines(proc.stdout, 1024) if row["path"] != str(HOME)]
        top_dirs = sorted(dir_rows, key=lambda row: row["size"], reverse=True)[:limit]
        if proc.stderr.strip():
            warnings.append("Directory scan warnings: " + proc.stderr.strip().splitlines()[-1])
    except subprocess.TimeoutExpired:
        warnings.append("Directory scan timed out after 30 seconds; showing cached/empty directory data.")
    except Exception as exc:
        warnings.append(f"Directory scan failed: {exc}")

    try:
        find_cmd = (
            f"/usr/bin/find {shlex.quote(str(HOME))} -xdev -type f -size +1M "
            "-exec /usr/bin/stat -f '%b\t%z\t%N' {} + 2>/dev/null "
            "| /usr/bin/sort -nr | /usr/bin/head -10"
        )
        proc = subprocess.run(
            ["/bin/bash", "-lc", find_cmd],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        top_files = _parse_file_stat_lines(proc.stdout)[:limit]
        if proc.stderr.strip():
            warnings.append("File scan warnings: " + proc.stderr.strip().splitlines()[-1])
    except subprocess.TimeoutExpired:
        warnings.append("File scan timed out after 30 seconds; showing cached/empty file data.")
    except Exception as exc:
        warnings.append(f"File scan failed: {exc}")

    DISK_INVENTORY_CACHE.update({
        "generated": now.timestamp(),
        "dirs": top_dirs,
        "files": top_files,
        "warnings": warnings,
    })
    return top_dirs, top_files, warnings, now


def disk_inventory_rows(rows: list[dict]) -> str:
    if not rows:
        return '<tr><td colspan="3">No entries found.</td></tr>'
    return "".join(
        f"<tr><td>{idx}</td><td>{html.escape(human_size(int(row['size'])))}</td><td><code>{html.escape(str(row['path']))}</code></td></tr>"
        for idx, row in enumerate(rows, 1)
    )


def disk_file_inventory_rows(rows: list[dict]) -> str:
    if not rows:
        return '<tr><td colspan="4">No entries found.</td></tr>'
    return "".join(
        f"<tr><td>{idx}</td><td>{html.escape(human_size(int(row['size'])))}</td><td>{html.escape(human_size(int(row.get('logical_size', row['size']))))}</td><td><code>{html.escape(str(row['path']))}</code></td></tr>"
        for idx, row in enumerate(rows, 1)
    )


def latest_hermes_backup_metric() -> tuple[str, str, bool]:
    """Return display value, detail text, and warning state for successful Hermes DR backups.

    A successful backup requires a complete backup set plus confirmation from the
    scheduled backup log. Incomplete/newer artifacts are ignored for the displayed
    timestamp and surfaced as warnings instead.
    """
    log_file = HERMES_DR_BACKUP_DIR / "backup-cron.log"

    def backup_base(path: Path) -> Path:
        raw = str(path)
        if raw.endswith(".tar.zst.enc"):
            return Path(raw.removesuffix(".tar.zst.enc"))
        return Path(raw.removesuffix(".tar.zst"))

    def backup_dt(path: Path) -> dt.datetime:
        stem = path.name
        if stem.endswith(".tar.zst.enc"):
            marker = stem.removeprefix("macstudio-hermes-dr_").removesuffix(".tar.zst.enc")
        else:
            marker = stem.removeprefix("macstudio-hermes-dr_").removesuffix(".tar.zst")
        try:
            return dt.datetime.strptime(marker, "%Y%m%d_%H%M%SZ").replace(tzinfo=dt.timezone.utc)
        except Exception:
            return dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)

    try:
        artifacts = sorted(
            [*HERMES_DR_BACKUP_DIR.glob("macstudio-hermes-dr_*.tar.zst"), *HERMES_DR_BACKUP_DIR.glob("macstudio-hermes-dr_*.tar.zst.enc")],
            key=backup_dt,
        )
    except Exception:
        artifacts = []

    completed_archives: set[str] = set()
    non_dry_starts: list[dt.datetime] = []
    scheduled_completions: list[dt.datetime] = []
    log_warning = ""
    try:
        log_text = log_file.read_text(encoding="utf-8", errors="replace")
        completed_archives = set(re.findall(r"^Archive: (.*macstudio-hermes-dr_\d{8}_\d{6}Z\.tar\.zst(?:\.enc)?)$", log_text, re.MULTILINE))
        for stamp, dry_run in re.findall(r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\] Scheduled backup start: dry_run=(\d)", log_text, re.MULTILINE):
            if dry_run == "0":
                non_dry_starts.append(dt.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc))
        for stamp in re.findall(r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\] Scheduled backup complete\.", log_text, re.MULTILINE):
            scheduled_completions.append(dt.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc))
    except Exception as exc:
        log_warning = f"Could not read backup log {log_file}: {exc}"

    complete_sets: list[Path] = []
    incomplete_sets: list[str] = []
    for archive in artifacts:
        base = backup_base(archive)
        missing = []
        if not archive.with_suffix(archive.suffix + ".sha256").exists():
            missing.append("checksum")
        if not Path(str(base) + ".RESTORE.txt").exists():
            missing.append("restore notes")
        try:
            if archive.stat().st_size <= 0:
                missing.append("non-empty archive")
        except Exception:
            missing.append("readable archive")
        if completed_archives and str(archive) not in completed_archives:
            missing.append("success log entry")
        if missing:
            incomplete_sets.append(f"{archive.name} missing {', '.join(missing)}")
        else:
            complete_sets.append(archive)

    if not complete_sets:
        warning = True
        detail_bits = [f"WARNING: No successful full Hermes backup sets found in {HERMES_DR_BACKUP_DIR}"]
        if incomplete_sets:
            detail_bits.append("Incomplete artifacts: " + "; ".join(incomplete_sets[-3:]))
        if log_warning:
            detail_bits.append(log_warning)
        return "⚠ None", " · ".join(detail_bits), warning

    newest_success = max(complete_sets, key=backup_dt)
    timestamp = backup_dt(newest_success).astimezone()
    last_success_utc = backup_dt(newest_success)
    warnings: list[str] = []

    if incomplete_sets:
        newest_artifact = max(artifacts, key=backup_dt) if artifacts else None
        if newest_artifact and backup_dt(newest_artifact) > last_success_utc:
            warnings.append("Newer backup artifact is incomplete/not confirmed successful: " + incomplete_sets[-1])
    if non_dry_starts:
        latest_start = max(non_dry_starts)
        latest_complete = max(scheduled_completions) if scheduled_completions else None
        if latest_start > last_success_utc and (latest_complete is None or latest_complete < latest_start):
            warnings.append(f"Latest scheduled backup attempt started {format_iso_timestamp(latest_start.astimezone())} but did not log a successful completion")
    if log_warning:
        warnings.append(log_warning)

    warning = bool(warnings)
    value = ("⚠ " if warning else "") + relative_time_label(timestamp.timestamp())
    detail_bits = [
        f"Latest successful full Hermes backup: {newest_success.name}",
        format_iso_timestamp(timestamp.astimezone()),
        human_size(newest_success.stat().st_size),
        "success confirmed by backup-cron.log",
    ]
    if warnings:
        detail_bits.insert(0, "WARNING: " + " | ".join(warnings))
    return value, " · ".join(detail_bits), warning


def macos_update_metric() -> tuple[str, str, int]:
    """Return display value, tooltip/detail text, and update count for cached macOS update status."""
    try:
        data = json.loads(MACOS_UPDATE_STATUS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return "Not checked", "macOS update status has not been checked yet.", -1
    status = str(data.get("status") or "Unknown")
    checked_at = str(data.get("checked_at") or "unknown time")
    updates = data.get("updates") or []
    try:
        count = int(data.get("count", -1))
    except Exception:
        count = -1
    detail_bits = [f"Checked {checked_at}"]
    if isinstance(updates, list) and updates:
        detail_bits.append("Updates: " + "; ".join(str(x) for x in updates[:5]))
    if data.get("error"):
        detail_bits.append("Error: " + str(data.get("error")))
    return status, " · ".join(detail_bits), count


def brew_update_source_metric() -> tuple[int, str, list[str]]:
    """Return Homebrew outdated count, detail, and package names."""
    try:
        proc = subprocess.run(
            ["/opt/homebrew/bin/brew", "outdated", "--quiet"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=12,
            env=ADMIN_COMMAND_ENV,
        )
        outdated = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if outdated:
            preview = ", ".join(outdated[:8])
            suffix = "" if len(outdated) <= 8 else f" and {len(outdated) - 8} more"
            return len(outdated), f"{len(outdated)} Homebrew package(s) outdated: {preview}{suffix}.", outdated
        if proc.returncode == 0:
            return 0, "No Homebrew updates available.", []
        return -1, f"Could not determine Homebrew updates: {proc.stderr.strip() or 'brew outdated failed'}.", []
    except Exception as exc:
        return -1, f"Could not determine Homebrew updates: {exc}", []


def hermes_update_source_metric() -> tuple[bool, str]:
    """Return whether Hermes Agent has an available update plus detail text."""
    try:
        proc = subprocess.run(
            [HERMES_BIN, "update", "--check"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            env=ADMIN_COMMAND_ENV,
        )
        output = proc.stdout.strip()
        lower = output.lower()
        if "update available" in lower or "commits behind" in lower or "run 'hermes update'" in lower:
            first_line = output.splitlines()[0] if output.splitlines() else "Hermes Agent update is available."
            return True, f"Hermes Agent update available: {first_line}"
        if "up to date" in lower or "already up" in lower or "no update" in lower or proc.returncode == 0:
            return False, "No Hermes Agent update available."
        return False, f"Could not determine Hermes Agent update availability: {output[-240:] or 'hermes update --check failed'}."
    except Exception as exc:
        return False, f"Could not determine Hermes Agent update availability: {exc}"


def latest_running_update_action() -> tuple[str, str] | None:
    """Return currently running update action for the homepage Updates metric."""
    for action_id in ("macos-update", "brew-update", "hermes-update"):
        status = read_admin_action_status(action_id)
        if status.get("state") != "running":
            continue
        pid = status.get("pid")
        if not process_is_running(pid):
            continue
        action = ADMIN_ACTIONS.get(action_id, {})
        label = str(status.get("label") or action.get("label") or action_id)
        timestamp = status.get("started_at") or status.get("updated_at")
        try:
            parsed = parse_iso_timestamp(timestamp).astimezone() if timestamp else None
        except Exception:
            parsed = None
        exact = format_iso_timestamp(parsed) if parsed else "unknown time"
        short = "Update running"
        if "Homebrew" in label:
            short = "brew running"
        elif "macOS" in label:
            short = "macOS running"
        elif "Hermes" in label:
            short = "Hermes running"
        return short, f"{label} is currently running as PID {pid or 'unknown'}; started at {exact}. The Updates metric will refresh availability after the action completes."
    return None


def latest_update_action_failure() -> tuple[str, str] | None:
    """Return latest failed/unknown update action for the homepage warning metric."""
    failures: list[tuple[dt.datetime, str, str]] = []
    for action_id in ("macos-update", "brew-update", "hermes-update"):
        status = read_admin_action_status(action_id)
        state = str(status.get("state") or "idle")
        if state not in {"failed", "error", "unknown"}:
            continue
        timestamp = status.get("finished_at") or status.get("updated_at") or status.get("started_at")
        try:
            parsed = parse_iso_timestamp(timestamp).astimezone() if timestamp else dt.datetime.fromtimestamp(0).astimezone()
        except Exception:
            parsed = dt.datetime.fromtimestamp(0).astimezone()
        action = ADMIN_ACTIONS.get(action_id, {})
        label = str(action.get("label") or action_id)
        exact = format_iso_timestamp(parsed) if timestamp else "unknown time"
        message = str(status.get("message") or "No failure message recorded.")
        failures.append((parsed, label, f"WARNING: {label} last failed at {exact}. {message}"))
    if not failures:
        return None
    _parsed, label, detail = max(failures, key=lambda item: item[0])
    short = "Failed"
    if "Homebrew" in label:
        short = "brew failed"
    elif "macOS" in label:
        short = "macOS failed"
    elif "Hermes" in label:
        short = "Hermes failed"
    return short, detail


def prioritized_updates_metric() -> tuple[str, str, int, str]:
    """Return homepage Updates metric using priority: running update > failure > macOS > Homebrew > Hermes."""
    running = latest_running_update_action()
    if running:
        label, detail = running
        return f"⏳ {label}", detail, 2, "running"

    failure = latest_update_action_failure()
    if failure:
        label, detail = failure
        return f"⚠ {label}", detail, -2, "failed"

    _mac_value, mac_detail, mac_count = macos_update_metric()
    detail_parts = ["Priority order: macOS > Homebrew > Hermes Agent.", f"macOS: {mac_detail}"]
    if mac_count > 0:
        return f"{mac_count} macOS", " · ".join(detail_parts), mac_count, "macos"

    brew_count, brew_detail, _brew_items = brew_update_source_metric()
    detail_parts.append(f"Homebrew: {brew_detail}")
    if brew_count > 0:
        return f"{brew_count} brew", " · ".join(detail_parts), brew_count, "brew"

    hermes_available, hermes_detail = hermes_update_source_metric()
    detail_parts.append(f"Hermes: {hermes_detail}")
    if hermes_available:
        return "Hermes", " · ".join(detail_parts), 1, "hermes"

    if mac_count < 0 or brew_count < 0:
        return "Unknown", " · ".join(detail_parts), -1, "unknown"
    return "Current", " · ".join(detail_parts), 0, "none"


def human_time(ts: float) -> str:
    return format_iso_timestamp(dt.datetime.fromtimestamp(ts).astimezone())


def update_time_label(ts: float) -> str:
    """Display an exact compact portal update timestamp."""
    return format_iso_timestamp(dt.datetime.fromtimestamp(ts).astimezone())


def relative_time_label(ts: float) -> str:
    """Display a compact relative time label such as 20m ago."""
    then = dt.datetime.fromtimestamp(ts).astimezone()
    now = dt.datetime.now().astimezone()
    seconds = max(0, int((now - then).total_seconds()))
    if seconds < 60:
        return "now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


def admin_last_performed_label(status: dict) -> tuple[str, str]:
    """Return compact/exact labels for the last completed or attempted admin action."""
    timestamp = status.get("finished_at") or status.get("updated_at") or status.get("started_at")
    if not timestamp:
        return "Never", "No previous run recorded."
    try:
        parsed = parse_iso_timestamp(timestamp)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        local = parsed.astimezone()
        relative = relative_time_label(local.timestamp())
        exact = format_iso_timestamp(local)
        state = str(status.get("state") or "unknown")
        rc = status.get("returncode")
        rc_text = "running" if state == "running" else (f"rc {rc}" if rc is not None else "no return code")
        return relative, f"{exact} · {state} · {rc_text}"
    except Exception:
        return str(timestamp), str(status.get("message") or "Timestamp could not be parsed.")


def portal_last_updated(reports: list[Report]) -> float | None:
    """Return the last time the mirrored LAN portal library actually changed.

    The sync script updates LAST_UPDATED_FILE only when it copies/removes mirrored
    artifacts. If that marker does not exist yet, fall back to the newest report
    mtime so the stat still shows an actual timestamp rather than a relative label.
    """
    try:
        raw = LAST_UPDATED_FILE.read_text().strip()
        if raw:
            return parse_iso_timestamp(raw).timestamp()
    except Exception:
        pass
    return max((r.mtime for r in reports), default=None)


def schedule_label(job: dict) -> str:
    schedule = job.get("schedule") or {}
    if isinstance(schedule, dict):
        return str(schedule.get("display") or schedule.get("expr") or schedule.get("kind") or "unscheduled")
    return str(job.get("schedule_display") or schedule or "unscheduled")


def next_run_label(value: str | None, enabled: bool) -> tuple[str, str]:
    if not enabled:
        return "Disabled", "9999"
    if not value:
        return "Not scheduled", "9998"
    try:
        parsed = parse_iso_timestamp(value)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        local = parsed.astimezone()
        label = format_iso_timestamp(local)
        return label, format_iso_timestamp(parsed)
    except Exception:
        return value, value


def load_cron_summaries() -> tuple[list[CronJobSummary], list[CronJobSummary]]:
    """Load current Hermes cron jobs for the portal dropdown.

    Enabled jobs are sorted by next run. Disabled/paused jobs are returned separately
    so the UI can pin them to the bottom of the menu.
    """
    try:
        data = json.loads(CRON_JOBS_FILE.read_text())
    except Exception:
        return [], []
    enabled_jobs: list[CronJobSummary] = []
    disabled_jobs: list[CronJobSummary] = []
    for job in data.get("jobs", []):
        is_enabled = bool(job.get("enabled")) and str(job.get("state", "")).lower() not in {"paused", "disabled"}
        next_label, sort_key = next_run_label(job.get("next_run_at"), is_enabled)
        summary = CronJobSummary(
            jid=str(job.get("id") or job.get("job_id") or "unknown"),
            name=str(job.get("name") or "Unnamed cron"),
            schedule=schedule_label(job),
            next_run=next_label,
            enabled=is_enabled,
            state=str(job.get("state") or ("scheduled" if is_enabled else "disabled")),
            last_status=str(job.get("last_status") or "never"),
            sort_key=sort_key,
        )
        (enabled_jobs if is_enabled else disabled_jobs).append(summary)
    enabled_jobs.sort(key=lambda j: (j.sort_key, j.name.lower()))
    disabled_jobs.sort(key=lambda j: j.name.lower())
    return enabled_jobs, disabled_jobs


def render_cron_menu() -> str:
    enabled_jobs, disabled_jobs = load_cron_summaries()
    total = len(enabled_jobs) + len(disabled_jobs)
    if total == 0:
        body = '<div class="cron-empty">No Hermes cron jobs found.</div>'
    else:
        enabled_html = "".join(render_cron_item(j) for j in enabled_jobs) or '<div class="cron-empty">No enabled cron jobs.</div>'
        disabled_html = "".join(render_cron_item(j, disabled=True) for j in disabled_jobs)
        disabled_section = f'<div class="cron-disabled"><div class="cron-section-label">Disabled / paused</div>{disabled_html}</div>' if disabled_jobs else ''
        body = f'{enabled_html}{disabled_section}'
    return f'''
    <details class="cron-menu">
      <summary>
        <span class="cron-summary-main"><span class="cron-dot"></span><span><b>Cron Schedule</b><small>{len(enabled_jobs)} enabled · {len(disabled_jobs)} disabled</small></span></span>
        <span class="cron-chevron">⌄</span>
      </summary>
      <div class="cron-panel">{body}</div>
    </details>'''


def render_cron_item(job: CronJobSummary, disabled: bool = False) -> str:
    status_class = "disabled" if disabled else "enabled"
    return f'''
      <div class="cron-item {status_class}">
        <div class="cron-item-top">
          <strong>{html.escape(job.name)}</strong>
          <span class="cron-status {status_class}">{'Disabled' if disabled else 'Enabled'}</span>
        </div>
        <div class="cron-next"><span>Next run</span><b>{html.escape(job.next_run)}</b></div>
        <div class="cron-meta"><span>ID: {html.escape(job.jid)}</span><span>Schedule: {html.escape(job.schedule)}</span><span>Last: {html.escape(job.last_status)}</span></div>
      </div>'''


def icon_for(cat: str) -> str:
    if "Threat" in cat:
        return "🛡️"
    if "Product" in cat:
        return "📈"
    if "Prototype" in cat:
        return "🧩"
    if "Web App Projects" in cat:
        return "🧩"
    if "Local AI" in cat:
        return "🧠"
    if "Cybersecurity" in cat or "Resource Library" in cat:
        return "📚"
    if "Portal Operations" in cat:
        return "🧭"
    return "📄"


def redact_sensitive_text(text: str) -> str:
    """Redact secrets/sensitive credential file references before rendering logs."""
    text = re.sub(re.escape(str(HOME / ".hermes" / "backup" / "full-backup.passphrase")), "[REDACTED_PASSPHRASE_FILE]", text)
    text = re.sub(r"(Passphrase file(?: at creation time)?:\s*)\S+", r"\1[REDACTED_PASSPHRASE_FILE]", text)
    return text


def read_macos_update_status() -> dict:
    try:
        data = json.loads(MACOS_UPDATE_STATUS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        return {"status": "Not checked", "count": -1, "updates": [], "error": str(exc)}


def backup_base_path(path: Path) -> Path:
    raw = str(path)
    if raw.endswith(".tar.zst.enc"):
        return Path(raw.removesuffix(".tar.zst.enc"))
    return Path(raw.removesuffix(".tar.zst"))


def backup_timestamp_from_name(path: Path) -> dt.datetime:
    stem = path.name
    if stem.endswith(".tar.zst.enc"):
        marker = stem.removeprefix("macstudio-hermes-dr_").removesuffix(".tar.zst.enc")
    else:
        marker = stem.removeprefix("macstudio-hermes-dr_").removesuffix(".tar.zst")
    try:
        return dt.datetime.strptime(marker, "%Y%m%d_%H%M%SZ").replace(tzinfo=dt.timezone.utc)
    except Exception:
        return dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)


def backup_inventory() -> tuple[list[dict], dict]:
    log_file = HERMES_DR_BACKUP_DIR / "backup-cron.log"
    completed_archives: set[str] = set()
    log_text = ""
    try:
        log_text = log_file.read_text(encoding="utf-8", errors="replace")
        completed_archives = set(re.findall(r"^Archive: (.*macstudio-hermes-dr_\d{8}_\d{6}Z\.tar\.zst(?:\.enc)?)$", log_text, re.MULTILINE))
    except Exception:
        pass
    try:
        archives = sorted([*HERMES_DR_BACKUP_DIR.glob("macstudio-hermes-dr_*.tar.zst"), *HERMES_DR_BACKUP_DIR.glob("macstudio-hermes-dr_*.tar.zst.enc")], key=backup_timestamp_from_name, reverse=True)
    except Exception:
        archives = []
    rows = []
    for archive in archives:
        base = backup_base_path(archive)
        checksum = archive.with_suffix(archive.suffix + ".sha256")
        restore = Path(str(base) + ".RESTORE.txt")
        missing = []
        if not checksum.exists():
            missing.append("checksum")
        if not restore.exists():
            missing.append("restore notes")
        try:
            size = archive.stat().st_size
            if size <= 0:
                missing.append("non-empty archive")
        except Exception:
            size = 0
            missing.append("readable archive")
        if completed_archives and str(archive) not in completed_archives:
            missing.append("success log entry")
        created = backup_timestamp_from_name(archive).astimezone()
        ok = not missing
        rows.append({
            "archive": archive,
            "checksum": checksum,
            "restore": restore,
            "created": created,
            "size": size,
            "ok": ok,
            "rating": "Successful" if ok else "Needs attention",
            "missing": missing,
        })
    successful = sum(1 for row in rows if row["ok"])
    total = len(rows)
    meta = {
        "directory": HERMES_DR_BACKUP_DIR,
        "remote_dest": HERMES_DR_REMOTE_DEST,
        "remote_directory": HERMES_DR_REMOTE_DIR,
        "remote_location": f"{HERMES_DR_REMOTE_DEST}:{HERMES_DR_REMOTE_DIR}",
        "log_file": log_file,
        "total": total,
        "successful": successful,
        "rating_percent": round((successful / total * 100), 1) if total else 0.0,
        "log_tail": redact_sensitive_text("\n".join(log_text.splitlines()[-40:])) if log_text else "",
    }
    return rows, meta


def metric_detail_shell(title: str, kicker: str, body_html: str, hero_extra_html: str = "") -> bytes:
    page = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · Mac Studio LAN Portal</title>
<style>
:root {{ --bg:#070b12; --panel:#111827; --panel2:#0b1220; --line:rgba(148,163,184,.18); --text:#edf5ff; --muted:#94a3b8; --cyan:#23d3ee; --green:#28e0a6; --blue:#4f8cff; --amber:#f8c76a; --pink:#ff7a90; --purple:#a78bfa; }}
* {{ box-sizing:border-box }}
body {{ margin:0; color:var(--text); font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:radial-gradient(circle at top left, rgba(35,211,238,.14), transparent 36%), linear-gradient(180deg, #07101c, #05070d 70%); }}
a {{ color:inherit }}
.shell {{ width:min(100% - 36px, 1180px); margin:0 auto; padding:28px 0 56px }}
.back {{ display:inline-flex; align-items:center; gap:8px; color:#aeeeff; text-decoration:none; border:1px solid var(--line); background:rgba(255,255,255,.035); border-radius:999px; padding:9px 12px; font-size:13px; font-weight:800 }}
.hero {{ margin:18px 0 18px; padding:24px; border:1px solid var(--line); border-radius:26px; background:linear-gradient(145deg, rgba(18,26,41,.96), rgba(10,15,25,.92)); box-shadow:0 18px 50px rgba(0,0,0,.22) }}
.hero-top {{ display:flex; align-items:flex-start; justify-content:space-between; gap:16px }}
.hero-main {{ min-width:0 }}
.hero-extra {{ flex:0 0 auto }}
.kicker {{ color:var(--cyan); font-size:12px; letter-spacing:.16em; text-transform:uppercase; font-weight:900 }}
h1 {{ margin:10px 0 0; font-size:clamp(32px, 5vw, 58px); line-height:.98; letter-spacing:-.055em }}
.grid {{ display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:14px; margin:18px 0 }}
.card,.section {{ border:1px solid var(--line); border-radius:22px; background:linear-gradient(145deg, rgba(18,26,41,.94), rgba(10,16,27,.90)); padding:18px; box-shadow:0 14px 40px rgba(0,0,0,.18); min-width:0 }}
.card span,.section-label {{ display:block; color:#9bdff2; font-size:11px; letter-spacing:.13em; text-transform:uppercase; font-weight:950; margin-bottom:8px }}
.card strong {{ display:block; font-size:clamp(22px, 3vw, 34px); letter-spacing:-.05em }}
.section {{ margin-top:14px }}
h2 {{ margin:0 0 14px; font-size:21px; letter-spacing:-.025em }}
p {{ color:#b7c4d8; line-height:1.55 }}
table {{ width:100%; border-collapse:collapse; overflow:hidden; border-radius:16px }}
th,td {{ text-align:left; border-bottom:1px solid rgba(148,163,184,.14); padding:11px 10px; vertical-align:top; font-size:13px }}
th {{ color:#dceaff; background:rgba(255,255,255,.045); font-size:11px; letter-spacing:.1em; text-transform:uppercase }}
td {{ color:#c8d6ea }}
code,pre {{ font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace }}
code {{ color:#aeeeff; overflow-wrap:anywhere }}
pre {{ white-space:pre-wrap; overflow:auto; color:#c8d6ea; background:#020403; border:1px solid rgba(148,163,184,.16); border-radius:18px; padding:14px; max-height:420px }}
.badge {{ display:inline-flex; align-items:center; border-radius:999px; padding:5px 8px; font-size:11px; font-weight:950; letter-spacing:.08em; text-transform:uppercase; border:1px solid rgba(40,224,166,.24); color:#a8f1dc; background:rgba(40,224,166,.07) }}
.badge.warn {{ border-color:rgba(248,199,106,.30); color:#ffd991; background:rgba(248,199,106,.08) }}
@media (max-width:800px) {{ .grid {{ grid-template-columns:1fr }} .shell {{ width:min(100% - 22px, 1180px); padding-top:18px }} .hero-top {{ flex-direction:column }} th,td {{ display:block; width:100% }} tr {{ display:block; border-bottom:1px solid rgba(148,163,184,.18); padding:8px 0 }} }}
</style>
</head>
<body><div class="shell"><a class="back" href="/">← Back to Mac Studio LAN Portal</a><section class="hero"><div class="hero-top"><div class="hero-main"><div class="kicker">{html.escape(kicker)}</div><h1>{html.escape(title)}</h1></div>{f'<div class="hero-extra">{hero_extra_html}</div>' if hero_extra_html else ''}</div></section>{body_html}</div></body></html>'''
    return page.encode("utf-8")


def render_macos_updates_detail() -> bytes:
    data = read_macos_update_status()
    status = str(data.get("status") or "Unknown")
    count = data.get("count", "Unknown")
    checked_at = str(data.get("checked_at") or "Not checked")
    ok = data.get("ok")
    updates = data.get("updates") if isinstance(data.get("updates"), list) else []
    update_rows = "".join(f"<tr><td>{idx}</td><td>{html.escape(str(item))}</td></tr>" for idx, item in enumerate(updates, 1)) or '<tr><td colspan="2">No cached update labels available.</td></tr>'
    raw_tail = html.escape(str(data.get("raw_tail") or "No raw softwareupdate output cached."))
    error = html.escape(str(data.get("error") or "None"))
    body = f'''
<section class="grid">
  <div class="card"><span>Status</span><strong>{html.escape(status)}</strong></div>
  <div class="card"><span>Available updates</span><strong>{html.escape(str(count))}</strong></div>
  <div class="card"><span>Last checked</span><strong>{html.escape(checked_at)}</strong></div>
</section>
<section class="section"><h2>Available update detail</h2><table><thead><tr><th>#</th><th>Update label</th></tr></thead><tbody>{update_rows}</tbody></table></section>
<section class="section"><h2>Check metadata</h2><table><tbody>
<tr><th>Cache file</th><td><code>{html.escape(str(MACOS_UPDATE_STATUS_FILE))}</code></td></tr>
<tr><th>Command</th><td><code>{html.escape(str(data.get('command') or '/usr/sbin/softwareupdate --list'))}</code></td></tr>
<tr><th>OK</th><td>{html.escape(str(ok))}</td></tr>
<tr><th>Return code</th><td>{html.escape(str(data.get('returncode', 'Unknown')))}</td></tr>
<tr><th>Error</th><td>{error}</td></tr>
</tbody></table></section>
<section class="section"><h2>Raw cached softwareupdate output tail</h2><pre>{raw_tail}</pre></section>'''
    return metric_detail_shell("macOS Updates", "Metric detail", body)


def render_prioritized_updates_detail() -> bytes:
    value, detail, count, source = prioritized_updates_metric()
    mac_value, mac_detail, mac_count = macos_update_metric()
    brew_count, brew_detail, brew_items = brew_update_source_metric()
    hermes_available, hermes_detail = hermes_update_source_metric()
    selected = {
        "macos": "macOS updates",
        "brew": "Homebrew updates",
        "hermes": "Hermes Agent updates",
        "none": "No updates available",
        "unknown": "Unknown update state",
        "failed": "Update action failed",
        "running": "Update currently running",
    }.get(source, source)
    brew_rows = "".join(f"<tr><td>{idx}</td><td>{html.escape(item)}</td></tr>" for idx, item in enumerate(brew_items, 1)) or '<tr><td colspan="2">No Homebrew package names available.</td></tr>'
    body = f'''
<section class="grid">
  <div class="card"><span>Displayed metric</span><strong>{html.escape(value)}</strong></div>
  <div class="card"><span>Selected source</span><strong>{html.escape(selected)}</strong></div>
  <div class="card"><span>Priority</span><strong>macOS → brew → Hermes</strong></div>
</section>
<section class="section"><h2>Current update precedence result</h2><p>{html.escape(detail)}</p></section>
<section class="section"><h2>Update source status</h2><table><tbody>
<tr><th>macOS</th><td>{html.escape(str(mac_value))} · count {html.escape(str(mac_count))}<br>{html.escape(mac_detail)}</td></tr>
<tr><th>Homebrew</th><td>count {html.escape(str(brew_count))}<br>{html.escape(brew_detail)}</td></tr>
<tr><th>Hermes Agent</th><td>{html.escape('Update available' if hermes_available else 'No update selected')}<br>{html.escape(hermes_detail)}</td></tr>
</tbody></table></section>
<section class="section"><h2>Homebrew outdated packages</h2><table><thead><tr><th>#</th><th>Package</th></tr></thead><tbody>{brew_rows}</tbody></table></section>'''
    return metric_detail_shell("Updates", "Metric detail", body)


def render_hermes_backups_detail() -> bytes:
    rows, meta = backup_inventory()
    row_html = "".join(
        f"<tr><td>{html.escape(format_iso_timestamp(row['created'].astimezone()))}</td>"
        f"<td><span class='badge{' warn' if not row['ok'] else ''}'>{html.escape(row['rating'])}</span></td>"
        f"<td>{html.escape(human_size(row['size']))}</td>"
        f"<td><code>{html.escape(str(row['archive']))}</code></td>"
        f"<td><code>{html.escape(str(row['checksum']))}</code><br><code>{html.escape(str(row['restore']))}</code></td>"
        f"<td>{html.escape(', '.join(row['missing']) if row['missing'] else 'Complete set + success log entry')}</td></tr>"
        for row in rows
    ) or '<tr><td colspan="6">No Hermes backup artifacts found.</td></tr>'
    latest = rows[0] if rows else None
    latest_label = relative_time_label(latest['created'].timestamp()) if latest else 'None'
    body = f'''
<section class="grid">
  <div class="card"><span>Latest backup</span><strong>{html.escape(latest_label)}</strong></div>
  <div class="card"><span>Successful backups</span><strong>{meta['successful']}/{meta['total']}</strong></div>
  <div class="card"><span>Success rating</span><strong>{meta['rating_percent']}%</strong></div>
</section>
<section class="section"><h2>Backup locations</h2><table><tbody>
<tr><th>Backup directory</th><td><code>{html.escape(str(meta['directory']))}</code></td></tr>
<tr><th>Mac mini backup directory</th><td><code>{html.escape(str(meta['remote_location']))}</code></td></tr>
<tr><th>Backup log</th><td><code>{html.escape(str(meta['log_file']))}</code></td></tr>
<tr><th>Expected backup set</th><td>Unencrypted archive <code>.tar.zst</code> (legacy encrypted <code>.tar.zst.enc</code> sets still listed), checksum <code>.sha256</code>, restore notes <code>.RESTORE.txt</code>, and success log entry.</td></tr>
</tbody></table></section>
<section class="section"><h2>Hermes backup inventory</h2><table><thead><tr><th>Created</th><th>Rating</th><th>Size</th><th>Archive</th><th>Companion files</th><th>Validation detail</th></tr></thead><tbody>{row_html}</tbody></table></section>
<section class="section"><h2>Recent backup log tail</h2><pre>{html.escape(str(meta['log_tail'] or 'No log content available.'))}</pre></section>'''
    return metric_detail_shell("Last Hermes Backup", "Metric detail", body)


def render_system_uptime_detail() -> bytes:
    value, detail, warning = system_uptime_metric()
    fan_running, fan_detail = macs_fan_control_status()
    fan_status = "Running" if fan_running else "Not running"
    body = f'''<section class="grid"><div class="card"><span>Displayed metric</span><strong>{html.escape(value)}</strong></div><div class="card"><span>Macs Fan Control</span><strong>{html.escape(fan_status)}</strong></div><div class="card"><span>Host</span><strong>{html.escape(socket.gethostname())}</strong></div></section><section class="section"><h2>Detail</h2><p>{html.escape(detail)}</p><p>{html.escape(fan_detail)}</p><p>Uptime is collected from <code>/usr/sbin/sysctl -n kern.boottime</code>. If Macs Fan Control is not running, this metric intentionally shows a warning instead of uptime.</p></section>'''
    return metric_detail_shell("System Uptime", "Metric detail", body)


def render_local_disk_detail() -> bytes:
    free, total, pct = local_disk_usage_metric()
    used = max(0, total - free)
    top_dirs, top_files, warnings, inventory_generated = local_disk_inventory()
    warning_html = ""
    if warnings:
        warning_html = '<section class="section"><span class="badge warn">Scan warning</span><p>' + html.escape(" · ".join(warnings)) + '</p></section>'
    body = f'''<section class="grid"><div class="card"><span>Free</span><strong>{human_size(free)}</strong></div><div class="card"><span>Total</span><strong>{human_size(total)}</strong></div><div class="card"><span>Percent free</span><strong>{pct:.1f}%</strong></div></section><section class="section"><h2>Volume detail</h2><table><tbody><tr><th>Measured path</th><td><code>{html.escape(str(HOME))}</code></td></tr><tr><th>Used</th><td>{human_size(used)}</td></tr><tr><th>Inventory generated</th><td>{html.escape(format_iso_timestamp(inventory_generated.astimezone()))}</td></tr><tr><th>Alert threshold</th><td>Amber/pink when free space is at or below 20%.</td></tr></tbody></table></section>{warning_html}<section class="section"><h2>Top 10 largest directories</h2><p>Recursive directory sizes under <code>{html.escape(str(HOME))}</code>, constrained to the same local filesystem.</p><table><thead><tr><th>#</th><th>Size</th><th>Directory</th></tr></thead><tbody>{disk_inventory_rows(top_dirs)}</tbody></table></section><section class="section"><h2>Top 10 largest files by disk used</h2><p>Allocated disk use under <code>{html.escape(str(HOME))}</code>, constrained to the same local filesystem. The logical-size column exposes sparse/virtual files such as Docker disk images that can advertise a much larger maximum capacity than they currently consume.</p><table><thead><tr><th>#</th><th>Disk used</th><th>Logical size</th><th>File</th></tr></thead><tbody>{disk_file_inventory_rows(top_files)}</tbody></table></section>'''
    return metric_detail_shell("Local Disk Free", "Metric detail", body)


def render_portal_update_detail(reports: list[Report]) -> bytes:
    ts = portal_last_updated(reports)
    if ts:
        update_dt = dt.datetime.fromtimestamp(ts).astimezone()
        age_seconds = max(0.0, (dt.datetime.now().astimezone() - update_dt).total_seconds())
        value = update_time_label(ts)
        detail = f"{int(age_seconds // 60)} minutes ago"
    else:
        update_dt = None
        age_seconds = 0
        value = "None"
        detail = "No update marker found"
    body = f'''<section class="grid"><div class="card"><span>Latest update</span><strong>{html.escape(value)}</strong></div><div class="card"><span>Age</span><strong>{html.escape(detail)}</strong></div><div class="card"><span>Reports indexed</span><strong>{len(reports)}</strong></div></section><section class="section"><h2>Portal update detail</h2><table><tbody><tr><th>Marker file</th><td><code>{html.escape(str(LAST_UPDATED_FILE))}</code></td></tr><tr><th>Exact timestamp</th><td>{html.escape(format_iso_timestamp(update_dt) if update_dt else 'None')}</td></tr><tr><th>Alert threshold</th><td>Amber/pink when older than 1 hour.</td></tr></tbody></table></section>'''
    return metric_detail_shell("Latest Portal Update", "Metric detail", body)


def render_admin_login(message: str = "", error: bool = False) -> bytes:
    token = ensure_admin_token()
    configured = admin_password_configured()
    message_html = ""
    if message:
        message_html = f'<section class="section"><span class="badge {"warn" if error else ""}">{"Authentication blocked" if error else "Authentication"}</span><p>{html.escape(message)}</p></section>'
    setup_html = "" if configured else f'''
<section class="section"><span class="badge warn">Password not configured</span><p>Set the local admin password before using the Administration dashboard:</p><pre>{html.escape(str(HOME / "report_portal" / "set_admin_password.py"))}</pre><p>The password is stored only as a salted PBKDF2-HMAC-SHA256 hash at <code>{html.escape(str(ADMIN_PASSWORD_FILE))}</code>.</p></section>'''
    disabled_attr = "" if configured else " disabled"
    body = f'''
<style>
.login-card {{ max-width:520px; border:1px solid var(--line); border-radius:22px; background:linear-gradient(145deg, rgba(18,26,41,.94), rgba(10,16,27,.90)); padding:20px; box-shadow:0 14px 40px rgba(0,0,0,.18) }}
.login-card form {{ display:grid; gap:12px }}
.login-card label {{ display:grid; gap:8px; color:#d7e5f8; font-size:13px; font-weight:900 }}
.login-card input {{ width:100%; border:1px solid rgba(35,211,238,.28); border-radius:14px; padding:12px 13px; color:#fff; background:rgba(2,6,23,.62); font:inherit }}
.login-card button {{ border:0; border-radius:14px; padding:12px 14px; font-weight:950; color:#061018; background:linear-gradient(135deg, var(--cyan), var(--blue)); cursor:pointer }}
.login-card button:disabled {{ cursor:not-allowed; opacity:.48; filter:saturate(.45); background:linear-gradient(135deg, #64748b, #334155); color:#dbeafe }}
</style>
{message_html}
{setup_html}
<section class="login-card">
  <form method="post" action="/admin/login">
    <input type="hidden" name="token" value="{html.escape(token)}" />
    <label>Admin password<input name="password" type="password" autocomplete="current-password" autofocus /></label>
    <button type="submit"{disabled_attr}>Sign in</button>
  </form>
</section>
<section class="section"><p>Administration uses a password form, local salted password hash, server-side session cookie, CSRF validation, POST-only actions, and the existing typed reboot confirmation.</p></section>'''
    return metric_detail_shell("Administration sign in", "Protected administration", body)


def render_admin_dashboard(message: str = "", error: bool = False) -> bytes:
    token = ensure_admin_token()
    active_action = running_admin_action()
    latest_outcome = None if active_action else latest_admin_action_outcome()
    service_statuses = admin_service_statuses()

    def render_service_card(service_id: str) -> str:
        service = service_statuses[service_id]
        running = bool(service.get("running"))
        level = str(service.get("level") or ("ok" if running else "warn"))
        class_name = "ok" if level == "ok" else ("alert" if level == "alert" else "warn")
        startable = bool(service.get("startable", True))
        button_html = "" if running or not startable else f'<button class="service-start-button" type="button" data-start-service="{html.escape(service_id)}">Start</button>'
        return f'''
  <div class="admin-indicator {class_name}" data-service-card="{html.escape(service_id)}" data-running="{str(running).lower()}" data-level="{html.escape(level)}">
    <div class="admin-indicator-top"><span>{html.escape(str(service.get('label', service_id)))}</span>{button_html}</div>
    <strong>{html.escape(str(service.get('value', 'Unknown')))}</strong>
    <small>{html.escape(str(service.get('detail', 'No detail available.')))}</small>
  </div>'''

    fan_status_html = f'''
<section class="admin-status-grid">
{render_service_card('macs-fan-control')}
{render_service_card('codex')}
{render_service_card('codex-cli')}
{render_service_card('docker')}
{render_service_card('n8n')}
</section>'''
    cards: list[str] = []
    log_sections: list[str] = []
    for action_id, action in ADMIN_ACTIONS.items():
        status = read_admin_action_status(action_id)
        state = str(status.get("state") or "idle")
        display_state = "completed" if state == "ok" else state
        badge_class = "warn" if state in {"failed", "error", "unknown"} else ""
        command_text = " ".join(str(part) for part in action["command"])
        last_performed, last_performed_detail = admin_last_performed_label(status)
        available, availability_message = check_admin_action_available(action_id, skip_expensive=bool(active_action))
        version_info = admin_action_version_info(action_id)
        is_reboot = action_id == "reboot"
        confirm_html = ""
        button_label = "Approve update"
        form_attrs = ""
        disabled_attr = " disabled" if active_action or (not is_reboot and not available) else ""
        if is_reboot:
            button_label = "Reboot system"
            confirm_html = '<label class="confirm-label">Type <code>REBOOT</code> to confirm<input name="confirmation" autocomplete="off" placeholder="REBOOT" /></label>'
            form_attrs = ' data-reboot-form="true"'
        if active_action:
            button_label = "Wait for running action"
        elif not is_reboot and not available:
            button_label = "No updates available"
        cards.append(f'''
<section class="admin-card" style="--admin-accent:{html.escape(str(action.get('accent', '#23d3ee')))}">
  <div class="admin-card-top"><div><span class="section-label">Action</span><h2>{html.escape(str(action['label']))}</h2></div><span class="badge {badge_class}">{html.escape(display_state)}</span></div>
  <p>{html.escape(str(action.get('summary', '')))}</p>
  <div class="admin-action-metric" title="{html.escape(last_performed_detail)}"><span>Last performed</span><strong>{html.escape(last_performed)}</strong><small>{html.escape(last_performed_detail)}</small></div>
  <div class="admin-version-grid">
    <div class="admin-version-metric" title="{html.escape(str(version_info.get('detail') or ''))}"><span>Current version</span><strong>{html.escape(str(version_info.get('current') or 'Unknown'))}</strong></div>
    <div class="admin-version-metric latest" title="{html.escape(str(version_info.get('detail') or ''))}"><span>Latest available</span><strong>{html.escape(str(version_info.get('latest') or 'Unknown'))}</strong></div>
  </div>
  <table><tbody>
    <tr><th>Last message</th><td>{html.escape(str(status.get('message') or 'Not run yet.'))}</td></tr>
    <tr><th>Availability</th><td><span class="badge {'' if available else 'warn'}">{html.escape('Available' if available else 'Unavailable')}</span> {html.escape(availability_message)}</td></tr>
    <tr><th>Version detail</th><td>{html.escape(str(version_info.get('detail') or 'No version detail available.'))}</td></tr>
    <tr><th>Started</th><td>{html.escape(str(status.get('started_at') or 'Not run yet.'))}</td></tr>
    <tr><th>PID / return code</th><td>{html.escape(str(status.get('pid') or '—'))} / {html.escape(str(status.get('returncode') if status.get('returncode') is not None else '—'))}</td></tr>
    <tr><th>Command</th><td><code>{html.escape(command_text)}</code></td></tr>
  </tbody></table>
  <form method="post" action="/admin/action"{form_attrs}>
    <input type="hidden" name="token" value="{html.escape(token)}" />
    <input type="hidden" name="action" value="{html.escape(action_id)}" />
    {confirm_html}
    <button class="admin-button {'danger' if is_reboot else ''}" type="submit"{disabled_attr}>{html.escape(button_label)}</button>
  </form>
</section>''')
        log_sections.append(f'''
<section class="section"><h2>{html.escape(str(action['label']))} log tail</h2><pre>{html.escape(tail_file(admin_log_path(action_id)))}</pre></section>''')
    try:
        admin_action_files = sorted(
            [p for p in ADMIN_STATE_DIR.iterdir() if p.is_file()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except Exception:
        admin_action_files = []
    admin_action_rows = "".join(
        f"<tr><td><code>{html.escape(path.name)}</code></td>"
        f"<td>{html.escape(human_size(path.stat().st_size))}</td>"
        f"<td>{html.escape(format_iso_timestamp(dt.datetime.fromtimestamp(path.stat().st_mtime).astimezone()))}</td></tr>"
        for path in admin_action_files
    ) or '<tr><td colspan="3">No files found in the Administration action directory.</td></tr>'
    log_sections.insert(0, f'''
<section class="section"><h2>Administration action directory</h2><p>Local action status and logs live under <code>{html.escape(str(ADMIN_STATE_DIR))}</code>.</p><table><thead><tr><th>File</th><th>Size</th><th>Modified</th></tr></thead><tbody>{admin_action_rows}</tbody></table></section>''')
    log_sections.insert(1, render_cron_failure_log_section())
    message_html = ""
    if active_action:
        message_html += f'<section class="section"><span class="badge warn">Action running</span><p>{html.escape(str(active_action.get("label", "An admin action")))} is currently running as PID {html.escape(str(active_action.get("pid", "unknown")))}. Additional updates and reboot are disabled until it completes.</p></section>'
    elif latest_outcome:
        outcome_state = str(latest_outcome.get("state") or "unknown")
        outcome_ok = outcome_state == "ok"
        outcome_badge = "Action completed" if outcome_ok else "Action failed"
        outcome_class = "" if outcome_ok else "warn"
        rc_text = "" if latest_outcome.get("returncode") is None else f" Return code: {latest_outcome.get('returncode')}."
        outcome_message = f'{latest_outcome.get("label", "Admin action")} {"completed successfully" if outcome_ok else "failed"} at {latest_outcome.get("when", "unknown time")}. {latest_outcome.get("message", "")}{rc_text}'
        message_html += f'<section class="section"><span class="badge {outcome_class}">{html.escape(outcome_badge)}</span><p>{html.escape(outcome_message)}</p></section>'
    if message:
        message_html += f'<section class="section"><span class="badge {"warn" if error else ""}">{"Action blocked" if error else "Action started"}</span><p>{html.escape(message)}</p></section>'
    body = f'''
<style>
.admin-status-grid {{ display:grid; grid-template-columns:repeat(5, minmax(0,1fr)); gap:14px; margin:18px 0 }}
.admin-indicator {{ --indicator-accent:#28e0a6; position:relative; border:1px solid color-mix(in srgb, var(--indicator-accent) 28%, rgba(148,163,184,.16)); border-radius:22px; padding:18px; background:linear-gradient(145deg, color-mix(in srgb, var(--indicator-accent) 10%, rgba(18,26,41,.94)), rgba(10,16,27,.90)); box-shadow:0 14px 40px rgba(0,0,0,.18) }}
.admin-indicator.warn {{ --indicator-accent:#f8c76a }}
.admin-indicator.alert {{ --indicator-accent:#ff7a90 }}
.admin-indicator-top {{ display:flex; align-items:flex-start; justify-content:space-between; gap:12px; margin-bottom:7px }}
.admin-indicator span {{ display:block; color:color-mix(in srgb, var(--indicator-accent) 50%, #9bdff2); font-size:10px; letter-spacing:.13em; text-transform:uppercase; font-weight:950 }}
.service-start-button {{ flex:0 0 auto; border:1px solid color-mix(in srgb, var(--indicator-accent) 38%, rgba(255,255,255,.18)); border-radius:999px; padding:7px 10px; color:#061018; background:linear-gradient(135deg, var(--indicator-accent), #23d3ee); font-size:11px; font-weight:950; cursor:pointer; box-shadow:0 10px 24px rgba(0,0,0,.16) }}
.service-start-button:disabled {{ cursor:wait; opacity:.55; filter:saturate(.55); color:#dbeafe; background:linear-gradient(135deg, #64748b, #334155) }}
.admin-indicator strong {{ display:block; color:#f8fbff; font-size:clamp(24px,3.4vw,40px); line-height:1; letter-spacing:-.05em }}
.admin-indicator small {{ display:block; margin-top:8px; color:#aebbd0; font-size:12px; line-height:1.4; overflow-wrap:anywhere }}
.admin-grid {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:14px; margin:18px 0 }}
.admin-card {{ position:relative; overflow:hidden; border:1px solid color-mix(in srgb, var(--admin-accent) 26%, rgba(148,163,184,.16)); border-radius:22px; background:linear-gradient(145deg, color-mix(in srgb, var(--admin-accent) 10%, rgba(18,26,41,.94)), rgba(10,16,27,.90)); padding:18px; box-shadow:0 14px 40px rgba(0,0,0,.18) }}
.admin-card:before {{ content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, var(--admin-accent), rgba(148,163,184,.32)) }}
.admin-card-top {{ display:flex; align-items:flex-start; justify-content:space-between; gap:12px }}
.admin-card h2 {{ margin:0 0 10px }}
.admin-action-metric {{ margin:14px 0; border:1px solid color-mix(in srgb, var(--admin-accent) 24%, rgba(148,163,184,.14)); border-radius:18px; padding:14px 15px; background:linear-gradient(135deg, color-mix(in srgb, var(--admin-accent) 10%, rgba(15,23,42,.88)), rgba(2,6,23,.36)); box-shadow:inset 0 1px 0 rgba(255,255,255,.045) }}
.admin-action-metric span {{ display:block; color:color-mix(in srgb, var(--admin-accent) 46%, #9bdff2); font-size:10px; letter-spacing:.13em; text-transform:uppercase; font-weight:950; margin-bottom:6px }}
.admin-action-metric strong {{ display:block; color:#f8fbff; font-size:clamp(24px,3.4vw,40px); line-height:1; letter-spacing:-.06em }}
.admin-action-metric small {{ display:block; margin-top:7px; color:#aebbd0; font-size:12px; line-height:1.35; overflow-wrap:anywhere }}
.admin-version-grid {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:10px; margin:14px 0 }}
.admin-version-metric {{ min-width:0; border:1px solid color-mix(in srgb, var(--admin-accent) 18%, rgba(148,163,184,.14)); border-radius:16px; padding:12px; background:rgba(2,6,23,.30) }}
.admin-version-metric.latest {{ background:linear-gradient(135deg, color-mix(in srgb, var(--admin-accent) 9%, rgba(2,6,23,.42)), rgba(2,6,23,.30)) }}
.admin-version-metric span {{ display:block; color:color-mix(in srgb, var(--admin-accent) 44%, #9bdff2); font-size:10px; letter-spacing:.12em; text-transform:uppercase; font-weight:950; margin-bottom:6px }}
.admin-version-metric strong {{ display:block; color:#edf5ff; font-size:13px; line-height:1.28; overflow-wrap:anywhere }}
.admin-card form {{ display:grid; gap:10px; margin-top:14px }}
.confirm-label {{ display:grid; gap:7px; color:#d7e5f8; font-size:13px; font-weight:800 }}
.confirm-label input {{ width:100%; border:1px solid rgba(255,122,144,.38); border-radius:14px; padding:11px 12px; color:#fff; background:rgba(2,6,23,.62); font:inherit }}
.admin-button {{ border:0; border-radius:14px; padding:12px 14px; font-weight:950; color:#061018; background:linear-gradient(135deg, var(--admin-accent), #23d3ee); cursor:pointer }}
.admin-button:disabled {{ cursor:not-allowed; opacity:.48; filter:saturate(.45); background:linear-gradient(135deg, #64748b, #334155); color:#dbeafe }}
.admin-button.danger {{ color:#fff; background:linear-gradient(135deg, #ff7a90, #dc2626) }}
.admin-button.danger:disabled {{ background:linear-gradient(135deg, #64748b, #334155); color:#dbeafe }}
.admin-logout-form {{ margin:0; flex:0 0 auto }}
.admin-logout-button {{ border:1px solid rgba(35,211,238,.32); border-radius:999px; padding:9px 12px; color:#aeeeff; background:rgba(35,211,238,.065); font-weight:950; cursor:pointer }}
.admin-logout-button:hover {{ border-color:rgba(35,211,238,.62); background:rgba(35,211,238,.12) }}
.cron-menu {{ --cron-accent:#7dd3fc; --cron-accent2:#94a3b8; position:relative; margin:18px 0; border:1px solid color-mix(in srgb, var(--cron-accent) 24%, rgba(148,163,184,.16)); border-radius:24px; background:linear-gradient(145deg, color-mix(in srgb, var(--cron-accent) 8%, rgba(18,26,41,.94)), rgba(10,15,25,.91) 62%, color-mix(in srgb, var(--cron-accent2) 7%, rgba(8,12,20,.92))); box-shadow:0 16px 44px rgba(0,0,0,.20), inset 0 1px 0 rgba(255,255,255,.045); overflow:hidden; isolation:isolate }}
.cron-menu:before {{ content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, color-mix(in srgb, var(--cron-accent) 72%, #64748b), color-mix(in srgb, var(--cron-accent2) 72%, #475569)); opacity:.62 }}
.cron-menu summary {{ min-height:68px; list-style:none; cursor:pointer; display:flex; align-items:center; justify-content:space-between; gap:14px; padding:17px 18px 16px; touch-action:manipulation }}
.cron-menu summary::-webkit-details-marker {{ display:none }}
.cron-summary-main {{ display:flex; align-items:center; gap:12px; min-width:0 }}
.cron-summary-main b {{ display:block; color:#eef6ff; font-size:18px; line-height:1.05; letter-spacing:-.025em }}
.cron-summary-main small {{ display:block; margin-top:5px; color:color-mix(in srgb, var(--cron-accent) 36%, #94a3b8); font-size:11px; font-weight:900; letter-spacing:.1em; text-transform:uppercase }}
.cron-dot {{ width:12px; height:12px; border-radius:999px; background:color-mix(in srgb, var(--green, #28e0a6) 70%, #94a3b8); box-shadow:0 0 18px rgba(40,224,166,.38); flex:0 0 auto }}
.cron-chevron {{ color:#c8d6ea; font-size:24px; line-height:1; transition:transform .16s ease, color .16s ease }}
.cron-menu[open] .cron-chevron {{ transform:rotate(180deg) }}
.cron-panel {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:12px; padding:0 12px 14px }}
.cron-item {{ --job-accent:#7dd3fc; position:relative; overflow:hidden; border:1px solid color-mix(in srgb, var(--job-accent) 20%, rgba(148,163,184,.14)); border-radius:18px; background:linear-gradient(145deg, color-mix(in srgb, var(--job-accent) 7%, rgba(18,26,41,.88)), rgba(10,16,27,.82)); padding:14px; display:grid; gap:10px; box-shadow:0 12px 32px rgba(0,0,0,.16), inset 0 1px 0 rgba(255,255,255,.035) }}
.cron-item:before {{ content:""; position:absolute; inset:0 0 auto 0; height:3px; background:linear-gradient(90deg, color-mix(in srgb, var(--job-accent) 58%, #64748b), rgba(148,163,184,.18)); opacity:.58 }}
.cron-item:nth-child(2n) {{ --job-accent:#a78bfa }}
.cron-item:nth-child(3n) {{ --job-accent:#28e0a6 }}
.cron-item:nth-child(4n) {{ --job-accent:#f8c76a }}
.cron-item.disabled {{ --job-accent:#94a3b8; opacity:.72; background:linear-gradient(145deg, rgba(18,26,41,.62), rgba(10,16,27,.58)) }}
.cron-item-top {{ display:flex; align-items:flex-start; justify-content:space-between; gap:10px }}
.cron-item-top strong {{ color:#edf5ff; font-size:15px; line-height:1.25; letter-spacing:-.01em }}
.cron-status {{ flex:0 0 auto; font-size:10px; font-weight:950; text-transform:uppercase; letter-spacing:.09em; border-radius:999px; padding:5px 8px; border:1px solid rgba(40,224,166,.20); color:#a8f1dc; background:rgba(40,224,166,.065) }}
.cron-status.disabled {{ color:#e8c989; background:rgba(248,199,106,.055); border-color:rgba(248,199,106,.18) }}
.cron-next {{ display:grid; gap:4px; border-radius:14px; padding:10px 12px; background:color-mix(in srgb, var(--job-accent) 7%, rgba(255,255,255,.025)); border:1px solid color-mix(in srgb, var(--job-accent) 15%, rgba(148,163,184,.12)) }}
.cron-next span,.cron-section-label {{ color:color-mix(in srgb, var(--job-accent) 32%, #94a3b8); font-size:10px; text-transform:uppercase; letter-spacing:.11em; font-weight:950 }}
.cron-next b {{ color:#f4f8ff; font-size:15px; line-height:1.12 }}
.cron-meta {{ display:flex; flex-wrap:wrap; gap:7px; color:#aebbd0; font-size:11px }}
.cron-meta span {{ border:1px solid color-mix(in srgb, var(--job-accent) 12%, rgba(148,163,184,.13)); background:rgba(255,255,255,.022); border-radius:999px; padding:5px 7px }}
.cron-disabled {{ display:grid; grid-column:1/-1; gap:10px; margin-top:2px; padding-top:12px; border-top:1px dashed rgba(148,163,184,.18) }}
.cron-empty {{ color:var(--muted, #8b98ac); padding:16px; text-align:center }}
.cron-failure-log table code {{ white-space:normal; word-break:break-word }}
.cron-failure-detail {{ margin-top:12px; border:1px solid rgba(248,199,106,.22); border-radius:16px; background:rgba(248,199,106,.045); overflow:hidden }}
.cron-failure-detail summary {{ cursor:pointer; padding:12px 14px; color:#ffdfa3; font-weight:900; line-height:1.35 }}
.cron-failure-detail pre {{ margin:0; border-top:1px solid rgba(248,199,106,.16); border-radius:0; max-height:460px; overflow:auto }}
@media (max-width:900px) {{ .admin-grid {{ grid-template-columns:1fr }} .admin-status-grid {{ grid-template-columns:1fr }} .cron-panel {{ grid-template-columns:1fr }} }}
</style>
{fan_status_html}
{render_cron_menu()}
{message_html}
<section class="admin-grid">{''.join(cards)}</section>
{''.join(log_sections)}
<script>
const adminServiceToken = {json.dumps(token)};
function updateServiceCard(service) {{
  const card = document.querySelector(`[data-service-card="${{service.id}}"]`);
  if (!card) return;
  const level = service.level || (service.running ? 'ok' : 'warn');
  const startable = service.startable !== false;
  card.dataset.running = service.running ? 'true' : 'false';
  card.dataset.level = level;
  card.classList.toggle('ok', level === 'ok');
  card.classList.toggle('warn', level !== 'ok' && level !== 'alert');
  card.classList.toggle('alert', level === 'alert');
  const value = card.querySelector('strong');
  const detail = card.querySelector('small');
  const top = card.querySelector('.admin-indicator-top');
  if (value) value.textContent = service.value || (service.running ? 'Running' : 'Not running');
  if (detail) detail.textContent = service.detail || '';
  const existing = card.querySelector('[data-start-service]');
  if (service.running || !startable) {{
    if (existing) existing.remove();
  }} else if (!existing && top) {{
    const button = document.createElement('button');
    button.className = 'service-start-button';
    button.type = 'button';
    button.dataset.startService = service.id;
    button.textContent = 'Start';
    top.appendChild(button);
  }} else if (existing) {{
    existing.disabled = false;
    existing.textContent = 'Start';
  }}
}}
async function refreshServiceStatuses() {{
  const response = await fetch('/api/admin/service-status', {{cache: 'no-store', credentials: 'same-origin'}});
  if (!response.ok) throw new Error(`Status check failed: ${{response.status}}`);
  const data = await response.json();
  Object.values(data.services || {{}}).forEach(updateServiceCard);
  return data.services || {{}};
}}
async function pollServiceUntilRunning(serviceId, button) {{
  for (let attempt = 0; attempt < 30; attempt += 1) {{
    const services = await refreshServiceStatuses();
    if (services[serviceId] && services[serviceId].running) return true;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }}
  if (button && document.body.contains(button)) {{
    button.disabled = false;
    button.textContent = 'Start';
  }}
  return false;
}}
document.addEventListener('click', async (event) => {{
  const button = event.target.closest('[data-start-service]');
  if (!button) return;
  event.preventDefault();
  const serviceId = button.dataset.startService;
  button.disabled = true;
  button.textContent = 'Starting…';
  try {{
    const response = await fetch('/api/admin/start-service', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      credentials: 'same-origin',
      body: JSON.stringify({{token: adminServiceToken, service: serviceId}})
    }});
    const data = await response.json().catch(() => ({{ok:false, error:'Invalid JSON response'}}));
    if (data.service) updateServiceCard(data.service);
    if (!response.ok || !data.ok) throw new Error(data.error || data.message || `Start failed: ${{response.status}}`);
    button.textContent = 'Checking…';
    await pollServiceUntilRunning(serviceId, button);
  }} catch (error) {{
    const card = document.querySelector(`[data-service-card="${{serviceId}}"]`);
    const detail = card ? card.querySelector('small') : null;
    if (detail) detail.textContent = `WARNING: ${{error.message}}`;
    if (button && document.body.contains(button)) {{
      button.disabled = false;
      button.textContent = 'Start';
    }}
  }}
}});
document.querySelectorAll('form[data-reboot-form="true"]').forEach((form) => {{
  form.addEventListener('submit', (event) => {{
    const input = form.querySelector('input[name="confirmation"]');
    if (!input || input.value !== 'REBOOT') {{
      event.preventDefault();
      alert('Type REBOOT to confirm before rebooting.');
      return;
    }}
    if (!confirm('Reboot this Mac now? This will interrupt running tasks.')) {{
      event.preventDefault();
    }}
  }});
}});
const adminActionRunning = {"true" if active_action else "false"};
if (adminActionRunning) {{
  setTimeout(() => window.location.reload(), 5000);
}}
</script>'''
    hero_logout = f'<form class="admin-logout-form" method="post" action="/admin/logout"><input type="hidden" name="token" value="{html.escape(token)}" /><button class="admin-logout-button" type="submit">Sign out</button></form>'
    return metric_detail_shell("⚙️ Administration", "System administration", body, hero_logout)


def render_home(reports: list[Report], host: str, port: int) -> bytes:
    system_uptime_value, system_uptime_detail, system_uptime_warning = system_uptime_metric()
    system_uptime_class = " stat-alert" if system_uptime_warning else " stat-ok"
    portal_updated_ts = portal_last_updated(reports)
    updates_value, updates_detail, updates_count, updates_source = prioritized_updates_metric()
    updates_class = " stat-alert" if updates_count != 0 else " stat-ok"
    hermes_backup_value, hermes_backup_detail, hermes_backup_warning = latest_hermes_backup_metric()
    hermes_backup_class = " stat-alert" if hermes_backup_warning else ""
    local_free_space, local_disk_total, local_disk_percent_free = local_disk_usage_metric()
    local_disk_class = " stat-alert" if local_disk_percent_free <= 20.0 else " stat-ok"
    local_disk_detail = f"{human_size(local_free_space)} free of {human_size(local_disk_total)} total · {local_disk_percent_free:.1f}% free"
    portal_update_warning = False
    portal_update_value = "None"
    portal_update_detail = "No portal update timestamp recorded."
    if portal_updated_ts:
        portal_update_dt = dt.datetime.fromtimestamp(portal_updated_ts).astimezone()
        portal_update_age_seconds = max(0.0, (dt.datetime.now().astimezone() - portal_update_dt).total_seconds())
        portal_update_warning = portal_update_age_seconds > 3600
        portal_update_age_minutes = int(portal_update_age_seconds // 60)
        portal_update_value = relative_time_label(portal_updated_ts)
        portal_update_detail = f"Latest portal update: {format_iso_timestamp(portal_update_dt)} · {portal_update_age_minutes} minutes ago"
    portal_update_class = " stat-alert" if portal_update_warning else ""
    llm_dashboard = next((r for r in reports if "Local LLM Benchmark Dashboard" in r.title or "Local LLM Benchmark Dashboard" in r.rel), None)
    athf_dashboard = next((r for r in reports if "Threat Hunt Command Center" in r.title or "Threat Hunting/ATHF/index.html" in r.rel), None)
    daily_threat_dashboard = next((r for r in reports if "Daily Threat Brief Dashboard" in r.title or "Threat Intel/index.html" in r.rel), None)
    osquery_dashboard = next((r for r in reports if "Elastic Osquery Threat Hunting Cheatsheet" in r.title or "Elastic Osquery Threat Hunting Cheatsheet" in r.rel), None)
    kql_oql_mitre_dashboard = next((r for r in reports if "Elastic KQL and Security Onion OQL MITRE ATT&CK Mapping" in r.title or "KQL_OQL_Mapped_to_Mitre/MITRE_KQL_Mapping_Portable.html" in r.rel), None)
    soc_alerts_dashboard = soc_alerts_report(reports)
    sigma_guide = next((r for r in reports if r.title == "Sigma Detection Engineering Guide" or "Sigma Detection Engineering Guide/index.html" in r.rel), None)
    pdf_library = next((r for r in reports if r.title in ("Cybersecurity Library", "Resource Library") or "Cybersecurity Library/index.html" in r.rel or "Resource Library/index.html" in r.rel), None)
    product_research_dashboard = next((r for r in reports if r.title == "Product Research Dashboard" or "Product Research/index.html" in r.rel), None)
    web_app_projects_dashboard = next((r for r in reports if r.title == "Web App Projects Dashboard" or "Web App Projects/index.html" in r.rel), None)
    portal_architecture = next((r for r in reports if "LAN Portal Web Server Architecture" in r.title or "LAN Portal Web Server Architecture" in r.rel), None)
    quick_cards = []
    cyber_cards = []
    if soc_alerts_dashboard:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{soc_alerts_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🚨</span>
        <span><b>SOC Alerts</b><span>Security Onion alert automation reports and detailed network findings</span></span>
      </a>''')
    if athf_dashboard:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{athf_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🛡️</span>
        <span><b>ATHF Command Center</b><span>Threat hunts, ATT&CK coverage, CQL, and Elastic KQL</span></span>
      </a>''')
    if daily_threat_dashboard:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{daily_threat_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🛰️</span>
        <span><b>Daily Threat Briefs</b><span>Standalone CTI dashboard and searchable brief archive</span></span>
      </a>''')
    if osquery_dashboard:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{osquery_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🧬</span>
        <span><b>Elastic Osquery Cheatsheet</b><span>Windows, macOS, and Linux endpoint hunt queries</span></span>
      </a>''')
    if kql_oql_mitre_dashboard:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{kql_oql_mitre_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🧭</span>
        <span><b>KQL/OQL MITRE Map</b><span>Elastic KQL and Security Onion OQL mapped to ATT&CK</span></span>
      </a>''')
    if sigma_guide:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{sigma_guide.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">Σ</span>
        <span><b>Sigma Guide</b><span>Detection engineering, threat hunting, sigma-cli, and rule tuning</span></span>
      </a>''')
    if pdf_library:
        cyber_cards.append(f'''
      <a class="app-card" href="/view/{pdf_library.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">📚</span>
        <span><b>Cybersecurity Library</b><span>Books, talk slides, posters, tools, certificates, and cybersecurity cheatsheets</span></span>
      </a>''')
    if product_research_dashboard:
        quick_cards.append(f'''
      <a class="app-card" href="/view/{product_research_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">📈</span>
        <span><b>Product Research</b><span>Searchable entrepreneurial product research report archive</span></span>
      </a>''')
    if web_app_projects_dashboard:
        quick_cards.append(f'''
      <a class="app-card" href="/view/{web_app_projects_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🧩</span>
        <span><b>Web App Projects</b><span>Interactive prototypes and project demos hosted on the LAN Portal</span></span>
      </a>''')
    if portal_architecture:
        quick_cards.append(f'''
      <a class="app-card" href="/view/{portal_architecture.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🧭</span>
        <span><b>Portal Architecture</b><span>Web server upgrade triggers, SQLite guidance, and migration path</span></span>
      </a>''')
    if llm_dashboard:
        quick_cards.append(f'''
      <a class="app-card" href="/view/{llm_dashboard.rid}/" target="_blank" rel="noopener">
        <span class="app-card-icon">🧠</span>
        <span><b>LLM Dashboard</b><span>Local Ollama/OpenClaw inventory and benchmarks</span></span>
      </a>''')
    mobile_apps_html = ""
    if quick_cards:
        mobile_apps_html = f'''
  <section class="mobile-apps" aria-label="Portal links">
    <h2>Portal Links</h2>
    <div class="app-strip">{''.join(quick_cards)}
    </div>
  </section>'''
    cyber_portal_html = ""
    if cyber_cards:
        cyber_portal_html = f'''
  <section class="mobile-apps cyber-portal" aria-label="Cyber Portal">
    <h2>Cyber Portal</h2>
    <div class="app-strip">{''.join(cyber_cards)}
    </div>
  </section>'''
    lan = f"http://{local_ip()}:{port}/"
    local = f"http://127.0.0.1:{port}/"

    page = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Mac Studio LAN Portal</title>
<style>
:root {{
  --bg:#080b12; --panel:#0e1420; --panel2:#121a29; --muted:#8b98ac; --text:#edf3ff;
  --line:rgba(148,163,184,.18); --cyan:#23d3ee; --blue:#4f8cff; --green:#28e0a6; --amber:#f8c76a;
  --shadow:0 24px 80px rgba(0,0,0,.42); --radius:22px;
}}
* {{ box-sizing:border-box }}
body {{ margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color:var(--text); background:
  radial-gradient(circle at 14% -10%, rgba(35,211,238,.22), transparent 38%),
  radial-gradient(circle at 90% 4%, rgba(79,140,255,.18), transparent 34%),
  linear-gradient(180deg, #080b12 0%, #0a0f19 48%, #070910 100%); min-height:100vh; }}
a {{ color:inherit; text-decoration:none }}
.shell {{ width:min(1280px, calc(100% - 32px)); margin:0 auto; padding:26px 0 50px }}
.hero {{ border:1px solid var(--line); background:linear-gradient(135deg, rgba(18,26,41,.92), rgba(8,11,18,.84)); border-radius:26px; padding:22px 24px; box-shadow:var(--shadow); position:relative; overflow:hidden }}
.hero:after {{ content:""; position:absolute; inset:auto -80px -160px auto; width:300px; height:300px; background:radial-gradient(circle, rgba(40,224,166,.16), transparent 68%); pointer-events:none }}
.hero-row {{ position:relative; z-index:2; display:flex; align-items:center; justify-content:space-between; gap:14px }}
.hero-refresh {{ --refresh-accent:#23d3ee; --refresh-glow:rgba(35,211,238,.42); flex:0 0 auto; width:56px; height:56px; min-width:56px; min-height:56px; display:inline-flex; align-items:center; justify-content:center; border:1px solid rgba(35,211,238,.56); border-radius:22px; padding:0; color:var(--refresh-accent); background:linear-gradient(145deg, rgba(14,24,38,.78), rgba(7,15,25,.92)); box-shadow:0 16px 38px rgba(0,0,0,.28), inset 0 1px 0 rgba(255,255,255,.045), inset 0 -14px 30px rgba(6,12,22,.36), 0 0 0 1px rgba(35,211,238,.035); cursor:pointer; touch-action:manipulation; -webkit-tap-highlight-color:transparent; transition:transform .16s ease, border-color .16s ease, box-shadow .2s ease, filter .16s ease, background .2s ease; position:relative; overflow:hidden }}
.hero-refresh:before {{ content:""; position:absolute; inset:1px; border:1px solid rgba(35,211,238,.18); border-radius:20px; background:radial-gradient(circle at 50% 45%, rgba(35,211,238,.10), transparent 58%); box-shadow:inset 0 0 20px rgba(35,211,238,.06); pointer-events:none }}
.hero-refresh:after {{ content:""; position:absolute; inset:auto -24px -34px -24px; height:58%; background:radial-gradient(ellipse at 50% 100%, rgba(35,211,238,.10), transparent 66%); pointer-events:none }}
.hero-refresh:hover {{ transform:translateY(-1px); border-color:rgba(35,211,238,.95); background:linear-gradient(145deg, rgba(16,31,46,.88), rgba(7,15,25,.94)); box-shadow:0 22px 54px rgba(0,0,0,.34), 0 0 18px rgba(35,211,238,.42), 0 0 44px rgba(35,211,238,.24), 0 0 76px rgba(35,211,238,.14), inset 0 1px 0 rgba(255,255,255,.065), inset 0 0 24px rgba(35,211,238,.08) }}
.hero-refresh:hover:before {{ border-color:rgba(35,211,238,.34); box-shadow:inset 0 0 28px rgba(35,211,238,.12), 0 0 18px rgba(35,211,238,.12) }}
.hero-refresh:active {{ transform:translateY(1px) scale(.99) }}
.hero-refresh[aria-busy="true"], .hero-refresh.refreshing {{ cursor:wait; filter:saturate(1.18); border-color:rgba(35,211,238,1); box-shadow:0 22px 56px rgba(0,0,0,.34), 0 0 22px rgba(35,211,238,.52), 0 0 56px rgba(35,211,238,.30), 0 0 88px rgba(35,211,238,.18), inset 0 1px 0 rgba(255,255,255,.08), inset 0 0 28px rgba(35,211,238,.10) }}
.hero-refresh-icon {{ position:relative; z-index:1; display:block; font-size:31px; line-height:1; transform-origin:center; color:var(--refresh-accent); text-shadow:0 0 10px rgba(35,211,238,.35), 0 0 24px rgba(35,211,238,.20) }}
.hero-refresh:hover .hero-refresh-icon {{ text-shadow:0 0 12px rgba(35,211,238,.62), 0 0 30px rgba(35,211,238,.34), 0 0 54px rgba(35,211,238,.18) }}
.hero-refresh[aria-busy="true"] .hero-refresh-icon, .hero-refresh.refreshing .hero-refresh-icon {{ animation:refresh-spin .72s linear infinite }}
@keyframes refresh-spin {{ to {{ transform:rotate(360deg) }} }}
.kicker {{ display:inline-flex; gap:8px; align-items:center; color:var(--cyan); font-size:12px; letter-spacing:.16em; text-transform:uppercase; font-weight:800 }}
h1 {{ font-size:clamp(30px, 4.4vw, 54px); line-height:.96; letter-spacing:-.055em; margin:10px 0 2px }}
.subtitle {{ color:#b7c4d8; max-width:820px; font-size:17px; line-height:1.65; margin:0 }}
.urls {{ display:flex; flex-wrap:wrap; gap:10px; margin-top:22px }}
.urlpill {{ font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:13px; border:1px solid var(--line); background:rgba(15,23,42,.72); color:#d9e6f7; padding:10px 12px; border-radius:999px }}
.stats {{ display:grid; grid-template-columns:repeat(5, minmax(0,1fr)); gap:14px; margin:18px 0 16px }}
.stat {{ --accent:var(--cyan); --accent2:var(--green); position:relative; overflow:hidden; min-width:0; background:linear-gradient(145deg, color-mix(in srgb, var(--accent) 14%, rgba(18,26,41,.94)), rgba(10,16,27,.90) 58%, color-mix(in srgb, var(--accent2) 9%, rgba(8,12,20,.92))); border:1px solid color-mix(in srgb, var(--accent) 34%, rgba(148,163,184,.16)); border-radius:22px; padding:17px 16px 18px; box-shadow:0 16px 44px rgba(0,0,0,.22), inset 0 1px 0 rgba(255,255,255,.055); display:flex; flex-direction:column; gap:8px; isolation:isolate; transition:transform .16s ease, border-color .16s ease, box-shadow .16s ease; color:inherit; text-decoration:none; cursor:pointer }}
.stat:before {{ content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, var(--accent), var(--accent2)); opacity:.95 }}
.stat:after {{ content:""; position:absolute; width:120px; height:120px; right:-58px; top:-58px; border-radius:999px; background:radial-gradient(circle, color-mix(in srgb, var(--accent) 28%, transparent), transparent 68%); filter:blur(.2px); opacity:.78; z-index:-1 }}
.stat:nth-child(1) {{ --accent:#23d3ee; --accent2:#4f8cff }}
.stat:nth-child(2) {{ --accent:#f8c76a; --accent2:#ff7a90 }}
.stat:nth-child(3) {{ --accent:#a78bfa; --accent2:#23d3ee }}
.stat:nth-child(4) {{ --accent:#28e0a6; --accent2:#23d3ee }}
.stat:nth-child(5) {{ --accent:#4f8cff; --accent2:#a78bfa }}
.stat.stat-alert {{ --accent:#f8c76a; --accent2:#ff7a90 }}
.stat.stat-ok {{ --accent:#28e0a6; --accent2:#23d3ee }}
.stat:hover {{ transform:translateY(-2px); border-color:color-mix(in srgb, var(--accent) 58%, rgba(148,163,184,.18)); box-shadow:0 20px 56px rgba(0,0,0,.30), 0 0 0 1px color-mix(in srgb, var(--accent) 12%, transparent), inset 0 1px 0 rgba(255,255,255,.07) }}
.stat span {{ order:1; color:color-mix(in srgb, var(--accent) 52%, #b7c4d8); font-size:11px; text-transform:uppercase; letter-spacing:.13em; font-weight:950; line-height:1.25 }}
.stat strong {{ order:2; display:block; color:#f8fbff; font-size:clamp(21px, 2.1vw, 31px); line-height:1.05; letter-spacing:-.055em; overflow-wrap:anywhere; text-shadow:0 0 24px color-mix(in srgb, var(--accent) 20%, transparent) }}
.mobile-apps {{ --quick-accent:#7dd3fc; --quick-accent2:#94a3b8; position:relative; margin:0 0 24px; padding:18px; border:1px solid color-mix(in srgb, var(--quick-accent) 24%, rgba(148,163,184,.16)); border-radius:24px; background:linear-gradient(145deg, color-mix(in srgb, var(--quick-accent) 8%, rgba(18,26,41,.94)), rgba(10,15,25,.91) 62%, color-mix(in srgb, var(--quick-accent2) 7%, rgba(8,12,20,.92))); box-shadow:0 16px 44px rgba(0,0,0,.20), inset 0 1px 0 rgba(255,255,255,.045); overflow:hidden; isolation:isolate }}
.mobile-apps:before {{ content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, color-mix(in srgb, var(--quick-accent) 72%, #64748b), color-mix(in srgb, var(--quick-accent2) 72%, #475569)); opacity:.62 }}
.mobile-apps:after {{ content:""; position:absolute; width:170px; height:170px; right:-96px; top:-96px; border-radius:999px; background:radial-gradient(circle, color-mix(in srgb, var(--quick-accent) 12%, transparent), transparent 70%); opacity:.72; z-index:-1 }}
.mobile-apps h2 {{ color:#eef6ff; font-size:18px; line-height:1.05; letter-spacing:-.025em; margin:0 0 14px; text-shadow:0 0 18px color-mix(in srgb, var(--quick-accent) 10%, transparent) }}
.app-strip {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:12px }}
.app-card {{ display:flex; gap:12px; align-items:center; border:1px solid rgba(35,211,238,.24); border-radius:22px; padding:16px; background:linear-gradient(135deg, rgba(35,211,238,.11), rgba(79,140,255,.07)); box-shadow:0 18px 54px rgba(0,0,0,.22) }}
.app-card b {{ display:block; font-size:17px; letter-spacing:-.02em; margin-bottom:3px }}
.app-card span {{ display:block; color:#b7c4d8; font-size:13px; line-height:1.35 }}
.app-card .app-card-icon {{ width:54px; height:54px; flex:0 0 54px; display:flex; align-items:center; justify-content:center; border-radius:18px; font-size:34px; line-height:1; color:#eaf4ff; background:rgba(255,255,255,.08); border:1px solid var(--line); text-align:center; transform:translateY(0) }}
.cron-menu {{ --cron-accent:#7dd3fc; --cron-accent2:#94a3b8; position:relative; margin:0 0 24px; border:1px solid color-mix(in srgb, var(--cron-accent) 24%, rgba(148,163,184,.16)); border-radius:24px; background:linear-gradient(145deg, color-mix(in srgb, var(--cron-accent) 8%, rgba(18,26,41,.94)), rgba(10,15,25,.91) 62%, color-mix(in srgb, var(--cron-accent2) 7%, rgba(8,12,20,.92))); box-shadow:0 16px 44px rgba(0,0,0,.20), inset 0 1px 0 rgba(255,255,255,.045); overflow:hidden; isolation:isolate }}
.cron-menu:before {{ content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, color-mix(in srgb, var(--cron-accent) 72%, #64748b), color-mix(in srgb, var(--cron-accent2) 72%, #475569)); opacity:.62 }}
.cron-menu:after {{ content:""; position:absolute; width:170px; height:170px; right:-96px; top:-96px; border-radius:999px; background:radial-gradient(circle, color-mix(in srgb, var(--cron-accent) 12%, transparent), transparent 70%); opacity:.72; z-index:-1 }}
.cron-menu summary {{ min-height:68px; list-style:none; cursor:pointer; display:flex; align-items:center; justify-content:space-between; gap:14px; padding:17px 18px 16px; touch-action:manipulation }}
.cron-menu summary::-webkit-details-marker {{ display:none }}
.cron-summary-main {{ display:flex; align-items:center; gap:12px; min-width:0 }}
.cron-summary-main b {{ display:block; color:#eef6ff; font-size:18px; line-height:1.05; letter-spacing:-.025em; text-shadow:0 0 18px color-mix(in srgb, var(--cron-accent) 10%, transparent) }}
.cron-summary-main small {{ display:block; margin-top:5px; color:color-mix(in srgb, var(--cron-accent) 36%, #94a3b8); font-size:11px; font-weight:900; letter-spacing:.1em; text-transform:uppercase }}
.cron-dot {{ width:12px; height:12px; border-radius:999px; background:color-mix(in srgb, var(--green) 70%, #94a3b8); box-shadow:0 0 18px rgba(40,224,166,.38); flex:0 0 auto }}
.cron-chevron {{ color:#c8d6ea; font-size:24px; line-height:1; transition:transform .16s ease, color .16s ease }}
.cron-menu:hover .cron-chevron {{ color:#e8f2ff }}
.cron-menu[open] .cron-chevron {{ transform:rotate(180deg) }}
.cron-panel {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:12px; padding:0 12px 14px }}
.cron-item {{ --job-accent:#7dd3fc; position:relative; overflow:hidden; border:1px solid color-mix(in srgb, var(--job-accent) 20%, rgba(148,163,184,.14)); border-radius:18px; background:linear-gradient(145deg, color-mix(in srgb, var(--job-accent) 7%, rgba(18,26,41,.88)), rgba(10,16,27,.82)); padding:14px; display:grid; gap:10px; box-shadow:0 12px 32px rgba(0,0,0,.16), inset 0 1px 0 rgba(255,255,255,.035) }}
.cron-item:before {{ content:""; position:absolute; inset:0 0 auto 0; height:3px; background:linear-gradient(90deg, color-mix(in srgb, var(--job-accent) 58%, #64748b), rgba(148,163,184,.18)); opacity:.58 }}
.cron-item:nth-child(2n) {{ --job-accent:#a78bfa }}
.cron-item:nth-child(3n) {{ --job-accent:#28e0a6 }}
.cron-item:nth-child(4n) {{ --job-accent:#f8c76a }}
.cron-item.disabled {{ --job-accent:#94a3b8; opacity:.72; background:linear-gradient(145deg, rgba(18,26,41,.62), rgba(10,16,27,.58)) }}
.cron-item-top {{ display:flex; align-items:flex-start; justify-content:space-between; gap:10px }}
.cron-item-top strong {{ color:#edf5ff; font-size:15px; line-height:1.25; letter-spacing:-.01em }}
.cron-status {{ flex:0 0 auto; font-size:10px; font-weight:950; text-transform:uppercase; letter-spacing:.09em; border-radius:999px; padding:5px 8px; border:1px solid rgba(40,224,166,.20); color:#a8f1dc; background:rgba(40,224,166,.065) }}
.cron-status.disabled {{ color:#e8c989; background:rgba(248,199,106,.055); border-color:rgba(248,199,106,.18) }}
.cron-next {{ display:grid; gap:4px; border-radius:14px; padding:10px 12px; background:color-mix(in srgb, var(--job-accent) 7%, rgba(255,255,255,.025)); border:1px solid color-mix(in srgb, var(--job-accent) 15%, rgba(148,163,184,.12)) }}
.cron-next span,.cron-section-label {{ color:color-mix(in srgb, var(--job-accent) 32%, #94a3b8); font-size:10px; text-transform:uppercase; letter-spacing:.11em; font-weight:950 }}
.cron-next b {{ color:#f4f8ff; font-size:15px; line-height:1.12 }}
.cron-meta {{ display:flex; flex-wrap:wrap; gap:7px; color:#aebbd0; font-size:11px }}
.cron-meta span {{ border:1px solid color-mix(in srgb, var(--job-accent) 12%, rgba(148,163,184,.13)); background:rgba(255,255,255,.022); border-radius:999px; padding:5px 7px }}
.cron-disabled {{ display:grid; grid-column:1/-1; gap:10px; margin-top:2px; padding-top:12px; border-top:1px dashed rgba(148,163,184,.18) }}
.cron-empty {{ color:var(--muted); padding:16px; text-align:center }}
.grid {{ display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:16px }}
.card {{ background:linear-gradient(180deg, rgba(18,26,41,.95), rgba(11,16,26,.95)); border:1px solid var(--line); border-radius:var(--radius); padding:20px; min-height:255px; display:flex; flex-direction:column; box-shadow:0 18px 48px rgba(0,0,0,.2); transition:transform .16s ease, border-color .16s ease }}
.card:hover {{ transform:translateY(-2px); border-color:rgba(35,211,238,.45) }}
.card-top {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:18px }}
.icon {{ font-size:24px; width:42px; height:42px; border-radius:14px; display:grid; place-items:center; background:rgba(255,255,255,.06); border:1px solid var(--line) }}
.badge {{ color:#89f7d1; background:rgba(40,224,166,.09); border:1px solid rgba(40,224,166,.24); padding:6px 10px; border-radius:999px; font-size:12px; font-weight:800 }}
.card h2 {{ font-size:20px; line-height:1.22; letter-spacing:-.025em; margin:0 0 10px }}
.path {{ color:var(--muted); font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; line-height:1.45; word-break:break-word; margin:0 0 16px }}
.meta {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:auto; color:#aebbd0; font-size:12px }}
.meta span {{ border:1px solid var(--line); background:rgba(255,255,255,.035); border-radius:999px; padding:6px 8px }}
.actions {{ display:flex; gap:10px; margin-top:16px }}
.primary,.secondary {{ border-radius:13px; padding:10px 12px; font-weight:800; font-size:13px; text-align:center }}
.primary {{ flex:1; background:linear-gradient(135deg, var(--blue), var(--cyan)); color:white }}
.secondary {{ border:1px solid var(--line); color:#c9d6e8; background:rgba(255,255,255,.04) }}
.footer {{ color:var(--muted); font-size:12px; margin-top:26px; text-align:center }}
@media (max-width:960px) {{ .grid {{ grid-template-columns:repeat(2, minmax(0,1fr)) }} .stats {{ grid-template-columns:repeat(2, minmax(0,1fr)) }} }}
@media (max-width:640px) {{ .shell {{ width:min(1280px, calc(100% - 20px)); padding:14px 0 36px }} .grid,.stats,.app-strip,.cron-panel {{ grid-template-columns:1fr }} .hero {{ padding:16px 18px; border-radius:22px }} .hero-row {{ gap:8px }} h1 {{ font-size:clamp(27px, 8vw, 36px); margin:10px 0 0 }} .hero-refresh {{ width:52px; height:52px; min-width:52px; min-height:52px; border-radius:20px }} .hero-refresh:before {{ border-radius:18px }} .hero-refresh-icon {{ font-size:29px }} .cron-menu,.mobile-apps {{ border-radius:20px; margin-bottom:18px }} .mobile-apps {{ padding:15px }} .cron-menu summary {{ padding:15px; min-height:62px }} .cron-panel {{ padding:0 8px 10px }} .cron-item {{ padding:12px; border-radius:16px }} .cron-item-top {{ flex-direction:column; align-items:flex-start }} .cron-next b {{ font-size:14px }} .cron-meta {{ flex-direction:column; align-items:flex-start }} .actions {{ flex-direction:column }} }}
</style>
</head>
<body>
<div class="shell">
  <section class="hero">
    <div class="hero-row">
      <div class="kicker">● Private LAN Portal</div>
      <button class="hero-refresh" type="button" aria-label="Refresh Mac Studio LAN Portal and metrics" title="Refresh Mac Studio LAN Portal and metrics" aria-busy="false">
        <span class="hero-refresh-icon" aria-hidden="true">↻</span>
      </button>
    </div>
    <h1>Mac Studio LAN Portal</h1>
  </section>
  <section class="stats">
    <a class="stat{system_uptime_class}" href="/metrics/system-uptime" title="{html.escape(system_uptime_detail)}"><span>System uptime</span><strong>{html.escape(system_uptime_value)}</strong></a>
    <a class="stat{updates_class}" href="/admin" title="{html.escape(updates_detail)}"><span>Updates</span><strong>{html.escape(updates_value)}</strong></a>
    <a class="stat{hermes_backup_class}" href="/metrics/hermes-backups" title="{html.escape(hermes_backup_detail)}"><span>Last Hermes backup</span><strong>{html.escape(hermes_backup_value)}</strong></a>
    <a class="stat{local_disk_class}" href="/metrics/local-disk" title="{html.escape(local_disk_detail)}"><span>Local disk free</span><strong>{human_size(local_free_space)}</strong></a>
    <a class="stat{portal_update_class}" href="/metrics/portal-update" title="{html.escape(portal_update_detail)}"><span>Latest Portal update</span><strong>{html.escape(portal_update_value)}</strong></a>
  </section>
  {cyber_portal_html}
  {mobile_apps_html}
  <div class="footer">Generated live by report_portal.py · metrics refresh from configured local checks · dashboard links are explicit only</div>
</div>
<script>
const DISK_METRIC_REFRESH_MS = 30 * 60 * 1000;
const refreshButton = document.querySelector('.hero-refresh');
function startMetricRefresh(paramName = 'refresh') {{
  const url = new URL(window.location.href);
  url.searchParams.set(paramName, Date.now().toString());
  if (refreshButton) {{
    refreshButton.classList.add('refreshing');
    refreshButton.setAttribute('aria-busy', 'true');
    refreshButton.setAttribute('aria-label', 'Refreshing Mac Studio LAN Portal metrics');
    refreshButton.setAttribute('title', 'Refreshing Mac Studio LAN Portal metrics');
    refreshButton.disabled = true;
  }}
  window.requestAnimationFrame(() => window.setTimeout(() => window.location.replace(url.toString()), 90));
}}
refreshButton?.addEventListener('click', () => startMetricRefresh('refresh'));
window.setTimeout(() => {{
  startMetricRefresh('disk_metric_refresh');
}}, DISK_METRIC_REFRESH_MS);
</script>
</body>
</html>'''
    return page.encode("utf-8")


def normalize_soc_alert_status_meta(value: object, *, now: str | None = None) -> dict | None:
    """Normalize analyst-controlled alert workflow state before persistence."""
    if not isinstance(value, dict):
        return None
    raw_status = str(value.get("status") or "open").strip().lower()
    if raw_status not in {"open", "acknowledged", "suppressed"}:
        return None
    try:
        repeat_count = max(0, int(value.get("repeat_count") or value.get("acknowledged_count") or 0))
    except (TypeError, ValueError):
        repeat_count = 0
    reason = str(value.get("reason") or "").strip()[:140]
    return {
        "status": raw_status,
        "repeat_count": repeat_count,
        "reason": reason,
        "updated_at": str(value.get("updated_at") or now or now_iso_utc()),
    }


def ensure_soc_alert_status_table(conn: sqlite3.Connection) -> None:
    """Create analyst state tables inside the alert store database.

    `analyst_alert_status` is the original per-rendered-row table. It is kept
    for backward compatibility. `analyst_alert_group_state` is the durable
    group-level state table used by the API and multi-analyst UI path.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_alert_status (
          alert_id TEXT PRIMARY KEY,
          status TEXT NOT NULL CHECK(status IN ('acknowledged', 'suppressed')),
          repeat_count INTEGER NOT NULL DEFAULT 0,
          reason TEXT,
          updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_analyst_alert_status_status ON analyst_alert_status(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_analyst_alert_status_updated_at ON analyst_alert_status(updated_at)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_alert_group_state (
          group_id TEXT PRIMARY KEY,
          group_key TEXT,
          status TEXT NOT NULL CHECK(status IN ('acknowledged', 'suppressed')),
          repeat_count INTEGER NOT NULL DEFAULT 0,
          reason TEXT,
          updated_at TEXT NOT NULL,
          updated_by TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_group_state_status ON analyst_alert_group_state(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_group_state_updated_at ON analyst_alert_group_state(updated_at)")


def soc_alert_group_key_from_values(
    triage_level: object,
    rule_name: object,
    source_ip: object,
    destination_ip: object,
    filter_status: object,
    suppression_key: object = None,
) -> str:
    """Return the stable grouped-detection key used by the dashboard/API."""
    if suppression_key:
        return str(suppression_key)
    return "|".join([
        str(triage_level or "unknown-level"),
        str(rule_name or "unknown-rule"),
        str(source_ip or "unknown-source"),
        str(destination_ip or "unknown-destination"),
        str(filter_status or "accepted"),
    ])


def soc_alert_group_id(group_key: object) -> str:
    return hashlib.sha1(str(group_key or "").encode("utf-8")).hexdigest()[:12]


def soc_alert_group_key_sql() -> str:
    return """
      COALESCE(
        NULLIF(suppression_key, ''),
        COALESCE(triage_level, 'unknown-level') || '|' ||
        COALESCE(rule_name, 'unknown-rule') || '|' ||
        COALESCE(source_ip, 'unknown-source') || '|' ||
        COALESCE(destination_ip, 'unknown-destination') || '|' ||
        COALESCE(filter_status, 'accepted')
      )
    """


def sqlite_table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
    except sqlite3.Error:
        return False
    return bool(row)


def soc_alert_group_summary_available(conn: sqlite3.Connection) -> bool:
    """Return true when alert-store has populated the fast grouped summary."""
    if not sqlite_table_exists(conn, "alert_group_summary"):
        return False
    try:
        row = conn.execute("SELECT COUNT(*) FROM alert_group_summary").fetchone()
    except sqlite3.Error:
        return False
    return bool(row and int(row[0] or 0) > 0)


def soc_alert_group_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Return current grouped repeat counts, keyed by group_id."""
    if soc_alert_group_summary_available(conn):
        try:
            rows = conn.execute(
                """
                SELECT group_id,
                       MAX(raw_alert_count, COALESCE(total_seen_count, 0)) AS repeat_count
                FROM alert_group_summary
                """
            ).fetchall()
            return {row["group_id"]: int(row["repeat_count"] or 0) for row in rows}
        except sqlite3.Error:
            pass
    group_expr = soc_alert_group_key_sql()
    try:
        rows = conn.execute(
            f"""
            SELECT {group_expr} AS group_key,
                   MAX(COUNT(*), COALESCE(SUM(MAX(1, COALESCE(seen_count, 1))), 0)) AS repeat_count
            FROM alerts
            GROUP BY group_key
            """
        ).fetchall()
    except sqlite3.Error:
        return {}
    return {soc_alert_group_id(row["group_key"]): int(row["repeat_count"] or 0) for row in rows}


def normalize_soc_group_statuses(conn: sqlite3.Connection) -> dict:
    """Load current group state and auto-expire stale acknowledgements.

    Acknowledged detections should reappear when the matching grouped detection
    count increases. Suppressed detections remain hidden until explicitly
    exposed.
    """
    ensure_soc_alert_status_table(conn)
    counts = soc_alert_group_counts(conn)
    rows = conn.execute(
        """
        SELECT group_id, group_key, status, repeat_count, reason, updated_at, updated_by
        FROM analyst_alert_group_state
        WHERE status IN ('acknowledged', 'suppressed')
        """
    ).fetchall()
    statuses: dict[str, dict] = {}
    expired_acknowledged: list[str] = []
    for row in rows:
        group_id = row["group_id"]
        status = row["status"]
        repeat_count = int(row["repeat_count"] or 0)
        current_count = counts.get(group_id, repeat_count)
        if status == "acknowledged" and current_count > repeat_count:
            expired_acknowledged.append(group_id)
            continue
        statuses[group_id] = {
            "status": status,
            "repeat_count": repeat_count,
            "reason": row["reason"] or "",
            "updated_at": row["updated_at"],
            "updated_by": row["updated_by"] or "",
            "group_key": row["group_key"] or "",
        }
    if expired_acknowledged:
        conn.executemany("DELETE FROM analyst_alert_group_state WHERE group_id = ?", [(gid,) for gid in expired_acknowledged])
        conn.commit()
    return statuses


def load_soc_alert_statuses_from_db() -> dict:
    if not SOC_ALERT_STORE_DB.exists():
        return {}
    conn = sqlite3.connect(SOC_ALERT_STORE_DB, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        return normalize_soc_group_statuses(conn)
    except Exception:
        return {}
    finally:
        conn.close()


def save_soc_alert_statuses_to_db(statuses: dict) -> None:
    if not SOC_ALERT_STORE_DB.parent.exists():
        return
    conn = sqlite3.connect(SOC_ALERT_STORE_DB, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        ensure_soc_alert_status_table(conn)
        conn.execute("BEGIN")
        conn.execute("DELETE FROM analyst_alert_group_state")
        for alert_id, raw_meta in statuses.items():
            meta = normalize_soc_alert_status_meta(raw_meta)
            if not meta or meta["status"] == "open":
                continue
            group_id = str(alert_id)
            group_key = str(raw_meta.get("group_key") or "") if isinstance(raw_meta, dict) else ""
            conn.execute(
                """
                INSERT INTO analyst_alert_group_state (
                  group_id, group_key, status, repeat_count, reason, updated_at, updated_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(group_id) DO UPDATE SET
                  group_key = excluded.group_key,
                  status = excluded.status,
                  repeat_count = excluded.repeat_count,
                  reason = excluded.reason,
                  updated_at = excluded.updated_at,
                  updated_by = excluded.updated_by
                """,
                (
                    group_id,
                    group_key,
                    meta["status"],
                    meta["repeat_count"],
                    meta["reason"],
                    meta["updated_at"],
                    str(raw_meta.get("updated_by") or "")[:80] if isinstance(raw_meta, dict) else "",
                ),
            )
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        conn.close()


def load_soc_alert_statuses() -> dict:
    """Load shared SOC alert status state, using JSON only if SQLite is absent."""
    if SOC_ALERT_STORE_DB.exists():
        return load_soc_alert_statuses_from_db()
    json_statuses: dict = {}
    try:
        data = json.loads(SOC_ALERT_STATUS_FILE.read_text(encoding="utf-8"))
        statuses = data.get("statuses", {}) if isinstance(data, dict) else {}
        json_statuses = statuses if isinstance(statuses, dict) else {}
    except Exception:
        json_statuses = {}
    return json_statuses


def save_soc_alert_statuses(statuses: dict) -> None:
    normalized_statuses: dict[str, dict] = {}
    for alert_id, raw_meta in statuses.items():
        meta = normalize_soc_alert_status_meta(raw_meta)
        if meta and meta["status"] != "open":
            normalized_statuses[str(alert_id)] = meta
    save_soc_alert_statuses_to_db(normalized_statuses)
    SOC_ALERT_STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "ok": True,
        "updated_at": now_iso_utc(),
        "statuses": normalized_statuses,
    }
    tmp = SOC_ALERT_STATUS_FILE.with_suffix(SOC_ALERT_STATUS_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, SOC_ALERT_STATUS_FILE)
    try:
        SOC_ALERT_STATUS_FILE.chmod(0o600)
    except Exception:
        pass


def soc_alert_status_response() -> dict:
    statuses = load_soc_alert_statuses()
    acknowledged = sorted(
        alert_id for alert_id, meta in statuses.items()
        if isinstance(meta, dict) and meta.get("status") == "acknowledged"
    )
    suppressed = sorted(
        alert_id for alert_id, meta in statuses.items()
        if isinstance(meta, dict) and meta.get("status") == "suppressed"
    )
    counts = {"open": 0, "acknowledged": len(acknowledged), "suppressed": len(suppressed)}
    try:
        conn = sqlite3.connect(SOC_ALERT_STORE_DB, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            group_counts = soc_alert_group_counts(conn)
        finally:
            conn.close()
        counts["open"] = max(0, len(group_counts) - counts["acknowledged"] - counts["suppressed"])
        counts["total"] = len(group_counts)
    except Exception:
        counts["total"] = len(statuses)
    return {
        "ok": True,
        "mode": "grouped",
        "statuses": statuses,
        "acknowledged": acknowledged,
        "suppressed": suppressed,
        "counts": counts,
    }


def update_soc_alert_status(payload: dict) -> tuple[bool, dict]:
    statuses = load_soc_alert_statuses()
    now = now_iso_utc()

    def valid_id(value: object) -> str:
        alert_id = str(value or "").strip()
        if re.fullmatch(r"[a-f0-9]{12}", alert_id):
            return alert_id
        return valid_soc_alert_store_id(alert_id)

    if isinstance(payload.get("statuses"), dict):
        next_statuses: dict[str, dict] = {}
        for raw_id, raw_meta in payload.get("statuses", {}).items():
            alert_id = valid_id(raw_id)
            meta = normalize_soc_alert_status_meta(raw_meta, now=now)
            if not alert_id or not meta or meta["status"] == "open":
                continue
            next_statuses[alert_id] = meta
        save_soc_alert_statuses(next_statuses)
        return True, soc_alert_status_response()

    if isinstance(payload.get("acknowledged"), list):
        acknowledged = {valid_id(v) for v in payload.get("acknowledged", [])}
        acknowledged.discard("")
        for alert_id in list(statuses):
            if isinstance(statuses.get(alert_id), dict) and statuses[alert_id].get("status") in ("acknowledged", "open"):
                statuses[alert_id] = {
                    "status": "acknowledged" if alert_id in acknowledged else "open",
                    "repeat_count": int(statuses[alert_id].get("repeat_count") or 0),
                    "reason": str(statuses[alert_id].get("reason") or "")[:140],
                    "updated_at": now,
                }
        for alert_id in acknowledged:
            statuses[alert_id] = {"status": "acknowledged", "repeat_count": 0, "reason": "", "updated_at": now}
        save_soc_alert_statuses(statuses)
        return True, soc_alert_status_response()

    alert_id = valid_id(payload.get("id"))
    if not alert_id:
        return False, {"ok": False, "error": "Invalid SOC alert id"}
    raw_status = str(payload.get("status") or "").strip().lower()
    if not raw_status:
        raw_status = "acknowledged" if bool(payload.get("acknowledged")) else "open"
    if raw_status not in {"open", "acknowledged", "suppressed"}:
        return False, {"ok": False, "error": "Invalid SOC alert status"}
    try:
        repeat_count = max(0, int(payload.get("repeat_count") or payload.get("acknowledged_count") or 0))
    except (TypeError, ValueError):
        repeat_count = 0
    reason = str(payload.get("reason") or "").strip()[:140]
    if raw_status == "open":
        statuses.pop(alert_id, None)
    else:
        statuses[alert_id] = {"status": raw_status, "repeat_count": repeat_count, "reason": reason, "updated_at": now}
    save_soc_alert_statuses(statuses)
    return True, soc_alert_status_response()


def valid_soc_alert_store_id(value: object) -> str:
    alert_id = str(value or "").strip()
    # Security Onion/Elastic alert ids include index:id forms. Keep this URL-safe
    # and forbid path separators/control characters because ids are accepted from
    # dynamic API routes.
    if 1 <= len(alert_id) <= 256 and re.fullmatch(r"[A-Za-z0-9._:@=-]+", alert_id):
        return alert_id
    return ""


def soc_alert_api_error(message: str, status: int = 400) -> tuple[int, dict]:
    return status, {"ok": False, "error": message}


@contextmanager
def soc_alert_db_connect():
    if not SOC_ALERT_STORE_DB.exists():
        raise FileNotFoundError(f"SOC alert store DB not found: {SOC_ALERT_STORE_DB}")
    conn = sqlite3.connect(f"file:{SOC_ALERT_STORE_DB}?mode=ro", uri=True, timeout=2)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def parse_soc_alert_since(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    match = re.fullmatch(r"(\d{1,4})([mhdw])", raw)
    if match:
        amount = int(match.group(1))
        unit = match.group(2)
        delta = {
            "m": dt.timedelta(minutes=amount),
            "h": dt.timedelta(hours=amount),
            "d": dt.timedelta(days=amount),
            "w": dt.timedelta(weeks=amount),
        }[unit]
        return format_iso_timestamp(dt.datetime.now(dt.timezone.utc) - delta, utc_z=True)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}t\d{2}:\d{2}(:\d{2})?z?", raw):
        return ISO_DATE_TIME_SEPARATOR_RE.sub(r"\1  ", raw.upper() if raw.endswith("z") else raw.upper() + "Z")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        return raw + "  00:00:00Z"
    return ""


def soc_alert_level_names(raw: str) -> list[str]:
    levels: list[str] = []
    for part in str(raw or "").split(","):
        level = part.strip().lower()
        if level in SOC_ALERT_LEVEL_RANK:
            levels.append("informational" if level == "info" else level)
    return sorted(set(levels), key=lambda x: SOC_ALERT_LEVEL_RANK.get(x, 0), reverse=True)


def soc_alert_limit(raw: object, default: int = 100) -> int:
    try:
        value = int(str(raw or default))
    except ValueError:
        value = default
    return max(1, min(SOC_ALERT_API_MAX_LIMIT, value))


def soc_alert_page(raw: object) -> int:
    try:
        value = int(str(raw or 1))
    except ValueError:
        value = 1
    return max(1, value)


SOC_ALERT_SORT_SQL = {
    "count": "COALESCE(total_seen_count, raw_alert_count, seen_count, 0)",
    "severity": "CASE lower(coalesce(triage_level, severity_label, 'informational')) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'informational' THEN 1 WHEN 'info' THEN 1 ELSE 0 END",
    "last_seen": "replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '')",
    "alert": "lower(coalesce(rule_name, ''))",
    "source_ip": "lower(coalesce(source_ip, ''))",
    "destination_ip": "lower(coalesce(destination_ip, ''))",
    "destination_port": "CAST(COALESCE(destination_port, '') AS INTEGER)",
    "ai": "'not-queued'",
    "log_source": "lower(coalesce(event_dataset, ''))",
    "size": "COALESCE(payload_size_bytes, 0)",
    "risk": "COALESCE(triage_score, 0)",
}


def soc_alert_sort_clause(query: dict[str, list[str]], *, fallback: bool = False) -> tuple[str, str, str]:
    """Return an allowlisted ORDER BY clause for grouped alert table sorting."""
    raw_sort = str((query.get("sort") or ["last_seen"])[0]).strip().lower().replace("-", "_")
    direction = str((query.get("direction") or query.get("dir") or ["desc"])[0]).strip().lower()
    if direction not in {"asc", "desc"}:
        direction = "desc"
    if raw_sort not in SOC_ALERT_SORT_SQL:
        raw_sort = "last_seen"
    expression = SOC_ALERT_SORT_SQL[raw_sort]
    if fallback:
        expression = "COALESCE(payload_size_bytes, LENGTH(COALESCE(alert_json, '')), 0)" if raw_sort == "size" else expression
    tie = "ASC" if direction == "asc" else "DESC"
    id_column = "group_key" if fallback else "group_id"
    return raw_sort, direction, f"{expression} {direction.upper()}, replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC, {id_column} {tie}"


def soc_alert_cursor_parts(raw: str) -> tuple[str, str]:
    cursor = str(raw or "")
    if "|" not in cursor:
        return "", ""
    last_seen, alert_id = cursor.split("|", 1)
    return (last_seen.strip(), valid_soc_alert_store_id(alert_id))


def soc_alert_row_to_api(row: sqlite3.Row, include_payload: bool = False) -> dict:
    alert_id = row["alert_id"]
    statuses = load_soc_alert_statuses()
    local_status = statuses.get(alert_id, {}) if isinstance(statuses, dict) else {}
    data = {
        "alert_id": alert_id,
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "seen_count": row["seen_count"],
        "timestamp": row["timestamp"],
        "rule_name": row["rule_name"],
        "event_dataset": row["event_dataset"],
        "severity": row["severity"],
        "severity_label": row["severity_label"],
        "triage_score": row["triage_score"],
        "triage_level": row["triage_level"],
        "routing": row["routing"],
        "traffic_direction": row["traffic_direction"],
        "source_ip": row["source_ip"],
        "destination_ip": row["destination_ip"],
        "filter_status": row["filter_status"] or "accepted",
        "filter_reason": row["filter_reason"],
        "suppression_key": row["suppression_key"],
        "analyst_status": local_status.get("status", "open") if isinstance(local_status, dict) else "open",
        "analyst_status_reason": local_status.get("reason") if isinstance(local_status, dict) else "",
        "analyst_status_updated_at": local_status.get("updated_at") if isinstance(local_status, dict) else None,
    }
    if include_payload:
        try:
            data["alert"] = json.loads(row["alert_json"] or "{}")
        except Exception:
            data["alert"] = None
    return data


def soc_alert_group_row_to_api(row: sqlite3.Row, statuses: dict) -> dict:
    group_key = row["group_key"]
    group_id = soc_alert_group_id(group_key)
    local_status = statuses.get(group_id, {}) if isinstance(statuses, dict) else {}
    repeat_count = max(
        int(row["raw_alert_count"] or 0),
        int(row["total_seen_count"] or 0),
        int(row["seen_count"] or 0),
    )
    return {
        "group_id": group_id,
        "group_key": group_key,
        "representative_alert_id": row["alert_id"],
        "first_seen": row["group_first_seen"] or row["first_seen"],
        "last_seen": row["group_last_seen"] or row["last_seen"],
        "raw_alert_count": int(row["raw_alert_count"] or 0),
        "seen_count": repeat_count,
        "timestamp": row["timestamp"],
        "rule_name": row["rule_name"],
        "event_dataset": row["event_dataset"],
        "severity": row["severity"],
        "severity_label": row["severity_label"],
        "triage_score": row["triage_score"],
        "triage_level": row["triage_level"],
        "routing": row["routing"],
        "traffic_direction": row["traffic_direction"],
        "source_ip": row["source_ip"],
        "source_port": row["source_port"],
        "destination_ip": row["destination_ip"],
        "destination_port": row["destination_port"],
        "payload_size_bytes": int(row["payload_size_bytes"] or 0) if "payload_size_bytes" in row.keys() else 0,
        "transport_protocol": row["transport_protocol"],
        "filter_status": row["filter_status"] or "accepted",
        "filter_reason": row["filter_reason"],
        "suppression_key": row["suppression_key"],
        "analyst_status": local_status.get("status", "open") if isinstance(local_status, dict) else "open",
        "analyst_status_reason": local_status.get("reason", "") if isinstance(local_status, dict) else "",
        "analyst_status_updated_at": local_status.get("updated_at") if isinstance(local_status, dict) else None,
        "analyst_status_updated_by": local_status.get("updated_by", "") if isinstance(local_status, dict) else "",
    }


def soc_alerts_summary_query_response(query: dict[str, list[str]]) -> tuple[int, dict] | None:
    """Serve grouped alert rows from alert_group_summary when available.

    The fallback grouped query below remains useful for old/restored databases,
    but this summary path keeps the hot dashboard API off full-table window
    functions during normal operation.
    """
    since = parse_soc_alert_since((query.get("since") or [""])[0])
    levels = soc_alert_level_names((query.get("level") or query.get("levels") or [""])[0])
    filter_status = str((query.get("filter_status") or query.get("status") or [""])[0]).strip().lower()
    analyst_status = str((query.get("analyst_status") or [""])[0]).strip().lower()
    q = str((query.get("q") or query.get("search") or [""])[0]).strip()
    cursor_seen, cursor_id = soc_alert_cursor_parts((query.get("cursor") or [""])[0])
    limit = soc_alert_limit((query.get("limit") or [""])[0])
    requested_page = soc_alert_page((query.get("page") or ["1"])[0])
    sort_key, sort_direction, order_sql = soc_alert_sort_clause(query)

    where = []
    args: list[object] = []
    if since:
        where.append("last_seen >= ?")
        args.append(since)
    if levels:
        placeholders = ",".join("?" for _ in levels)
        where.append(f"lower(coalesce(triage_level, severity_label, 'unknown')) in ({placeholders})")
        args.extend(levels)
    if filter_status in {"accepted", "suppressed", "dropped", "duplicate"}:
        where.append("lower(coalesce(filter_status, 'accepted')) = ?")
        args.append(filter_status)
    if q:
        where.append(
            "("
            "rule_name like ? or source_ip like ? or destination_ip like ? or "
            "event_dataset like ? or representative_alert_id like ? or group_key like ?"
            ")"
        )
        like = f"%{q}%"
        args.extend([like, like, like, like, like, like])
    where_sql = " WHERE " + " AND ".join(where) if where else ""
    sql = f"""
        SELECT group_id, group_key, representative_alert_id AS alert_id,
               first_seen AS group_first_seen, first_seen,
               last_seen AS group_last_seen, last_seen,
               raw_alert_count, total_seen_count, total_seen_count AS seen_count,
               timestamp, rule_name, event_dataset, severity, severity_label,
               source_ip, source_port, destination_ip, destination_port,
               transport_protocol, traffic_direction, triage_score, triage_level,
               routing, filter_status, filter_reason, suppression_key,
               (
                 SELECT LENGTH(COALESCE(alert_json, ''))
                 FROM alerts
                 WHERE alert_id = alert_group_summary.representative_alert_id
                 LIMIT 1
               ) AS payload_size_bytes
        FROM alert_group_summary
        {where_sql}
        ORDER BY {order_sql}
    """
    try:
        with soc_alert_db_connect() as conn:
            if not soc_alert_group_summary_available(conn):
                return None
            rows = conn.execute(sql, args).fetchall()
    except Exception as e:
        return soc_alert_api_error(str(e), 503)

    statuses = load_soc_alert_statuses()
    filtered_rows = []
    for row in rows:
        group_id = row["group_id"] or soc_alert_group_id(row["group_key"])
        current_status = (statuses.get(group_id, {}) or {}).get("status", "open") if isinstance(statuses, dict) else "open"
        if analyst_status in {"open", "new"} and current_status != "open":
            continue
        if analyst_status in {"acknowledged", "suppressed"} and current_status != analyst_status:
            continue
        if cursor_seen and cursor_id:
            group_last_seen = row["group_last_seen"] or row["last_seen"] or ""
            if not (group_last_seen < cursor_seen or (group_last_seen == cursor_seen and group_id < cursor_id)):
                continue
        filtered_rows.append(row)

    total_matching = len(filtered_rows)
    total_pages = max(1, (total_matching + limit - 1) // limit)
    current_page = min(requested_page, total_pages)
    offset = (current_page - 1) * limit
    page_rows = filtered_rows[offset:offset + limit]
    next_cursor = None
    if len(filtered_rows) > offset + limit and page_rows:
        tail = page_rows[-1]
        next_cursor = f"{tail['group_last_seen'] or tail['last_seen']}|{tail['group_id'] or soc_alert_group_id(tail['group_key'])}"
    return 200, {
        "ok": True,
        "source": "sqlite-summary",
        "mode": "grouped",
        "db_path": str(SOC_ALERT_STORE_DB),
        "count": len(page_rows),
        "total_matching": total_matching,
        "limit": limit,
        "page": current_page,
        "page_size": limit,
        "total_pages": total_pages,
        "sort": sort_key,
        "direction": sort_direction,
        "next_cursor": next_cursor,
        "alerts": [soc_alert_group_row_to_api(row, statuses) for row in page_rows],
    }


def soc_alerts_query_response(query: dict[str, list[str]]) -> tuple[int, dict]:
    summary_response = soc_alerts_summary_query_response(query)
    if summary_response is not None:
        return summary_response

    since = parse_soc_alert_since((query.get("since") or [""])[0])
    levels = soc_alert_level_names((query.get("level") or query.get("levels") or [""])[0])
    filter_status = str((query.get("filter_status") or query.get("status") or [""])[0]).strip().lower()
    analyst_status = str((query.get("analyst_status") or [""])[0]).strip().lower()
    q = str((query.get("q") or query.get("search") or [""])[0]).strip()
    cursor_seen, cursor_id = soc_alert_cursor_parts((query.get("cursor") or [""])[0])
    limit = soc_alert_limit((query.get("limit") or [""])[0])
    requested_page = soc_alert_page((query.get("page") or ["1"])[0])
    sort_key, sort_direction, order_sql = soc_alert_sort_clause(query, fallback=True)

    where = []
    args: list[object] = []
    if since:
        where.append("last_seen >= ?")
        args.append(since)
    if levels:
        placeholders = ",".join("?" for _ in levels)
        where.append(f"lower(coalesce(triage_level, severity_label, 'unknown')) in ({placeholders})")
        args.extend(levels)
    if filter_status in {"accepted", "suppressed", "dropped"}:
        where.append("lower(coalesce(filter_status, 'accepted')) = ?")
        args.append(filter_status)
    if q:
        where.append("(rule_name like ? or source_ip like ? or destination_ip like ? or alert_json like ?)")
        like = f"%{q}%"
        args.extend([like, like, like, like])
    where_sql = " where " + " and ".join(where) if where else ""
    group_expr = soc_alert_group_key_sql()
    sql = f"""
        WITH ranked AS (
          SELECT alert_id, first_seen, last_seen, seen_count, timestamp, rule_name,
                 event_dataset, severity, severity_label, source_ip, source_port,
                 destination_ip, destination_port, transport_protocol,
                 traffic_direction, triage_score, triage_level, routing, filter_status,
                 filter_reason, suppression_key, alert_json,
                 LENGTH(COALESCE(alert_json, '')) AS payload_size_bytes,
                 {group_expr} AS group_key,
                 COUNT(*) OVER (PARTITION BY {group_expr}) AS raw_alert_count,
                 SUM(MAX(1, COALESCE(seen_count, 1))) OVER (PARTITION BY {group_expr}) AS total_seen_count,
                 MIN(first_seen) OVER (PARTITION BY {group_expr}) AS group_first_seen,
                 MAX(last_seen) OVER (PARTITION BY {group_expr}) AS group_last_seen,
                 ROW_NUMBER() OVER (
                   PARTITION BY {group_expr}
                   ORDER BY replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC,
                            alert_id DESC
                 ) AS rn
          FROM alerts
          {where_sql}
        )
        SELECT *
        FROM ranked
        WHERE rn = 1
        ORDER BY {order_sql}
    """
    try:
        with soc_alert_db_connect() as conn:
            rows = conn.execute(sql, args).fetchall()
    except Exception as e:
        return soc_alert_api_error(str(e), 503)

    statuses = load_soc_alert_statuses()
    filtered_rows = []
    for row in rows:
        group_id = soc_alert_group_id(row["group_key"])
        current_status = (statuses.get(group_id, {}) or {}).get("status", "open") if isinstance(statuses, dict) else "open"
        if analyst_status in {"open", "new"} and current_status != "open":
            continue
        if analyst_status in {"acknowledged", "suppressed"} and current_status != analyst_status:
            continue
        if cursor_seen and cursor_id:
            group_last_seen = row["group_last_seen"] or row["last_seen"] or ""
            if not (group_last_seen < cursor_seen or (group_last_seen == cursor_seen and group_id < cursor_id)):
                continue
        filtered_rows.append(row)

    total_matching = len(filtered_rows)
    total_pages = max(1, (total_matching + limit - 1) // limit)
    current_page = min(requested_page, total_pages)
    offset = (current_page - 1) * limit
    page_rows = filtered_rows[offset:offset + limit]
    next_cursor = None
    if len(filtered_rows) > offset + limit and page_rows:
        tail = page_rows[-1]
        next_cursor = f"{tail['group_last_seen'] or tail['last_seen']}|{soc_alert_group_id(tail['group_key'])}"
    return 200, {
        "ok": True,
        "source": "sqlite",
        "mode": "grouped",
        "db_path": str(SOC_ALERT_STORE_DB),
        "count": len(page_rows),
        "total_matching": total_matching,
        "limit": limit,
        "page": current_page,
        "page_size": limit,
        "total_pages": total_pages,
        "sort": sort_key,
        "direction": sort_direction,
        "next_cursor": next_cursor,
        "alerts": [soc_alert_group_row_to_api(row, statuses) for row in page_rows],
    }


def soc_alert_detail_fragment_response(group_id: str) -> tuple[int, dict]:
    group_id = str(group_id or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{12}", group_id):
        return soc_alert_api_error("Invalid SOC alert group id")
    detail_path = SOC_ALERT_DETAIL_DIR / f"{group_id}.html"
    try:
        base = SOC_ALERT_DETAIL_DIR.resolve()
        target = detail_path.resolve()
    except Exception:
        return soc_alert_api_error("SOC alert detail path unavailable", 503)
    if base not in target.parents or target.suffix != ".html":
        return soc_alert_api_error("Invalid SOC alert detail path")
    if not target.exists():
        return soc_alert_api_error("SOC alert detail fragment not found", 404)
    try:
        detail_html = target.read_text(encoding="utf-8")
    except OSError as exc:
        return soc_alert_api_error(str(exc), 503)
    return 200, {
        "ok": True,
        "source": "detail-fragment",
        "group_id": group_id,
        "detail_html": detail_html,
    }


def soc_alert_detail_response(alert_id: str) -> tuple[int, dict]:
    alert_id = valid_soc_alert_store_id(alert_id)
    if not alert_id:
        return soc_alert_api_error("Invalid SOC alert id")
    try:
        with soc_alert_db_connect() as conn:
            row = conn.execute("""
                select alert_id, first_seen, last_seen, seen_count, timestamp, rule_name,
                       event_dataset, severity, severity_label, source_ip, destination_ip,
                       traffic_direction, triage_score, triage_level, routing, filter_status,
                       filter_reason, suppression_key, alert_json
                from alerts where alert_id = ?
            """, (alert_id,)).fetchone()
    except Exception as e:
        return soc_alert_api_error(str(e), 503)
    if not row:
        return soc_alert_api_error("SOC alert not found", 404)
    return 200, {"ok": True, "source": "sqlite", "alert": soc_alert_row_to_api(row, include_payload=True)}


def soc_alert_metrics_response(query: dict[str, list[str]]) -> tuple[int, dict]:
    since = parse_soc_alert_since((query.get("since") or ["24h"])[0])
    where = " where last_seen >= ?" if since else ""
    args = [since] if since else []
    group_expr = soc_alert_group_key_sql()
    metrics_source = "sqlite"
    try:
        with soc_alert_db_connect() as conn:
            total = conn.execute(f"select count(*) from alerts{where}", args).fetchone()[0]
            latest = conn.execute(f"select max(last_seen) from alerts{where}", args).fetchone()[0]
            if soc_alert_group_summary_available(conn):
                metrics_source = "sqlite-summary"
                summary_where = " where last_seen >= ?" if since else ""
                grouped_rows = conn.execute(
                    f"""
                    SELECT group_id, group_key, raw_alert_count, total_seen_count, last_seen
                    FROM alert_group_summary
                    {summary_where}
                    """,
                    args,
                ).fetchall()
            else:
                grouped_rows = conn.execute(
                    f"""
                    SELECT {group_expr} AS group_key,
                           COUNT(*) AS raw_alert_count,
                           COALESCE(SUM(MAX(1, COALESCE(seen_count, 1))), 0) AS total_seen_count,
                           MAX(last_seen) AS last_seen
                    FROM alerts
                    {where}
                    GROUP BY group_key
                    """,
                    args,
                ).fetchall()
            by_filter = {r[0] or "accepted": r[1] for r in conn.execute(f"select coalesce(filter_status, 'accepted'), count(*) from alerts{where} group by coalesce(filter_status, 'accepted')", args)}
            by_level = {r[0] or "unknown": r[1] for r in conn.execute(f"select coalesce(triage_level, severity_label, 'unknown'), count(*) from alerts{where} group by coalesce(triage_level, severity_label, 'unknown')", args)}
            top_rules = [dict(rule_name=r[0] or "unknown", count=r[1]) for r in conn.execute(f"select coalesce(rule_name, 'unknown'), count(*) from alerts{where} group by coalesce(rule_name, 'unknown') order by count(*) desc limit 10", args)]
            suppression_windows = conn.execute("select count(*), coalesce(sum(suppressed_count), 0), coalesce(sum(escalated_count), 0) from suppression_log").fetchone()
    except Exception as e:
        return soc_alert_api_error(str(e), 503)
    statuses = load_soc_alert_statuses()
    by_analyst_status = {"open": 0, "acknowledged": 0, "suppressed": 0}
    grouped_observations = 0
    for row in grouped_rows:
        group_id = soc_alert_group_id(row["group_key"])
        status = (statuses.get(group_id, {}) or {}).get("status", "open") if isinstance(statuses, dict) else "open"
        if status not in by_analyst_status:
            status = "open"
        by_analyst_status[status] += 1
        grouped_observations += max(int(row["raw_alert_count"] or 0), int(row["total_seen_count"] or 0))
    return 200, {
        "ok": True,
        "source": metrics_source,
        "mode": "grouped",
        "since": since or None,
        "total": total,
        "grouped_total": len(grouped_rows),
        "grouped_observations": grouped_observations,
        "latest_seen": latest,
        "by_filter_status": by_filter,
        "by_analyst_status": by_analyst_status,
        "by_level": by_level,
        "top_rules": top_rules,
        "suppression_log": {
            "windows": suppression_windows[0],
            "suppressed_count": suppression_windows[1],
            "escalated_count": suppression_windows[2],
        },
    }


def soc_alert_suppressions_response(query: dict[str, list[str]]) -> tuple[int, dict]:
    limit = soc_alert_limit((query.get("limit") or [100])[0])
    try:
        with soc_alert_db_connect() as conn:
            rows = conn.execute("""
                select suppression_key, rule_name, reason, window_start, last_seen,
                       seen_count, suppressed_count, escalated_count, ttl_seconds,
                       escalation_threshold
                from suppression_log
                order by last_seen desc, suppression_key asc
                limit ?
            """, (limit,)).fetchall()
    except Exception as e:
        return soc_alert_api_error(str(e), 503)
    return 200, {"ok": True, "source": "sqlite", "count": len(rows), "suppressions": [dict(row) for row in rows]}


def read_soc_alert_json_file(path: Path) -> dict:
    try:
        if path.exists() and path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}
    return {}


def soc_alert_events_snapshot() -> dict:
    analyst_status = soc_alert_status_response()
    static_status = read_soc_alert_json_file(SOC_ALERT_STATIC_STATUS_FILE)
    beacon = read_soc_alert_json_file(SOC_ALERT_N8N_BEACON_FILE)
    metrics_status, metrics = soc_alert_metrics_response({"since": ["7d"]})
    if metrics_status != 200:
        metrics = {"ok": False, "error": metrics.get("error", "SOC alert metrics unavailable")}
    return {
        "ok": True,
        "event": "soc-alerts",
        "time": now_iso_utc(),
        "counts": analyst_status.get("counts", {}),
        "statuses": analyst_status.get("statuses", {}),
        "ai": static_status.get("ai", {}),
        "reports": static_status.get("reports", {}),
        "status_updated_at": static_status.get("updated_at"),
        "metrics": metrics,
        "beacon": beacon,
    }


def ack_soc_alert_store_id(alert_id: str, payload: dict) -> tuple[int, dict]:
    alert_id = valid_soc_alert_store_id(alert_id)
    if not alert_id:
        return soc_alert_api_error("Invalid SOC alert id")
    payload = {**payload, "id": alert_id}
    ok, data = update_soc_alert_status(payload)
    status = HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST
    if ok:
        alert_status = load_soc_alert_statuses().get(alert_id, {})
        data = {
            **data,
            "alert_id": alert_id,
            "analyst_status": alert_status.get("status", "open") if isinstance(alert_status, dict) else "open",
            "analyst_status_reason": alert_status.get("reason", "") if isinstance(alert_status, dict) else "",
        }
    return int(status), data


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "ArronReportPortal/1.0"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args))

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8", extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, extra: dict[str, str] | None = None, status: HTTPStatus = HTTPStatus.FOUND) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()

    def _serve_file(self, target: Path) -> None:
        if not target.is_file():
            return self._send(HTTPStatus.NOT_FOUND, b"Asset not found", "text/plain; charset=utf-8")
        try:
            body = target.read_bytes()
        except Exception as e:
            return self._send(HTTPStatus.INTERNAL_SERVER_ERROR, str(e).encode(), "text/plain; charset=utf-8")
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if target.suffix.lower() in (".html", ".htm"):
            ctype = "text/html; charset=utf-8"
        return self._send(HTTPStatus.OK, body, ctype)

    def _send_soc_alert_events(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        last_digest = ""
        # Recycle the stream periodically so browser EventSource reconnect logic
        # can recover from stale LAN connections without user interaction.
        for _ in range(150):
            try:
                payload = soc_alert_events_snapshot()
                raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
                digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()
                if digest != last_digest:
                    event_id = str(int(time.time()))
                    self.wfile.write(f"id: {event_id}\nevent: soc-alerts\ndata: {raw}\n\n".encode("utf-8"))
                    last_digest = digest
                else:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
                time.sleep(2)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

    def reports_by_id(self) -> dict[str, Report]:
        return {r.rid: r for r in scan_reports()}

    def _admin_session_id(self) -> str:
        return parse_cookie_header(self.headers.get("Cookie")).get(ADMIN_SESSION_COOKIE, "")

    def _admin_authenticated(self) -> bool:
        session_id = self._admin_session_id()
        if not session_id:
            return False
        sessions = prune_admin_sessions()
        return admin_session_hash(session_id) in sessions

    def _require_admin_auth(self) -> bool:
        if self._admin_authenticated():
            return True
        self._redirect("/admin/login")
        return False

    def do_HEAD(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html", "/healthz", "/api/reports", "/api/soc-alerts", "/api/soc-alerts/events", "/api/soc-alerts/metrics", "/api/soc-alerts/suppressions", "/api/soc-alerts/status", "/api/soc-settings/analyst-prompt", "/api/soc-settings/ai-model", "/api/soc-settings/ollama-models", "/api/resource-library/favorites", "/admin", "/admin/login") or (parsed.path.startswith("/api/soc-alerts/") and not parsed.path.endswith("/ack")):
            if parsed.path == "/admin" and not self._admin_authenticated():
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/admin/login")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            self.send_response(HTTPStatus.OK)
            content_type = "text/html; charset=utf-8" if parsed.path in ("/", "/index.html", "/admin", "/admin/login") else "application/json; charset=utf-8"
            if parsed.path == "/api/soc-alerts/events":
                content_type = "text/event-stream; charset=utf-8"
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path not in ("/admin/login", "/admin/logout", "/admin/action", "/api/admin/start-service", "/api/soc-alerts/status", "/api/soc-settings/analyst-prompt", "/api/soc-settings/ai-model", "/api/resource-library/remove", "/api/resource-library/tags", "/api/resource-library/rename", "/api/resource-library/favorite") and not (parsed.path.startswith("/api/soc-alerts/") and parsed.path.endswith("/ack")):
            return self._send(HTTPStatus.NOT_FOUND, b"Not found", "text/plain; charset=utf-8")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 50000:
            if parsed.path == "/api/admin/start-service":
                return self._send(HTTPStatus.BAD_REQUEST, json.dumps({"ok": False, "error": "Invalid request size"}).encode(), "application/json; charset=utf-8")
            if parsed.path in ("/api/soc-alerts/status", "/api/soc-settings/analyst-prompt", "/api/soc-settings/siem-engineer-prompt", "/api/soc-settings/ai-model") or (parsed.path.startswith("/api/soc-alerts/") and parsed.path.endswith("/ack")):
                return self._send(HTTPStatus.BAD_REQUEST, json.dumps({"ok": False, "error": "Invalid request size"}).encode(), "application/json; charset=utf-8")
            if parsed.path.startswith("/api/resource-library/"):
                return self._send(HTTPStatus.BAD_REQUEST, json.dumps({"ok": False, "error": "Invalid request size"}).encode(), "application/json; charset=utf-8")
            if parsed.path == "/admin/action" and self._admin_authenticated():
                return self._send(HTTPStatus.BAD_REQUEST, render_admin_dashboard("Invalid admin action request size.", True))
            return self._send(HTTPStatus.BAD_REQUEST, render_admin_login("Invalid request size.", True))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        if parsed.path.startswith("/api/soc-alerts/") and parsed.path.endswith("/ack"):
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            encoded_id = parsed.path[len("/api/soc-alerts/"):-len("/ack")].strip("/")
            status, data = ack_soc_alert_store_id(unquote(encoded_id), payload)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/soc-alerts/status":
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            ok, data = update_soc_alert_status(payload)
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/soc-settings/analyst-prompt":
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            if not self._admin_authenticated():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in to Administration before saving SOC settings."}).encode(), "application/json; charset=utf-8")
            ok, data = save_soc_analyst_prompt(payload.get("prompt", ""))
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/soc-settings/siem-engineer-prompt":
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            if not self._admin_authenticated():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in to Administration before saving SOC settings."}).encode(), "application/json; charset=utf-8")
            ok, data = save_siem_engineer_prompt(payload.get("prompt", ""))
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/soc-settings/ai-model":
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            if not self._admin_authenticated():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in to Administration before saving SOC settings."}).encode(), "application/json; charset=utf-8")
            ok, data = save_soc_ai_settings(payload)
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path == "/api/admin/start-service":
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            if not self._admin_authenticated():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in before starting services."}).encode(), "application/json; charset=utf-8")
            if str(payload.get("token", "")) != ensure_admin_token():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Admin action token validation failed."}).encode(), "application/json; charset=utf-8")
            service_id = str(payload.get("service", "")).strip()
            ok, message, status = start_admin_service(service_id)
            body = {"ok": ok, "message": message, "service": status}
            if not ok:
                body["error"] = message
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(body, indent=2).encode(), "application/json; charset=utf-8")
        if parsed.path.startswith("/api/resource-library/"):
            try:
                payload = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload = {}
            if parsed.path == "/api/resource-library/remove":
                ok, data = move_resource_to_removal(str(payload.get("id", "")).strip(), str(payload.get("source", "")).strip())
            elif parsed.path == "/api/resource-library/tags":
                ok, data = set_resource_tags(str(payload.get("id", "")).strip(), payload.get("tags", []))
            elif parsed.path == "/api/resource-library/rename":
                ok, data = rename_resource_file(str(payload.get("id", "")).strip(), str(payload.get("source", "")).strip(), str(payload.get("new_name", "")).strip())
            elif parsed.path == "/api/resource-library/favorite":
                ok, data = set_resource_favorite(str(payload.get("id", "")).strip(), bool(payload.get("favorite")))
            else:
                ok, data = False, {"ok": False, "error": "Unknown Resource Library API"}
            return self._send(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        form = parse_qs(raw, keep_blank_values=True)
        token = form.get("token", [""])[0]
        if token != ensure_admin_token():
            if parsed.path == "/admin/action" and self._admin_authenticated():
                return self._send(HTTPStatus.FORBIDDEN, render_admin_dashboard("Admin action token validation failed.", True))
            return self._send(HTTPStatus.FORBIDDEN, render_admin_login("Form token validation failed.", True))
        if parsed.path == "/admin/login":
            if not admin_password_configured():
                return self._send(HTTPStatus.SERVICE_UNAVAILABLE, render_admin_login("Admin password is not configured yet. Run the local password setup script first.", True))
            password = form.get("password", [""])[0]
            if not verify_admin_password(password):
                return self._send(HTTPStatus.UNAUTHORIZED, render_admin_login("Invalid admin password.", True))
            session_id = create_admin_session(self.client_address[0])
            return self._redirect("/admin", {"Set-Cookie": admin_session_cookie_header(session_id)})
        if parsed.path == "/admin/logout":
            destroy_admin_session(self._admin_session_id())
            return self._redirect("/admin/login", {"Set-Cookie": expired_admin_session_cookie_header()})
        if not self._admin_authenticated():
            return self._send(HTTPStatus.FORBIDDEN, render_admin_login("Sign in before running Administration actions.", True))
        action_id = form.get("action", [""])[0]
        confirmation = form.get("confirmation", [""])[0]
        ok, message = start_admin_action(action_id, confirmation)
        query = f"?{'admin_msg' if ok else 'admin_error'}={quote(message)}"
        return self._redirect(f"/admin{query}", status=HTTPStatus.SEE_OTHER)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)
        reports = scan_reports()
        if path == "/" or path == "/index.html":
            body = render_home(reports, self.server.server_address[0], self.server.server_address[1])
            return self._send(HTTPStatus.OK, body)
        if path == "/admin/login":
            if self._admin_authenticated():
                return self._redirect("/admin")
            return self._send(HTTPStatus.OK, render_admin_login())
        if path == "/admin":
            if not self._require_admin_auth():
                return None
            admin_message = (query.get("admin_msg") or [""])[0]
            admin_error = (query.get("admin_error") or [""])[0]
            return self._send(HTTPStatus.OK, render_admin_dashboard(admin_message or admin_error, bool(admin_error)))
        if path == "/healthz":
            roots = []
            for root in SCAN_ROOTS:
                info = {"path": str(root), "exists": root.exists(), "is_dir": root.is_dir(), "html_here": 0, "error": None}
                try:
                    info["html_here"] = len(list(root.glob("*.html"))) if root.exists() else 0
                except Exception as e:
                    info["error"] = repr(e)
                roots.append(info)
            data = {"ok": True, "reports": len(reports), "ip": local_ip(), "time": now_iso_local(), "roots": roots}
            return self._send(HTTPStatus.OK, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/admin/service-status":
            if not self._admin_authenticated():
                return self._send(HTTPStatus.FORBIDDEN, json.dumps({"ok": False, "error": "Sign in before reading Administration service status."}).encode(), "application/json; charset=utf-8")
            return self._send(HTTPStatus.OK, json.dumps(defang_admin_service_json(admin_service_statuses()), indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/resource-library/favorites":
            data = {"ok": True, "favorites": resource_favorites()}
            return self._send(HTTPStatus.OK, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-alerts/events":
            return self._send_soc_alert_events()
        if path == "/api/soc-alerts/status":
            return self._send(HTTPStatus.OK, json.dumps(soc_alert_status_response(), indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-settings/analyst-prompt":
            data = read_soc_analyst_prompt()
            return self._send(HTTPStatus.OK if data.get("ok") else HTTPStatus.INTERNAL_SERVER_ERROR, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-settings/siem-engineer-prompt":
            data = read_siem_engineer_prompt()
            return self._send(HTTPStatus.OK if data.get("ok") else HTTPStatus.INTERNAL_SERVER_ERROR, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-settings/ai-model":
            data = read_soc_ai_settings()
            return self._send(HTTPStatus.OK if data.get("ok") else HTTPStatus.INTERNAL_SERVER_ERROR, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-settings/ollama-models":
            return self._send(HTTPStatus.OK, json.dumps(ollama_models_response(), indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-alerts":
            status, data = soc_alerts_query_response(query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-alerts/metrics":
            status, data = soc_alert_metrics_response(query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/soc-alerts/suppressions":
            status, data = soc_alert_suppressions_response(query)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path.startswith("/api/soc-alerts/") and path.endswith("/detail"):
            group_id = unquote(path[len("/api/soc-alerts/"):-len("/detail")].strip("/"))
            status, data = soc_alert_detail_fragment_response(group_id)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path.startswith("/api/soc-alerts/"):
            alert_id = unquote(path[len("/api/soc-alerts/"):].strip("/"))
            status, data = soc_alert_detail_response(alert_id)
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/resource-library/action-status":
            action_id = (query.get("id") or [""])[0]
            if not re.fullmatch(r"[a-f0-9-]{32,36}", action_id):
                return self._send(HTTPStatus.BAD_REQUEST, json.dumps({"ok": False, "error": "Invalid action id"}).encode(), "application/json; charset=utf-8")
            status_path = RESOURCE_LIBRARY_ACTION_STATUS_DIR / f"{action_id}.json"
            if not status_path.exists():
                return self._send(HTTPStatus.OK, json.dumps({"ok": True, "state": "pending"}).encode(), "application/json; charset=utf-8")
            return self._send(HTTPStatus.OK, status_path.read_bytes(), "application/json; charset=utf-8")
        if path == "/api/reports":
            data = [{"id": r.rid, "title": r.title, "path": r.rel, "category": r.category, "mtime": r.mtime, "size": r.size} for r in reports]
            return self._send(HTTPStatus.OK, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        metric_routes = {
            "/metrics/system-uptime": lambda: render_system_uptime_detail(),
            "/metrics/updates": lambda: render_prioritized_updates_detail(),
            "/metrics/macos-updates": lambda: render_macos_updates_detail(),
            "/metrics/hermes-backups": lambda: render_hermes_backups_detail(),
            "/metrics/local-disk": lambda: render_local_disk_detail(),
            "/metrics/portal-update": lambda: render_portal_update_detail(reports),
        }
        if path in metric_routes:
            return self._send(HTTPStatus.OK, metric_routes[path]())
        # Backward-compatible static aliases for Forest Room 5. These make old
        # /open/<id> pages, cached pages, and direct LAN asset URLs resolve their
        # relative image/PDF links instead of showing alt-text-only blank cards.
        asset_prefixes = ["/forest_room5_assets/", "/open/forest_room5_assets/"]
        for ap in asset_prefixes:
            if path.startswith(ap):
                rel_asset = unquote(path[len(ap):])
                base = (HOME / "report_portal" / "library" / "Prototype Web App" / "forest_room5_assets").resolve()
                target = (base / rel_asset).resolve()
                try:
                    target.relative_to(base)
                except ValueError:
                    return self._send(HTTPStatus.FORBIDDEN, b"Forbidden", "text/plain; charset=utf-8")
                return self._serve_file(target)
        if path in ("/qr_landing_source.pdf", "/open/qr_landing_source.pdf"):
            return self._serve_file(HOME / "report_portal" / "library" / "Prototype Web App" / "qr_landing_source.pdf")
        if path.startswith("/view/"):
            parts = path[len("/view/"):].split("/", 1)
            rid = unquote(parts[0]).strip()
            report = self.reports_by_id().get(rid)
            if not report:
                return self._send(HTTPStatus.NOT_FOUND, b"Report not found", "text/plain; charset=utf-8")
            asset_rel = unquote(parts[1]) if len(parts) > 1 else ""
            if asset_rel in ("", "/"):
                target = report.path
            else:
                base = report.path.parent.resolve()
                target = (base / asset_rel).resolve()
                try:
                    target.relative_to(base)
                except ValueError:
                    return self._send(HTTPStatus.FORBIDDEN, b"Forbidden", "text/plain; charset=utf-8")
            if not target.is_file():
                return self._send(HTTPStatus.NOT_FOUND, b"Asset not found", "text/plain; charset=utf-8")
            try:
                body = target.read_bytes()
            except Exception as e:
                return self._send(HTTPStatus.INTERNAL_SERVER_ERROR, str(e).encode(), "text/plain; charset=utf-8")
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if target.suffix.lower() in (".html", ".htm"):
                ctype = "text/html; charset=utf-8"
            return self._send(HTTPStatus.OK, body, ctype)
        for prefix, download in (("/open/", False), ("/download/", True)):
            if path.startswith(prefix):
                rid = unquote(path[len(prefix):]).strip("/")
                report = self.reports_by_id().get(rid)
                if not report:
                    return self._send(HTTPStatus.NOT_FOUND, b"Report not found", "text/plain; charset=utf-8")
                if not download:
                    return self._redirect(f"/view/{report.rid}/")
                # The mirrored Threat Intel index.html is a "Latest" shim with a relative
                # meta-refresh. When served at /open/<id>, that relative URL resolves under
                # /open/ and breaks. For Open Report, serve the newest real brief directly.
                if not download and report.category == "Threat Intel" and report.is_index:
                    latest = latest_threat_report(reports)
                    if latest:
                        report = latest
                try:
                    body = report.path.read_bytes()
                except Exception as e:
                    return self._send(HTTPStatus.INTERNAL_SERVER_ERROR, str(e).encode(), "text/plain; charset=utf-8")
                ctype = mimetypes.guess_type(report.path.name)[0] or "text/html; charset=utf-8"
                extra = {}
                if download:
                    extra["Content-Disposition"] = f"attachment; filename={quote(report.path.name)}"
                return self._send(HTTPStatus.OK, body, ctype, extra)
        return self._send(HTTPStatus.NOT_FOUND, b"Not found", "text/plain; charset=utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Arron's persistent LAN report portal")
    parser.add_argument("--host", default=os.environ.get("REPORT_PORTAL_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.environ.get("REPORT_PORTAL_PORT", DEFAULT_PORT)))
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), PortalHandler)
    print(f"Work LAN Portal listening on http://{local_ip()}:{args.port}/ (bind {args.host}:{args.port})", flush=True)
    server.serve_forever()

if __name__ == "__main__":
    main()
