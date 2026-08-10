"""Runtime wiring for admin sessions and Resource Library mutations."""
from __future__ import annotations

from typing import Any


def ensure_admin_token(r: Any) -> str:
    return r.ensure_persisted_admin_token(r.ADMIN_TOKEN_FILE, random_bytes=r.os.urandom)


def load_admin_password_record(r: Any) -> dict | None:
    return r.load_persisted_admin_password_record(r.ADMIN_PASSWORD_FILE)


def admin_password_configured(r: Any) -> bool:
    return r.load_admin_password_record() is not None


def verify_admin_password(r: Any, password: str) -> bool:
    return r.verify_persisted_admin_password(password, r.load_admin_password_record())


def admin_session_hash(r: Any, session_id: str) -> str:
    return r.derive_admin_session_hash(session_id)


def load_admin_sessions(r: Any) -> dict:
    return r.load_persisted_admin_sessions(r.ADMIN_SESSIONS_FILE)


def save_admin_sessions(r: Any, sessions: dict) -> None:
    r.save_persisted_admin_sessions(r.ADMIN_STATE_DIR, r.ADMIN_SESSIONS_FILE, sessions)


def prune_admin_sessions(r: Any, sessions: dict | None = None) -> dict:
    sessions = r.load_admin_sessions() if sessions is None else sessions
    return r.prune_persisted_admin_sessions(
        sessions, now_timestamp=int(r.dt.datetime.now().timestamp()),
        save_sessions=r.save_admin_sessions,
    )


def create_admin_session(r: Any, client_ip: str) -> str:
    return r.create_persisted_admin_session(
        client_ip, now_timestamp=int(r.dt.datetime.now().timestamp()),
        ttl_seconds=r.ADMIN_SESSION_TTL_SECONDS,
        new_session_id=lambda: r.secrets.token_urlsafe(32),
        load_pruned_sessions=r.prune_admin_sessions,
        save_sessions=r.save_admin_sessions,
    )


def destroy_admin_session(r: Any, session_id: str) -> None:
    r.destroy_persisted_admin_session(
        session_id, load_sessions=r.load_admin_sessions,
        save_sessions=r.save_admin_sessions,
    )


def resource_library_id_for(r: Any, path: Any) -> str:
    return r.derive_resource_library_id(path)


def find_resource_library_pdf(r: Any, resource_id: str, source_path: str = "") -> Any:
    return r.locate_resource_library_pdf(
        resource_id, source_path, r.RESOURCE_LIBRARY_SOURCES
    )


def unique_destination(r: Any, path: Any) -> Any:
    return r.available_resource_destination(path)


def refresh_resource_library(r: Any) -> None:
    env = {**r.os.environ, "PATH": r.ADMIN_COMMAND_ENV.get("PATH", r.os.environ.get("PATH", ""))}
    for script in (r.RESOURCE_LIBRARY_BUILDER, r.RESOURCE_LIBRARY_SYNC):
        r.subprocess.run(
            [r.sys.executable, str(script)], check=True, timeout=180, env=env,
            capture_output=True, text=True,
        )


def load_resource_library_metadata(r: Any) -> dict:
    return r.load_resource_metadata_file(r.RESOURCE_LIBRARY_METADATA_FILE)


def save_resource_library_metadata(r: Any, data: dict) -> None:
    r.save_resource_metadata_file(r.RESOURCE_LIBRARY_METADATA_FILE, data)


def clean_resource_tags(r: Any, values: Any) -> list[str]:
    return r.normalize_resource_tags(values)


def sanitize_resource_filename(r: Any, name: str, original_suffix: str) -> str:
    return r.normalize_resource_filename(name, original_suffix)


def queue_resource_action(r: Any, record: dict) -> dict:
    r.RESOURCE_LIBRARY_REMOVAL_QUEUE.parent.mkdir(parents=True, exist_ok=True)
    action_id = str(record.get("action_id") or r.uuid.uuid4())
    payload = {**record, "action_id": action_id, "queued_at": r.now_iso_local()}
    with r.RESOURCE_LIBRARY_REMOVAL_QUEUE.open("a", encoding="utf-8") as fh:
        fh.write(r.json.dumps(payload, sort_keys=True) + "\n")
    return {
        "ok": True, "queued": True, "action_id": action_id,
        "message": "Resource Library action queued for the Hermes worker.",
    }


def trigger_resource_library_worker(r: Any) -> None:
    hermes = r.HOME / ".hermes" / "hermes-agent" / "venv" / "bin" / "hermes"
    cmd = [str(hermes if hermes.exists() else "hermes"), "cron", "run", r.RESOURCE_LIBRARY_MUTATION_CRON_ID]
    try:
        r.subprocess.Popen(
            cmd, stdout=r.subprocess.DEVNULL, stderr=r.subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        pass


def resource_favorites(r: Any) -> list[str]:
    return r.project_resource_favorites(r.load_resource_library_metadata())


def set_resource_favorite(r: Any, resource_id: str, favorite: bool) -> tuple[bool, dict]:
    return r.update_resource_favorite(
        resource_id, favorite, load_metadata=r.load_resource_library_metadata,
        save_metadata=r.save_resource_library_metadata,
        queue_action=r.queue_resource_action, trigger_worker=r.trigger_resource_library_worker,
    )


def set_resource_tags(r: Any, resource_id: str, tags: Any) -> tuple[bool, dict]:
    return r.update_resource_tags(
        resource_id, tags, load_metadata=r.load_resource_library_metadata,
        save_metadata=r.save_resource_library_metadata,
        queue_action=r.queue_resource_action, trigger_worker=r.trigger_resource_library_worker,
    )


def rename_resource_file(r: Any, resource_id: str, source_path: str, new_name: str) -> tuple[bool, dict]:
    return r.rename_resource_library_file(
        resource_id, source_path, new_name, find_pdf=r.find_resource_library_pdf,
        load_metadata=r.load_resource_library_metadata,
        save_metadata=r.save_resource_library_metadata,
        queue_action=r.queue_resource_action, trigger_worker=r.trigger_resource_library_worker,
        refresh_library=r.refresh_resource_library,
    )


def queue_resource_removal(r: Any, resource_id: str, source_path: str, error: str) -> dict:
    data = r.queue_resource_action({
        "action": "remove", "id": resource_id, "source": source_path,
        "portal_error": error,
    })
    r.trigger_resource_library_worker()
    data.update({
        "message": "Removal queued for the Hermes Resource Library worker.",
        "source": source_path,
    })
    return data


def move_resource_to_removal(r: Any, resource_id: str, source_path: str = "") -> tuple[bool, dict]:
    return r.move_resource_file_to_removal(
        resource_id, source_path, removal_dir=r.RESOURCE_LIBRARY_REMOVAL_DIR,
        find_pdf=r.find_resource_library_pdf, queue_removal=r.queue_resource_removal,
        refresh_library=r.refresh_resource_library,
    )


def parse_cookie_header(r: Any, cookie_header: str | None) -> dict[str, str]:
    return r.parse_request_cookie_header(cookie_header)


def admin_session_cookie_header(r: Any, session_id: str, max_age: int | None = None) -> str:
    max_age = r.ADMIN_SESSION_TTL_SECONDS if max_age is None else max_age
    return r.compose_admin_session_cookie(r.ADMIN_SESSION_COOKIE, session_id, max_age)


def expired_admin_session_cookie_header(r: Any) -> str:
    return r.compose_expired_admin_session_cookie(r.ADMIN_SESSION_COOKIE)
