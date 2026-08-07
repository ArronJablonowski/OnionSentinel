"""Administration dashboard view-model composition and HTML rendering."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import datetime as dt
import html
import json
from pathlib import Path

from portal_admin_dashboard_assets import (
    ADMIN_DASHBOARD_SCRIPT_TEMPLATE,
    ADMIN_DASHBOARD_STYLE,
)


@dataclass(frozen=True)
class AdminDashboardSources:
    ensure_token: Callable[[], str]
    running_action: Callable[[], dict | None]
    latest_outcome: Callable[[], dict | None]
    service_statuses: Callable[[], dict]
    actions: Mapping[str, Mapping[str, object]]
    read_action_status: Callable[[str], dict]
    last_performed_label: Callable[[dict], tuple[str, str]]
    check_action_available: Callable[..., tuple[bool, str]]
    action_version_info: Callable[[str], dict]
    state_dir: Path
    human_size: Callable[[int], str]
    format_timestamp: Callable[[dt.datetime], str]
    tail_file: Callable[[Path], str]
    admin_log_path: Callable[[str], Path]
    render_cron_failure: Callable[[], str]
    render_cron_menu: Callable[[], str]


@dataclass(frozen=True)
class AdminServiceCard:
    service_id: str
    label: str
    running: bool
    level: str
    startable: bool
    value: str
    detail: str


@dataclass(frozen=True)
class AdminActionCard:
    action_id: str
    label: str
    accent: str
    summary: str
    state: str
    display_state: str
    command: str
    last_performed: str
    last_performed_detail: str
    available: bool
    availability_message: str
    current_version: str
    latest_version: str
    version_detail: str
    message: str
    started_at: str
    pid: str
    returncode: str
    is_reboot: bool
    button_label: str
    disabled: bool
    log_tail: str


@dataclass(frozen=True)
class AdminStateFile:
    name: str
    size: str
    modified: str


@dataclass(frozen=True)
class AdminDashboardView:
    token: str
    active_action: dict | None
    latest_outcome: dict | None
    services: tuple[AdminServiceCard, ...]
    actions: tuple[AdminActionCard, ...]
    state_dir: str
    state_files: tuple[AdminStateFile, ...]
    cron_failure_html: str
    cron_menu_html: str


def _service_cards(statuses: dict) -> tuple[AdminServiceCard, ...]:
    cards = []
    for service_id in ("macs-fan-control", "codex", "codex-cli", "docker", "n8n"):
        service = statuses[service_id]
        running = bool(service.get("running"))
        level = str(service.get("level") or ("ok" if running else "warn"))
        cards.append(
            AdminServiceCard(
                service_id=service_id,
                label=str(service.get("label", service_id)),
                running=running,
                level=level,
                startable=bool(service.get("startable", True)),
                value=str(service.get("value", "Unknown")),
                detail=str(service.get("detail", "No detail available.")),
            )
        )
    return tuple(cards)


def _action_button_state(
    action_id: str,
    active_action: dict | None,
    available: bool,
) -> tuple[str, bool, bool]:
    reboot = action_id == "reboot"
    if active_action:
        return "Wait for running action", True, reboot
    if not reboot and not available:
        return "No updates available", True, reboot
    return ("Reboot system" if reboot else "Approve update"), False, reboot


def _text_value(values: Mapping[str, object], key: str, fallback: str) -> str:
    return str(values.get(key) or fallback)


def _returncode(status: dict) -> str:
    value = status.get("returncode")
    return str(value) if value is not None else "—"


def _action_card(
    action_id: str,
    action: Mapping[str, object],
    active_action: dict | None,
    sources: AdminDashboardSources,
) -> AdminActionCard:
    status = sources.read_action_status(action_id)
    state = _text_value(status, "state", "idle")
    available, availability = sources.check_action_available(
        action_id, skip_expensive=bool(active_action)
    )
    version = sources.action_version_info(action_id)
    last_performed, last_detail = sources.last_performed_label(status)
    button, disabled, reboot = _action_button_state(action_id, active_action, available)
    return AdminActionCard(
        action_id=action_id,
        label=str(action["label"]),
        accent=str(action.get("accent", "#23d3ee")),
        summary=str(action.get("summary", "")),
        state=state,
        display_state="completed" if state == "ok" else state,
        command=" ".join(str(part) for part in action["command"]),
        last_performed=last_performed,
        last_performed_detail=last_detail,
        available=available,
        availability_message=availability,
        current_version=_text_value(version, "current", "Unknown"),
        latest_version=_text_value(version, "latest", "Unknown"),
        version_detail=_text_value(version, "detail", "No version detail available."),
        message=_text_value(status, "message", "Not run yet."),
        started_at=_text_value(status, "started_at", "Not run yet."),
        pid=_text_value(status, "pid", "—"),
        returncode=_returncode(status),
        is_reboot=reboot,
        button_label=button,
        disabled=disabled,
        log_tail=sources.tail_file(sources.admin_log_path(action_id)),
    )


def _action_cards(
    active_action: dict | None,
    sources: AdminDashboardSources,
) -> tuple[AdminActionCard, ...]:
    return tuple(
        _action_card(action_id, action, active_action, sources)
        for action_id, action in sources.actions.items()
    )


def _state_files(sources: AdminDashboardSources) -> tuple[AdminStateFile, ...]:
    try:
        candidates = [path for path in sources.state_dir.iterdir() if path.is_file()]
    except OSError:
        return ()
    rows = []
    for path in candidates:
        try:
            metadata = path.stat()
        except OSError:
            continue
        rows.append((metadata.st_mtime, path, metadata.st_size))
    rows.sort(key=lambda row: row[0], reverse=True)
    return tuple(
        AdminStateFile(
            name=path.name,
            size=sources.human_size(size),
            modified=sources.format_timestamp(
                dt.datetime.fromtimestamp(modified).astimezone()
            ),
        )
        for modified, path, size in rows
    )


def compose_admin_dashboard(sources: AdminDashboardSources) -> AdminDashboardView:
    """Collect one bounded Administration dashboard view model."""
    token = sources.ensure_token()
    active_action = sources.running_action()
    return AdminDashboardView(
        token=token,
        active_action=active_action,
        latest_outcome=None if active_action else sources.latest_outcome(),
        services=_service_cards(sources.service_statuses()),
        actions=_action_cards(active_action, sources),
        state_dir=str(sources.state_dir),
        state_files=_state_files(sources),
        cron_failure_html=sources.render_cron_failure(),
        cron_menu_html=sources.render_cron_menu(),
    )


def _service_card(card: AdminServiceCard) -> str:
    class_name = "ok" if card.level == "ok" else (
        "alert" if card.level == "alert" else "warn"
    )
    button = ""
    if not card.running and card.startable:
        button = (
            '<button class="service-start-button" type="button" '
            f'data-start-service="{html.escape(card.service_id)}">Start</button>'
        )
    return (
        f'<div class="admin-indicator {class_name}" '
        f'data-service-card="{html.escape(card.service_id)}" '
        f'data-running="{str(card.running).lower()}" data-level="{html.escape(card.level)}">'
        '<div class="admin-indicator-top">'
        f'<span>{html.escape(card.label)}</span>{button}</div>'
        f'<strong>{html.escape(card.value)}</strong>'
        f'<small>{html.escape(card.detail)}</small></div>'
    )


def _service_grid(view: AdminDashboardView) -> str:
    return (
        '<section class="admin-status-grid">'
        f'{"".join(_service_card(card) for card in view.services)}</section>'
    )


def _action_table(card: AdminActionCard) -> str:
    availability_class = "" if card.available else "warn"
    availability_label = "Available" if card.available else "Unavailable"
    return (
        '<table><tbody>'
        f'<tr><th>Last message</th><td>{html.escape(card.message)}</td></tr>'
        f'<tr><th>Availability</th><td><span class="badge {availability_class}">'
        f'{availability_label}</span> {html.escape(card.availability_message)}</td></tr>'
        f'<tr><th>Version detail</th><td>{html.escape(card.version_detail)}</td></tr>'
        f'<tr><th>Started</th><td>{html.escape(card.started_at)}</td></tr>'
        f'<tr><th>PID / return code</th><td>{html.escape(card.pid)} / '
        f'{html.escape(card.returncode)}</td></tr>'
        f'<tr><th>Command</th><td><code>{html.escape(card.command)}</code></td></tr>'
        '</tbody></table>'
    )


def _action_form(card: AdminActionCard, token: str) -> str:
    confirm = ""
    form_attrs = ""
    if card.is_reboot:
        confirm = (
            '<label class="confirm-label">Type <code>REBOOT</code> to confirm'
            '<input name="confirmation" autocomplete="off" placeholder="REBOOT" /></label>'
        )
        form_attrs = ' data-reboot-form="true"'
    disabled = " disabled" if card.disabled else ""
    danger = "danger" if card.is_reboot else ""
    return (
        f'<form method="post" action="/admin/action"{form_attrs}>'
        f'<input type="hidden" name="token" value="{html.escape(token)}" />'
        f'<input type="hidden" name="action" value="{html.escape(card.action_id)}" />'
        f'{confirm}<button class="admin-button {danger}" type="submit"{disabled}>'
        f'{html.escape(card.button_label)}</button></form>'
    )


def _action_card_html(card: AdminActionCard, token: str) -> str:
    badge = "warn" if card.state in {"failed", "error", "unknown"} else ""
    detail = html.escape(card.version_detail)
    return (
        f'<section class="admin-card" style="--admin-accent:{html.escape(card.accent)}">'
        '<div class="admin-card-top"><div><span class="section-label">Action</span>'
        f'<h2>{html.escape(card.label)}</h2></div>'
        f'<span class="badge {badge}">{html.escape(card.display_state)}</span></div>'
        f'<p>{html.escape(card.summary)}</p>'
        f'<div class="admin-action-metric" title="{html.escape(card.last_performed_detail)}">'
        f'<span>Last performed</span><strong>{html.escape(card.last_performed)}</strong>'
        f'<small>{html.escape(card.last_performed_detail)}</small></div>'
        '<div class="admin-version-grid">'
        f'<div class="admin-version-metric" title="{detail}"><span>Current version</span>'
        f'<strong>{html.escape(card.current_version)}</strong></div>'
        f'<div class="admin-version-metric latest" title="{detail}">'
        f'<span>Latest available</span><strong>{html.escape(card.latest_version)}</strong></div></div>'
        f'{_action_table(card)}{_action_form(card, token)}</section>'
    )


def _state_directory(view: AdminDashboardView) -> str:
    rows = "".join(
        f'<tr><td><code>{html.escape(item.name)}</code></td>'
        f'<td>{html.escape(item.size)}</td><td>{html.escape(item.modified)}</td></tr>'
        for item in view.state_files
    ) or '<tr><td colspan="3">No files found in the Administration action directory.</td></tr>'
    return (
        '<section class="section"><h2>Administration action directory</h2>'
        f'<p>Local action status and logs live under <code>{html.escape(view.state_dir)}</code>.</p>'
        '<table><thead><tr><th>File</th><th>Size</th><th>Modified</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></section>'
    )


def _log_sections(view: AdminDashboardView) -> str:
    action_logs = "".join(
        '<section class="section">'
        f'<h2>{html.escape(card.label)} log tail</h2>'
        f'<pre>{html.escape(card.log_tail)}</pre></section>'
        for card in view.actions
    )
    return _state_directory(view) + view.cron_failure_html + action_logs


def _active_message(active: dict) -> str:
    label = html.escape(str(active.get("label", "An admin action")))
    pid = html.escape(str(active.get("pid", "unknown")))
    return (
        '<section class="section"><span class="badge warn">Action running</span>'
        f'<p>{label} is currently running as PID {pid}. Additional updates and reboot '
        'are disabled until it completes.</p></section>'
    )


def _outcome_message(outcome: dict) -> str:
    state = str(outcome.get("state") or "unknown")
    succeeded = state == "ok"
    badge = "Action completed" if succeeded else "Action failed"
    badge_class = "" if succeeded else "warn"
    returncode = (
        "" if outcome.get("returncode") is None
        else f" Return code: {outcome.get('returncode')}."
    )
    message = (
        f'{outcome.get("label", "Admin action")} '
        f'{"completed successfully" if succeeded else "failed"} at '
        f'{outcome.get("when", "unknown time")}. {outcome.get("message", "")}{returncode}'
    )
    return (
        f'<section class="section"><span class="badge {badge_class}">'
        f'{html.escape(badge)}</span><p>{html.escape(message)}</p></section>'
    )


def _messages(view: AdminDashboardView, message: str, error: bool) -> str:
    rendered = ""
    if view.active_action:
        rendered += _active_message(view.active_action)
    elif view.latest_outcome:
        rendered += _outcome_message(view.latest_outcome)
    if message:
        badge = "Action blocked" if error else "Action started"
        badge_class = "warn" if error else ""
        rendered += (
            f'<section class="section"><span class="badge {badge_class}">'
            f'{badge}</span><p>{html.escape(message)}</p></section>'
        )
    return rendered


def _script(view: AdminDashboardView) -> str:
    return (
        ADMIN_DASHBOARD_SCRIPT_TEMPLATE
        .replace("__TOKEN_JSON__", json.dumps(view.token))
        .replace("__ACTION_RUNNING__", "true" if view.active_action else "false")
    )


def render_admin_dashboard(
    view: AdminDashboardView,
    message: str,
    error: bool,
    shell: Callable[[str, str, str, str], bytes],
) -> bytes:
    """Render one escaped Administration dashboard from its view model."""
    cards = "".join(_action_card_html(card, view.token) for card in view.actions)
    body = (
        f'{ADMIN_DASHBOARD_STYLE}{_service_grid(view)}{view.cron_menu_html}'
        f'{_messages(view, message, error)}<section class="admin-grid">{cards}</section>'
        f'{_log_sections(view)}{_script(view)}'
    )
    logout = (
        '<form class="admin-logout-form" method="post" action="/admin/logout">'
        f'<input type="hidden" name="token" value="{html.escape(view.token)}" />'
        '<button class="admin-logout-button" type="submit">Sign out</button></form>'
    )
    return shell("⚙️ Administration", "System administration", body, logout)
