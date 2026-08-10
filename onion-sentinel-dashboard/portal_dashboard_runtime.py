"""Runtime composition for portal metric, admin, and home dashboard views."""
from __future__ import annotations

from typing import Any


def backup_inventory(r: Any) -> tuple[list[dict], dict]:
    return r.compose_backup_inventory(r.hermes_backup_sources())


def metric_detail_shell(r: Any, title: str, kicker: str, body_html: str, hero_extra_html: str = "") -> bytes:
    return r.render_metric_detail_shell(title, kicker, body_html, hero_extra_html)


def render_macos_updates_detail(r: Any) -> bytes:
    return r.render_macos_update_metrics(r.read_macos_update_status(), r.MACOS_UPDATE_STATUS_FILE)


def render_prioritized_updates_detail(r: Any) -> bytes:
    return r.render_prioritized_update_metrics(
        r.prioritized_updates_metric(), r.macos_update_metric(),
        r.brew_update_source_metric(), r.hermes_update_source_metric(),
    )


def render_hermes_backups_detail(r: Any) -> bytes:
    rows, meta = r.backup_inventory()
    return r.render_hermes_backup_metrics(
        rows, meta, format_timestamp=r.format_iso_timestamp,
        human_size=r.human_size, relative_time=r.relative_time_label,
    )


def render_system_uptime_detail(r: Any) -> bytes:
    return r.render_system_uptime_metrics(
        r.system_uptime_metric(), r.macs_fan_control_status(), r.socket.gethostname()
    )


def render_local_disk_detail(r: Any) -> bytes:
    return r.render_local_disk_metrics(
        r.local_disk_usage_metric(), r.local_disk_inventory(), home=r.HOME,
        human_size=r.human_size, format_timestamp=r.format_iso_timestamp,
        directory_rows=r.disk_inventory_rows, file_rows=r.disk_file_inventory_rows,
    )


def render_portal_update_detail(r: Any, reports: list[Any]) -> bytes:
    return r.render_portal_update_metrics(
        len(reports), r.portal_last_updated(reports), marker_file=r.LAST_UPDATED_FILE,
        from_timestamp=r.dt.datetime.fromtimestamp, now=r.dt.datetime.now,
        update_time_label=r.update_time_label, format_timestamp=r.format_iso_timestamp,
    )


def render_admin_login(r: Any, message: str = "", error: bool = False) -> bytes:
    token = r.ensure_admin_token()
    configured = r.admin_password_configured()
    message_html = ""
    if message:
        badge = "Authentication blocked" if error else "Authentication"
        message_html = (
            f'<section class="section"><span class="badge {"warn" if error else ""}">'
            f'{badge}</span><p>{r.html.escape(message)}</p></section>'
        )
    setup_html = "" if configured else f'''
<section class="section"><span class="badge warn">Password not configured</span><p>Set the local admin password before using the Administration dashboard:</p><pre>{r.html.escape(str(r.HOME / "report_portal" / "set_admin_password.py"))}</pre><p>The password is stored only as a salted PBKDF2-HMAC-SHA256 hash at <code>{r.html.escape(str(r.ADMIN_PASSWORD_FILE))}</code>.</p></section>'''
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
    <input type="hidden" name="token" value="{r.html.escape(token)}" />
    <label>Admin password<input name="password" type="password" autocomplete="current-password" autofocus /></label>
    <button type="submit"{disabled_attr}>Sign in</button>
  </form>
</section>
<section class="section"><p>Administration uses a password form, local salted password hash, server-side session cookie, CSRF validation, POST-only actions, and the existing typed reboot confirmation.</p></section>'''
    return r.metric_detail_shell("Administration sign in", "Protected administration", body)


def render_admin_dashboard(r: Any, message: str = "", error: bool = False) -> bytes:
    sources = r.AdminDashboardSources(
        ensure_token=r.ensure_admin_token, running_action=r.running_admin_action,
        latest_outcome=r.latest_admin_action_outcome,
        service_statuses=r.admin_service_statuses, actions=r.ADMIN_ACTIONS,
        read_action_status=r.read_admin_action_status,
        last_performed_label=r.admin_last_performed_label,
        check_action_available=r.check_admin_action_available,
        action_version_info=r.admin_action_version_info, state_dir=r.ADMIN_STATE_DIR,
        human_size=r.human_size, format_timestamp=r.format_iso_timestamp,
        tail_file=r.tail_file, admin_log_path=r.admin_log_path,
        render_cron_failure=r.render_cron_failure_log_section,
        render_cron_menu=r.render_cron_menu,
    )
    return r.render_admin_dashboard_view(
        r.compose_admin_dashboard(sources), message, error, r.metric_detail_shell
    )


def render_home(r: Any, reports: list[Any], host: str, port: int) -> bytes:
    del host, port
    sources = r.HomeDashboardSources(
        system_uptime=r.system_uptime_metric,
        portal_last_updated=r.portal_last_updated,
        prioritized_updates=r.prioritized_updates_metric,
        latest_hermes_backup=r.latest_hermes_backup_metric,
        local_disk_usage=r.local_disk_usage_metric, human_size=r.human_size,
        relative_time=r.relative_time_label, format_timestamp=r.format_iso_timestamp,
        soc_alerts_report=r.soc_alerts_report,
        now=lambda: r.dt.datetime.now().astimezone(),
    )
    return r.render_home_dashboard(r.compose_home_dashboard(reports, sources))
