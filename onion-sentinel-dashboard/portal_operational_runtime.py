"""Late-bound operational metrics, update health, disk, backup, and cron views."""
from __future__ import annotations

from typing import Any


def system_uptime_metric(runtime: Any) -> tuple[str, str, bool]:
    fan_running, fan_detail = runtime.macs_fan_control_status()
    try:
        proc = runtime.subprocess.run(
            ["/usr/sbin/sysctl", "-n", "kern.boottime"],
            text=True,
            stdout=runtime.subprocess.PIPE,
            stderr=runtime.subprocess.PIPE,
            timeout=2,
            check=True,
        )
        match = runtime.re.search(r"sec\s*=\s*(\d+)", proc.stdout)
        if not match:
            raise ValueError(proc.stdout.strip() or "Unable to parse kern.boottime")
        boot_epoch = int(match.group(1))
        boot_dt = runtime.dt.datetime.fromtimestamp(boot_epoch).astimezone()
        now = runtime.dt.datetime.now().astimezone()
        total_seconds = max(0, int((now - boot_dt).total_seconds()))
        days, remainder = divmod(total_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes = remainder // 60
        if days:
            uptime_value = f"{days}d {hours}h"
        elif hours:
            uptime_value = f"{hours}h {minutes}m"
        else:
            uptime_value = f"{minutes}m"
        detail = (
            f"Booted {runtime.format_iso_timestamp(boot_dt)} · uptime "
            f"{days} days, {hours} hours, {minutes} minutes"
        )
        if not fan_running:
            return "⚠ Fan Ctrl", f"{fan_detail} · {detail}", True
        return uptime_value, f"{detail} · {fan_detail}", False
    except Exception as exc:
        if not fan_running:
            return (
                "⚠ Fan Ctrl",
                f"{fan_detail} · Unable to determine system uptime: {exc}",
                True,
            )
        return "Unknown", f"Unable to determine system uptime: {exc} · {fan_detail}", True


def local_disk_usage_metric(runtime: Any) -> tuple[int, int, float]:
    return runtime.compose_local_disk_usage(runtime.HOME, runtime.shutil.disk_usage)


def directory_disk_scan(runtime: Any):
    try:
        proc = runtime.subprocess.run(
            ["/usr/bin/du", "-k", "-x", "-d", "4", str(runtime.HOME)],
            text=True,
            stdout=runtime.subprocess.PIPE,
            stderr=runtime.subprocess.PIPE,
            timeout=30,
            check=False,
        )
        return runtime.DiskScanOutcome(stdout=proc.stdout, stderr=proc.stderr)
    except runtime.subprocess.TimeoutExpired:
        return runtime.DiskScanOutcome(timed_out=True)
    except Exception as exc:
        return runtime.DiskScanOutcome(error=str(exc))


def file_disk_scan(runtime: Any):
    find_cmd = (
        f"/usr/bin/find {runtime.shlex.quote(str(runtime.HOME))} "
        "-xdev -type f -size +1M "
        "-exec /usr/bin/stat -f '%b\t%z\t%N' {} + 2>/dev/null "
        "| /usr/bin/sort -nr | /usr/bin/head -10"
    )
    try:
        proc = runtime.subprocess.run(
            ["/bin/bash", "-lc", find_cmd],
            text=True,
            stdout=runtime.subprocess.PIPE,
            stderr=runtime.subprocess.PIPE,
            timeout=30,
            check=False,
        )
        return runtime.DiskScanOutcome(stdout=proc.stdout, stderr=proc.stderr)
    except runtime.subprocess.TimeoutExpired:
        return runtime.DiskScanOutcome(timed_out=True)
    except Exception as exc:
        return runtime.DiskScanOutcome(error=str(exc))


def local_disk_inventory(
    runtime: Any, limit: int = 10, cache_seconds: int = 600
) -> tuple[list[dict], list[dict], list[str], Any]:
    return runtime.compose_local_disk_inventory(
        runtime.DiskInventorySources(
            home=runtime.HOME,
            cache=runtime.DISK_INVENTORY_CACHE,
            now=lambda: runtime.dt.datetime.now().astimezone(),
            directory_scan=runtime._directory_disk_scan,
            file_scan=runtime._file_disk_scan,
        ),
        limit=limit,
        cache_seconds=cache_seconds,
    )


def disk_inventory_rows(runtime: Any, rows: list[dict]) -> str:
    if not rows:
        return '<tr><td colspan="3">No entries found.</td></tr>'
    return "".join(
        f"<tr><td>{index}</td><td>{runtime.html.escape(runtime.human_size(int(row['size'])))}</td><td><code>{runtime.html.escape(str(row['path']))}</code></td></tr>"
        for index, row in enumerate(rows, 1)
    )


def disk_file_inventory_rows(runtime: Any, rows: list[dict]) -> str:
    if not rows:
        return '<tr><td colspan="4">No entries found.</td></tr>'
    return "".join(
        f"<tr><td>{index}</td><td>{runtime.html.escape(runtime.human_size(int(row['size'])))}</td><td>{runtime.html.escape(runtime.human_size(int(row.get('logical_size', row['size']))))}</td><td><code>{runtime.html.escape(str(row['path']))}</code></td></tr>"
        for index, row in enumerate(rows, 1)
    )


def hermes_backup_sources(runtime: Any):
    return runtime.HermesBackupSources(
        backup_dir=runtime.HERMES_DR_BACKUP_DIR,
        remote_dest=runtime.HERMES_DR_REMOTE_DEST,
        remote_directory=runtime.HERMES_DR_REMOTE_DIR,
        format_timestamp=runtime.format_iso_timestamp,
        human_size=runtime.human_size,
        relative_time_label=runtime.relative_time_label,
        redact_text=runtime.redact_sensitive_text,
    )


def latest_hermes_backup_metric(runtime: Any) -> tuple[str, str, bool]:
    return runtime.compose_latest_hermes_backup_metric(runtime.hermes_backup_sources())


def macos_update_metric(runtime: Any) -> tuple[str, str, int]:
    return runtime.compose_macos_update_metric(runtime.MACOS_UPDATE_STATUS_FILE)


def brew_update_check(runtime: Any):
    proc = runtime.subprocess.run(
        ["/opt/homebrew/bin/brew", "outdated", "--quiet"],
        text=True,
        stdout=runtime.subprocess.PIPE,
        stderr=runtime.subprocess.PIPE,
        timeout=12,
        env=runtime.ADMIN_COMMAND_ENV,
    )
    return runtime.UpdateCommandOutcome(proc.returncode, proc.stdout, proc.stderr)


def hermes_update_check(runtime: Any):
    proc = runtime.subprocess.run(
        [runtime.HERMES_BIN, "update", "--check"],
        text=True,
        stdout=runtime.subprocess.PIPE,
        stderr=runtime.subprocess.STDOUT,
        timeout=20,
        env=runtime.ADMIN_COMMAND_ENV,
    )
    return runtime.UpdateCommandOutcome(proc.returncode, proc.stdout or "")


def update_health_sources(runtime: Any):
    return runtime.UpdateHealthSources(
        macos_status_file=runtime.MACOS_UPDATE_STATUS_FILE,
        run_brew_check=runtime._brew_update_check,
        run_hermes_check=runtime._hermes_update_check,
        read_action_status=runtime.read_admin_action_status,
        process_running=runtime.process_is_running,
        action_labels={
            action_id: str(action.get("label") or action_id)
            for action_id, action in runtime.ADMIN_ACTIONS.items()
        },
        parse_timestamp=runtime.parse_iso_timestamp,
        format_timestamp=runtime.format_iso_timestamp,
    )


def brew_update_source_metric(runtime: Any) -> tuple[int, str, list[str]]:
    return runtime.compose_brew_update_source_metric(runtime._brew_update_check)


def hermes_update_source_metric(runtime: Any) -> tuple[bool, str]:
    return runtime.compose_hermes_update_source_metric(runtime._hermes_update_check)


def latest_running_update_action(runtime: Any) -> tuple[str, str] | None:
    return runtime.compose_latest_running_update_action(runtime.update_health_sources())


def latest_update_action_failure(runtime: Any) -> tuple[str, str] | None:
    return runtime.compose_latest_update_action_failure(runtime.update_health_sources())


def prioritized_updates_metric(runtime: Any) -> tuple[str, str, int, str]:
    return runtime.compose_prioritized_updates_metric(runtime.update_health_sources())


def human_time(runtime: Any, timestamp: float) -> str:
    return runtime.format_iso_timestamp(
        runtime.dt.datetime.fromtimestamp(timestamp).astimezone()
    )


def update_time_label(runtime: Any, timestamp: float) -> str:
    return runtime.format_iso_timestamp(
        runtime.dt.datetime.fromtimestamp(timestamp).astimezone()
    )


def relative_time_label(runtime: Any, timestamp: float) -> str:
    then = runtime.dt.datetime.fromtimestamp(timestamp).astimezone()
    now = runtime.dt.datetime.now().astimezone()
    seconds = max(0, int((now - then).total_seconds()))
    if seconds < 60:
        return "now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


def admin_last_performed_label(runtime: Any, status: dict) -> tuple[str, str]:
    timestamp = (
        status.get("finished_at")
        or status.get("updated_at")
        or status.get("started_at")
    )
    if not timestamp:
        return "Never", "No previous run recorded."
    try:
        parsed = runtime.parse_iso_timestamp(timestamp)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        local = parsed.astimezone()
        relative = runtime.relative_time_label(local.timestamp())
        exact = runtime.format_iso_timestamp(local)
        state = str(status.get("state") or "unknown")
        returncode = status.get("returncode")
        returncode_text = (
            "running"
            if state == "running"
            else (
                f"rc {returncode}"
                if returncode is not None
                else "no return code"
            )
        )
        return relative, f"{exact} · {state} · {returncode_text}"
    except Exception:
        return str(timestamp), str(
            status.get("message") or "Timestamp could not be parsed."
        )


def portal_last_updated(runtime: Any, reports: list[Any]) -> float | None:
    try:
        raw = runtime.LAST_UPDATED_FILE.read_text().strip()
        if raw:
            return runtime.parse_iso_timestamp(raw).timestamp()
    except Exception:
        pass
    return max((report.mtime for report in reports), default=None)


def schedule_label(_runtime: Any, job: dict) -> str:
    schedule = job.get("schedule") or {}
    if isinstance(schedule, dict):
        return str(
            schedule.get("display")
            or schedule.get("expr")
            or schedule.get("kind")
            or "unscheduled"
        )
    return str(job.get("schedule_display") or schedule or "unscheduled")


def next_run_label(runtime: Any, value: str | None, enabled: bool) -> tuple[str, str]:
    if not enabled:
        return "Disabled", "9999"
    if not value:
        return "Not scheduled", "9998"
    try:
        parsed = runtime.parse_iso_timestamp(value)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        local = parsed.astimezone()
        return runtime.format_iso_timestamp(local), runtime.format_iso_timestamp(parsed)
    except Exception:
        return value, value


def _cron_job_summary(runtime: Any, job: dict) -> tuple[Any, bool]:
    is_enabled = bool(job.get("enabled")) and str(
        job.get("state", "")
    ).lower() not in {"paused", "disabled"}
    next_label, sort_key = runtime.next_run_label(
        job.get("next_run_at"), is_enabled
    )
    return runtime.CronJobSummary(
        jid=str(job.get("id") or job.get("job_id") or "unknown"),
        name=str(job.get("name") or "Unnamed cron"),
        schedule=runtime.schedule_label(job),
        next_run=next_label,
        enabled=is_enabled,
        state=str(
            job.get("state") or ("scheduled" if is_enabled else "disabled")
        ),
        last_status=str(job.get("last_status") or "never"),
        sort_key=sort_key,
    ), is_enabled


def load_cron_summaries(runtime: Any) -> tuple[list[Any], list[Any]]:
    try:
        data = runtime.json.loads(runtime.CRON_JOBS_FILE.read_text())
    except Exception:
        return [], []
    enabled_jobs: list[Any] = []
    disabled_jobs: list[Any] = []
    for job in data.get("jobs", []):
        summary, is_enabled = _cron_job_summary(runtime, job)
        (enabled_jobs if is_enabled else disabled_jobs).append(summary)
    enabled_jobs.sort(key=lambda job: (job.sort_key, job.name.lower()))
    disabled_jobs.sort(key=lambda job: job.name.lower())
    return enabled_jobs, disabled_jobs


def render_cron_item(runtime: Any, job: Any, disabled: bool = False) -> str:
    status_class = "disabled" if disabled else "enabled"
    return f'''
      <div class="cron-item {status_class}">
        <div class="cron-item-top">
          <strong>{runtime.html.escape(job.name)}</strong>
          <span class="cron-status {status_class}">{'Disabled' if disabled else 'Enabled'}</span>
        </div>
        <div class="cron-next"><span>Next run</span><b>{runtime.html.escape(job.next_run)}</b></div>
        <div class="cron-meta"><span>ID: {runtime.html.escape(job.jid)}</span><span>Schedule: {runtime.html.escape(job.schedule)}</span><span>Last: {runtime.html.escape(job.last_status)}</span></div>
      </div>'''


def render_cron_menu(runtime: Any) -> str:
    enabled_jobs, disabled_jobs = runtime.load_cron_summaries()
    if not enabled_jobs and not disabled_jobs:
        body = '<div class="cron-empty">No Hermes cron jobs found.</div>'
    else:
        enabled_html = "".join(
            runtime.render_cron_item(job) for job in enabled_jobs
        ) or '<div class="cron-empty">No enabled cron jobs.</div>'
        disabled_html = "".join(
            runtime.render_cron_item(job, disabled=True) for job in disabled_jobs
        )
        disabled_section = (
            f'<div class="cron-disabled"><div class="cron-section-label">Disabled / paused</div>{disabled_html}</div>'
            if disabled_jobs
            else ""
        )
        body = f"{enabled_html}{disabled_section}"
    return f'''
    <details class="cron-menu">
      <summary>
        <span class="cron-summary-main"><span class="cron-dot"></span><span><b>Cron Schedule</b><small>{len(enabled_jobs)} enabled · {len(disabled_jobs)} disabled</small></span></span>
        <span class="cron-chevron">⌄</span>
      </summary>
      <div class="cron-panel">{body}</div>
    </details>'''


def icon_for(_runtime: Any, category: str) -> str:
    icons = (
        ("Threat", "🛡️"),
        ("Product", "📈"),
        ("Prototype", "🧩"),
        ("Web App Projects", "🧩"),
        ("Local AI", "🧠"),
        ("Cybersecurity", "📚"),
        ("Resource Library", "📚"),
        ("Portal Operations", "🧭"),
    )
    return next((icon for marker, icon in icons if marker in category), "📄")


def redact_sensitive_text(runtime: Any, text: str) -> str:
    text = runtime.re.sub(
        runtime.re.escape(
            str(runtime.HOME / ".hermes" / "backup" / "full-backup.passphrase")
        ),
        "[REDACTED_PASSPHRASE_FILE]",
        text,
    )
    return runtime.re.sub(
        r"(Passphrase file(?: at creation time)?:\s*)\S+",
        r"\1[REDACTED_PASSPHRASE_FILE]",
        text,
    )


def read_macos_update_status(runtime: Any) -> dict:
    return runtime.load_macos_update_status(runtime.MACOS_UPDATE_STATUS_FILE)
