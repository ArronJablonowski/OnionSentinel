"""HTML renderers for portal operational metric detail pages."""
from __future__ import annotations

import datetime as dt
import html
from collections.abc import Callable, Sequence
from pathlib import Path


def metric_detail_shell(
    title: str,
    kicker: str,
    body_html: str,
    hero_extra_html: str = "",
) -> bytes:
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


def render_macos_updates_detail(data: dict, status_file: Path) -> bytes:
    status = str(data.get("status") or "Unknown")
    count = data.get("count", "Unknown")
    checked_at = str(data.get("checked_at") or "Not checked")
    ok = data.get("ok")
    updates = data.get("updates") if isinstance(data.get("updates"), list) else []
    update_rows = "".join(
        f"<tr><td>{index}</td><td>{html.escape(str(item))}</td></tr>"
        for index, item in enumerate(updates, 1)
    ) or '<tr><td colspan="2">No cached update labels available.</td></tr>'
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
<tr><th>Cache file</th><td><code>{html.escape(str(status_file))}</code></td></tr>
<tr><th>Command</th><td><code>{html.escape(str(data.get('command') or '/usr/sbin/softwareupdate --list'))}</code></td></tr>
<tr><th>OK</th><td>{html.escape(str(ok))}</td></tr>
<tr><th>Return code</th><td>{html.escape(str(data.get('returncode', 'Unknown')))}</td></tr>
<tr><th>Error</th><td>{error}</td></tr>
</tbody></table></section>
<section class="section"><h2>Raw cached softwareupdate output tail</h2><pre>{raw_tail}</pre></section>'''
    return metric_detail_shell("macOS Updates", "Metric detail", body)


def render_prioritized_updates_detail(
    prioritized: tuple[str, str, int, str],
    macos: tuple[str, str, int],
    brew: tuple[int, str, list[str]],
    hermes: tuple[bool, str],
) -> bytes:
    value, detail, _count, source = prioritized
    mac_value, mac_detail, mac_count = macos
    brew_count, brew_detail, brew_items = brew
    hermes_available, hermes_detail = hermes
    selected = {
        "macos": "macOS updates", "brew": "Homebrew updates",
        "hermes": "Hermes Agent updates", "none": "No updates available",
        "unknown": "Unknown update state", "failed": "Update action failed",
        "running": "Update currently running",
    }.get(source, source)
    brew_rows = "".join(
        f"<tr><td>{index}</td><td>{html.escape(item)}</td></tr>"
        for index, item in enumerate(brew_items, 1)
    ) or '<tr><td colspan="2">No Homebrew package names available.</td></tr>'
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


def render_hermes_backups_detail(
    rows: list[dict],
    meta: dict,
    *,
    format_timestamp: Callable[[dt.datetime], str],
    human_size: Callable[[int], str],
    relative_time: Callable[[float], str],
) -> bytes:
    row_html = "".join(
        f"<tr><td>{html.escape(format_timestamp(row['created'].astimezone()))}</td>"
        f"<td><span class='badge{' warn' if not row['ok'] else ''}'>{html.escape(row['rating'])}</span></td>"
        f"<td>{html.escape(human_size(row['size']))}</td>"
        f"<td><code>{html.escape(str(row['archive']))}</code></td>"
        f"<td><code>{html.escape(str(row['checksum']))}</code><br><code>{html.escape(str(row['restore']))}</code></td>"
        f"<td>{html.escape(', '.join(row['missing']) if row['missing'] else 'Complete set + success log entry')}</td></tr>"
        for row in rows
    ) or '<tr><td colspan="6">No Hermes backup artifacts found.</td></tr>'
    latest = rows[0] if rows else None
    latest_label = relative_time(latest['created'].timestamp()) if latest else 'None'
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


def render_system_uptime_detail(
    uptime: tuple[str, str, bool],
    fan: tuple[bool, str],
    hostname: str,
) -> bytes:
    value, detail, _warning = uptime
    fan_running, fan_detail = fan
    fan_status = "Running" if fan_running else "Not running"
    body = f'''<section class="grid"><div class="card"><span>Displayed metric</span><strong>{html.escape(value)}</strong></div><div class="card"><span>Macs Fan Control</span><strong>{html.escape(fan_status)}</strong></div><div class="card"><span>Host</span><strong>{html.escape(hostname)}</strong></div></section><section class="section"><h2>Detail</h2><p>{html.escape(detail)}</p><p>{html.escape(fan_detail)}</p><p>Uptime is collected from <code>/usr/sbin/sysctl -n kern.boottime</code>. If Macs Fan Control is not running, this metric intentionally shows a warning instead of uptime.</p></section>'''
    return metric_detail_shell("System Uptime", "Metric detail", body)


def render_local_disk_detail(
    disk_usage: tuple[int, int, float],
    inventory: tuple[list[dict], list[dict], list[str], dt.datetime],
    *,
    home: Path,
    human_size: Callable[[int], str],
    format_timestamp: Callable[[dt.datetime], str],
    directory_rows: Callable[[list[dict]], str],
    file_rows: Callable[[list[dict]], str],
) -> bytes:
    free, total, pct = disk_usage
    used = max(0, total - free)
    top_dirs, top_files, warnings, inventory_generated = inventory
    warning_html = ""
    if warnings:
        warning_html = '<section class="section"><span class="badge warn">Scan warning</span><p>' + html.escape(" · ".join(warnings)) + '</p></section>'
    body = f'''<section class="grid"><div class="card"><span>Free</span><strong>{human_size(free)}</strong></div><div class="card"><span>Total</span><strong>{human_size(total)}</strong></div><div class="card"><span>Percent free</span><strong>{pct:.1f}%</strong></div></section><section class="section"><h2>Volume detail</h2><table><tbody><tr><th>Measured path</th><td><code>{html.escape(str(home))}</code></td></tr><tr><th>Used</th><td>{human_size(used)}</td></tr><tr><th>Inventory generated</th><td>{html.escape(format_timestamp(inventory_generated.astimezone()))}</td></tr><tr><th>Alert threshold</th><td>Amber/pink when free space is at or below 20%.</td></tr></tbody></table></section>{warning_html}<section class="section"><h2>Top 10 largest directories</h2><p>Recursive directory sizes under <code>{html.escape(str(home))}</code>, constrained to the same local filesystem.</p><table><thead><tr><th>#</th><th>Size</th><th>Directory</th></tr></thead><tbody>{directory_rows(top_dirs)}</tbody></table></section><section class="section"><h2>Top 10 largest files by disk used</h2><p>Allocated disk use under <code>{html.escape(str(home))}</code>, constrained to the same local filesystem. The logical-size column exposes sparse/virtual files such as Docker disk images that can advertise a much larger maximum capacity than they currently consume.</p><table><thead><tr><th>#</th><th>Disk used</th><th>Logical size</th><th>File</th></tr></thead><tbody>{file_rows(top_files)}</tbody></table></section>'''
    return metric_detail_shell("Local Disk Free", "Metric detail", body)


def render_portal_update_detail(
    report_count: int,
    timestamp: float,
    *,
    marker_file: Path,
    from_timestamp: Callable[[float], dt.datetime],
    now: Callable[[], dt.datetime],
    update_time_label: Callable[[float], str],
    format_timestamp: Callable[[dt.datetime], str],
) -> bytes:
    if timestamp:
        update_dt = from_timestamp(timestamp).astimezone()
        age_seconds = max(0.0, (now().astimezone() - update_dt).total_seconds())
        value = update_time_label(timestamp)
        detail = f"{int(age_seconds // 60)} minutes ago"
    else:
        update_dt = None
        value = "None"
        detail = "No update marker found"
    body = f'''<section class="grid"><div class="card"><span>Latest update</span><strong>{html.escape(value)}</strong></div><div class="card"><span>Age</span><strong>{html.escape(detail)}</strong></div><div class="card"><span>Reports indexed</span><strong>{report_count}</strong></div></section><section class="section"><h2>Portal update detail</h2><table><tbody><tr><th>Marker file</th><td><code>{html.escape(str(marker_file))}</code></td></tr><tr><th>Exact timestamp</th><td>{html.escape(format_timestamp(update_dt) if update_dt else 'None')}</td></tr><tr><th>Alert threshold</th><td>Amber/pink when older than 1 hour.</td></tr></tbody></table></section>'''
    return metric_detail_shell("Latest Portal Update", "Metric detail", body)
