"""Pure Reports page view models and server-side renderers."""
from __future__ import annotations

from dataclasses import dataclass
import html


@dataclass(frozen=True)
class ReportsLogRowViewModel:
    started: str
    alert_count: str
    rule_name: str
    route: str
    status_key: str
    status_label: str
    agent: str
    job: str
    runtime: str
    gpu_temperature: str
    gpu_utilization: str
    cpu_temperature: str
    soc_temperature: str
    memory: str
    power: str
    cpu: str
    pcap_size: str
    alert_size: str
    model: str
    detail: str
    run_kind: str


@dataclass(frozen=True)
class ReportsCurrentRunViewModel:
    title: str
    route: str
    started: str
    running: bool
    status_label: str
    agent: str
    job: str
    model: str
    alert_count: str
    queue_size: str


@dataclass(frozen=True)
class ReportsPageViewModel:
    current: ReportsCurrentRunViewModel
    rows: tuple[ReportsLogRowViewModel, ...]
    total_runs: int


def render_reports_status_badge(status_key: str, status_label: str) -> str:
    css = {'success': 'success', 'failure': 'failed', 'running': 'running'}.get(status_key, 'unknown')
    return f'<span class="llm-status-badge {css}">{html.escape(status_label)}</span>'


def render_reports_log_row(row: ReportsLogRowViewModel) -> str:
    row_class = {
        'second_opinion': ' class="llm-log-second-opinion"',
        'disagreement_adjudication': ' class="llm-log-adjudication"',
    }.get(row.run_kind, '')
    return f'''
      <tr{row_class}>
        <td>{html.escape(row.started)}</td>
        <td>{html.escape(row.alert_count)}</td>
        <td><strong title="{html.escape(row.rule_name, quote=True)}">{html.escape(row.rule_name)}</strong><code title="{html.escape(row.route, quote=True)}">{html.escape(row.route)}</code></td>
        <td>{render_reports_status_badge(row.status_key, row.status_label)}</td>
        <td>{html.escape(row.agent)}</td>
        <td>{html.escape(row.job)}</td>
        <td>{html.escape(row.runtime)}</td>
        <td>{html.escape(row.gpu_temperature)}</td>
        <td>{html.escape(row.gpu_utilization)}</td>
        <td>{html.escape(row.cpu_temperature)}</td>
        <td>{html.escape(row.soc_temperature)}</td>
        <td>{html.escape(row.memory)}</td>
        <td>{html.escape(row.power)}</td>
        <td>{html.escape(row.cpu)}</td>
        <td>{html.escape(row.pcap_size)}</td>
        <td>{html.escape(row.alert_size)}</td>
        <td><code>{html.escape(row.model)}</code></td>
        <td>{html.escape(row.detail)}</td>
      </tr>'''


def render_reports_current_panel(current: ReportsCurrentRunViewModel) -> str:
    status_key = 'running' if current.running else 'unknown'
    return f'''
      <section class="llm-current-card" aria-label="Current alert being analyzed">
        <div>
          <span class="settings-kicker">Observed AI execution</span>
          <h2 id="llm-current-title">{html.escape(current.title)}</h2>
          <p id="llm-current-route">{html.escape(current.route)}</p>
        </div>
        <div class="llm-current-meta">
          <span id="llm-current-status" class="llm-status-badge {status_key}" role="status" aria-live="polite" aria-atomic="true">{html.escape(current.status_label)}</span>
          <span><b>Agent</b><em id="llm-current-agent">{html.escape(current.agent)}</em></span>
          <span><b>Job</b><em id="llm-current-job">{html.escape(current.job)}</em></span>
          <span><b>Model</b><em id="llm-current-model">{html.escape(current.model)}</em></span>
          <span class="llm-current-stack"><b>Started</b><em id="llm-current-started">{html.escape(current.started or 'n/a')}</em><small><b>Runtime</b><em id="llm-current-runtime">n/a</em></small></span>
          <span class="llm-current-stack"><b>Alerts</b><em id="llm-current-count">{html.escape(current.alert_count)}</em><small><b>Queue</b><em id="llm-current-queue">{html.escape(current.queue_size)}</em></small></span>
        </div>
      </section>'''


def render_reports_page(view: ReportsPageViewModel) -> str:
    rows = ''.join(render_reports_log_row(row) for row in view.rows)
    if not rows:
        rows = '<tr><td colspan="18" class="llm-empty-row">No AI analysis logs found yet.</td></tr>'
    return f'''
    <section class="view-section active reports-view" aria-label="AI analysis reports">
      {render_reports_current_panel(view.current)}
      <section class="llm-log-section" aria-label="Agent analysis activity log">
        <div class="llm-log-toolbar">
          <div>
            <span class="settings-kicker">Reports</span>
            <h2>Agent Analysis Activity Log</h2>
            <span class="llm-log-total-runs"><b id="llm-log-total-runs">{view.total_runs}</b><em>Total runs</em></span>
            <div id="llm-log-agent-totals" class="llm-log-agent-totals" aria-label="Runs by agent"></div>
          </div>
          <label>Rows
            <select id="llm-log-page-size" aria-label="Rows per log page">
              <option value="10">10</option><option value="25" selected>25</option><option value="50">50</option>
            </select>
          </label>
        </div>
        <div class="llm-log-table-wrap"><table class="llm-log-table">
          <colgroup>
            <col class="llm-log-started"><col class="llm-log-count"><col class="llm-log-alerts"><col class="llm-log-status">
            <col class="llm-log-agent"><col class="llm-log-job"><col class="llm-log-runtime"><col class="llm-log-gpu">
            <col class="llm-log-gpu-util"><col class="llm-log-cpu-temp"><col class="llm-log-soc-temp"><col class="llm-log-memory">
            <col class="llm-log-power"><col class="llm-log-cpu"><col class="llm-log-pcap-size"><col class="llm-log-alert-size">
            <col class="llm-log-model"><col class="llm-log-detail">
          </colgroup>
          <thead><tr><th>Started</th><th>Count</th><th>Alert(s)</th><th>Status</th><th>Agent</th><th>Job</th><th>Runtime</th><th>GPU °C</th><th>GPU %</th><th>CPU °C</th><th>SOC °C</th><th>Max Memory</th><th>Max Power</th><th>Max CPU</th><th>PCAP Size</th><th>Alert Data</th><th>Model</th><th>Detail</th></tr></thead>
          <tbody id="llm-log-table-body">{rows}</tbody>
        </table></div>
        <div class="llm-log-footer">
          <button id="llm-log-prev" class="ack-button api-page-button" type="button">Previous</button>
          <span id="llm-log-page-status">Loading logs...</span>
          <button id="llm-log-next" class="ack-button api-page-button" type="button">Next</button>
        </div>
      </section>
    </section>'''
