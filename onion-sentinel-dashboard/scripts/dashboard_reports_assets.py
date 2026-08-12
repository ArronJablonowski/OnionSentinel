"""Reports page styles and reactive activity-log client."""
from __future__ import annotations


REPORTS_PAGE_ASSETS = '''
<style>
.reports-view{display:grid;gap:18px}
.llm-current-card,.llm-log-section{border:1px solid rgba(34,211,238,.18);border-radius:12px;background:linear-gradient(180deg,rgba(13,22,32,.96),rgba(9,17,25,.96));box-shadow:inset 0 1px 0 rgba(255,255,255,.03);padding:18px}
.llm-current-card{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:18px;align-items:start}
.llm-current-card h2,.llm-log-toolbar h2{margin:4px 0 0;color:#f2f7ff;font-size:24px;line-height:1.1}
.llm-current-card p{margin:8px 0 0;color:#aebbd0;font:700 13px/1.35 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;overflow-wrap:anywhere}
.llm-current-meta{display:grid;grid-template-columns:repeat(2,max-content);gap:10px 18px;align-items:center}
.llm-current-meta span:not(.llm-status-badge){display:grid;gap:3px;color:#9fb0c4;font-size:11px;font-weight:850;text-transform:uppercase;letter-spacing:.06em}
.llm-current-meta em{font-style:normal;color:#e6eef8;font-size:13px;text-transform:none;letter-spacing:0}
.llm-current-meta small{display:grid;gap:3px;margin-top:7px;color:#9fb0c4;font-size:11px;font-weight:850;text-transform:uppercase;letter-spacing:.06em}
.llm-current-meta small em{font-size:13px}
.llm-status-badge{display:inline-flex;align-items:center;width:max-content;border:1px solid rgba(148,163,184,.22);border-radius:999px;padding:5px 9px;color:#aab7c8;background:rgba(148,163,184,.08);font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.08em}
.llm-status-badge.success{border-color:rgba(34,197,94,.34);color:#37e071;background:rgba(34,197,94,.08)}
.llm-status-badge.failed{border-color:rgba(251,113,133,.38);color:#fb7185;background:rgba(251,113,133,.08)}
.llm-status-badge.running{border-color:rgba(34,211,238,.42);color:#8ff4ff;background:rgba(34,211,238,.09);animation:analysisPulse 1.3s ease-in-out infinite}
.llm-log-toolbar{display:flex;justify-content:space-between;gap:16px;align-items:end;margin-bottom:14px}
.llm-log-total-runs{display:inline-flex;align-items:baseline;gap:6px;width:max-content;margin-top:8px;border:1px solid rgba(34,211,238,.22);border-radius:999px;padding:5px 10px;color:#9fb0c4;background:rgba(34,211,238,.055);font-size:12px;font-weight:850}
.llm-log-total-runs b{color:#8ff4ff;font-size:16px;line-height:1}
.llm-log-total-runs em{font-style:normal;color:#9fb0c4}
.llm-log-agent-totals{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}.llm-log-agent-total{display:inline-flex;align-items:center;gap:5px;border:1px solid rgba(148,163,184,.18);border-radius:999px;padding:4px 8px;color:#9fb0c4;background:rgba(148,163,184,.045);font-size:10px;font-weight:850}.llm-log-agent-total b{color:#dce9f8;font-size:11px}
.llm-log-toolbar label{display:flex;align-items:center;gap:8px;color:#9fb0c4;font-size:12px;font-weight:850}
.llm-log-toolbar select{min-height:44px;border:1px solid rgba(34,211,238,.32);border-radius:8px;background:#0a141e;color:#e8f1fb;padding:8px 28px 8px 10px;font-weight:850}
.llm-log-table-wrap{max-width:100%;overflow:auto;border:1px solid rgba(148,163,184,.12);border-radius:10px;box-shadow:inset -18px 0 18px -18px rgba(143,244,255,.38)}
.llm-log-table{width:100%;border-collapse:collapse;min-width:2320px;table-layout:fixed}
.llm-log-started{width:205px}
.llm-log-count{width:64px}
.llm-log-alerts{width:400px}
.llm-log-status{width:104px}
.llm-log-agent{width:150px}
.llm-log-job{width:220px}
.llm-log-runtime{width:88px}
.llm-log-gpu{width:80px}
.llm-log-gpu-util{width:82px}
.llm-log-cpu-temp{width:82px}
.llm-log-soc-temp{width:82px}
.llm-log-memory{width:104px}
.llm-log-power{width:104px}
.llm-log-cpu{width:88px}
.llm-log-pcap-size{width:100px}
.llm-log-alert-size{width:100px}
.llm-log-model{width:220px}
.llm-log-detail{width:220px}
.llm-log-table th{padding:10px 12px;background:#111d29;color:#9fb0c4;text-align:left;font-size:12px;font-weight:950}
.llm-log-table td{padding:12px;border-top:1px solid rgba(148,163,184,.11);vertical-align:top;color:#d9e4f2;font-size:13px}
.llm-log-table tr.llm-log-second-opinion td{background:rgba(139,92,246,.055)}.llm-log-table tr.llm-log-second-opinion td:first-child{box-shadow:inset 3px 0 0 #a78bfa}.llm-log-table tr.llm-log-adjudication td{background:rgba(245,158,11,.055)}.llm-log-table tr.llm-log-adjudication td:first-child{box-shadow:inset 3px 0 0 #f59e0b}
.llm-log-table td strong{display:block;color:#f2f7ff;line-height:1.2;overflow-wrap:normal;word-break:normal}
.llm-log-table td code{display:block;margin-top:4px;color:#aebbd0;background:transparent;font-size:12px;line-height:1.2;white-space:normal;overflow-wrap:normal;word-break:normal}
.llm-log-table th:nth-child(2),.llm-log-table td:nth-child(2){text-align:center}
.llm-log-table td:nth-child(1),.llm-log-table td:nth-child(2),.llm-log-table td:nth-child(4),.llm-log-table td:nth-child(5),.llm-log-table td:nth-child(6),.llm-log-table td:nth-child(7),.llm-log-table td:nth-child(8),.llm-log-table td:nth-child(9),.llm-log-table td:nth-child(10),.llm-log-table td:nth-child(11),.llm-log-table td:nth-child(12),.llm-log-table td:nth-child(13),.llm-log-table td:nth-child(14),.llm-log-table td:nth-child(15),.llm-log-table td:nth-child(16),.llm-log-table td:nth-child(17){white-space:nowrap}
.llm-log-table td:nth-child(3) strong{display:-webkit-box;max-width:100%;overflow:hidden;-webkit-box-orient:vertical;-webkit-line-clamp:2;line-clamp:2}
.llm-log-table td:nth-child(3) code{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.llm-log-table td:nth-child(17) code{white-space:nowrap;overflow-wrap:normal}
.llm-empty-row{text-align:center;color:#91a4ba!important;padding:28px!important}
.llm-log-footer{display:flex;justify-content:flex-end;align-items:center;gap:12px;margin-top:12px;color:#91a4ba;font-size:12px;font-weight:850}
@media(max-width:900px){.llm-current-card{grid-template-columns:1fr}.llm-current-meta{grid-template-columns:1fr 1fr}.llm-log-toolbar{align-items:flex-start;flex-direction:column}.llm-log-page-size select{min-height:44px}.llm-log-table{min-width:1760px}.llm-log-started{width:190px}.llm-log-alerts{width:360px}.llm-log-detail{width:200px}}
@media(max-width:720px){.llm-log-table-wrap{overflow:visible;box-shadow:none}.llm-log-table{display:block;min-width:0;table-layout:auto}.llm-log-table thead{display:none}.llm-log-table tbody,.llm-log-table tr,.llm-log-table td{display:block;width:100%;box-sizing:border-box}.llm-log-table tr{padding:12px 14px;border-top:1px solid rgba(148,163,184,.12)}.llm-log-table td{display:grid;grid-template-columns:104px minmax(0,1fr);gap:8px;border:0;padding:5px 0;white-space:normal!important}.llm-log-table td::before{color:#8ff4ff;font-size:10px;font-weight:950;letter-spacing:.08em;text-transform:uppercase}.llm-log-table td:nth-child(1)::before{content:"Started"}.llm-log-table td:nth-child(2)::before{content:"Count"}.llm-log-table td:nth-child(3)::before{content:"Alert(s)"}.llm-log-table td:nth-child(4)::before{content:"Status"}.llm-log-table td:nth-child(5)::before{content:"Agent"}.llm-log-table td:nth-child(6)::before{content:"Job"}.llm-log-table td:nth-child(7)::before{content:"Runtime"}.llm-log-table td:nth-child(8)::before{content:"GPU °C"}.llm-log-table td:nth-child(9)::before{content:"GPU %"}.llm-log-table td:nth-child(10)::before{content:"CPU °C"}.llm-log-table td:nth-child(11)::before{content:"SOC °C"}.llm-log-table td:nth-child(12)::before{content:"Memory"}.llm-log-table td:nth-child(13)::before{content:"Power"}.llm-log-table td:nth-child(14)::before{content:"CPU"}.llm-log-table td:nth-child(15)::before{content:"PCAP Size"}.llm-log-table td:nth-child(16)::before{content:"Alert Data"}.llm-log-table td:nth-child(17)::before{content:"Model"}.llm-log-table td:nth-child(18)::before{content:"Detail"}.llm-log-table td:nth-child(3) strong{display:block;overflow:visible;-webkit-line-clamp:unset;line-clamp:unset}.llm-log-table td:nth-child(3) code{overflow:visible;text-overflow:clip;white-space:normal}.llm-log-alerts,.llm-log-detail{width:auto}}@media(max-width:360px){.content,.topbar,.toggle-refresh-group,.reports-view,.llm-current-card,.llm-log-section{max-width:100%;min-width:0;overflow:hidden}.toggle-stack{min-width:0}.toggle-wrap{min-width:0}}
</style>
<script>
(() => {
  const body = document.querySelector('#llm-log-table-body');
  const pageSizeSelect = document.querySelector('#llm-log-page-size');
  const prev = document.querySelector('#llm-log-prev');
  const next = document.querySelector('#llm-log-next');
  const status = document.querySelector('#llm-log-page-status');
  const totalRuns = document.querySelector('#llm-log-total-runs');
  const agentTotals = document.querySelector('#llm-log-agent-totals');
  let page = 1;
  let totalPages = 1;
  let currentAnalysisState = {};
  let currentSignature = '';
  let logSignature = '';
  const stableSignature = value => JSON.stringify(value, (key, item) => key === 'runtime_seconds' ? undefined : item);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const runtime = seconds => {
    seconds = Number(seconds || 0);
    if (!seconds) return 'n/a';
    const s = Math.round(seconds), m = Math.floor(s / 60), r = s % 60, h = Math.floor(m / 60), mm = m % 60;
    if (h) return `${h}h ${mm}m ${r}s`;
    if (m) return `${m}m ${r}s`;
    return `${r}s`;
  };
  const bytes = value => {
    let n = Number(value || 0);
    const units = ['B','KB','MB','GB','TB'];
    for (const unit of units) {
      if (n < 1024 || unit === 'TB') return unit === 'B' ? `${Math.round(n)} B` : `${n.toFixed(1)} ${unit}`;
      n /= 1024;
    }
    return `${n.toFixed(1)} TB`;
  };
  const parseProjectTime = value => {
    const raw = String(value || '').trim();
    if (!raw || raw === 'n/a') return NaN;
    return Date.parse(raw.replace('  ', 'T'));
  };
  const renderCurrentRuntime = () => {
    const runtimeEl = document.querySelector('#llm-current-runtime');
    if (!runtimeEl) return;
    if (currentAnalysisState?.status !== 'running') {
      runtimeEl.textContent = 'n/a';
      return;
    }
    const startedMs = parseProjectTime(currentAnalysisState.started_at);
    if (!Number.isFinite(startedMs)) {
      runtimeEl.textContent = 'n/a';
      return;
    }
    const elapsedSeconds = Math.max(0, (Date.now() - startedMs) / 1000);
    runtimeEl.textContent = runtime(elapsedSeconds);
  };
  const badge = raw => {
    const key = String(raw || 'unknown').toLowerCase();
    const label = key === 'success' ? 'Success' : key === 'failure' ? 'Failed' : key === 'running' ? 'Running' : key.replaceAll('_',' ');
    const css = key === 'failure' ? 'failed' : key;
    return `<span class="llm-status-badge ${esc(css)}">${esc(label)}</span>`;
  };
  const agentLabel = log => log?.agent_label || ({
    'soc-analyst':'SOC Analyst',
    'incident-responder':'Incident Responder',
    'siem-engineer':'SIEM Engineer',
    'cyber-threat-intel':'Cyber Threat Intel',
    'threat-hunter':'Threat Hunter',
  }[String(log?.agent_role || '').replaceAll('_','-').toLowerCase()] || 'Unknown agent');
  const jobLabel = log => log?.job_label || ({
    'soc-analyst':'SOC alert triage',
    'incident-responder':'Incident response investigation',
    'siem-engineer':'Detection engineering analysis',
    'cyber-threat-intel':'Threat-intelligence analysis',
    'threat-hunter':'Threat-hunting analysis',
  }[String(log?.agent_role || '').replaceAll('_','-').toLowerCase()] || 'Unknown analysis job');
  const executedModel = (log, live=false) => {
    if (log?.runtime_model_label) return String(log.runtime_model_label);
    if (live && log?.status !== 'running') return 'No model running';
    const hasPhase = live && Object.prototype.hasOwnProperty.call(log || {}, 'active_phase');
    const route = String(hasPhase ? (log?.active_model_route || '') : (log?.model_route || ''));
    let model = String(hasPhase ? (log?.active_model || '') : (log?.model || ''));
    const path = String(hasPhase ? (log?.active_model_path || '') : (log?.model_path || '')).toLowerCase();
    const providerKey = String(hasPhase ? (log?.active_provider || '') : (log?.mode || '')).toLowerCase();
    if (hasPhase && log?.active_phase === 'post_processing' && !route && !model) return 'No model running';
    let provider = '', effort = '';
    if (route.startsWith('codex-cli:')) {
      const parts = route.slice('codex-cli:'.length).split(':');
      if (parts.length > 1) effort = parts.pop() || '';
      model = parts.join(':') || model;
      provider = 'Codex CLI';
    } else if (route.startsWith('hermes-agent:')) {
      const parts = route.slice('hermes-agent:'.length).split(':');
      if (parts.length > 1) effort = parts.pop() || '';
      model = parts.join(':') || model;
      provider = 'Hermes Agent';
    } else if (route.startsWith('openclaw:')) {
      const parts = route.slice('openclaw:'.length).split(':');
      if (parts.length > 1) effort = parts.pop() || '';
      model = parts.join(':') || model;
      provider = 'OpenClaw';
    } else if (route.startsWith('ollama:')) {
      model = route.slice('ollama:'.length) || model;
      provider = 'Ollama';
    } else if (providerKey === 'codex-cli' || providerKey === 'gpt-cli' || path === 'frontier-codex-cli') {
      provider = 'Codex CLI';
    } else if (providerKey === 'hermes-agent' || providerKey === 'openai-codex' || path === 'hermes-agent') {
      provider = 'Hermes Agent';
    } else if (providerKey === 'openclaw' || path === 'openclaw') {
      provider = 'OpenClaw';
    } else if (providerKey === 'ollama' || path === 'ollama') {
      provider = 'Ollama';
    }
    if (!model) return live ? 'No model running' : 'No model started';
    return `${provider ? provider + ' · ' : ''}${model}${['Codex CLI', 'Hermes Agent', 'OpenClaw'].includes(provider) && effort ? ' (' + effort + ')' : ''}`;
  };
  const rowHtml = log => {
    const alert = log.alert || {};
    const route = [alert.source_ip, alert.destination_ip].filter(Boolean).join(' > ') + (alert.destination_port ? ` : ${alert.destination_port}` : '');
    const gpu = log.gpu_temperature_celsius_max != null ? `${Number(log.gpu_temperature_celsius_max).toFixed(1)}` : 'Unavailable';
    const gpuUtil = (log.gpu_utilization_percent_max ?? log.gpu_percent_max) != null ? `${Number(log.gpu_utilization_percent_max ?? log.gpu_percent_max).toFixed(1)}%` : 'Unavailable';
    const cpuTemp = log.cpu_temperature_celsius_max != null ? `${Number(log.cpu_temperature_celsius_max).toFixed(1)}` : 'Unavailable';
    const socTemp = log.soc_temperature_celsius_max != null ? `${Number(log.soc_temperature_celsius_max).toFixed(1)}` : 'Unavailable';
    const memory = log.memory_used_percent_max != null ? `${Number(log.memory_used_percent_max).toFixed(1)}%` : 'Unavailable';
    const power = log.power_watts_max != null ? `${Number(log.power_watts_max).toFixed(1)} W` : 'Unavailable';
    const cpu = log.cpu_used_percent_max != null ? `${Number(log.cpu_used_percent_max).toFixed(1)}%` : 'Unavailable';
    const detail = log.error || alert.primary_alert_id || '';
    const ruleName = alert.rule_name || 'Security Onion Alert';
    const routeText = route || 'n/a';
    const rowClass=log.run_kind==='second_opinion'?' class="llm-log-second-opinion"':log.run_kind==='disagreement_adjudication'?' class="llm-log-adjudication"':'';
    return `<tr${rowClass}><td>${esc(log.started_at || '')}</td><td>${esc(alert.alert_count || 0)}</td><td><strong title="${esc(ruleName)}">${esc(ruleName)}</strong><code title="${esc(routeText)}">${esc(routeText)}</code></td><td>${badge(log.status)}</td><td>${esc(agentLabel(log))}</td><td>${esc(jobLabel(log))}</td><td>${esc(runtime(log.runtime_seconds))}</td><td>${esc(gpu)}</td><td>${esc(gpuUtil)}</td><td>${esc(cpuTemp)}</td><td>${esc(socTemp)}</td><td>${esc(memory)}</td><td>${esc(power)}</td><td>${esc(cpu)}</td><td>${esc(bytes(log.pcap_total_size_bytes))}</td><td>${esc(bytes(log.alert_context_size_bytes))}</td><td><code>${esc(executedModel(log, log.status === 'running'))}</code></td><td>${esc(detail)}</td></tr>`;
  };
  const renderCurrent = current => {
    currentAnalysisState = current || {};
    const alert = current?.alert || {};
    const running = current?.status === 'running';
    const title = document.querySelector('#llm-current-title');
    const route = document.querySelector('#llm-current-route');
    const currentStatus = document.querySelector('#llm-current-status');
    const agent = document.querySelector('#llm-current-agent');
    const job = document.querySelector('#llm-current-job');
    const model = document.querySelector('#llm-current-model');
    const started = document.querySelector('#llm-current-started');
    const currentRuntime = document.querySelector('#llm-current-runtime');
    const count = document.querySelector('#llm-current-count');
    const queue = document.querySelector('#llm-current-queue');
    if (title) title.textContent = running ? (alert.rule_name || 'Analyzing Security Onion alert') : 'No active AI analysis';
    if (route) route.textContent = running ? `${alert.source_ip || ''} > ${alert.destination_ip || ''}${alert.destination_port ? ' : ' + alert.destination_port : ''}`.trim() : 'Idle';
    const activePhase = String(current?.active_phase || 'primary_analysis');
    const phaseLabel = String(current?.phase_label || (activePhase === 'second_opinion'
      ? 'Second-opinion review'
      : activePhase === 'disagreement_adjudication' ? 'Disagreement adjudication'
      : activePhase === 'live_follow_up' ? 'Live-evidence follow-up'
      : activePhase === 'preparing' ? 'Preparing analysis'
      : activePhase === 'post_processing' ? 'Finalizing report'
      : activePhase === 'concurrent' ? 'Concurrent analyses' : 'Primary analysis'));
    if (currentStatus) { currentStatus.textContent = running ? phaseLabel : 'Idle'; currentStatus.className = `llm-status-badge ${running ? 'running' : 'unknown'}`; }
    if (agent) agent.textContent = running ? agentLabel(current) : 'No agent running';
    if (job) job.textContent = running ? jobLabel(current) : 'No active job';
    if (model) model.textContent = running ? executedModel(current, true) : 'No model running';
    if (started) started.textContent = current?.started_at || 'n/a';
    if (currentRuntime) renderCurrentRuntime();
    if (count) count.textContent = alert.alert_count || '0';
    if (queue) queue.textContent = current?.queue_size ?? '0';
  };
  async function loadCurrent() {
    try {
      const response = await fetch('/api/llm-analysis/current', {cache:'no-store'});
      if (!response.ok) return false;
      const current = await response.json();
      const nextSignature = stableSignature(current);
      if (nextSignature === currentSignature) return false;
      currentSignature = nextSignature;
      renderCurrent(current);
      return true;
    } catch (_) {}
    return false;
  }
  async function loadLogs(reset=false) {
    if (reset) page = 1;
    const limit = Math.min(50, Math.max(1, Number(pageSizeSelect?.value || 25)));
    try {
      const response = await fetch(`/api/llm-analysis/logs?page=${page}&limit=${limit}`, {cache:'no-store'});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const nextSignature = stableSignature(data);
      if (nextSignature === logSignature) return false;
      logSignature = nextSignature;
      totalPages = Math.max(1, Number(data.total_pages || 1));
      page = Math.min(Math.max(1, Number(data.page || page)), totalPages);
      const historical = Array.isArray(data.logs) ? data.logs : [];
      const activeRuns = page === 1 && Array.isArray(data.active_runs) ? data.active_runs : [];
      const rows = [...activeRuns, ...historical];
      if (body) {
        body.innerHTML = rows.length ? rows.map(rowHtml).join('') : '<tr><td colspan="18" class="llm-empty-row">No AI analysis runs found yet.</td></tr>';
        body.dataset.liveRenderVersion = String(Number(body.dataset.liveRenderVersion || 0) + 1);
      }
      if (status) status.textContent = `Page ${page} of ${totalPages} · ${data.primary_total || 0} primary · ${data.second_opinion_total || 0} second opinion · ${data.disagreement_adjudication_total || 0} adjudication${activeRuns.length ? ` · ${activeRuns.length} running` : ''}`;
      if (totalRuns) totalRuns.textContent = String(data.total || 0);
      if (agentTotals) {
        const labels = {
          'soc-analyst':'SOC Analyst',
          'incident-responder':'Incident Responder',
          'siem-engineer':'SIEM Engineer',
          'cyber-threat-intel':'Cyber Threat Intel',
          'threat-hunter':'Threat Hunter',
          'unknown':'Legacy / unknown',
        };
        const totals = data.agent_totals && typeof data.agent_totals === 'object' ? data.agent_totals : {};
        agentTotals.innerHTML = Object.entries(totals)
          .sort((left, right) => Number(right[1] || 0) - Number(left[1] || 0))
          .map(([role, count]) => `<span class="llm-log-agent-total">${esc(labels[role] || role)} <b>${esc(count)}</b></span>`)
          .join('');
      }
      if (prev) prev.disabled = page <= 1;
      if (next) next.disabled = page >= totalPages;
      return true;
    } catch (error) {
      if (status) status.textContent = `Log API unavailable: ${error.message}`;
      return false;
    }
  }
  pageSizeSelect?.addEventListener('change', () => loadLogs(true));
  prev?.addEventListener('click', () => { if (page > 1) { page -= 1; loadLogs(); } });
  next?.addEventListener('click', () => { if (page < totalPages) { page += 1; loadLogs(); } });
  loadCurrent();
  loadLogs(true);
  setInterval(renderCurrentRuntime, 1000);
  const reportsLiveRefresh = async () => (await Promise.all([loadCurrent(), loadLogs(false)])).some(Boolean);
  if (window.OnionSentinelReactiveTables) {
    window.OnionSentinelReactiveTables.register('llm-analysis-tables', reportsLiveRefresh, {intervalMs: 4000});
  } else {
    setInterval(reportsLiveRefresh, 4000);
  }
})();
</script>
'''


def inject_reports_assets(text: str) -> str:
    if REPORTS_PAGE_ASSETS not in text:
        text = text.replace('</body>', REPORTS_PAGE_ASSETS + '</body>', 1)
    return text
