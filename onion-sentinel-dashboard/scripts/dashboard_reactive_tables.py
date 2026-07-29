"""Shared browser runtime for live Onion Sentinel table updates."""

from __future__ import annotations


REACTIVE_TABLES_CSS = r'''
<style>
.os-live-status{display:inline-flex;align-items:center;gap:6px;width:max-content;margin-left:10px;border:1px solid rgba(34,211,238,.24);border-radius:999px;padding:4px 8px;color:#8ff4ff;background:rgba(34,211,238,.055);font-size:9.5px;font-weight:950;letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}
.os-live-status-dot{width:7px;height:7px;border-radius:999px;background:#46e58b;box-shadow:0 0 0 3px rgba(70,229,139,.10),0 0 10px rgba(70,229,139,.45)}
.os-live-status[data-state="updating"] .os-live-status-dot{background:#8ff4ff;box-shadow:0 0 0 3px rgba(143,244,255,.10),0 0 12px rgba(143,244,255,.55);animation:os-live-pulse 1s ease-in-out infinite}
.os-live-status[data-state="paused"]{color:#91a4ba;border-color:rgba(148,163,184,.20);background:rgba(148,163,184,.045)}
.os-live-status[data-state="paused"] .os-live-status-dot{background:#91a4ba;box-shadow:none}
.os-live-status[data-state="retrying"]{color:#ffcb67;border-color:rgba(255,203,103,.28);background:rgba(255,203,103,.055)}
.os-live-status[data-state="retrying"] .os-live-status-dot{background:#ffcb67;box-shadow:0 0 10px rgba(255,203,103,.38)}
@keyframes os-live-pulse{50%{opacity:.35;transform:scale(.72)}}
@media(max-width:700px){.os-live-status{margin-left:7px;padding:3px 7px;font-size:8.5px}.os-live-status-dot{width:6px;height:6px}}
@media(prefers-reduced-motion:reduce){.os-live-status[data-state="updating"] .os-live-status-dot{animation:none}}
</style>
'''


REACTIVE_TABLES_JS = r'''
<script>
(() => {
  if (window.OnionSentinelReactiveTables) return;
  const jobs = new Map();
  let statusElement = null;
  let statusTimer = 0;
  const now = () => Date.now();
  const normalizeInterval = value => Math.max(1000, Number(value || 5000));
  const statusCopy = {
    live: ['Live', 'Tables update automatically while this page is visible.'],
    updating: ['Updating', 'Refreshing live table data.'],
    paused: ['Paused', 'Live table updates pause while this page is hidden.'],
    retrying: ['Retrying', 'A live update failed. Onion Sentinel will retry automatically.']
  };
  function ensureStatus() {
    if (statusElement?.isConnected) return statusElement;
    const titleRow = document.querySelector('.title-row');
    if (!titleRow || jobs.size === 0) return null;
    statusElement = document.createElement('span');
    statusElement.id = 'onion-sentinel-live-status';
    statusElement.className = 'os-live-status';
    statusElement.setAttribute('role', 'status');
    statusElement.setAttribute('aria-live', 'polite');
    statusElement.innerHTML = '<i class="os-live-status-dot" aria-hidden="true"></i><span>Live</span>';
    titleRow.insertBefore(statusElement, titleRow.querySelector('.mobile-controls-toggle'));
    setStatus(document.hidden ? 'paused' : 'live');
    return statusElement;
  }
  function setStatus(state) {
    const element = ensureStatus();
    if (!element) return;
    const [label, title] = statusCopy[state] || statusCopy.live;
    element.dataset.state = state;
    element.querySelector('span').textContent = label;
    element.title = title;
  }
  function updateAggregateStatus() {
    window.clearTimeout(statusTimer);
    if (document.hidden) {
      setStatus('paused');
      return;
    }
    if ([...jobs.values()].some(job => job.running)) {
      setStatus('updating');
      return;
    }
    if ([...jobs.values()].some(job => job.lastError && now() - job.lastErrorAt < job.intervalMs * 2)) {
      setStatus('retrying');
      return;
    }
    setStatus('live');
  }
  async function run(job, reason = 'interval') {
    if (!job || job.running || document.hidden) return false;
    if (job.when && !job.when()) {
      job.nextAt = now() + Math.min(job.intervalMs, 1000);
      return false;
    }
    job.running = true;
    updateAggregateStatus();
    let succeeded = false;
    try {
      await Promise.resolve(job.refresh({reason, name: job.name}));
      job.lastSuccessAt = now();
      job.lastError = '';
      succeeded = true;
      document.dispatchEvent(new CustomEvent('onion-sentinel:reactive-update', {
        detail: {name: job.name, reason, updatedAt: job.lastSuccessAt}
      }));
    } catch (error) {
      job.lastError = String(error?.message || error || 'Live update failed');
      job.lastErrorAt = now();
      document.dispatchEvent(new CustomEvent('onion-sentinel:reactive-error', {
        detail: {name: job.name, reason, error: job.lastError, failedAt: job.lastErrorAt}
      }));
    } finally {
      job.running = false;
      job.nextAt = now() + job.intervalMs;
      updateAggregateStatus();
      statusTimer = window.setTimeout(updateAggregateStatus, 1400);
    }
    return succeeded;
  }
  function register(name, refresh, options = {}) {
    if (!name || typeof refresh !== 'function') throw new TypeError('A live table job requires a name and refresh function.');
    const intervalMs = normalizeInterval(options.intervalMs);
    const existing = jobs.get(name);
    const job = existing || {name, running: false, lastError: '', lastErrorAt: 0, lastSuccessAt: 0};
    Object.assign(job, {
      refresh,
      intervalMs,
      when: typeof options.when === 'function' ? options.when : null,
      nextAt: now() + (options.immediate ? 0 : intervalMs)
    });
    jobs.set(name, job);
    ensureStatus();
    updateAggregateStatus();
    if (options.immediate) void run(job, 'register');
    return () => jobs.delete(name);
  }
  function refreshAll(reason = 'manual') {
    if (document.hidden) return Promise.resolve([]);
    return Promise.all([...jobs.values()].map(job => run(job, reason)));
  }
  function fragmentSignature(element) {
    const clone = element.cloneNode(true);
    clone.querySelectorAll('[aria-expanded]').forEach(node => node.setAttribute('aria-expanded', 'false'));
    clone.querySelectorAll('.siem-recommendation-detail,.threat-hunt-detail').forEach(node => { node.hidden = true; });
    clone.querySelectorAll('[data-copy-target]').forEach(button => { button.textContent = 'Copy'; });
    return clone.innerHTML;
  }
  async function refreshFragment(selector, options = {}) {
    const current = document.querySelector(selector);
    if (!current) return false;
    const response = await fetch(`${location.pathname}?live_fragment=${now()}`, {cache: 'no-store'});
    if (!response.ok) throw new Error(`Dashboard fragment HTTP ${response.status}`);
    const parsed = new DOMParser().parseFromString(await response.text(), 'text/html');
    const replacement = parsed.querySelector(selector);
    if (!replacement || fragmentSignature(replacement) === fragmentSignature(current)) return false;
    const state = typeof options.capture === 'function' ? options.capture(current) : null;
    const scrollX = window.scrollX;
    const scrollY = window.scrollY;
    current.innerHTML = replacement.innerHTML;
    if (typeof options.restore === 'function') options.restore(current, state);
    window.scrollTo(scrollX, scrollY);
    return true;
  }
  function tick() {
    if (document.hidden) return;
    const timestamp = now();
    jobs.forEach(job => {
      if (!job.running && timestamp >= job.nextAt) void run(job, 'interval');
    });
  }
  document.addEventListener('visibilitychange', () => {
    updateAggregateStatus();
    if (!document.hidden) void refreshAll('visible');
  });
  window.addEventListener('focus', () => void refreshAll('focus'));
  window.addEventListener('online', () => void refreshAll('online'));
  window.setInterval(tick, 500);
  window.OnionSentinelReactiveTables = Object.freeze({
    register,
    refreshAll,
    refreshFragment,
    status: () => [...jobs.values()].map(job => ({
      name: job.name,
      running: job.running,
      intervalMs: job.intervalMs,
      lastSuccessAt: job.lastSuccessAt,
      lastError: job.lastError
    }))
  });
})();
</script>
'''


def inject_reactive_table_assets(text: str) -> str:
    """Install the shared live-update runtime once in a generated page."""
    if REACTIVE_TABLES_CSS not in text:
        text = text.replace('</head>', REACTIVE_TABLES_CSS + '</head>', 1)
    if REACTIVE_TABLES_JS not in text:
        text = text.replace('</head>', REACTIVE_TABLES_JS + '</head>', 1)
    return text
