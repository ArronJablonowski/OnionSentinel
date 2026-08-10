"""LLM report views and SOC-alert client behavior assets."""
from __future__ import annotations

from dashboard_builder_contract import *  # noqa: F403
from dashboard_builder_settings import *  # noqa: F403
from dashboard_builder_report_core import *  # noqa: F403


def load_llm_analysis_logs(limit: int = 250) -> list[dict[str, object]]:
    """Read recent local LLM analysis audit rows from the runtime JSONL file."""
    return LLM_ANALYSIS_LOG_INDEX.tail(limit)


def count_llm_analysis_logs() -> int:
    """Count local LLM analysis audit rows without parsing every JSON payload."""
    total, _, _ = LLM_ANALYSIS_LOG_INDEX.page(page=1, limit=1)
    return total


def load_current_llm_analysis() -> dict[str, object]:
    """Return the current or most recent local LLM analysis state."""
    try:
        data = json.loads(LLM_ANALYSIS_CURRENT_FILE.read_text(encoding='utf-8'))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def current_llm_queue_size() -> int:
    try:
        status = json.loads(STATUS_JSON.read_text(encoding='utf-8'))
        counts = status.get('ai', {}).get('counts', {}) if isinstance(status, dict) else {}
        return max(0, int(counts.get('queued') or 0))
    except Exception:
        return 0


def llm_log_alert(log: dict[str, object]) -> dict[str, object]:
    alert = log.get('alert') if isinstance(log.get('alert'), dict) else {}
    return alert


def llm_log_runtime(log: dict[str, object]) -> str:
    try:
        seconds = float(log.get('runtime_seconds') or 0)
    except (TypeError, ValueError):
        return 'n/a'
    if seconds <= 0:
        return 'n/a'
    minutes, sec = divmod(int(round(seconds)), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f'{hours}h {minutes}m {sec}s'
    if minutes:
        return f'{minutes}m {sec}s'
    return f'{sec}s'


def llm_log_gpu(log: dict[str, object]) -> str:
    value = log.get('gpu_temperature_celsius_max')
    try:
        if value is not None:
            return f'{float(value):.1f}'
    except (TypeError, ValueError):
        pass
    return 'Unavailable'


def llm_log_gpu_utilization(log: dict[str, object]) -> str:
    value = log.get('gpu_utilization_percent_max', log.get('gpu_percent_max'))
    try:
        if value is not None:
            return f'{float(value):.1f}%'
    except (TypeError, ValueError):
        pass
    return 'Unavailable'


def llm_log_cpu_temperature(log: dict[str, object]) -> str:
    value = log.get('cpu_temperature_celsius_max')
    try:
        if value is not None:
            return f'{float(value):.1f}'
    except (TypeError, ValueError):
        pass
    return 'Unavailable'


def llm_log_soc_temperature(log: dict[str, object]) -> str:
    value = log.get('soc_temperature_celsius_max')
    try:
        if value is not None:
            return f'{float(value):.1f}'
    except (TypeError, ValueError):
        pass
    return 'Unavailable'


def llm_log_memory(log: dict[str, object]) -> str:
    value = log.get('memory_used_percent_max')
    try:
        if value is not None:
            return f'{float(value):.1f}%'
    except (TypeError, ValueError):
        pass
    return 'Unavailable'


def llm_log_power(log: dict[str, object]) -> str:
    value = log.get('power_watts_max')
    try:
        if value is not None:
            return f'{float(value):.1f} W'
    except (TypeError, ValueError):
        pass
    return 'Unavailable'


def llm_log_cpu(log: dict[str, object]) -> str:
    value = log.get('cpu_used_percent_max')
    try:
        if value is not None:
            return f'{float(value):.1f}%'
    except (TypeError, ValueError):
        pass
    return 'Unavailable'


def llm_log_size(log: dict[str, object], key: str) -> str:
    try:
        return human_size(max(0, int(log.get(key) or 0)))
    except (TypeError, ValueError):
        return '0 B'


def llm_log_status_badge(log: dict[str, object]) -> str:
    status = str(log.get('status') or 'unknown').lower()
    label = {'success': 'Success', 'failure': 'Failed', 'running': 'Running'}.get(status, status.title())
    return render_reports_status_badge(status, label)




def _reports_alert_route(alert: dict[str, object], empty: str) -> str:
    src = str(alert.get('source_ip') or '').strip()
    dst = str(alert.get('destination_ip') or '').strip()
    port = str(alert.get('destination_port') or '').strip()
    return f'{src} > {dst}' + (f' : {port}' if port else '') if src or dst else empty


def _reports_status(log: dict[str, object]) -> tuple[str, str]:
    status = str(log.get('status') or 'unknown').lower()
    label = {'success': 'Success', 'failure': 'Failed', 'running': 'Running'}.get(status, status.title())
    return status, label


def _reports_log_detail(log: dict[str, object], alert: dict[str, object]) -> str:
    error = str(log.get('error') or '').strip()
    return compact_text(error or str(alert.get('primary_alert_id') or ''), 120)


def _reports_log_row_view(log: dict[str, object]) -> ReportsLogRowViewModel:
    alert = llm_log_alert(log)
    status, status_label = _reports_status(log)
    return ReportsLogRowViewModel(
        started=normalize_iso_display_text(log.get('started_at') or ''),
        alert_count=str(alert.get('alert_count') or 0),
        rule_name=str(alert.get('rule_name') or 'Security Onion Alert'),
        route=_reports_alert_route(alert, 'n/a'),
        status_key=status, status_label=status_label,
        agent=str(log.get('agent_label') or llm_agent_label(log)),
        job=str(log.get('job_label') or llm_job_label(log)),
        runtime=llm_log_runtime(log), gpu_temperature=llm_log_gpu(log),
        gpu_utilization=llm_log_gpu_utilization(log),
        cpu_temperature=llm_log_cpu_temperature(log), soc_temperature=llm_log_soc_temperature(log),
        memory=llm_log_memory(log), power=llm_log_power(log), cpu=llm_log_cpu(log),
        pcap_size=llm_log_size(log, 'pcap_total_size_bytes'),
        alert_size=llm_log_size(log, 'alert_context_size_bytes'),
        model=llm_executed_model_label(log, live=status == 'running'),
        detail=_reports_log_detail(log, alert),
        run_kind=str(log.get('run_kind') or ''),
    )


def _reports_current_owner(current: dict[str, object], running: bool) -> tuple[str, str]:
    if not running:
        return 'No agent running', 'No active job'
    return llm_agent_label(current), llm_job_label(current)


def _reports_current_view(current: dict[str, object]) -> ReportsCurrentRunViewModel:
    alert = llm_log_alert(current)
    status = str(current.get('status') or 'idle').lower()
    running = status == 'running'
    phase = str(current.get('phase_label') or (llm_phase_label(current) if running else 'Idle'))
    default_agent, default_job = _reports_current_owner(current, running)
    return ReportsCurrentRunViewModel(
        title=str(alert.get('rule_name') or 'No active AI analysis'),
        route=_reports_alert_route(alert, 'Idle'),
        started=normalize_iso_display_text(current.get('started_at') or ''), running=running,
        status_label=phase,
        agent=str(current.get('agent_label') or default_agent),
        job=str(current.get('job_label') or default_job),
        model=str(current.get('runtime_model_label') or llm_executed_model_label(current, live=True)),
        alert_count=str(alert.get('alert_count') or 0),
        queue_size=str(current.get('queue_size', current_llm_queue_size())),
    )


def llm_log_table_row(log: dict[str, object]) -> str:
    return render_reports_log_row(_reports_log_row_view(log))



def llm_current_panel(current: dict[str, object]) -> str:
    return render_reports_current_panel(_reports_current_view(current))



def reports_page_section(_reports: list[AlertReport]) -> str:
    logs = load_llm_analysis_logs()
    view = ReportsPageViewModel(
        current=_reports_current_view(load_current_llm_analysis()),
        rows=tuple(_reports_log_row_view(log) for log in logs[:50]),
        total_runs=count_llm_analysis_logs(),
    )
    return render_reports_page(view)





ALERTS_REACTIVE_FALLBACK = '''
<script>
(() => {
  const runtime = window.OnionSentinelReactiveTables;
  const refreshButton = document.querySelector('#alerts-refresh');
  if (!runtime || !refreshButton) return;
  runtime.register('soc-alerts-live-stream', () => {
    if (window.__socEventsConnected) return;
    const page = document.querySelector('#api-page-select');
    const modalOpen = document.querySelector('#suppress-modal')?.hidden === false
      || document.querySelector('#analyst-adjudication-modal')?.hidden === false;
    if ((page && page.value !== '1') || modalOpen || document.querySelector('tbody.report-row-group.expanded')) return;
    refreshButton.click();
  }, {intervalMs: 5000});
})();
</script>
'''


ALERTS_PAGE_SCROLL_STABILIZER = '''
<style>
html.alerts-scroll-stable,.alerts-scroll-stable body,.alerts-scroll-stable .alert-table,.alerts-scroll-stable .detail-template{overflow-anchor:none}
html.alerts-scroll-stable,.alerts-scroll-stable body{max-width:100%;overflow-x:hidden}
.alert-timeline-burst{position:absolute;top:50%;z-index:0;height:22px;min-width:28px;border:1px solid rgba(143,244,255,.26);border-radius:999px;background:linear-gradient(90deg,rgba(34,211,238,.16),rgba(143,244,255,.38),rgba(34,211,238,.16));box-shadow:0 0 20px rgba(34,211,238,.20),inset 0 0 16px rgba(143,244,255,.12);transform:translateY(-50%)}
.alert-timeline-burst i{position:absolute;left:50%;top:-29px;transform:translateX(-50%);display:inline-flex;align-items:center;justify-content:center;min-width:26px;border:1px solid rgba(143,244,255,.28);border-radius:999px;padding:2px 7px;color:#dce9f8;background:#071018;font-size:10px;font-style:normal;font-weight:900;white-space:nowrap}
</style>
<script>
(() => {
  if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
  function init(attempt = 0) {
  const table = document.querySelector('.alert-table');
  if (!table) {
    if (attempt < 50) window.setTimeout(() => init(attempt + 1), 100);
    return;
  }
  if (window.__socAlertScrollStabilizer) return;
  document.documentElement.classList.add('alerts-scroll-stable');
  const tableCard = document.querySelector('.table-card');
  let snapshot = null;
  let frozenSnapshot = null;

  const expandedGroup = () => document.querySelector('tbody.report-row-group.expanded');
  const anchorFor = group => group?.querySelector('.detail-template-row') || group?.querySelector('.report-row') || group;

  function rememberExpandedPosition() {
    if (frozenSnapshot) return null;
    const group = expandedGroup();
    const anchor = anchorFor(group);
    if (!group || !anchor) return null;
    snapshot = {
      id: group.dataset.reportId || '',
      scrollY: window.scrollY,
      horizontal: tableCard?.scrollLeft || 0,
    };
    return snapshot;
  }

  function captureExpandedPosition() {
    rememberExpandedPosition();
    frozenSnapshot = snapshot ? { ...snapshot, scrollY: window.scrollY } : null;
    return frozenSnapshot;
  }

  async function loadDetailFor(group) {
    const id = group?.dataset?.reportId || '';
    const target = group?.querySelector('.api-detail-content');
    if (!id || !target || target.dataset.detailLoaded === 'true' || target.dataset.detailLoading === 'true') return;
    target.dataset.detailLoading = 'true';
    target.insertAdjacentHTML('afterbegin', '<p class="api-detail-loading">Loading full Detailed Alert Report...</p>');
    try {
      const response = await fetch(`/api/soc-alerts/${encodeURIComponent(id)}/detail`, { cache: 'no-store' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (!data.ok || !data.detail_html) throw new Error(data.error || 'Detail unavailable');
      target.innerHTML = data.detail_html;
      target.dataset.detailLoaded = 'true';
    } catch (error) {
      target.querySelector('.api-detail-loading')?.remove();
      target.insertAdjacentHTML('afterbegin', `<p class="api-detail-error">Full detail load failed: ${String(error.message || error).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]))}</p>`);
    } finally {
      delete target.dataset.detailLoading;
      if (frozenSnapshot?.id === id) {
        window.requestAnimationFrame(() => restoreExpandedPosition(frozenSnapshot));
      }
    }
  }

  function ensureExpandedGroup(captured) {
    if (!captured?.id) return null;
    const group = document.querySelector(`tbody.report-row-group[data-report-id="${CSS.escape(captured.id)}"]`);
    if (!group || getComputedStyle(group).display === 'none') return null;
    if (!group.classList.contains('expanded')) {
      document.querySelectorAll('tbody.report-row-group.expanded').forEach(other => {
        if (other !== group) {
          other.classList.remove('expanded');
          other.querySelector('.report-row')?.classList.remove('selected');
          other.querySelector('.report-row')?.setAttribute('aria-selected', 'false');
        }
      });
      group.classList.add('expanded');
      group.querySelector('.report-row')?.classList.add('selected');
      group.querySelector('.report-row')?.setAttribute('aria-selected', 'true');
    }
    loadDetailFor(group);
    return group;
  }

  function restoreExpandedPosition(captured = snapshot) {
    if (!captured?.id) return;
    const group = ensureExpandedGroup(captured);
    if (!group || !group.classList.contains('expanded')) return;
    if (tableCard && Number.isFinite(captured.horizontal)) tableCard.scrollLeft = captured.horizontal;
    const targetY = Number(captured.scrollY);
    if (Number.isFinite(targetY) && Math.abs(window.scrollY - targetY) > 1) {
      window.scrollTo({ top: targetY, left: 0, behavior: 'auto' });
    }
  }

  function scheduleRestore(captured = frozenSnapshot || snapshot) {
    if (!captured?.id) return;
    window.requestAnimationFrame(() => {
      restoreExpandedPosition(captured);
    });
  }

  function thawAfterRestore() {
    window.setTimeout(() => {
      frozenSnapshot = null;
    }, 250);
  }

  window.__socAlertScrollStabilizer = {
    capture: captureExpandedPosition,
    restore(captured) {
      if (captured) {
        snapshot = { ...captured };
        frozenSnapshot = { ...captured };
      }
      scheduleRestore(frozenSnapshot || snapshot);
      thawAfterRestore();
    },
    clear() {
      snapshot = null;
      frozenSnapshot = null;
    },
  };

  window.addEventListener('scroll', () => { if (expandedGroup()) rememberExpandedPosition(); }, { passive: true });
  window.addEventListener('resize', () => { if (expandedGroup()) rememberExpandedPosition(); }, { passive: true });
  tableCard?.addEventListener('scroll', () => { if (expandedGroup()) rememberExpandedPosition(); }, { passive: true });
  }
  init();
})();
</script>
'''


PINNED_ALERT_ROW_SCROLL_SYNC = '''
<style>
.pinned-alert-viewport{
  overflow-x:auto!important;
  overflow-y:hidden!important;
  overscroll-behavior-x:contain;
  scrollbar-width:thin;
  scrollbar-color:rgba(143,244,255,.45) rgba(7,16,24,.72);
  touch-action:pan-x;
}
.pinned-alert-viewport::-webkit-scrollbar{height:7px}
.pinned-alert-viewport::-webkit-scrollbar-track{background:rgba(7,16,24,.72)}
.pinned-alert-viewport::-webkit-scrollbar-thumb{border-radius:999px;background:rgba(143,244,255,.38)}
.pinned-alert-row{min-width:max-content;transform:none!important;will-change:auto!important}
.pinned-alert-cell{width:auto!important;min-width:0!important}
.pinned-alert-cell.port-cell{margin-left:0!important}
.pinned-alert-cell.action-cell{display:flex;gap:6px;min-width:max-content;white-space:nowrap}
.pinned-alert-cell.action-cell .ack-button{flex:0 0 auto;margin-left:0}
</style>
<script>
(() => {
  function init(attempt = 0) {
    const viewport = document.querySelector('.pinned-alert-viewport');
    const pinnedRow = document.querySelector('.pinned-alert-row');
    const tableCard = document.querySelector('.table-card');
    if (!viewport || !pinnedRow || !tableCard) {
      if (attempt < 50) window.setTimeout(() => init(attempt + 1), 100);
      return;
    }
    if (viewport.dataset.horizontalSync === 'true') return;
    viewport.dataset.horizontalSync = 'true';
    let frame = 0;

    const visibleSourceCells = () => {
      const row = document.querySelector('tbody.report-row-group.expanded .report-row');
      if (!row) return [];
      return [...row.children].filter(cell => getComputedStyle(cell).display !== 'none');
    };

    function alignPinnedColumns() {
      frame = 0;
      const sourceCells = visibleSourceCells();
      const cloneCells = [...pinnedRow.children];
      if (!sourceCells.length || sourceCells.length !== cloneCells.length) return;
      const widths = sourceCells.map(cell => Math.max(1, Math.ceil(cell.getBoundingClientRect().width)));
      pinnedRow.style.setProperty('grid-template-columns', widths.map(width => `${width}px`).join(' '), 'important');
      pinnedRow.style.setProperty('width', `${widths.reduce((sum, width) => sum + width, 0)}px`, 'important');
      pinnedRow.style.setProperty('transform', 'none', 'important');
      if (Math.abs(viewport.scrollLeft - tableCard.scrollLeft) > 1) viewport.scrollLeft = tableCard.scrollLeft;
    }

    function scheduleAlignment() {
      if (frame) return;
      frame = window.requestAnimationFrame(alignPinnedColumns);
    }

    function synchronize(source, target) {
      if (Math.abs(target.scrollLeft - source.scrollLeft) <= 1) return;
      target.scrollLeft = source.scrollLeft;
    }

    tableCard.addEventListener('scroll', () => {
      synchronize(tableCard, viewport);
      scheduleAlignment();
    }, { passive: true });
    viewport.addEventListener('scroll', () => synchronize(viewport, tableCard), { passive: true });
    viewport.addEventListener('wheel', event => {
      if (viewport.scrollWidth <= viewport.clientWidth + 1) return;
      const delta = Math.abs(event.deltaX) >= Math.abs(event.deltaY) ? event.deltaX : event.deltaY;
      if (!delta) return;
      event.preventDefault();
      viewport.scrollLeft += delta;
      synchronize(viewport, tableCard);
      scheduleAlignment();
    }, { passive: false });
    new MutationObserver(scheduleAlignment).observe(pinnedRow, { childList: true, subtree: true });
    document.addEventListener('soc:alert-column-width-changed', scheduleAlignment);
    window.addEventListener('resize', scheduleAlignment, { passive: true });
    window.addEventListener('scroll', scheduleAlignment, { passive: true });
    scheduleAlignment();
  }
  init();
})();
</script>
'''


ALERT_COLUMN_SINGLE_WRAP_CONTRACT = '''
<style>
:root{--soc-alert-title-column-width:420px}
.alert-table th:nth-child(5),
.alert-table td.alert-cell{
  width:var(--soc-alert-title-column-width)!important;
  min-width:var(--soc-alert-title-column-width)!important;
}
.alert-table .alert-cell strong,
.pinned-alert-row .alert-cell strong{
  display:-webkit-box!important;
  overflow:hidden;
  color:#f2f7ff;
  font-size:13px;
  line-height:1.35;
  overflow-wrap:normal;
  word-break:normal;
  hyphens:none;
  -webkit-box-orient:vertical;
  -webkit-line-clamp:2;
  line-clamp:2;
}
</style>
<script>
(() => {
  function init(attempt = 0) {
    const table = document.querySelector('.alert-table');
    if (!table) {
      if (attempt < 50) window.setTimeout(() => init(attempt + 1), 100);
      return;
    }
    if (table.dataset.dynamicAlertWidth === 'true') return;
    table.dataset.dynamicAlertWidth = 'true';
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    let frame = 0;
    let currentWidth = 0;

    function minimumTwoLineWidth(text) {
      const words = String(text || '').trim().split(/\\s+/).filter(Boolean);
      if (!words.length || !context) return 0;
      if (words.length === 1) return context.measureText(words[0]).width;
      let best = context.measureText(words.join(' ')).width;
      for (let split = 1; split < words.length; split += 1) {
        const first = context.measureText(words.slice(0, split).join(' ')).width;
        const second = context.measureText(words.slice(split).join(' ')).width;
        best = Math.min(best, Math.max(first, second));
      }
      return best;
    }

    function updateAlertColumnWidth() {
      frame = 0;
      const titles = [...table.querySelectorAll('.report-row .alert-cell strong')];
      if (!titles.length || !context) return;
      const style = getComputedStyle(titles[0]);
      context.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
      const contentWidth = titles.reduce(
        (largest, title) => Math.max(largest, minimumTwoLineWidth(title.textContent)),
        0,
      );
      const nextWidth = Math.max(420, Math.min(960, Math.ceil(contentWidth + 28)));
      if (Math.abs(nextWidth - currentWidth) <= 1) return;
      currentWidth = nextWidth;
      document.documentElement.style.setProperty('--soc-alert-title-column-width', `${nextWidth}px`);
      document.dispatchEvent(new CustomEvent('soc:alert-column-width-changed', { detail: { width: nextWidth } }));
    }

    function scheduleUpdate() {
      if (frame) return;
      frame = window.requestAnimationFrame(updateAlertColumnWidth);
    }

    new MutationObserver(scheduleUpdate).observe(table, { childList: true, subtree: true });
    window.addEventListener('resize', scheduleUpdate, { passive: true });
    document.fonts?.ready?.then(scheduleUpdate);
    scheduleUpdate();
  }
  init();
})();
</script>
'''
