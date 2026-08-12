"""Executive Home styles and viewer-local timestamp client."""
from __future__ import annotations


EXECUTIVE_HOME_CSS = '''
<style>
.executive-home-view{display:block;padding-top:14px}.exec-hero{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:16px;border:1px solid rgba(148,163,184,.14);border-radius:14px;padding:20px;background:linear-gradient(135deg,#0d1620 0%,#101923 58%,#0b131c 100%);box-shadow:0 22px 48px rgba(0,0,0,.24),inset 0 1px 0 rgba(255,255,255,.035)}.exec-kicker{display:inline-block;border:1px solid rgba(34,211,238,.28);border-radius:999px;padding:6px 10px;color:#8ff4ff;background:rgba(34,211,238,.06);font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.12em}.exec-hero h2{margin:14px 0 8px;color:#f5f9ff;font-size:34px;line-height:1;letter-spacing:-.04em}.exec-hero p{max-width:68ch;margin:0;color:#9aaabd;font-size:14px;line-height:1.55}.exec-hero-stamp{min-width:210px;border:1px solid rgba(34,211,238,.16);border-radius:12px;padding:14px 16px;background:#071018;text-align:right}.exec-hero-stamp span,.exec-kpi span,.exec-card-title span{display:block;color:#8ff4ff;font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.11em}.exec-hero-stamp strong{display:block;margin-top:7px;color:#f3f8ff;font-size:14px}.exec-kpi-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;margin-bottom:18px}.exec-kpi,.exec-card{border:1px solid rgba(148,163,184,.13);border-radius:12px;background:#0d1620;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}.exec-kpi{min-height:120px;padding:18px}.exec-kpi strong{display:block;margin-top:10px;color:#f7fbff;font-size:34px;line-height:1;letter-spacing:0}.exec-kpi em{display:block;margin-top:8px;color:#9aa8b8;font-size:12px;font-style:normal;line-height:1.35}.exec-chart-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}.exec-card{min-height:286px;padding:18px 20px;overflow:hidden}.exec-card-title{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;min-height:38px;margin-bottom:14px}.exec-card-title b{max-width:150px;color:#f4f8ff;font-size:13px;line-height:1.25;text-align:right}.donut-layout{display:grid;grid-template-columns:128px minmax(0,1fr);gap:16px;align-items:center}.donut-wrap{position:relative;width:128px;height:128px}.donut-chart{width:128px;height:128px;transform:rotate(-90deg);overflow:visible}.donut-track{fill:none;stroke:rgba(148,163,184,.12);stroke-width:4}.donut-segment{fill:none;stroke-width:4;stroke-linecap:round}.donut-center{position:absolute;inset:0;display:grid;place-items:center;color:#f5f9ff;font-size:24px;font-weight:950}.donut-legend{display:grid;gap:8px;min-width:0}.donut-legend span{display:flex;align-items:center;gap:7px;color:#aeb9c7;font-size:12px;min-width:0}.donut-legend b{color:#f4f8ff}.legend-dot{width:8px;height:8px;border-radius:999px;flex:0 0 8px}.donut-critical,.donut-bg-critical{stroke:var(--red);background:var(--red)}.donut-high,.donut-bg-high{stroke:var(--orange);background:var(--orange)}.donut-medium,.donut-bg-medium{stroke:var(--amber);background:var(--amber)}.donut-low,.donut-bg-low{stroke:#86efac;background:#86efac}.donut-informational,.donut-bg-informational,.donut-info,.donut-bg-info{stroke:#93c5fd;background:#93c5fd}.donut-accepted,.donut-bg-accepted,.donut-cyan,.donut-bg-cyan{stroke:var(--cyan);background:var(--cyan)}.donut-suppressed,.donut-bg-suppressed{stroke:#a78bfa;background:#a78bfa}.donut-escalated,.donut-bg-escalated{stroke:var(--red);background:var(--red)}.donut-stored,.donut-bg-stored{stroke:#94a3b8;background:#94a3b8}.donut-other,.donut-bg-other{stroke:#64748b;background:#64748b}.donut-green,.donut-bg-green{stroke:var(--green);background:var(--green)}.donut-amber,.donut-bg-amber{stroke:var(--amber);background:var(--amber)}.exec-bars{display:grid;gap:10px;min-width:0}.exec-bar-row{display:grid;grid-template-columns:minmax(108px,1.05fr) minmax(64px,.9fr) minmax(66px,max-content);gap:10px;align-items:center;min-width:0}.exec-bar-label{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#dce8f7;font-size:12px;font-weight:800}.exec-bar-track{min-width:0;height:9px;border-radius:999px;background:rgba(148,163,184,.10);overflow:hidden}.exec-bar-track span{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,rgba(34,211,238,.55),rgba(143,244,255,.95));box-shadow:0 0 12px rgba(34,211,238,.22)}.exec-bar-value{min-width:66px;color:#8ff4ff;font-size:12px;font-weight:950;text-align:right;font-variant-numeric:tabular-nums}@media(max-width:1500px){.exec-chart-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:1300px){.exec-kpi-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.exec-chart-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:760px){.exec-hero{display:grid}.exec-hero-stamp{text-align:left;min-width:0}.exec-kpi-grid,.exec-chart-grid{grid-template-columns:1fr}.donut-layout{grid-template-columns:1fr;justify-items:center}.donut-legend{width:100%}.exec-bar-row{grid-template-columns:minmax(0,1fr) minmax(64px,.8fr) minmax(56px,max-content)}.exec-bar-value{min-width:56px}}
@media(max-width:900px){.siem-table-wrap{overflow:visible!important;box-shadow:none!important}.siem-engineering-table{display:block!important;min-width:0!important}.siem-engineering-table thead{display:none!important}.siem-engineering-table tbody,.siem-engineering-table tr,.siem-engineering-table td{display:block!important;width:100%!important;box-sizing:border-box!important}.siem-engineering-table tbody tr{height:auto!important;padding:12px 14px!important;border-bottom:1px solid rgba(148,163,184,.12)!important}.siem-engineering-table td{display:grid!important;grid-template-columns:82px minmax(0,1fr)!important;gap:8px!important;min-width:0!important;border:0!important;padding:5px 0!important;overflow-wrap:anywhere!important}.siem-engineering-table td>*{min-width:0!important}.siem-reason-cell,.threat-hunt-table .hunt-hypothesis{min-width:0!important}}
.exec-kpi-grid{grid-template-columns:repeat(6,minmax(0,1fr))}
.exec-chart-grid{grid-template-columns:repeat(3,minmax(0,1fr))}
.exec-hourly-card .exec-bar-value{display:flex;align-items:baseline;justify-content:flex-end;gap:4px}
.exec-hourly-card .exec-bar-value span{color:#91a4ba;font-size:10px;font-weight:750;letter-spacing:0}
.exec-card-note{margin-top:14px;border-top:1px solid rgba(148,163,184,.10);padding-top:12px;color:#91a4ba;font-size:10.5px;line-height:1.45;letter-spacing:0}
.exec-card-note b{color:#dce8f7}
.exec-cache-rows{display:grid;gap:0}
.exec-cache-row{display:grid;grid-template-columns:minmax(0,1fr) max-content;gap:14px;align-items:center;border-top:1px solid rgba(148,163,184,.08);padding:8px 0}
.exec-cache-row:first-child{border-top:0;padding-top:0}
.exec-cache-row div{min-width:0}
.exec-cache-row span,.exec-cache-row small{display:block;letter-spacing:0}
.exec-cache-row span{color:#dce8f7;font-size:12px;font-weight:850}
.exec-cache-row small{margin-top:2px;color:#7f91a6;font-size:9.5px;line-height:1.25}
.exec-cache-row strong{color:#8ff4ff;font-size:17px;font-variant-numeric:tabular-nums;letter-spacing:0}
@media(max-width:1500px){.exec-kpi-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.exec-chart-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(max-width:1100px){.exec-chart-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:760px){.exec-kpi-grid,.exec-chart-grid{grid-template-columns:1fr}.exec-hourly-card .exec-bar-value span{display:none}}
</style>
'''


EXECUTIVE_HOME_JS = '''
<script>
(() => {
  const hourFormatter = new Intl.DateTimeFormat(undefined, {
    hour: 'numeric',
    minute: '2-digit'
  });
  const fullFormatter = new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short'
  });
  const dayFormatter = new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric'
  });
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  document.querySelectorAll('.exec-hour-label[data-hour-start]').forEach((label) => {
    const value = new Date(label.dataset.hourStart || '');
    if (Number.isNaN(value.getTime())) return;
    const localDay = new Date(value.getFullYear(), value.getMonth(), value.getDate());
    let prefix = dayFormatter.format(value);
    if (localDay.getTime() === today.getTime()) prefix = 'Today';
    if (localDay.getTime() === yesterday.getTime()) prefix = 'Yesterday';
    const partial = label.dataset.currentHour === 'true' ? ' so far' : '';
    label.textContent = `${prefix}, ${hourFormatter.format(value)}${partial}`;
    label.title = fullFormatter.format(value);
  });
})();
</script>
'''


def inject_executive_home_assets(text: str) -> str:
    if EXECUTIVE_HOME_CSS not in text:
        text = text.replace('</head>', EXECUTIVE_HOME_CSS + '</head>', 1)
    if EXECUTIVE_HOME_JS not in text:
        text = text.replace('</body>', EXECUTIVE_HOME_JS + '</body>', 1)
    return text
