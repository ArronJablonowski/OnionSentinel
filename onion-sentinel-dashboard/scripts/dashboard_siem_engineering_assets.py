"""SIEM Engineering page styles and reactive expansion client."""
from __future__ import annotations


SIEM_ENGINEERING_CSS = '''
<style>
.siem-engineering-view{display:grid;gap:14px;padding-top:8px}.siem-eng-hero{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:18px;align-items:end;border-bottom:1px solid rgba(148,163,184,.12);padding:4px 0 16px}.siem-eng-hero h2{margin:8px 0 5px;color:#f5f9ff;font-size:26px;line-height:1;letter-spacing:-.02em}.siem-eng-hero p{margin:0;color:#9aaabd;font-size:13px;line-height:1.4}.settings-kicker{display:inline-block;color:#8ff4ff;font-size:10.5px;font-weight:950;text-transform:uppercase;letter-spacing:.13em}.siem-model-card{min-width:250px;text-align:right}.siem-model-card span,.siem-eng-kpis span{display:block;color:#8ff4ff;font-size:10px;font-weight:950;text-transform:uppercase;letter-spacing:.1em}.siem-model-card strong{display:block;margin-top:6px;color:#f3f8ff;font-size:16px}.siem-model-card em{display:block;margin-top:4px;color:#91a4ba;font-size:12px;font-style:normal}.siem-eng-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.siem-eng-kpis article{border:1px solid rgba(148,163,184,.10);border-radius:8px;padding:10px 12px;background:#0b141d}.siem-eng-kpis strong{display:block;margin-top:6px;color:#f7fbff;font-size:18px;line-height:1}.siem-eng-kpis em{display:block;margin-top:5px;color:#91a4ba;font-size:11.5px;font-style:normal}.siem-roi-card{display:grid;gap:12px;border:1px solid rgba(34,211,238,.16);border-radius:8px;padding:14px;background:#0d1620}.siem-roi-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px}.siem-roi-head h3{margin:6px 0 0;color:#f5f9ff;font-size:18px;line-height:1.2;letter-spacing:-.01em}.siem-roi-head code{display:block;margin-top:6px;color:#91a4ba;background:transparent;font:11.5px/1.35 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;white-space:normal;overflow-wrap:anywhere}.siem-roi-rank{min-width:94px;text-align:right}.siem-roi-rank span{display:block;color:#8ff4ff;font-size:10px;font-weight:950;text-transform:uppercase;letter-spacing:.1em}.siem-roi-rank strong{display:block;margin-top:6px;font-size:17px;line-height:1;text-transform:capitalize}.siem-roi-table{width:100%;border-collapse:collapse}.siem-roi-table th{width:84px;padding:9px 10px 9px 0;border-top:1px solid rgba(148,163,184,.10);color:#8ff4ff;font-size:10px;font-weight:950;text-align:left;text-transform:uppercase;letter-spacing:.1em;vertical-align:top}.siem-roi-table td{padding:9px 0;border-top:1px solid rgba(148,163,184,.10);color:#dce8f7;font-size:13px;line-height:1.42;vertical-align:top;overflow-wrap:anywhere}.siem-table-section{display:grid;gap:8px}.siem-table-title{padding:0 2px}.siem-table-title h3{margin:0;color:#f4f8ff;font-size:16px;letter-spacing:-.01em}.siem-table-title p{display:none}.siem-table-wrap{overflow:auto;border:1px solid rgba(148,163,184,.11);border-radius:8px;background:#0d1620;box-shadow:inset -18px 0 18px -18px rgba(143,244,255,.38)}.siem-engineering-table{width:100%;min-width:1040px;border-collapse:collapse}.siem-engineering-table th{padding:9px 11px;border-bottom:1px solid rgba(148,163,184,.12);color:#96a6b8;background:#101b26;font-size:10px;font-weight:900;text-align:left;text-transform:uppercase;letter-spacing:.08em}.siem-engineering-table td{padding:11px;border-bottom:1px solid rgba(148,163,184,.09);vertical-align:top;color:#d7e3f1;font-size:12.5px;line-height:1.36}.siem-engineering-table tbody tr{height:86px}.siem-engineering-table tbody tr:hover{background:rgba(34,211,238,.03)}.siem-engineering-table td:nth-child(1){width:108px}.siem-engineering-table td:nth-child(2){width:260px}.siem-engineering-table td:nth-child(3){width:116px}.siem-engineering-table td:nth-child(5){width:116px}.siem-engineering-table strong{display:block;color:#f4f8ff;font-size:12.5px;line-height:1.25}.siem-engineering-table code{display:block;margin-top:6px;color:#91a4ba;background:transparent;font:11px/1.3 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;white-space:normal;overflow-wrap:anywhere}.siem-table-pill{display:inline-flex;align-items:center;border:1px solid rgba(34,211,238,.16);border-radius:999px;padding:3px 7px;color:#8ff4ff;background:rgba(34,211,238,.035);font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:.04em}.siem-reason-cell{min-width:380px}.siem-reason-cell p{margin:0;color:#dce8f7;font-size:12.5px;line-height:1.42;overflow-wrap:anywhere}.siem-reason-cell em{display:block;margin-top:5px;color:#9fb0c4;font-size:12px;font-style:normal;line-height:1.35;overflow-wrap:anywhere}.siem-engineering-table td:last-child b{display:block;color:#f4f8ff;font-size:17px;line-height:1}.siem-engineering-table td:last-child span{display:block;margin-top:5px;color:#91a4ba;font-size:11px;line-height:1.3;overflow-wrap:anywhere}.siem-empty-row td{padding:18px 12px;color:#91a4ba;text-align:center}@media(max-width:1100px){.siem-eng-hero{grid-template-columns:1fr}.siem-model-card{text-align:left}.siem-eng-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.siem-table-title{display:grid}.siem-engineering-table{min-width:900px}}@media(max-width:720px){.siem-table-wrap{overflow:visible;box-shadow:none}.siem-engineering-table{display:block;min-width:0}.siem-engineering-table thead{display:none}.siem-engineering-table tbody,.siem-engineering-table tr,.siem-engineering-table td{display:block;width:100%;box-sizing:border-box}.siem-engineering-table tbody tr{height:auto;padding:12px 14px;border-bottom:1px solid rgba(148,163,184,.12)}.siem-engineering-table td{display:grid;grid-template-columns:92px minmax(0,1fr);gap:8px;border:0;padding:5px 0}.siem-reason-cell{min-width:0}.siem-engineering-table td::before{color:#8ff4ff;font-size:10px;font-weight:950;letter-spacing:.08em;text-transform:uppercase}.siem-engineering-table td:nth-child(1)::before{content:"Severity"}.siem-engineering-table td:nth-child(2)::before{content:"Detection"}.siem-engineering-table td:nth-child(3)::before{content:"Type"}.siem-engineering-table td:nth-child(4)::before{content:"Reason"}.siem-engineering-table td:nth-child(5)::before{content:"Seen"}}@media(max-width:680px){.siem-eng-kpis{grid-template-columns:1fr}.siem-roi-head{display:grid}.siem-roi-rank{text-align:left}.siem-roi-table th{width:70px}}
@media(max-width:900px){.siem-table-wrap{overflow:visible!important;box-shadow:none!important}.siem-engineering-table{display:block!important;min-width:0!important}.siem-engineering-table thead{display:none!important}.siem-engineering-table tbody,.siem-engineering-table tr,.siem-engineering-table td{display:block!important;width:100%!important;box-sizing:border-box!important}.siem-engineering-table tbody tr{height:auto!important;padding:12px 14px!important;border-bottom:1px solid rgba(148,163,184,.12)!important}.siem-engineering-table td{display:grid!important;grid-template-columns:82px minmax(0,1fr)!important;gap:8px!important;min-width:0!important;border:0!important;padding:5px 0!important;overflow-wrap:anywhere!important}.siem-engineering-table td>*{min-width:0!important}.siem-reason-cell{min-width:0!important}}
</style>
'''


SIEM_ENGINEERING_EXPANSION_CSS = '''
<style>
.siem-recommendation-row{cursor:pointer;outline:0}
.siem-recommendation-row:focus-visible{box-shadow:inset 0 0 0 2px rgba(143,244,255,.78)}
.siem-recommendation-row[aria-expanded="true"]{background:rgba(34,211,238,.055);box-shadow:inset 3px 0 0 #22d3ee}
.siem-expand-indicator{display:inline-block!important;margin:0 7px 0 0!important;color:#8ff4ff!important;font-size:17px!important;line-height:.8!important;transform:rotate(0);transform-origin:center;transition:transform .16s ease}
.siem-recommendation-row[aria-expanded="true"] .siem-expand-indicator{transform:rotate(90deg)}
.siem-recommendation-detail[hidden]{display:none!important}
.siem-engineering-table tbody tr.siem-recommendation-detail{height:auto;background:#08111a}
.siem-engineering-table .siem-recommendation-detail>td{width:auto!important;padding:0!important;border-bottom:1px solid rgba(34,211,238,.18);background:#08111a}
.siem-analysis-report{display:grid;gap:14px;padding:18px;color:#dce8f7}
.siem-analysis-report b,.siem-analysis-report span{display:inline;margin:0;color:inherit;font-size:inherit;line-height:inherit}
.siem-analysis-header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding-bottom:12px;border-bottom:1px solid rgba(143,244,255,.16)}
.siem-analysis-header h3{margin:5px 0 0;color:#f6f9ff;font-size:19px;line-height:1.2}
.siem-analysis-header .settings-kicker{display:inline-block;color:#8ff4ff;font-size:10.5px;font-weight:950;text-transform:uppercase;letter-spacing:.13em}
.siem-analysis-header .siem-table-pill{display:inline-flex;color:#8ff4ff;font-size:10px;line-height:1}
.siem-analysis-generated{color:#91a4ba;font-size:11.5px;line-height:1.4}
.siem-analysis-bluf,.siem-analysis-section{border:1px solid rgba(148,163,184,.11);border-radius:8px;padding:13px 14px;background:#0d1620}
.siem-analysis-bluf{border-color:rgba(34,211,238,.19);box-shadow:inset 3px 0 0 rgba(34,211,238,.58)}
.siem-analysis-report h4{margin:0 0 8px;color:#f3f8ff;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.siem-analysis-report p{margin:0;color:#d4e0ee;font-size:12.5px;line-height:1.5;overflow-wrap:anywhere}
.siem-analysis-report ul{margin:0;padding-left:18px;color:#d4e0ee;font-size:12.5px;line-height:1.5}
.siem-analysis-lead{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px}
.siem-analysis-lead>section,.siem-analysis-evidence>div{border:1px solid rgba(148,163,184,.11);border-radius:8px;padding:13px 14px;background:#0d1620}
.siem-detection-context{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:0;margin:0}
.siem-detection-context>div{min-width:0;padding:9px 11px;border-top:1px solid rgba(148,163,184,.09)}
.siem-detection-context dt,.siem-analysis-findings dt{color:#8ff4ff;font-size:9.5px;font-weight:950;text-transform:uppercase;letter-spacing:.07em}
.siem-detection-context dd,.siem-analysis-findings dd{margin:4px 0 0;color:#dce8f7;font-size:12px;line-height:1.4;overflow-wrap:anywhere}
.siem-analysis-findings{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin:0}
.siem-analysis-findings>div{min-width:0}
.siem-analysis-evidence{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.siem-ai-json{border:1px solid rgba(148,163,184,.11);border-radius:8px;overflow:hidden;background:#071018}
.siem-ai-json summary{padding:11px 13px;color:#8ff4ff;font-size:11px;font-weight:900;cursor:pointer}
.siem-ai-json pre{max-height:320px;margin:0;overflow:auto;padding:13px;border-top:1px solid rgba(148,163,184,.09);color:#dce8f7;font:11px/1.45 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:900px){
  .siem-engineering-table tbody tr.siem-recommendation-detail[hidden]{display:none!important}
  .siem-engineering-table tbody tr.siem-recommendation-detail{padding:0!important;border-bottom:1px solid rgba(34,211,238,.18)!important}
  .siem-engineering-table .siem-recommendation-detail>td{display:block!important;width:100%!important;padding:0!important}
  .siem-engineering-table .siem-recommendation-detail>td::before{content:none!important}
  .siem-analysis-report{padding:14px}
  .siem-detection-context{grid-template-columns:repeat(2,minmax(0,1fr))}
}
@media(max-width:620px){
  .siem-analysis-header,.siem-analysis-lead{display:grid;grid-template-columns:1fr}
  .siem-analysis-evidence,.siem-analysis-findings,.siem-detection-context{grid-template-columns:1fr}
  .siem-analysis-report{gap:10px;padding:11px}
}
</style>
'''


SIEM_ENGINEERING_JS = '''
<script>
(() => {
  const root = document.querySelector('.siem-engineering-view');
  if (!root) return;
  const toggle = row => {
    const detailId = row.getAttribute('aria-controls') || '';
    const detail = detailId ? document.getElementById(detailId) : null;
    if (!detail) return;
    const expanded = row.getAttribute('aria-expanded') !== 'true';
    row.setAttribute('aria-expanded', String(expanded));
    detail.hidden = !expanded;
  };
  root.addEventListener('click', event => {
    if (event.target.closest('a,button,input,select,textarea,summary')) return;
    const row = event.target.closest('[data-siem-toggle]');
    if (row) toggle(row);
  });
  root.addEventListener('keydown', event => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const row = event.target.closest('[data-siem-toggle]');
    if (!row) return;
    event.preventDefault();
    toggle(row);
  });
  window.OnionSentinelReactiveTables?.register('siem-engineering-tables', () =>
    window.OnionSentinelReactiveTables.refreshFragment('.siem-engineering-view', {
      capture: current => [...current.querySelectorAll('[data-siem-toggle][aria-expanded="true"]')]
        .map(row => row.getAttribute('aria-controls')).filter(Boolean),
      restore: (current, expanded) => (expanded || []).forEach(detailId => {
        const row = current.querySelector(`[data-siem-toggle][aria-controls="${CSS.escape(detailId)}"]`);
        const detail = current.querySelector(`#${CSS.escape(detailId)}`);
        if (row && detail) { row.setAttribute('aria-expanded', 'true'); detail.hidden = false; }
      })
    }), {intervalMs: 15000});
})();
</script>
'''


def inject_siem_engineering_assets(text: str) -> str:
    if SIEM_ENGINEERING_CSS not in text:
        text = text.replace('</head>', SIEM_ENGINEERING_CSS + '</head>', 1)
    if SIEM_ENGINEERING_EXPANSION_CSS not in text:
        text = text.replace('</head>', SIEM_ENGINEERING_EXPANSION_CSS + '</head>', 1)
    if SIEM_ENGINEERING_JS not in text:
        text = text.replace('</body>', SIEM_ENGINEERING_JS + '</body>', 1)
    return text
