#!/usr/bin/env python3
"""System Health dashboard page components.

Kept outside the main dashboard builder so PCAP/beacon UI changes stay small,
reviewable, and less risky for future human and LLM maintainers.
"""
from __future__ import annotations


def system_health_page_section() -> str:
    return '''
    <section class="view-section active system-health-view" aria-label="System Health">
      <section class="system-health-hero">
        <div>
          <span class="settings-kicker">Relay health</span>
          <h2>n8n beacon history</h2>
          <p>Last 24 hours of relay-to-n8n beacon activity, unsuccessful attempts, and successful-beacon gaps longer than 10 minutes.</p>
        </div>
        <button id="system-health-refresh" class="alerts-refresh" type="button" aria-label="Refresh System Health" title="Refresh System Health" aria-busy="false"><span class="alerts-refresh-icon" aria-hidden="true">↻</span></button>
      </section>
      <section class="system-health-kpis" aria-label="System Health summary">
        <article><span>Latest</span><strong id="health-latest">Checking...</strong><em id="health-latest-detail">Waiting for beacon history.</em></article>
        <article><span>Successful</span><strong id="health-successful">0</strong><em>beacons in 24 hours</em></article>
        <article><span>Unsuccessful</span><strong id="health-unsuccessful">0</strong><em>failed or recovery-marked events</em></article>
        <article><span>Gaps &gt;10m</span><strong id="health-gaps">0</strong><em>without a successful beacon</em></article>
        <article><span>PCAP Queue</span><strong id="health-pcap-queue">0</strong><em id="health-pcap-queue-detail">pending or claimed requests</em></article>
        <article><span>PCAP Parser</span><strong id="health-pcap-parser">0</strong><em id="health-pcap-parser-detail">parsed evidence artifacts</em></article>
      </section>
      <section class="system-health-panel" aria-label="Beacon gaps">
        <div class="system-health-panel-title"><h3>Beacon gaps</h3><span id="health-gap-note">No data loaded yet.</span></div>
        <div id="health-gap-list" class="health-gap-list"></div>
      </section>
      <section class="system-health-panel" aria-label="PCAP workflow health">
        <div class="system-health-panel-title"><h3>PCAP workflow</h3><span id="health-pcap-note">No data loaded yet.</span></div>
        <div id="health-pcap-details" class="health-pcap-details"></div>
      </section>
      <section class="system-health-panel" aria-label="Pipeline throughput and backlog">
        <div class="system-health-panel-title"><h3>Pipeline flow</h3><span id="health-pipeline-note">No data loaded yet.</span></div>
        <div id="health-pipeline-details" class="health-pipeline-details"></div>
      </section>
      <section class="system-health-panel" aria-label="Beacon history">
        <div class="system-health-panel-title"><h3>Beacon events</h3><span id="health-event-note">Last 24 hours</span></div>
        <div class="system-health-table-controls" aria-label="Beacon events pagination">
          <label>Rows
            <select id="health-beacon-page-size" aria-label="Beacon rows per page">
              <option value="25" selected>25</option>
              <option value="50">50</option>
              <option value="100">100</option>
              <option value="250">250</option>
            </select>
          </label>
          <button id="health-beacon-prev" type="button">Previous</button>
          <span id="health-beacon-page-label">Page 1 of 1</span>
          <button id="health-beacon-next" type="button">Next</button>
        </div>
        <div class="system-health-table-wrap">
          <table class="system-health-table health-data-table health-beacon-table">
            <colgroup>
              <col class="health-col-time">
              <col class="health-col-result">
              <col class="health-col-stage">
              <col class="health-col-relay">
              <col class="health-col-alerts">
              <col class="health-col-http">
              <col class="health-col-details">
            </colgroup>
            <thead><tr><th>Time</th><th>Result</th><th>Stage</th><th>Relay</th><th>Alerts</th><th>HTTP</th><th>Details</th></tr></thead>
            <tbody id="health-beacon-rows"><tr><td colspan="7">Loading beacon history...</td></tr></tbody>
          </table>
        </div>
      </section>
    </section>'''


SYSTEM_HEALTH_CSS = '''
<style>
.system-health-link{display:block;text-decoration:none}.system-health-view{display:grid;gap:14px;min-width:0;padding-top:8px}.system-health-hero{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:18px;align-items:end;border-bottom:1px solid rgba(148,163,184,.12);padding:4px 0 16px}.system-health-hero h2{margin:8px 0 5px;color:#f5f9ff;font-size:26px;line-height:1;letter-spacing:-.02em}.system-health-hero p{max-width:82ch;margin:0;color:#9aaabd;font-size:13px;line-height:1.45}.system-health-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.system-health-kpis article,.system-health-panel{min-width:0;border:1px solid rgba(148,163,184,.11);border-radius:8px;background:#0d1620}.system-health-kpis article{padding:11px 12px}.system-health-kpis span{display:block;color:#8ff4ff;font-size:10px;font-weight:950;text-transform:uppercase;letter-spacing:.1em}.system-health-kpis strong{display:block;margin-top:7px;color:#f7fbff;font-size:18px;line-height:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.system-health-kpis em{display:block;margin-top:6px;color:#91a4ba;font-size:11.5px;font-style:normal;line-height:1.35}.system-health-panel{overflow:hidden}.system-health-panel-title{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;border-bottom:1px solid rgba(148,163,184,.10);background:#101b26}.system-health-panel-title h3{margin:0;color:#f4f8ff;font-size:16px;letter-spacing:-.01em}.system-health-panel-title span{color:#91a4ba;font-size:12px}.system-health-table-controls{display:flex;align-items:center;justify-content:flex-end;gap:8px;padding:9px 12px;border-bottom:1px solid rgba(148,163,184,.08);background:rgba(16,27,38,.55);color:#91a4ba;font-size:12px;font-weight:800}.system-health-table-controls label{display:inline-flex;align-items:center;gap:7px}.system-health-table-controls select,.system-health-table-controls button{border:1px solid rgba(143,244,255,.28);border-radius:8px;background:#08111a;color:#dce8f7;font:inherit;font-weight:900}.system-health-table-controls select{min-height:36px;padding:4px 26px 4px 9px}.system-health-table-controls button{min-height:36px;padding:5px 10px}.system-health-table-controls button:disabled{opacity:.45;cursor:not-allowed}.health-gap-list{display:grid;gap:8px;padding:12px}.health-gap-item{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;border:1px solid rgba(246,199,109,.22);border-radius:8px;padding:9px 10px;background:rgba(246,199,109,.055);color:#dce8f7;font-size:12px}.health-gap-item b{color:#f6c76d}.health-gap-item code{color:#f3f8ff;background:transparent;font:11.5px/1.35 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace}.health-gap-empty{padding:12px;color:#91a4ba;font-size:12px}.health-pcap-details{display:grid;gap:10px;padding:12px}.health-pcap-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px}.health-pcap-grid div{min-width:0;border:1px solid rgba(148,163,184,.11);border-radius:8px;padding:9px;background:rgba(148,163,184,.035)}.health-pcap-grid b{display:block;color:#8ff4ff;font-size:10px;text-transform:uppercase;letter-spacing:.08em}.health-pcap-grid span{display:block;min-width:0;margin-top:5px;color:#dce8f7;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.health-pcap-warnings,.health-pcap-advisories{display:grid;gap:6px}.health-pcap-warnings span,.health-pcap-advisories span{border-radius:8px;padding:8px 10px;font-size:12px;font-weight:800}.health-pcap-warnings span{border:1px solid rgba(251,113,133,.28);color:#ff9aae;background:rgba(251,113,133,.065)}.health-pcap-advisories span{border:1px solid rgba(246,199,109,.28);color:#f6c76d;background:rgba(246,199,109,.06)}.health-pcap-recent{max-width:100%;overflow:auto;border:1px solid rgba(148,163,184,.11);border-radius:8px;box-shadow:inset -18px 0 18px -18px rgba(143,244,255,.38)}.health-pcap-recent table{width:100%;min-width:860px;border-collapse:collapse}.health-pcap-recent th{padding:8px 10px;color:#91a4ba;background:#101b26;border-bottom:1px solid rgba(148,163,184,.10);font-size:10px;text-align:left;text-transform:uppercase;letter-spacing:.08em}.health-pcap-recent td{padding:9px 10px;border-bottom:1px solid rgba(148,163,184,.08);color:#d7e3f1;font-size:12px;overflow-wrap:anywhere}.health-pcap-recent code{color:#dce9f8;background:rgba(148,163,184,.05);border:1px solid rgba(148,163,184,.12);border-radius:6px;padding:3px 6px;font-size:11.5px;white-space:normal;overflow-wrap:anywhere}.system-health-table-wrap{max-width:100%;overflow:auto;box-shadow:inset -18px 0 18px -18px rgba(143,244,255,.38)}.system-health-table{width:100%;min-width:860px;border-collapse:collapse}.system-health-table th{padding:9px 11px;border-bottom:1px solid rgba(148,163,184,.12);color:#96a6b8;background:#101b26;font-size:10px;font-weight:900;text-align:left;text-transform:uppercase;letter-spacing:.08em}.system-health-table td{padding:11px;border-bottom:1px solid rgba(148,163,184,.09);vertical-align:top;color:#d7e3f1;font-size:12.5px;line-height:1.35;overflow-wrap:anywhere}.system-health-table code{color:#dce9f8;background:rgba(148,163,184,.05);border:1px solid rgba(148,163,184,.12);border-radius:6px;padding:3px 6px;font-size:11.5px;white-space:normal;overflow-wrap:anywhere}.health-result{display:inline-flex;align-items:center;border:1px solid rgba(34,197,94,.24);border-radius:999px;padding:3px 8px;color:#86efac;background:rgba(34,197,94,.055);font-size:10.5px;font-weight:950;text-transform:uppercase;letter-spacing:.04em}.health-result.failed{border-color:rgba(251,113,133,.34);color:#fb7185;background:rgba(251,113,133,.075)}.health-row-failed{background:rgba(251,113,133,.045)}.health-row-failed td{border-bottom-color:rgba(251,113,133,.16)}@media(max-width:1100px){.health-pcap-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:900px){.system-health-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.system-health-hero{grid-template-columns:1fr}.system-health-view .alerts-refresh{min-width:44px;min-height:44px}}@media(max-width:620px){.system-health-kpis,.health-pcap-grid{grid-template-columns:1fr}.system-health-kpis strong{white-space:normal;overflow-wrap:anywhere;line-height:1.18}.health-gap-item{grid-template-columns:1fr}.system-health-table-controls{justify-content:flex-start;flex-wrap:wrap}.system-health-table-wrap,.health-pcap-recent{overflow:visible;box-shadow:none}.system-health-table,.health-pcap-recent table,.system-health-table tbody,.health-pcap-recent tbody,.system-health-table tr,.health-pcap-recent tr,.system-health-table td,.health-pcap-recent td{display:block;width:100%;min-width:0;box-sizing:border-box}.system-health-table thead,.health-pcap-recent thead{display:none}.system-health-table tr,.health-pcap-recent tr{padding:10px 12px;border-top:1px solid rgba(148,163,184,.12)}.system-health-table td,.health-pcap-recent td{display:grid;grid-template-columns:86px minmax(0,1fr);gap:8px;border:0;padding:5px 0}.system-health-table td::before,.health-pcap-recent td::before{color:#8ff4ff;font-size:10px;font-weight:950;letter-spacing:.08em;text-transform:uppercase}.system-health-table td:nth-child(1)::before{content:"Time"}.system-health-table td:nth-child(2)::before{content:"Result"}.system-health-table td:nth-child(3)::before{content:"HTTP"}.system-health-table td:nth-child(4)::before{content:"Age"}.system-health-table td:nth-child(5)::before{content:"Gap"}.system-health-table td:nth-child(6)::before{content:"Source"}.system-health-table td:nth-child(7)::before{content:"Detail"}.health-pcap-recent td:nth-child(1)::before{content:"Updated"}.health-pcap-recent td:nth-child(2)::before{content:"Status"}.health-pcap-recent td:nth-child(3)::before{content:"Request"}.health-pcap-recent td:nth-child(4)::before{content:"Group"}.health-pcap-recent td:nth-child(5)::before{content:"Size"}.health-pcap-recent td:nth-child(6)::before{content:"Error"}}
@media(min-width:621px){
  .health-data-table{width:100%;table-layout:fixed}
  .health-beacon-table{min-width:980px}
  .health-beacon-table .health-col-time{width:200px}
  .health-beacon-table .health-col-result{width:132px}
  .health-beacon-table .health-col-stage{width:104px}
  .health-beacon-table .health-col-relay{width:190px}
  .health-beacon-table .health-col-alerts{width:82px}
  .health-beacon-table .health-col-http{width:76px}
  .health-beacon-table th,.health-beacon-table td{padding-left:9px;padding-right:9px}
  .health-beacon-table th:nth-child(2),.health-beacon-table td:nth-child(2){white-space:nowrap;overflow-wrap:normal;word-break:normal}
  .health-beacon-table td:nth-child(3),.health-beacon-table td:nth-child(5),.health-beacon-table td:nth-child(6){white-space:nowrap;overflow-wrap:normal;word-break:normal}
  .health-beacon-table td:last-child{overflow-wrap:anywhere}
  .health-pcap-table{min-width:1120px}
  .health-pcap-table .health-col-updated{width:200px}
  .health-pcap-table .health-col-status{width:110px}
  .health-pcap-table .health-col-outcome{width:170px}
  .health-pcap-table .health-col-request{width:180px}
  .health-pcap-table .health-col-group{width:180px}
  .health-pcap-table .health-col-size{width:108px}
  .health-pcap-table .health-col-transfer{width:126px}
  .health-pcap-table th,.health-pcap-table td{padding-left:9px;padding-right:9px}
  .health-pcap-table td:nth-child(1),.health-pcap-table td:nth-child(2),.health-pcap-table td:nth-child(6),.health-pcap-table td:nth-child(7){white-space:nowrap;overflow-wrap:normal;word-break:normal}
  .health-pcap-table td:last-child{overflow-wrap:anywhere}
  .health-pcap-recent td::before{display:none;content:none}
  .health-pipeline-stage-table{min-width:1020px;table-layout:fixed}
  .health-pipeline-stage-table .health-col-pipeline-stage{width:220px}
  .health-pipeline-stage-table .health-col-queued{width:90px}
  .health-pipeline-stage-table .health-col-active{width:90px}
  .health-pipeline-stage-table .health-col-oldest{width:126px}
  .health-pipeline-stage-table .health-col-hour-in{width:86px}
  .health-pipeline-stage-table .health-col-hour-done{width:96px}
  .health-pipeline-stage-table .health-col-backlog{width:260px}
  .health-pipeline-stage-table th,.health-pipeline-stage-table td{padding-left:9px;padding-right:9px}
  .health-pipeline-stage-table td:last-child{overflow-wrap:anywhere}
}
@media(max-width:620px){
  .system-health-table td:nth-child(3)::before{content:"Stage"}
  .system-health-table td:nth-child(4)::before{content:"Relay"}
  .system-health-table td:nth-child(5)::before{content:"Alerts"}
  .system-health-table td:nth-child(6)::before{content:"HTTP"}
  .system-health-table td:nth-child(7)::before{content:"Details"}
  .health-pcap-recent td:nth-child(3)::before{content:"Outcome"}
  .health-pcap-recent td:nth-child(4)::before{content:"Request"}
  .health-pcap-recent td:nth-child(5)::before{content:"Group"}
  .health-pcap-recent td:nth-child(6)::before{content:"Size"}
  .health-pcap-recent td:nth-child(7)::before{content:"Transfer Time"}
  .health-pcap-recent td:nth-child(8)::before{content:"Error"}
}
.health-result{box-sizing:border-box;min-width:104px;justify-content:center;white-space:nowrap;overflow-wrap:normal;word-break:keep-all}
.system-health-table-controls select,.system-health-table-controls button{min-height:44px}
.health-pipeline-details{display:grid;gap:10px;padding:12px}.health-pipeline-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.health-pipeline-grid div{min-width:0;border:1px solid rgba(148,163,184,.11);border-radius:8px;padding:9px;background:rgba(148,163,184,.035)}.health-pipeline-grid b{display:block;color:#8ff4ff;font-size:10px;text-transform:uppercase;letter-spacing:.08em}.health-pipeline-grid span{display:block;margin-top:5px;color:#dce8f7;font-size:12px;overflow-wrap:anywhere}.health-pipeline-table{max-width:100%;overflow:auto;border:1px solid rgba(148,163,184,.11);border-radius:8px}.health-pipeline-table table{width:100%;min-width:920px;border-collapse:collapse}.health-pipeline-table th{padding:8px 10px;color:#91a4ba;background:#101b26;border-bottom:1px solid rgba(148,163,184,.10);font-size:10px;text-align:left;text-transform:uppercase;letter-spacing:.08em}.health-pipeline-table td{padding:9px 10px;border-bottom:1px solid rgba(148,163,184,.08);color:#d7e3f1;font-size:12px;white-space:nowrap}.health-pipeline-table td:first-child{color:#8ff4ff;font-weight:900}.health-pipeline-stalled{color:#f6c76d;font-weight:900}@media(max-width:900px){.health-pipeline-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:620px){.health-pipeline-grid{grid-template-columns:1fr}.health-pipeline-table{overflow:auto}}
</style>
'''


SYSTEM_HEALTH_JS = '''
<script>
(() => {
  const refreshButton = document.querySelector('#system-health-refresh');
  const latest = document.querySelector('#health-latest');
  const latestDetail = document.querySelector('#health-latest-detail');
  const successful = document.querySelector('#health-successful');
  const unsuccessful = document.querySelector('#health-unsuccessful');
  const gaps = document.querySelector('#health-gaps');
  const gapList = document.querySelector('#health-gap-list');
  const gapNote = document.querySelector('#health-gap-note');
  const rows = document.querySelector('#health-beacon-rows');
  const eventNote = document.querySelector('#health-event-note');
  const beaconPageSizeSelect = document.querySelector('#health-beacon-page-size');
  const beaconPrev = document.querySelector('#health-beacon-prev');
  const beaconNext = document.querySelector('#health-beacon-next');
  const beaconPageLabel = document.querySelector('#health-beacon-page-label');
  const pcapQueue = document.querySelector('#health-pcap-queue');
  const pcapQueueDetail = document.querySelector('#health-pcap-queue-detail');
  const pcapParser = document.querySelector('#health-pcap-parser');
  const pcapParserDetail = document.querySelector('#health-pcap-parser-detail');
  const pcapNote = document.querySelector('#health-pcap-note');
  const pcapDetails = document.querySelector('#health-pcap-details');
  const pipelineNote = document.querySelector('#health-pipeline-note');
  const pipelineDetails = document.querySelector('#health-pipeline-details');
  let beaconEntries = [];
  let beaconGeneratedAt = '';
  let beaconPage = 1;
  let beaconPageSize = 25;
  let pcapSnapshot = {};
  let pcapRecentRequests = [];
  let pcapPage = 1;
  let pcapPageSize = 25;
  let healthSignature = '';
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const stableSignature = value => JSON.stringify(value, (key, item) => key === 'generated_at' || key.endsWith('_age_seconds') ? undefined : item);
  const fmt = value => typeof formatProjectIso === 'function' ? formatProjectIso(value) : String(value || '');
  const bytes = value => typeof formatApiBytes === 'function' ? formatApiBytes(Number(value || 0)) : `${Number(value || 0)} B`;
  const duration = value => {
    if (value === null || value === undefined || value === '') return 'n/a';
    let seconds = Math.max(0, Math.round(Number(value) || 0));
    const parts = [];
    const hours = Math.floor(seconds / 3600);
    seconds %= 3600;
    const minutes = Math.floor(seconds / 60);
    seconds %= 60;
    if (hours) parts.push(`${hours}h`);
    if (minutes || hours) parts.push(`${minutes}m`);
    parts.push(`${seconds}s`);
    return parts.join(' ');
  };
  function pageInfo(total, page, pageSize) {
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const safePage = Math.min(Math.max(1, page), totalPages);
    const start = total ? ((safePage - 1) * pageSize) : 0;
    const end = total ? Math.min(start + pageSize, total) : 0;
    return {page: safePage, totalPages, start, end};
  }
  function updatePager({total, page, pageSize, prev, next, label}) {
    const info = pageInfo(total, page, pageSize);
    if (prev) prev.disabled = info.page <= 1;
    if (next) next.disabled = info.page >= info.totalPages;
    if (label) label.textContent = `Page ${info.page} of ${info.totalPages} · Showing ${total ? info.start + 1 : 0}-${info.end} of ${total}`;
    return info;
  }
  function detailText(entry) {
    if (entry.error) return entry.error;
    if (entry.rule_name) return entry.rule_name;
    if (entry.message_type === 'relay_heartbeat') return 'relay heartbeat';
    if (entry.message_type === 'relay_health_recovery') return 'relay recovery';
    return 'beacon';
  }
  function renderGaps(items) {
    if (!gapList) return;
    if (!items.length) {
      gapList.innerHTML = '<div class="health-gap-empty">No successful-beacon gaps over 10 minutes in this window.</div>';
      return;
    }
    gapList.innerHTML = items.map(gap => `
      <div class="health-gap-item">
        <b>${esc(gap.minutes)} min</b>
        <code>${esc(fmt(gap.start))} -> ${esc(fmt(gap.end))}</code>
        <span>${esc(gap.status || 'closed')}</span>
      </div>`).join('');
  }
  function renderRows() {
    if (!rows) return;
    if (!beaconEntries.length) {
      rows.innerHTML = '<tr><td colspan="7">No beacon history found in the last 24 hours.</td></tr>';
      updatePager({total: 0, page: 1, pageSize: beaconPageSize, prev: beaconPrev, next: beaconNext, label: beaconPageLabel});
      return;
    }
    const sorted = [...beaconEntries].reverse();
    const info = updatePager({total: sorted.length, page: beaconPage, pageSize: beaconPageSize, prev: beaconPrev, next: beaconNext, label: beaconPageLabel});
    beaconPage = info.page;
    if (eventNote) eventNote.textContent = `${sorted.length} event(s), generated ${fmt(beaconGeneratedAt)}`;
    rows.innerHTML = sorted.slice(info.start, info.end).map(entry => {
      const failed = !entry.successful;
      return `<tr class="${failed ? 'health-row-failed' : ''}">
        <td><code>${esc(fmt(entry.timestamp))}</code></td>
        <td><span class="health-result ${failed ? 'failed' : ''}">${failed ? 'Unsuccessful' : 'Success'}</span></td>
        <td>${esc(entry.stage || 'unknown')}</td>
        <td>${esc(entry.relay_host || 'n8n')}</td>
        <td>${esc(entry.alert_count ?? entry.posted_webhook_alerts ?? 'n/a')}</td>
        <td>${entry.http_status ? `<code>${esc(entry.http_status)}</code>` : '<span>n/a</span>'}</td>
        <td>${esc(detailText(entry))}</td>
      </tr>`;
    }).join('');
  }
  function renderPcapTableControls(total) {
    const info = updatePager({total, page: pcapPage, pageSize: pcapPageSize});
    pcapPage = info.page;
    return `<div class="system-health-table-controls" aria-label="PCAP workflow pagination">
      <label>Rows
        <select id="health-pcap-page-size" aria-label="PCAP workflow rows per page">
          ${[25, 50, 100, 250].map(size => `<option value="${size}" ${size === pcapPageSize ? 'selected' : ''}>${size}</option>`).join('')}
        </select>
      </label>
      <button id="health-pcap-prev" type="button" ${info.page <= 1 ? 'disabled' : ''}>Previous</button>
      <span id="health-pcap-page-label">Page ${info.page} of ${info.totalPages} · Showing ${total ? info.start + 1 : 0}-${info.end} of ${total}</span>
      <button id="health-pcap-next" type="button" ${info.page >= info.totalPages ? 'disabled' : ''}>Next</button>
    </div>`;
  }
  function renderPcapHealth(pcap) {
    if (pcap) {
      pcapSnapshot = pcap;
      pcapRecentRequests = Array.isArray(pcap?.recent_requests) ? pcap.recent_requests : [];
    }
    pcap = pcapSnapshot || {};
    const counts = pcap?.request_counts || {};
    const queued = Number(counts.pending || 0) + Number(counts.claimed || 0);
    if (pcapQueue) pcapQueue.textContent = String(queued);
    if (pcapQueueDetail) {
      const failed = Number(counts.failed || 0), noPackets = Number(pcap?.no_packet_failures || 0);
      pcapQueueDetail.textContent = `${counts.fulfilled || 0} fulfilled · ${failed} failed · ${noPackets} no-packet`;
    }
    if (pcapParser) pcapParser.textContent = String(pcap?.analysis_count || 0);
    if (pcapParserDetail) {
      const latest = pcap?.latest_analysis?.updated_at ? fmt(pcap.latest_analysis.updated_at) : 'no parsed artifacts';
      pcapParserDetail.textContent = `latest ${latest}`;
    }
    if (pcapNote) {
      const warnings = Number(pcap?.warning_count || 0);
      const hold = Boolean(pcap?.capture_protection?.active);
      pcapNote.textContent = warnings ? `${warnings} warning(s) require review` : (hold ? 'Security Onion capture-protection hold' : 'No PCAP workflow warnings');
    }
    if (pcapDetails) {
      const latestRequest = pcap?.latest_request || {};
      const latestAnalysis = pcap?.latest_analysis || {};
      const warnings = Array.isArray(pcap?.warnings) ? pcap.warnings : [];
      const advisories = Array.isArray(pcap?.advisories) ? pcap.advisories : [];
      const recent = pcapRecentRequests;
      const page = pageInfo(recent.length, pcapPage, pcapPageSize);
      pcapPage = page.page;
      const visibleRecent = recent.slice(page.start, page.end);
      const warningHtml = warnings.length
        ? `<div class="health-pcap-warnings">${warnings.map(item => `<span>${esc(item)}</span>`).join('')}</div>`
        : '<div class="health-gap-empty">No stale PCAP queue items or unexpected PCAP failures.</div>';
      const advisoryHtml = advisories.length
        ? `<div class="health-pcap-advisories">${advisories.map(item => `<span>${esc(item)}</span>`).join('')}</div>`
        : '';
      const recentHtml = recent.length
        ? `${renderPcapTableControls(recent.length)}<div class="health-pcap-recent"><table class="health-data-table health-pcap-table"><colgroup><col class="health-col-updated"><col class="health-col-status"><col class="health-col-outcome"><col class="health-col-request"><col class="health-col-group"><col class="health-col-size"><col class="health-col-transfer"><col class="health-col-error"></colgroup><thead><tr><th>Updated</th><th>Status</th><th>Outcome</th><th>Request</th><th>Group</th><th>Size</th><th>Transfer Time</th><th>Error</th></tr></thead><tbody>${visibleRecent.map(item => `<tr><td><code>${esc(item.updated_at ? fmt(item.updated_at) : 'n/a')}</code></td><td><span class="pcap-status-pill pcap-status-${esc(String(item.status || 'none').toLowerCase())}">${esc(item.status || 'n/a')}</span></td><td>${esc(item.outcome || 'n/a')}</td><td><code>${esc(item.request_id || 'n/a')}</code></td><td><code>${esc(item.group_id || 'n/a')}</code></td><td>${esc(bytes(item.artifact_size_bytes || 0))}</td><td>${esc(duration(item.transfer_duration_seconds))}</td><td>${esc(item.error || '')}</td></tr>`).join('')}</tbody></table></div>`
        : '<div class="health-gap-empty">No PCAP request history found.</div>';
      pcapDetails.innerHTML = `
        ${advisoryHtml}
        ${warningHtml}
        <div class="health-pcap-grid">
          <div><b>Pending</b><span>${esc(counts.pending || 0)}</span></div>
          <div><b>Claimed</b><span>${esc(counts.claimed || 0)}</span></div>
          <div><b>Fulfilled</b><span>${esc(counts.fulfilled || 0)}</span></div>
          <div><b>Failed</b><span>${esc(counts.failed || 0)}</span></div>
          <div><b>No Packets</b><span>${esc(pcap?.no_packet_failures || 0)}</span></div>
          <div><b>Oversize</b><span>${esc(pcap?.oversize_failures || 0)}</span></div>
          <div><b>Artifact Size</b><span>${esc(bytes(pcap?.artifact_size_bytes || 0))}</span></div>
          <div><b>24h Transfer</b><span>${esc(bytes(pcap?.storage?.bytes_24h || 0))}</span></div>
          <div><b>Average Capture</b><span>${esc(bytes(pcap?.storage?.bytes_average || 0))}</span></div>
          <div><b>Largest Capture</b><span>${esc(bytes(pcap?.storage?.bytes_maximum || 0))}</span></div>
          <div><b>Latest Request</b><span>${esc(latestRequest.request_id || 'n/a')} · ${esc(latestRequest.status || 'n/a')}</span></div>
          <div><b>Latest Request Time</b><span>${esc(latestRequest.updated_at ? fmt(latestRequest.updated_at) : 'n/a')}</span></div>
          <div><b>Latest Analysis</b><span>${esc(latestAnalysis.name || 'n/a')}</span></div>
          <div><b>Latest Analysis Time</b><span>${esc(latestAnalysis.updated_at ? fmt(latestAnalysis.updated_at) : 'n/a')}</span></div>
        </div>
        ${recentHtml}`;
    }
  }
  function renderPipelineHealth(pipeline) {
    if (!pipelineDetails) return;
    if (!pipeline?.available) {
      if (pipelineNote) pipelineNote.textContent = 'Metrics unavailable';
      pipelineDetails.innerHTML = `<div class="health-gap-empty">${esc(pipeline?.error || 'Alert-store pipeline metrics are unavailable.')}</div>`;
      return;
    }
    const stages = Array.isArray(pipeline.stages) ? pipeline.stages : [];
    const disk = pipeline.disk || {};
    const pending = stages.reduce((total, stage) => total + Number(stage.pending || 0), 0);
    const processing = stages.reduce((total, stage) => total + Number(stage.processing || 0), 0);
    if (pipelineNote) pipelineNote.textContent = `${pending} queued · ${processing} active · generated ${fmt(pipeline.generated_at)}`;
    const stageLabel = value => String(value || '').replaceAll('_', ' ').replace(/\\b\\w/g, char => char.toUpperCase());
    const eta = value => value === null || value === undefined ? '<span class="health-pipeline-stalled">stalled</span>' : esc(duration(value));
    const rows = stages.map(stage => {
      const hour = stage?.throughput?.['1h'] || {};
      const backlog = Number(stage.backlog_bytes_known || 0);
      const unknown = Number(stage.backlog_bytes_unknown_items || 0);
      const backlogText = `${backlog ? bytes(backlog) : '0 B'}${unknown ? ` + ${unknown} unknown` : ''}`;
      return `<tr>
        <td>${esc(stageLabel(stage.stage))}</td>
        <td>${esc(stage.pending || 0)}</td>
        <td>${esc(stage.processing || 0)}</td>
        <td>${esc(duration(stage.oldest_pending_seconds || 0))}</td>
        <td>${esc(hour.enqueued || 0)}</td>
        <td>${esc(hour.completed || 0)}</td>
        <td>${esc(backlogText)}</td>
        <td>${eta(stage.byte_drain_eta_seconds ?? stage.drain_eta_seconds)}</td>
      </tr>`;
    }).join('');
    const growth = disk?.net_growth?.['1h'] || {};
    pipelineDetails.innerHTML = `
      <div class="health-pipeline-grid">
        <div><b>Disk Used</b><span>${esc(Number(disk.used_percent || 0).toFixed(1))}%</span></div>
        <div><b>Projected With Known Backlog</b><span>${esc(Number(disk.projected_used_percent_with_known_backlog || 0).toFixed(1))}%</span></div>
        <div><b>Known Byte Backlog</b><span>${esc(bytes(disk.known_pipeline_backlog_bytes || 0))}</span></div>
        <div><b>Start-limit Headroom</b><span>${esc(bytes(disk.start_limit_headroom_bytes || 0))}</span></div>
        <div><b>Unknown-size Items</b><span>${esc(disk.unknown_pipeline_backlog_items || 0)}</span></div>
        <div><b>1h Net Growth</b><span>${esc(bytes(growth.bytes_per_second || 0))}/s</span></div>
        <div><b>Start-limit ETA</b><span>${growth.eta_to_start_limit_seconds == null ? 'collecting samples' : esc(duration(growth.eta_to_start_limit_seconds))}</span></div>
        <div><b>Hard-limit ETA</b><span>${growth.eta_to_hard_limit_seconds == null ? 'collecting samples' : esc(duration(growth.eta_to_hard_limit_seconds))}</span></div>
      </div>
      <div class="health-pipeline-table"><table class="health-data-table health-pipeline-stage-table">
        <colgroup><col class="health-col-pipeline-stage"><col class="health-col-queued"><col class="health-col-active"><col class="health-col-oldest"><col class="health-col-hour-in"><col class="health-col-hour-done"><col class="health-col-backlog"><col class="health-col-drain"></colgroup>
        <thead><tr><th>Stage</th><th>Queued</th><th>Active</th><th>Oldest</th><th>1h In</th><th>1h Done</th><th>Byte Backlog</th><th>Drain ETA</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="8">No pipeline stages reported.</td></tr>'}</tbody>
      </table></div>`;
  }
  async function loadHealth(options = {}) {
    const showBusy = options.showBusy === true;
    if (showBusy) {
      refreshButton?.setAttribute('aria-busy', 'true');
      refreshButton?.classList.add('refreshing');
    }
    try {
      const response = await fetch('/api/system-health/beacons?hours=24&ts=' + Date.now(), {cache: 'no-store'});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const nextSignature = stableSignature(data);
      if (nextSignature === healthSignature) return false;
      healthSignature = nextSignature;
      const summary = data.summary || {};
      if (latest) latest.textContent = summary.latest ? fmt(summary.latest.timestamp) : 'No beacons';
      if (latestDetail) latestDetail.textContent = summary.latest ? detailText(summary.latest) : 'No beacon history found.';
      if (successful) successful.textContent = String(summary.successful || 0);
      if (unsuccessful) unsuccessful.textContent = String(summary.unsuccessful || 0);
      if (gaps) gaps.textContent = String(summary.gap_count || 0);
      if (gapNote) gapNote.textContent = summary.gap_count ? `${summary.gap_count} gap(s) require review` : 'No gaps over 10 minutes';
      beaconGeneratedAt = data.generated_at || '';
      beaconEntries = Array.isArray(data.entries) ? data.entries : [];
      beaconPage = Math.min(beaconPage, Math.max(1, Math.ceil(beaconEntries.length / beaconPageSize)));
      renderPcapHealth(data.pcap || {});
      renderPipelineHealth(data.pipeline || {});
      renderGaps(data.gaps || []);
      renderRows();
      if (rows) rows.dataset.liveRenderVersion = String(Number(rows.dataset.liveRenderVersion || 0) + 1);
      return true;
    } catch (error) {
      if (latest) latest.textContent = 'Unavailable';
      if (latestDetail) latestDetail.textContent = String(error.message || error);
      if (rows) rows.innerHTML = `<tr><td colspan="7">System Health API failed: ${esc(error.message || error)}</td></tr>`;
    } finally {
      if (showBusy) {
        refreshButton?.setAttribute('aria-busy', 'false');
        refreshButton?.classList.remove('refreshing');
      }
    }
  }
  beaconPageSizeSelect?.addEventListener('change', () => {
    beaconPageSize = Number(beaconPageSizeSelect.value || 25) || 25;
    beaconPage = 1;
    renderRows();
  });
  beaconPrev?.addEventListener('click', () => {
    if (beaconPage > 1) {
      beaconPage -= 1;
      renderRows();
    }
  });
  beaconNext?.addEventListener('click', () => {
    beaconPage += 1;
    renderRows();
  });
  pcapDetails?.addEventListener('change', event => {
    if (event.target?.id !== 'health-pcap-page-size') return;
    pcapPageSize = Number(event.target.value || 25) || 25;
    pcapPage = 1;
    renderPcapHealth(null);
  });
  pcapDetails?.addEventListener('click', event => {
    if (event.target?.id === 'health-pcap-prev') {
      if (pcapPage > 1) {
        pcapPage -= 1;
        renderPcapHealth(null);
      }
      return;
    }
    if (event.target?.id === 'health-pcap-next') {
      pcapPage += 1;
      renderPcapHealth(null);
    }
  });
  refreshButton?.addEventListener('click', () => loadHealth({showBusy: true}));
  loadHealth();
  if (window.OnionSentinelReactiveTables) {
    window.OnionSentinelReactiveTables.register('system-health-tables', loadHealth, {intervalMs: 10000});
  } else {
    setInterval(loadHealth, 10000);
  }
})();
</script>
'''


def inject_system_health_assets(text: str) -> str:
    if SYSTEM_HEALTH_CSS not in text:
        text = text.replace('</head>', SYSTEM_HEALTH_CSS + '</head>', 1)
    if SYSTEM_HEALTH_JS not in text:
        text = text.replace('</body>', SYSTEM_HEALTH_JS + '</body>', 1)
    return text
