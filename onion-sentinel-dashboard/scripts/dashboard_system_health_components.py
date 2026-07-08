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
      <section class="system-health-panel" aria-label="Beacon history">
        <div class="system-health-panel-title"><h3>Beacon events</h3><span id="health-event-note">Last 24 hours</span></div>
        <div class="system-health-table-wrap">
          <table class="system-health-table">
            <thead><tr><th>Time</th><th>Result</th><th>Stage</th><th>Relay</th><th>Alerts</th><th>HTTP</th><th>Details</th></tr></thead>
            <tbody id="health-beacon-rows"><tr><td colspan="7">Loading beacon history...</td></tr></tbody>
          </table>
        </div>
      </section>
    </section>'''


SYSTEM_HEALTH_CSS = '''
<style>
.system-health-link{display:block;text-decoration:none}.system-health-view{display:grid;gap:14px;padding-top:8px}.system-health-hero{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:18px;align-items:end;border-bottom:1px solid rgba(148,163,184,.12);padding:4px 0 16px}.system-health-hero h2{margin:8px 0 5px;color:#f5f9ff;font-size:26px;line-height:1;letter-spacing:-.02em}.system-health-hero p{max-width:82ch;margin:0;color:#9aaabd;font-size:13px;line-height:1.45}.system-health-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.system-health-kpis article,.system-health-panel{border:1px solid rgba(148,163,184,.11);border-radius:8px;background:#0d1620}.system-health-kpis article{padding:11px 12px}.system-health-kpis span{display:block;color:#8ff4ff;font-size:10px;font-weight:950;text-transform:uppercase;letter-spacing:.1em}.system-health-kpis strong{display:block;margin-top:7px;color:#f7fbff;font-size:18px;line-height:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.system-health-kpis em{display:block;margin-top:6px;color:#91a4ba;font-size:11.5px;font-style:normal;line-height:1.35}.system-health-panel{overflow:hidden}.system-health-panel-title{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;border-bottom:1px solid rgba(148,163,184,.10);background:#101b26}.system-health-panel-title h3{margin:0;color:#f4f8ff;font-size:16px;letter-spacing:-.01em}.system-health-panel-title span{color:#91a4ba;font-size:12px}.health-gap-list{display:grid;gap:8px;padding:12px}.health-gap-item{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;border:1px solid rgba(246,199,109,.22);border-radius:8px;padding:9px 10px;background:rgba(246,199,109,.055);color:#dce8f7;font-size:12px}.health-gap-item b{color:#f6c76d}.health-gap-item code{color:#f3f8ff;background:transparent;font:11.5px/1.35 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace}.health-gap-empty{padding:12px;color:#91a4ba;font-size:12px}.health-pcap-details{display:grid;gap:10px;padding:12px}.health-pcap-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px}.health-pcap-grid div{min-width:0;border:1px solid rgba(148,163,184,.11);border-radius:8px;padding:9px;background:rgba(148,163,184,.035)}.health-pcap-grid b{display:block;color:#8ff4ff;font-size:10px;text-transform:uppercase;letter-spacing:.08em}.health-pcap-grid span{display:block;min-width:0;margin-top:5px;color:#dce8f7;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.health-pcap-warnings{display:grid;gap:6px}.health-pcap-warnings span{border:1px solid rgba(251,113,133,.28);border-radius:8px;padding:8px 10px;color:#ff9aae;background:rgba(251,113,133,.065);font-size:12px;font-weight:800}.health-pcap-recent{overflow:auto;border:1px solid rgba(148,163,184,.11);border-radius:8px}.health-pcap-recent table{width:100%;min-width:980px;border-collapse:collapse}.health-pcap-recent th{padding:8px 10px;color:#91a4ba;background:#101b26;border-bottom:1px solid rgba(148,163,184,.10);font-size:10px;text-align:left;text-transform:uppercase;letter-spacing:.08em}.health-pcap-recent td{padding:9px 10px;border-bottom:1px solid rgba(148,163,184,.08);color:#d7e3f1;font-size:12px}.health-pcap-recent code{color:#dce9f8;background:rgba(148,163,184,.05);border:1px solid rgba(148,163,184,.12);border-radius:6px;padding:3px 6px;font-size:11.5px;white-space:nowrap}.system-health-table-wrap{overflow:auto}.system-health-table{width:100%;min-width:980px;border-collapse:collapse}.system-health-table th{padding:9px 11px;border-bottom:1px solid rgba(148,163,184,.12);color:#96a6b8;background:#101b26;font-size:10px;font-weight:900;text-align:left;text-transform:uppercase;letter-spacing:.08em}.system-health-table td{padding:11px;border-bottom:1px solid rgba(148,163,184,.09);vertical-align:top;color:#d7e3f1;font-size:12.5px;line-height:1.35}.system-health-table code{color:#dce9f8;background:rgba(148,163,184,.05);border:1px solid rgba(148,163,184,.12);border-radius:6px;padding:3px 6px;font-size:11.5px;white-space:nowrap}.health-result{display:inline-flex;align-items:center;border:1px solid rgba(34,197,94,.24);border-radius:999px;padding:3px 8px;color:#86efac;background:rgba(34,197,94,.055);font-size:10.5px;font-weight:950;text-transform:uppercase;letter-spacing:.04em}.health-result.failed{border-color:rgba(251,113,133,.34);color:#fb7185;background:rgba(251,113,133,.075)}.health-row-failed{background:rgba(251,113,133,.045)}.health-row-failed td{border-bottom-color:rgba(251,113,133,.16)}@media(max-width:1100px){.health-pcap-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:900px){.system-health-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.system-health-hero{grid-template-columns:1fr}}@media(max-width:620px){.system-health-kpis,.health-pcap-grid{grid-template-columns:1fr}.health-gap-item{grid-template-columns:1fr}}
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
  const pcapQueue = document.querySelector('#health-pcap-queue');
  const pcapQueueDetail = document.querySelector('#health-pcap-queue-detail');
  const pcapParser = document.querySelector('#health-pcap-parser');
  const pcapParserDetail = document.querySelector('#health-pcap-parser-detail');
  const pcapNote = document.querySelector('#health-pcap-note');
  const pcapDetails = document.querySelector('#health-pcap-details');
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const fmt = value => typeof formatProjectIso === 'function' ? formatProjectIso(value) : String(value || '');
  const bytes = value => typeof formatApiBytes === 'function' ? formatApiBytes(Number(value || 0)) : `${Number(value || 0)} B`;
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
  function renderRows(entries) {
    if (!rows) return;
    if (!entries.length) {
      rows.innerHTML = '<tr><td colspan="7">No beacon history found in the last 24 hours.</td></tr>';
      return;
    }
    rows.innerHTML = [...entries].reverse().map(entry => {
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
  function renderPcapHealth(pcap) {
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
      pcapNote.textContent = warnings ? `${warnings} warning(s) require review` : 'No PCAP workflow warnings';
    }
    if (pcapDetails) {
      const latestRequest = pcap?.latest_request || {};
      const latestAnalysis = pcap?.latest_analysis || {};
      const warnings = Array.isArray(pcap?.warnings) ? pcap.warnings : [];
      const recent = Array.isArray(pcap?.recent_requests) ? pcap.recent_requests : [];
      const warningHtml = warnings.length
        ? `<div class="health-pcap-warnings">${warnings.map(item => `<span>${esc(item)}</span>`).join('')}</div>`
        : '<div class="health-gap-empty">No stale PCAP queue items or unexpected PCAP failures.</div>';
      const recentHtml = recent.length
        ? `<div class="health-pcap-recent"><table><thead><tr><th>Updated</th><th>Status</th><th>Request</th><th>Group</th><th>Size</th><th>Error</th></tr></thead><tbody>${recent.map(item => `<tr><td><code>${esc(item.updated_at ? fmt(item.updated_at) : 'n/a')}</code></td><td><span class="pcap-status-pill pcap-status-${esc(String(item.status || 'none').toLowerCase())}">${esc(item.status || 'n/a')}</span></td><td><code>${esc(item.request_id || 'n/a')}</code></td><td><code>${esc(item.group_id || 'n/a')}</code></td><td>${esc(bytes(item.artifact_size_bytes || 0))}</td><td>${esc(item.error || '')}</td></tr>`).join('')}</tbody></table></div>`
        : '<div class="health-gap-empty">No PCAP request history found.</div>';
      pcapDetails.innerHTML = `
        ${warningHtml}
        <div class="health-pcap-grid">
          <div><b>Pending</b><span>${esc(counts.pending || 0)}</span></div>
          <div><b>Claimed</b><span>${esc(counts.claimed || 0)}</span></div>
          <div><b>Fulfilled</b><span>${esc(counts.fulfilled || 0)}</span></div>
          <div><b>Failed</b><span>${esc(counts.failed || 0)}</span></div>
          <div><b>No Packets</b><span>${esc(pcap?.no_packet_failures || 0)}</span></div>
          <div><b>Artifact Size</b><span>${esc(bytes(pcap?.artifact_size_bytes || 0))}</span></div>
          <div><b>Latest Request</b><span>${esc(latestRequest.request_id || 'n/a')} · ${esc(latestRequest.status || 'n/a')}</span></div>
          <div><b>Latest Request Time</b><span>${esc(latestRequest.updated_at ? fmt(latestRequest.updated_at) : 'n/a')}</span></div>
          <div><b>Latest Analysis</b><span>${esc(latestAnalysis.name || 'n/a')}</span></div>
          <div><b>Latest Analysis Time</b><span>${esc(latestAnalysis.updated_at ? fmt(latestAnalysis.updated_at) : 'n/a')}</span></div>
        </div>
        ${recentHtml}`;
    }
  }
  async function loadHealth() {
    refreshButton?.setAttribute('aria-busy', 'true');
    refreshButton?.classList.add('refreshing');
    try {
      const response = await fetch('/api/system-health/beacons?hours=24&ts=' + Date.now(), {cache: 'no-store'});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const summary = data.summary || {};
      if (latest) latest.textContent = summary.latest ? fmt(summary.latest.timestamp) : 'No beacons';
      if (latestDetail) latestDetail.textContent = summary.latest ? detailText(summary.latest) : 'No beacon history found.';
      if (successful) successful.textContent = String(summary.successful || 0);
      if (unsuccessful) unsuccessful.textContent = String(summary.unsuccessful || 0);
      if (gaps) gaps.textContent = String(summary.gap_count || 0);
      if (gapNote) gapNote.textContent = summary.gap_count ? `${summary.gap_count} gap(s) require review` : 'No gaps over 10 minutes';
      if (eventNote) eventNote.textContent = `${summary.total || 0} event(s), generated ${fmt(data.generated_at)}`;
      renderPcapHealth(data.pcap || {});
      renderGaps(data.gaps || []);
      renderRows(data.entries || []);
    } catch (error) {
      if (latest) latest.textContent = 'Unavailable';
      if (latestDetail) latestDetail.textContent = String(error.message || error);
      if (rows) rows.innerHTML = `<tr><td colspan="7">System Health API failed: ${esc(error.message || error)}</td></tr>`;
    } finally {
      refreshButton?.setAttribute('aria-busy', 'false');
      refreshButton?.classList.remove('refreshing');
    }
  }
  refreshButton?.addEventListener('click', loadHealth);
  loadHealth();
  setInterval(loadHealth, 60000);
})();
</script>
'''


def inject_system_health_assets(text: str) -> str:
    if SYSTEM_HEALTH_CSS not in text:
        text = text.replace('</head>', SYSTEM_HEALTH_CSS + '</head>', 1)
    if SYSTEM_HEALTH_JS not in text:
        text = text.replace('</body>', SYSTEM_HEALTH_JS + '</body>', 1)
    return text
