"""Threat Hunter view models, safe query generation, rendering, and assets."""
from __future__ import annotations

import html
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatHuntCandidateViewModel:
    digest: str
    rule_name: str
    title: str
    source_ip: str
    destination_ip: str
    destination_port: str
    alert_source: str
    criticality: str
    criticality_rank: int
    repeat_count: int
    first_seen: str
    last_seen: str
    hypothesis: str


def criticality_class(label: str) -> str:
    return re.sub(r'[^a-z0-9]+', '-', label.lower()).strip('-') or 'informational'


def query_part(value: str) -> str:
    cleaned = str(value or '').strip().strip('"\'') or '—'
    return '' if cleaned in {'n/a', 'unknown'} else cleaned


def kql_string(value: str) -> str:
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def sql_string(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _event_query(
    candidate: ThreatHuntCandidateViewModel,
    operator: str,
    conjunction: str,
) -> str:
    rule = query_part(candidate.rule_name)
    fields = (
        ('rule.name', rule),
        ('event.dataset', query_part(candidate.alert_source)),
        ('source.ip', query_part(candidate.source_ip)),
        ('destination.ip', query_part(candidate.destination_ip)),
        ('destination.port', query_part(candidate.destination_port)),
    )
    parts = []
    for field, value in fields:
        if not value:
            continue
        rendered = value if field == 'destination.port' and value.isdigit() else kql_string(value)
        parts.append(f'{field} {operator} {rendered}')
    fallback = rule or candidate.title
    return f' {conjunction} '.join(parts) or f'rule.name {operator} {kql_string(fallback)}'


def _osquery_where(candidate: ThreatHuntCandidateViewModel) -> str:
    destination = query_part(candidate.destination_ip)
    port = query_part(candidate.destination_port)
    filters = []
    if destination:
        filters.append(f"remote_address = {sql_string(destination)}")
    if port and port.isdigit():
        filters.append(f'remote_port = {port}')
    return ' AND '.join(filters) if filters else "remote_address != ''"


def threat_hunt_queries(candidate: ThreatHuntCandidateViewModel) -> tuple[str, str, str]:
    kql = _event_query(candidate, ':', 'and')
    oql = _event_query(candidate, '==', 'AND')
    osquery = f"""SELECT
  pos.pid,
  p.name,
  p.path,
  pos.local_address,
  pos.local_port,
  pos.remote_address,
  pos.remote_port,
  pos.protocol
FROM process_open_sockets AS pos
LEFT JOIN processes AS p ON pos.pid = p.pid
WHERE {_osquery_where(candidate)}
ORDER BY p.name, pos.remote_address, pos.remote_port;"""
    return kql, oql, osquery


def threat_hunt_code_block(title: str, code: str, block_id: str) -> str:
    return f'''
    <article class="hunt-code-card">
      <header><span>{html.escape(title)}</span><button type="button" data-copy-target="{html.escape(block_id)}">Copy</button></header>
      <pre><code id="{html.escape(block_id)}">{html.escape(code)}</code></pre>
    </article>'''


def threat_hunt_row(candidate: ThreatHuntCandidateViewModel, index: int) -> str:
    kql, oql, osquery = threat_hunt_queries(candidate)
    route = f'{candidate.source_ip} > {candidate.destination_ip} : {candidate.destination_port}'
    priority = 'Immediate' if candidate.criticality_rank >= 4 else 'Review'
    return f'''
    <tbody class="threat-hunt-group" data-hunt-key="{html.escape(candidate.digest)}">
      <tr class="threat-hunt-row" tabindex="0" aria-expanded="false" data-hunt-toggle>
        <td><span class="severity-label severity-text-{html.escape(criticality_class(candidate.criticality))}">{html.escape(candidate.criticality)}</span></td>
        <td><strong>{html.escape(candidate.rule_name or candidate.title)}</strong><code>{html.escape(route)}</code></td>
        <td><span class="siem-table-pill">{priority}</span></td>
        <td class="hunt-hypothesis">{html.escape(candidate.hypothesis)}</td>
        <td><b>{candidate.repeat_count}</b><span>{html.escape(candidate.last_seen)}</span></td>
      </tr>
      <tr class="threat-hunt-detail" hidden>
        <td colspan="5">
          <section class="hunt-detail-panel">
            <div class="hunt-detail-copy">
              <h3>Threat hunt details</h3>
              <p>Validate whether this detection is isolated noise, repeated reconnaissance, policy-expected traffic, or a pivot point for deeper endpoint and network review.</p>
              <dl>
                <div><dt>Observed route</dt><dd>{html.escape(route)}</dd></div>
                <div><dt>First seen</dt><dd>{html.escape(candidate.first_seen)}</dd></div>
                <div><dt>Last seen</dt><dd>{html.escape(candidate.last_seen)}</dd></div>
                <div><dt>Evidence gap</dt><dd>Confirm endpoint owner, process context, authentication outcome, and whether related destinations appear in the same window.</dd></div>
              </dl>
            </div>
            <div class="hunt-query-grid">
              {threat_hunt_code_block('Elastic KQL', kql, f'hunt-{index}-kql')}
              {threat_hunt_code_block('Security Onion OQL', oql, f'hunt-{index}-oql')}
              {threat_hunt_code_block('OSQuery', osquery, f'hunt-{index}-osquery')}
            </div>
          </section>
        </td>
      </tr>
    </tbody>'''


THREAT_HUNTER_MARKUP = '''
    <section class="view-section active threat-hunter-view" aria-label="Threat Hunter workspace">
      <section class="threat-hunter-hero">
        <div>
          <span class="settings-kicker">Threat Hunter</span>
          <h2>Proposed threat hunts</h2>
          <p>Skimmable hunt ideas built from current grouped detections. Open a row to review the hypothesis, validation notes, and query-ready pivots.</p>
        </div>
      </section>
      <section class="siem-table-section" aria-label="Proposed threat hunts">
        <div class="siem-table-wrap">
          <table class="siem-engineering-table threat-hunt-table">
            <thead><tr><th>Severity</th><th>Hunt focus</th><th>Priority</th><th>Hypothesis</th><th>Activity</th></tr></thead>
            {rows}
          </table>
        </div>
      </section>
    </section>'''


def render_threat_hunter_page(candidates: list[ThreatHuntCandidateViewModel]) -> str:
    rows = ''.join(
        threat_hunt_row(candidate, index)
        for index, candidate in enumerate(candidates, 1)
    )
    if not rows:
        rows = '<tbody><tr class="siem-empty-row"><td colspan="5">No threat hunt candidates are available yet.</td></tr></tbody>'
    return THREAT_HUNTER_MARKUP.format(rows=rows)


THREAT_HUNTER_CSS = '''
<style>
.threat-hunter-view{display:grid;gap:16px;padding-top:12px}.threat-hunter-hero{border:1px solid rgba(148,163,184,.12);border-radius:10px;padding:18px;background:#0d1620;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}.threat-hunter-hero h2{margin:10px 0 7px;color:#f5f9ff;font-size:28px;line-height:1;letter-spacing:-.025em}.threat-hunter-hero p{max-width:82ch;margin:0;color:#9aaabd;font-size:13px;line-height:1.55}.threat-hunt-row{cursor:pointer}.threat-hunt-row[aria-expanded="true"]{background:rgba(34,211,238,.07);box-shadow:inset 3px 0 0 #22d3ee}.threat-hunt-table .hunt-hypothesis{min-width:420px;color:#dce8f7;line-height:1.52}.threat-hunt-table td:last-child b{display:block;color:#f4f8ff;font-size:18px;line-height:1}.threat-hunt-table td:last-child span{display:block;margin-top:7px;color:#91a4ba;font-size:11.5px;line-height:1.35}.threat-hunt-detail td{padding:0;border-bottom:1px solid rgba(34,211,238,.14);background:#08111a}.hunt-detail-panel{display:grid;grid-template-columns:minmax(260px,.42fr) minmax(420px,1fr);gap:16px;padding:16px}.hunt-detail-copy{border:1px solid rgba(148,163,184,.12);border-radius:10px;padding:14px;background:#0d1620}.hunt-detail-copy h3{margin:0 0 8px;color:#f4f8ff;font-size:16px}.hunt-detail-copy p{margin:0 0 12px;color:#9aa8b8;font-size:13px;line-height:1.5}.hunt-detail-copy dl{display:grid;gap:8px;margin:0}.hunt-detail-copy div{border-top:1px solid rgba(148,163,184,.09);padding-top:8px}.hunt-detail-copy dt{color:#8ff4ff;font-size:10.5px;font-weight:950;text-transform:uppercase;letter-spacing:.08em}.hunt-detail-copy dd{margin:4px 0 0;color:#d7e3f1;font-size:12.5px;line-height:1.4;overflow-wrap:anywhere}.hunt-query-grid{display:grid;gap:12px}.hunt-code-card{border:1px solid rgba(148,163,184,.12);border-radius:10px;overflow:hidden;background:#071018}.hunt-code-card header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px;border-bottom:1px solid rgba(148,163,184,.10);background:#101b26}.hunt-code-card header span{color:#8ff4ff;font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.08em}.hunt-code-card button{border:1px solid rgba(34,211,238,.28);border-radius:8px;padding:6px 9px;color:#8ff4ff;background:rgba(34,211,238,.06);font-size:11px;font-weight:900;cursor:pointer}.hunt-code-card button:hover{border-color:rgba(143,244,255,.72);color:#f5fdff}.hunt-code-card pre{margin:0;max-height:260px;overflow:auto;padding:13px;color:#dce9f8;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;white-space:pre}@media(max-width:900px){.hunt-detail-panel{grid-template-columns:1fr}.threat-hunt-table .hunt-hypothesis{min-width:260px}}@media(max-width:720px){.threat-hunt-table .hunt-hypothesis{min-width:0}.threat-hunt-table tbody tr.threat-hunt-detail{padding:0}.threat-hunt-table tbody tr.threat-hunt-detail td{display:block;padding:0}.threat-hunt-table tbody tr.threat-hunt-detail td::before{content:none}.threat-hunt-table td:nth-child(1)::before{content:"Severity"}.threat-hunt-table td:nth-child(2)::before{content:"Focus"}.threat-hunt-table td:nth-child(3)::before{content:"Priority"}.threat-hunt-table td:nth-child(4)::before{content:"Hypothesis"}.threat-hunt-table td:nth-child(5)::before{content:"Activity"}.hunt-detail-panel{padding:12px}.hunt-code-toolbar{flex-wrap:wrap}}
@media(max-width:900px){.threat-hunt-table .hunt-hypothesis{min-width:0!important}.threat-hunt-table tbody tr.threat-hunt-detail{padding:0!important}.threat-hunt-table tbody tr.threat-hunt-detail td{display:block!important;padding:0!important}.threat-hunt-table tbody tr.threat-hunt-detail td::before{content:none!important}.threat-hunt-table td:nth-child(1)::before{content:"Severity"}.threat-hunt-table td:nth-child(2)::before{content:"Focus"}.threat-hunt-table td:nth-child(3)::before{content:"Priority"}.threat-hunt-table td:nth-child(4)::before{content:"Hypothesis"}.threat-hunt-table td:nth-child(5)::before{content:"Activity"}}
@media(max-width:720px){.hunt-code-card button{min-height:44px;padding:7px 10px}}
</style>
'''


THREAT_HUNTER_JS = '''
<script>
(() => {
  const root = document.querySelector('.threat-hunter-view');
  if (!root) return;
  const toggle = row => {
    const detail = row.parentElement?.querySelector('.threat-hunt-detail');
    const expanded = row.getAttribute('aria-expanded') === 'true';
    row.setAttribute('aria-expanded', String(!expanded));
    if (detail) detail.hidden = expanded;
  };
  root.addEventListener('click', async event => {
    const copyButton = event.target.closest('[data-copy-target]');
    if (copyButton) {
      event.preventDefault();
      event.stopPropagation();
      const target = document.getElementById(copyButton.dataset.copyTarget || '');
      const text = target?.textContent || '';
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        copyButton.textContent = 'Copied';
      } catch (_) {
        copyButton.textContent = 'Copy failed';
      }
      window.setTimeout(() => { copyButton.textContent = 'Copy'; }, 1200);
      return;
    }
    const row = event.target.closest('[data-hunt-toggle]');
    if (row) toggle(row);
  });
  root.addEventListener('keydown', event => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const row = event.target.closest('[data-hunt-toggle]');
    if (!row) return;
    event.preventDefault();
    toggle(row);
  });
  window.OnionSentinelReactiveTables?.register('threat-hunter-tables', () =>
    window.OnionSentinelReactiveTables.refreshFragment('.threat-hunter-view', {
      capture: current => [...current.querySelectorAll('.threat-hunt-group')]
        .filter(group => group.querySelector('[data-hunt-toggle]')?.getAttribute('aria-expanded') === 'true')
        .map(group => group.dataset.huntKey).filter(Boolean),
      restore: (current, expanded) => (expanded || []).forEach(key => {
        const group = current.querySelector(`.threat-hunt-group[data-hunt-key="${CSS.escape(key)}"]`);
        const row = group?.querySelector('[data-hunt-toggle]');
        const detail = group?.querySelector('.threat-hunt-detail');
        if (row && detail) { row.setAttribute('aria-expanded', 'true'); detail.hidden = false; }
      })
    }), {intervalMs: 15000});
})();
</script>
'''


def inject_threat_hunter_page_assets(text: str) -> str:
    if THREAT_HUNTER_CSS not in text:
        text = text.replace('</head>', THREAT_HUNTER_CSS + '</head>', 1)
    if THREAT_HUNTER_JS not in text:
        text = text.replace('</body>', THREAT_HUNTER_JS + '</body>', 1)
    return text
