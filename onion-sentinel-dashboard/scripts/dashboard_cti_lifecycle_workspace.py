"""Durable requirement, intelligence, and audit workspace assets for CTI."""
from __future__ import annotations


CTI_LIFECYCLE_MARKUP = '''
      <section class="cti-panel cti-table-panel" aria-labelledby="cti-requirements-title">
        <header class="cti-section-header">
          <div><span class="cti-kicker">Requirements</span><h3 id="cti-requirements-title">Priority intelligence requirement register</h3><p>Record the decision, sponsor, consumers, horizon, collection gaps, deliverable, success criteria, and review state that direct collection.</p></div>
          <div class="cti-table-actions"><label class="cti-search"><span>Search requirements</span><input id="cti-requirement-search" type="search" placeholder="Title, sponsor, consumer, decision"></label><button type="button" class="cti-primary-button" data-cti-add="requirement">Add requirement</button></div>
        </header>
        <div class="cti-table-wrap">
          <table class="cti-table cti-requirement-table">
            <thead><tr><th>Use</th><th>Requirement / decision</th><th>Priority</th><th>Sponsor / consumers</th><th>Product / success</th><th>Gaps / review</th><th><span class="sr-only">Actions</span></th></tr></thead>
            <tbody id="cti-requirement-rows"><tr><td colspan="7" class="cti-loading-cell">Loading priority requirements…</td></tr></tbody>
          </table>
        </div>
        <p class="cti-table-footnote">Requirements are durable program records. Pausing or retiring one does not erase the intelligence and audit history produced against it.</p>
      </section>

      <section class="cti-panel cti-table-panel" aria-labelledby="cti-intelligence-title">
        <header class="cti-section-header">
          <div><span class="cti-kicker">Processing through evaluation</span><h3 id="cti-intelligence-title">Intelligence evidence register</h3><p>Preserve source reliability, information credibility, confidence, timestamps, handling, expiration, and evidence-linked entities through every lifecycle state.</p></div>
          <div class="cti-table-actions"><label class="cti-search"><span>Search intelligence</span><input id="cti-intelligence-search" type="search" placeholder="Title, entity, lifecycle, source"></label><button type="button" class="cti-primary-button" data-cti-add="intelligence">Add intelligence</button></div>
        </header>
        <div class="cti-authority-banner"><strong>Context only · never fact or detection outcome</strong><span>Intelligence can guide an investigation, but independent case evidence must support every fact, verdict, detection outcome, or response action.</span></div>
        <div class="cti-table-wrap">
          <table class="cti-table cti-intelligence-table">
            <thead><tr><th>Lifecycle</th><th>Intelligence / judgment</th><th>Reliability / credibility</th><th>Confidence / handling</th><th>Freshness</th><th>Evidence</th><th>Linked entities / actions</th><th><span class="sr-only">Actions</span></th></tr></thead>
            <tbody id="cti-intelligence-rows"><tr><td colspan="8" class="cti-loading-cell">Loading intelligence records…</td></tr></tbody>
          </table>
        </div>
        <p class="cti-table-footnote">Indicators, actors, campaigns, vulnerabilities, and defensive actions must link to admitted evidence and affected monitored technologies.</p>
      </section>

      <section class="cti-panel" aria-labelledby="cti-audit-title">
        <header class="cti-section-header compact"><div><span class="cti-kicker">Auditability</span><h3 id="cti-audit-title">Revision history</h3><p>Metadata-only change records show which governed entries changed without copying intelligence content into application logs.</p></div></header>
        <div id="cti-audit-rows" class="cti-audit-list"><span>Loading revision history…</span></div>
      </section>

      <div id="cti-lifecycle-editor" class="cti-modal" hidden>
        <button class="cti-modal-backdrop" type="button" data-cti-lifecycle-close aria-label="Close lifecycle editor"></button>
        <section class="cti-dialog" role="dialog" aria-modal="true" aria-labelledby="cti-lifecycle-editor-title">
          <header><div><span id="cti-lifecycle-editor-kicker" class="cti-kicker">Requirements</span><h2 id="cti-lifecycle-editor-title">Add requirement</h2><p id="cti-lifecycle-editor-description">Direct collection with an owned decision and measurable success.</p></div><button type="button" class="cti-close-button" data-cti-lifecycle-close aria-label="Close lifecycle editor">×</button></header>
          <form id="cti-lifecycle-editor-form">
            <input id="cti-life-id" type="hidden"><input id="cti-life-original-id" type="hidden">
            <div class="cti-form-banner"><span id="cti-lifecycle-editor-status" role="status" aria-live="polite"></span></div>
            <div id="cti-requirement-fields" class="cti-form-grid">
              <label class="wide"><span>Requirement title</span><input id="cti-req-title" maxlength="180" required></label>
              <label class="wide"><span>Decision supported</span><textarea id="cti-req-decision" maxlength="1000" rows="3" required></textarea></label>
              <label><span>Sponsor</span><input id="cti-req-sponsor" maxlength="120" required></label>
              <label><span>Consumers · comma separated</span><input id="cti-req-consumers" maxlength="1500"></label>
              <label><span>Priority</span><select id="cti-req-priority"><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
              <label><span>Status</span><select id="cti-req-status"><option value="draft">Draft</option><option value="active">Active</option><option value="answered">Answered</option><option value="paused">Paused</option><option value="retired">Retired</option></select></label>
              <label><span>Active</span><select id="cti-req-active"><option value="true">Active</option><option value="false">Inactive</option></select></label>
              <label><span>Collection cadence</span><select id="cti-req-cadence"><option value="realtime">Realtime</option><option value="hourly">Hourly</option><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option><option value="on-demand">On demand</option></select></label>
              <label><span>Decision horizon</span><input id="cti-req-horizon" maxlength="120" required></label>
              <label><span>Next review</span><input id="cti-req-review" type="date"></label>
              <label class="wide"><span>Collection gaps · comma separated</span><input id="cti-req-gaps" maxlength="2000"></label>
              <label class="wide"><span>Deliverable</span><textarea id="cti-req-deliverable" maxlength="500" rows="2" required></textarea></label>
              <label class="wide"><span>Success criteria</span><textarea id="cti-req-success" maxlength="1000" rows="3" required></textarea></label>
            </div>
            <div id="cti-intelligence-fields" class="cti-form-grid" hidden>
              <label class="wide"><span>Intelligence title</span><input id="cti-intel-title" maxlength="240" required></label>
              <label class="wide"><span>Deduplication key · stable source identity</span><input id="cti-intel-dedup" maxlength="180" required></label>
              <label><span>Lifecycle state</span><select id="cti-intel-state"><option value="requirements">Requirements</option><option value="collection">Collection</option><option value="processing">Processing</option><option value="analysis">Analysis</option><option value="dissemination">Dissemination</option><option value="feedback">Feedback</option><option value="evaluation">Evaluation</option></select></label>
              <label><span>Investigation use</span><input id="cti-intel-authority" value="context-only" readonly></label>
              <label><span>Source reliability</span><select id="cti-intel-reliability"><option>A</option><option>B</option><option>C</option><option>D</option><option>E</option><option>F</option></select></label>
              <label><span>Information credibility</span><select id="cti-intel-credibility"><option value="1">1 · Confirmed</option><option value="2">2 · Probably true</option><option value="3">3 · Possibly true</option><option value="4">4 · Doubtful</option><option value="5">5 · Improbable</option><option value="6">6 · Cannot be judged</option></select></label>
              <label><span>Confidence</span><select id="cti-intel-confidence"><option value="high">High</option><option value="moderate">Moderate</option><option value="low">Low</option><option value="unknown">Unknown</option></select></label>
              <label><span>Handling marking</span><select id="cti-intel-handling"><option>TLP:CLEAR</option><option>TLP:GREEN</option><option>TLP:AMBER</option><option>TLP:AMBER+STRICT</option><option>TLP:RED</option></select></label>
              <label><span>Collected at</span><input id="cti-intel-collected" type="datetime-local" required></label>
              <label><span>Analyzed at</span><input id="cti-intel-analyzed" type="datetime-local"></label>
              <label><span>Published at</span><input id="cti-intel-published" type="datetime-local"></label>
              <label><span>Expires at</span><input id="cti-intel-expires" type="datetime-local" required></label>
              <label class="wide"><span>Requirement ids · comma separated</span><input id="cti-intel-requirements" maxlength="2200"></label>
              <label class="wide"><span>Source ids · comma separated</span><input id="cti-intel-sources" maxlength="2200"></label>
              <label class="wide"><span>Affected technology ids · comma separated</span><input id="cti-intel-technologies" maxlength="2200"></label>
              <label class="wide"><span>Evidence summary</span><textarea id="cti-intel-summary" maxlength="2000" rows="3" required></textarea></label>
              <label class="wide"><span>Analytic judgment</span><textarea id="cti-intel-judgment" maxlength="2000" rows="3" required></textarea></label>
              <label class="wide"><span>Assumptions · one per line</span><textarea id="cti-intel-assumptions" maxlength="4000" rows="3"></textarea></label>
              <label class="wide"><span>Alternatives · one per line</span><textarea id="cti-intel-alternatives" maxlength="4000" rows="3"></textarea></label>
              <label class="wide"><span>Evidence · one per line: id | kind | reference | observed_at | source_id | handling | description</span><textarea id="cti-intel-evidence" maxlength="12000" rows="5" required></textarea></label>
              <label class="wide"><span>Entities/actions · one per line: id | indicator/actor/campaign/vulnerability/defensive-action | value | evidence ids comma-separated | technology ids comma-separated</span><textarea id="cti-intel-entities" maxlength="12000" rows="5" required></textarea></label>
            </div>
            <footer><button id="cti-life-delete" type="button" class="cti-danger-button" hidden>Delete</button><span></span><button type="button" class="cti-secondary-button" data-cti-lifecycle-close>Cancel</button><button id="cti-life-save" type="submit" class="cti-primary-button">Save requirement</button></footer>
          </form>
        </section>
      </div>
'''


CTI_LIFECYCLE_CSS = '''
<style>
.cti-authority-banner{display:grid;grid-template-columns:260px minmax(0,1fr);gap:14px;margin:0 16px 14px;border:1px solid rgba(246,199,109,.22);border-radius:8px;padding:10px 12px;background:rgba(246,199,109,.045)}.cti-authority-banner strong{color:#f6c76d;font-size:11px}.cti-authority-banner span{color:#9eacbc;font-size:10.5px;line-height:1.4}.cti-requirement-table,.cti-intelligence-table{min-width:1380px}.cti-requirement-table td:nth-child(2){min-width:300px}.cti-requirement-table td:nth-child(4),.cti-requirement-table td:nth-child(5),.cti-requirement-table td:nth-child(6){min-width:210px}.cti-intelligence-table td:nth-child(2){min-width:310px}.cti-intelligence-table td:nth-child(6),.cti-intelligence-table td:nth-child(7){min-width:220px}.cti-audit-list{display:grid;gap:6px}.cti-audit-entry{display:grid;grid-template-columns:90px 180px minmax(0,1fr) 130px;gap:10px;align-items:center;border-top:1px solid rgba(148,163,184,.09);padding:8px 0;color:#92a4b7;font-size:10.5px}.cti-audit-entry strong{color:#e5eef8}.cti-audit-entry code{color:#8ff4ff;font-size:9.5px}.cti-audit-entry span:last-child{text-align:right}.cti-freshness-stale{border-color:rgba(251,113,133,.42)!important;color:#fb7185!important}.cti-freshness-current{border-color:rgba(74,222,128,.38)!important;color:#4ade80!important}@media(max-width:720px){.cti-authority-banner,.cti-audit-entry{grid-template-columns:1fr}.cti-audit-entry span:last-child{text-align:left}}
</style>
'''


CTI_LIFECYCLE_JS = r'''
<script>
(() => {
  const root = document.querySelector('#cti-workspace');
  if (!root) return;
  const apiPath = '/api/cyber-threat-intel/program';
  const byId = id => document.getElementById(id);
  const modal = byId('cti-lifecycle-editor');
  const form = byId('cti-lifecycle-editor-form');
  const requirementFields = byId('cti-requirement-fields');
  const intelligenceFields = byId('cti-intelligence-fields');
  const status = byId('cti-lifecycle-editor-status');
  const saveButton = byId('cti-life-save');
  const deleteButton = byId('cti-life-delete');
  const state = {program: null, authenticated: false, kind: '', previousFocus: null};
  const clone = value => JSON.parse(JSON.stringify(value));
  const node = (tag, className = '', text = '') => { const element = document.createElement(tag); if (className) element.className = className; if (text !== '') element.textContent = text; return element; };
  const splitList = value => [...new Set(String(value || '').split(',').map(item => item.trim()).filter(Boolean))];
  const splitLines = value => String(value || '').split('\n').map(item => item.trim()).filter(Boolean);
  const labelize = value => String(value || '').replaceAll('-', ' ').replace(/\b\w/g, char => char.toUpperCase());
  const localTimestamp = value => { if (!value) return ''; const date = new Date(value); const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000); return local.toISOString().slice(0, 16); };
  const utcTimestamp = value => value ? new Date(value).toISOString().replace(/\.\d{3}Z$/, 'Z') : '';
  const value = (id, next = undefined) => { const control = byId(id); if (next !== undefined) control.value = next ?? ''; return control.value; };
  const tags = values => { const result = node('div', 'cti-inline-tags'); (values || []).slice(0, 6).forEach(entry => result.append(node('span', '', entry))); if ((values || []).length > 6) result.append(node('span', '', `+${values.length - 6}`)); return result; };
  const pill = (text, className = '') => node('span', `cti-table-pill ${className}`.trim(), text);
  const addLine = (cell, primary, secondary = '') => { cell.append(node('strong', '', primary)); if (secondary) cell.append(node('small', '', secondary)); return cell; };
  const emptyRow = (tbody, columns, text) => { tbody.replaceChildren(); const row = node('tr'); const cell = node('td', 'cti-loading-cell', text); cell.colSpan = columns; row.append(cell); tbody.append(row); };
  const editButton = (kind, id, label) => { const button = node('button', 'cti-edit-button', 'Edit'); button.type = 'button'; button.setAttribute('aria-label', `Edit ${label}`); button.addEventListener('click', () => openEditor(kind, id)); return button; };
  const filter = kind => { const input = byId(`cti-${kind}-search`); const tbody = byId(`cti-${kind}-rows`); const query = String(input?.value || '').trim().toLowerCase(); [...tbody.querySelectorAll('tr[data-search-text]')].forEach(row => { row.hidden = Boolean(query && !row.dataset.searchText.includes(query)); }); };
  const freshness = item => !item.expires_at || new Date(item.expires_at).getTime() < Date.now() ? 'stale' : 'current';

  const renderRequirements = () => {
    const tbody = byId('cti-requirement-rows'); tbody.replaceChildren();
    const records = state.program?.requirements || [];
    if (!records.length) { emptyRow(tbody, 7, 'No active intelligence requirements are recorded.'); return; }
    records.forEach(item => {
      const row = node('tr'); row.dataset.searchText = [item.title, item.decision, item.sponsor, ...(item.consumers || []), item.status].join(' ').toLowerCase();
      const active = node('td'); active.append(pill(item.active ? 'Active' : 'Inactive', item.active ? 'cti-freshness-current' : ''));
      const requirement = addLine(node('td'), item.title, item.decision);
      const priority = node('td'); priority.append(pill(item.priority, `priority-${item.priority}`)); priority.append(node('small', '', `${labelize(item.status)} · ${item.horizon}`));
      const sponsor = addLine(node('td'), item.sponsor); sponsor.append(tags(item.consumers));
      const product = addLine(node('td'), item.deliverable, item.success_criteria);
      const gaps = node('td'); gaps.append(tags(item.collection_gaps)); gaps.append(node('small', '', item.review_date ? `Review ${item.review_date}` : 'Review date missing'));
      const action = node('td'); action.append(editButton('requirement', item.id, item.title));
      row.append(active, requirement, priority, sponsor, product, gaps, action); tbody.append(row);
    }); filter('requirement');
  };
  const renderIntelligence = () => {
    const tbody = byId('cti-intelligence-rows'); tbody.replaceChildren();
    const records = state.program?.intelligence || [];
    if (!records.length) { emptyRow(tbody, 8, 'No intelligence records have been admitted.'); return; }
    records.forEach(item => {
      const row = node('tr'); const entityValues = (item.entities || []).map(entity => `${entity.entity_type} ${entity.value}`); row.dataset.searchText = [item.title, item.lifecycle_state, ...(item.source_ids || []), ...entityValues].join(' ').toLowerCase();
      const lifecycle = node('td'); lifecycle.append(pill(labelize(item.lifecycle_state)));
      const judgment = addLine(node('td'), item.title, item.analytic_judgment);
      const reliability = addLine(node('td'), `Source ${item.source_reliability}`, `Information ${item.information_credibility}`);
      const confidence = node('td'); confidence.append(pill(item.confidence)); confidence.append(node('small', '', item.handling));
      const current = freshness(item); const fresh = addLine(node('td'), labelize(current), `Expires ${item.expires_at}`); fresh.prepend(pill(current, `cti-freshness-${current}`));
      const evidence = addLine(node('td'), `${(item.evidence || []).length} evidence record(s)`, `${item.collected_at} collected`); evidence.append(tags((item.evidence || []).map(entry => entry.id)));
      const entities = node('td'); entities.append(tags(entityValues)); entities.append(node('small', '', `${(item.affected_technology_ids || []).length} affected technology link(s)`));
      const action = node('td'); action.append(editButton('intelligence', item.id, item.title));
      row.append(lifecycle, judgment, reliability, confidence, fresh, evidence, entities, action); tbody.append(row);
    }); filter('intelligence');
  };
  const renderAudit = () => {
    const target = byId('cti-audit-rows'); target.replaceChildren(); const history = [...(state.program?.audit_history || [])].reverse().slice(0, 12);
    if (!history.length) { target.append(node('span', '', 'No persisted analyst edits yet.')); return; }
    history.forEach(event => { const row = node('div', 'cti-audit-entry'); row.append(node('strong', '', `Revision ${event.revision}`), node('span', '', event.changed_at), node('span', '', (event.changes || []).join(' · ') || 'No content change'), node('code', '', String(event.after_digest || '').slice(0, 12))); target.append(row); });
  };
  const render = () => { renderRequirements(); renderIntelligence(); renderAudit(); };

  const setFields = (group, enabled) => { group.hidden = !enabled; group.querySelectorAll('input,select,textarea').forEach(control => { control.disabled = !enabled; }); };
  const defaultRequirement = () => ({id: '', active: true, title: '', decision: '', sponsor: 'CTI Program', consumers: [], priority: 'high', horizon: '30 days', cadence: 'daily', collection_gaps: [], deliverable: '', success_criteria: '', review_date: '', status: 'draft'});
  const defaultIntelligence = () => ({id: '', deduplication_key: '', title: '', lifecycle_state: 'requirements', requirement_ids: [], source_ids: [], affected_technology_ids: [], source_reliability: 'F', information_credibility: '6', confidence: 'unknown', handling: 'TLP:CLEAR', collected_at: '', analyzed_at: '', published_at: '', expires_at: '', summary: '', analytic_judgment: '', assumptions: [], alternatives: [], evidence: [], entities: [], investigation_use: 'context-only'});
  const evidenceText = records => (records || []).map(entry => [entry.id, entry.kind, entry.reference, entry.observed_at, entry.source_id, entry.handling, entry.description].join(' | ')).join('\n');
  const entityText = records => (records || []).map(entry => [entry.id, entry.entity_type, entry.value, (entry.evidence_ids || []).join(','), (entry.affected_technology_ids || []).join(',')].join(' | ')).join('\n');
  const openEditor = (kind, id = '') => {
    if (!state.authenticated) { byId('cti-page-status-text').textContent = 'Administration sign-in is required before changing CTI lifecycle records.'; byId('cti-admin-link').hidden = false; return; }
    state.kind = kind; state.previousFocus = document.activeElement; const key = kind === 'requirement' ? 'requirements' : 'intelligence'; const existing = (state.program?.[key] || []).find(item => item.id === id); const item = clone(existing || (kind === 'requirement' ? defaultRequirement() : defaultIntelligence()));
    value('cti-life-id', item.id); value('cti-life-original-id', existing?.id || ''); deleteButton.hidden = !existing; setFields(requirementFields, kind === 'requirement'); setFields(intelligenceFields, kind === 'intelligence');
    byId('cti-lifecycle-editor-kicker').textContent = kind === 'requirement' ? 'Requirements' : 'Intelligence evidence'; byId('cti-lifecycle-editor-title').textContent = `${existing ? 'Edit' : 'Add'} ${kind}`; byId('cti-lifecycle-editor-description').textContent = kind === 'requirement' ? 'Direct collection with an owned decision and measurable success.' : 'Preserve provenance and uncertainty; investigation use remains context-only.'; saveButton.textContent = `Save ${kind}`;
    if (kind === 'requirement') {
      value('cti-req-title', item.title); value('cti-req-decision', item.decision); value('cti-req-sponsor', item.sponsor); value('cti-req-consumers', (item.consumers || []).join(', ')); value('cti-req-priority', item.priority); value('cti-req-status', item.status); value('cti-req-active', String(item.active)); value('cti-req-cadence', item.cadence); value('cti-req-horizon', item.horizon); value('cti-req-review', item.review_date); value('cti-req-gaps', (item.collection_gaps || []).join(', ')); value('cti-req-deliverable', item.deliverable); value('cti-req-success', item.success_criteria);
    } else {
      value('cti-intel-title', item.title); value('cti-intel-dedup', item.deduplication_key); value('cti-intel-state', item.lifecycle_state); value('cti-intel-reliability', item.source_reliability); value('cti-intel-credibility', item.information_credibility); value('cti-intel-confidence', item.confidence); value('cti-intel-handling', item.handling); value('cti-intel-collected', localTimestamp(item.collected_at)); value('cti-intel-analyzed', localTimestamp(item.analyzed_at)); value('cti-intel-published', localTimestamp(item.published_at)); value('cti-intel-expires', localTimestamp(item.expires_at)); value('cti-intel-requirements', (item.requirement_ids || []).join(', ')); value('cti-intel-sources', (item.source_ids || []).join(', ')); value('cti-intel-technologies', (item.affected_technology_ids || []).join(', ')); value('cti-intel-summary', item.summary); value('cti-intel-judgment', item.analytic_judgment); value('cti-intel-assumptions', (item.assumptions || []).join('\n')); value('cti-intel-alternatives', (item.alternatives || []).join('\n')); value('cti-intel-evidence', evidenceText(item.evidence)); value('cti-intel-entities', entityText(item.entities));
    }
    status.textContent = ''; modal.hidden = false; document.body.classList.add('cti-modal-open'); window.setTimeout(() => (kind === 'requirement' ? byId('cti-req-title') : byId('cti-intel-title')).focus(), 0);
  };
  const closeEditor = () => { modal.hidden = true; document.body.classList.remove('cti-modal-open'); status.textContent = ''; state.previousFocus?.focus?.(); };
  const parseEvidence = () => splitLines(value('cti-intel-evidence')).map((line, index) => { const parts = line.split('|').map(part => part.trim()); if (parts.length !== 7) throw new Error(`Evidence line ${index + 1} must contain seven pipe-separated fields.`); return {id: parts[0], kind: parts[1], reference: parts[2], observed_at: utcTimestamp(parts[3]), source_id: parts[4], handling: parts[5], description: parts[6]}; });
  const parseEntities = () => splitLines(value('cti-intel-entities')).map((line, index) => { const parts = line.split('|').map(part => part.trim()); if (parts.length !== 5) throw new Error(`Entity line ${index + 1} must contain five pipe-separated fields.`); return {id: parts[0], entity_type: parts[1], value: parts[2], evidence_ids: splitList(parts[3]), affected_technology_ids: splitList(parts[4])}; });
  const formEntry = () => state.kind === 'requirement' ? {id: value('cti-life-id'), active: value('cti-req-active') === 'true', title: value('cti-req-title'), decision: value('cti-req-decision'), sponsor: value('cti-req-sponsor'), consumers: splitList(value('cti-req-consumers')), priority: value('cti-req-priority'), horizon: value('cti-req-horizon'), cadence: value('cti-req-cadence'), collection_gaps: splitList(value('cti-req-gaps')), deliverable: value('cti-req-deliverable'), success_criteria: value('cti-req-success'), review_date: value('cti-req-review'), status: value('cti-req-status')} : {id: value('cti-life-id'), deduplication_key: value('cti-intel-dedup'), title: value('cti-intel-title'), lifecycle_state: value('cti-intel-state'), requirement_ids: splitList(value('cti-intel-requirements')), source_ids: splitList(value('cti-intel-sources')), affected_technology_ids: splitList(value('cti-intel-technologies')), source_reliability: value('cti-intel-reliability'), information_credibility: value('cti-intel-credibility'), confidence: value('cti-intel-confidence'), handling: value('cti-intel-handling'), collected_at: utcTimestamp(value('cti-intel-collected')), analyzed_at: utcTimestamp(value('cti-intel-analyzed')), published_at: utcTimestamp(value('cti-intel-published')), expires_at: utcTimestamp(value('cti-intel-expires')), summary: value('cti-intel-summary'), analytic_judgment: value('cti-intel-judgment'), assumptions: splitLines(value('cti-intel-assumptions')), alternatives: splitLines(value('cti-intel-alternatives')), evidence: parseEvidence(), entities: parseEntities(), investigation_use: 'context-only'};
  const persist = async next => {
    const response = await fetch(apiPath, {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json', 'X-Onion-Sentinel-Request': 'dashboard'}, body: JSON.stringify({expected_revision: state.program.revision, sources: next.sources, technologies: next.technologies, requirements: next.requirements, intelligence: next.intelligence})});
    let data = {}; try { data = await response.json(); } catch (_) {}
    if (!response.ok || !data.ok || !data.program) { if (response.status === 409) await load(); throw new Error(data.error || `Save failed with HTTP ${response.status}`); }
    state.program = data.program; render(); document.dispatchEvent(new CustomEvent('cti-program-updated', {detail: {program: data.program}}));
  };
  const load = async () => { const response = await fetch(apiPath, {cache: 'no-store', credentials: 'same-origin'}); const data = await response.json(); if (!response.ok || !data.ok || !data.program) throw new Error(data.error || 'Could not load CTI lifecycle records.'); state.program = data.program; render(); };
  const loadSession = async () => { try { const response = await fetch('/api/admin/session-status', {cache: 'no-store', credentials: 'same-origin'}); const data = await response.json(); state.authenticated = Boolean(response.ok && data.authenticated); } catch (_) { state.authenticated = false; } };
  form.addEventListener('submit', async event => { event.preventDefault(); saveButton.disabled = true; status.textContent = 'Saving…'; try { const next = clone(state.program); const key = state.kind === 'requirement' ? 'requirements' : 'intelligence'; const entry = formEntry(); const original = value('cti-life-original-id'); const index = next[key].findIndex(item => item.id === original && original); if (index >= 0) next[key][index] = entry; else next[key].push(entry); await persist(next); closeEditor(); } catch (error) { status.textContent = error.message || 'Could not save this lifecycle record.'; } finally { saveButton.disabled = false; } });
  deleteButton.addEventListener('click', async () => { const original = value('cti-life-original-id'); if (!original || !window.confirm(`Remove this ${state.kind} from the active CTI workspace? Its prior revisions remain auditable.`)) return; deleteButton.disabled = true; try { const next = clone(state.program); const key = state.kind === 'requirement' ? 'requirements' : 'intelligence'; next[key] = next[key].filter(item => item.id !== original); await persist(next); closeEditor(); } catch (error) { status.textContent = error.message || 'Could not remove this lifecycle record.'; } finally { deleteButton.disabled = false; } });
  root.querySelectorAll('[data-cti-add="requirement"],[data-cti-add="intelligence"]').forEach(button => button.addEventListener('click', () => openEditor(button.dataset.ctiAdd)));
  root.querySelectorAll('[data-cti-lifecycle-close]').forEach(button => button.addEventListener('click', closeEditor)); byId('cti-requirement-search').addEventListener('input', () => filter('requirement')); byId('cti-intelligence-search').addEventListener('input', () => filter('intelligence')); document.addEventListener('cti-program-updated', event => { if (event.detail?.program) { state.program = event.detail.program; render(); } }); document.addEventListener('keydown', event => { if (event.key === 'Escape' && !modal.hidden) closeEditor(); });
  Promise.all([loadSession(), load()]).catch(error => { emptyRow(byId('cti-requirement-rows'), 7, error.message || 'Requirements are unavailable.'); emptyRow(byId('cti-intelligence-rows'), 8, 'Intelligence records are unavailable.'); });
})();
</script>
'''


def inject_cti_lifecycle_markup(text: str) -> str:
    marker = '      <section class="cti-panel cti-table-panel" aria-labelledby="cti-sources-title">'
    if CTI_LIFECYCLE_MARKUP not in text:
        text = text.replace(marker, CTI_LIFECYCLE_MARKUP + "\n" + marker, 1)
    return text


__all__ = (
    "CTI_LIFECYCLE_CSS",
    "CTI_LIFECYCLE_JS",
    "CTI_LIFECYCLE_MARKUP",
    "inject_cti_lifecycle_markup",
)
