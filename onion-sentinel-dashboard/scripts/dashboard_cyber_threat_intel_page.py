"""Pure Cyber Threat Intelligence workspace renderer and client assets."""
from __future__ import annotations

import html
from dataclasses import dataclass


@dataclass(frozen=True)
class CyberThreatIntelPageViewModel:
    urgent_local_signals: int
    repeated_local_signals: int
    model_label: str


CYBER_THREAT_INTEL_MARKUP = '''
    <section id="cti-workspace" class="view-section active cti-workspace" aria-label="Cyber Threat Intelligence program workspace">
      <div class="cti-hero">
        <div class="cti-hero-copy">
          <span class="cti-kicker">Threat-informed defense</span>
          <h2>Intelligence that changes a decision</h2>
          <p>Direct collection with requirements, assess evidence with explicit uncertainty, and turn validated intelligence into owned defensive action. Feed volume and indicator counts are not program outcomes.</p>
          <div class="cti-hero-meta">
            <span class="cti-maturity-pill">Program foundation</span>
            <span>Human review gates publication and blocking</span>
            <span id="cti-last-saved">Loading workspace…</span>
          </div>
        </div>
        <aside class="cti-doctrine-card" aria-label="CTI operating doctrine">
          <span>Operating doctrine</span>
          <strong>Requirement → evidence → assessment → action → feedback</strong>
          <p>Facts, assumptions, judgments, confidence, freshness, provenance, and action safety remain separate.</p>
          <div class="cti-hero-actions">
            <button type="button" class="cti-primary-button" data-cti-add="source">Add source</button>
            <button type="button" class="cti-secondary-button" data-cti-add="technology">Add technology</button>
          </div>
        </aside>
      </div>

      <div id="cti-page-status" class="cti-page-status" role="status" aria-live="polite">
        <span class="cti-status-dot" aria-hidden="true"></span>
        <span id="cti-page-status-text">Loading the CTI program workspace…</span>
        <a id="cti-admin-link" href="/admin/login" hidden>Sign in to edit</a>
      </div>

      <section class="cti-kpi-grid" aria-label="CTI program posture">
        <article><span>Active sources</span><strong id="cti-active-sources">—</strong><em>Governed source portfolio</em></article>
        <article><span>Monitored technologies</span><strong id="cti-active-technologies">—</strong><em>Enabled watchlist entries</em></article>
        <article><span>High-priority exposure</span><strong id="cti-high-priority">—</strong><em>Critical and high watch items</em></article>
        <article><span>Review gaps</span><strong id="cti-review-gaps">—</strong><em>Missing or overdue review dates</em></article>
        <article><span>Urgent local signals</span><strong>{urgent_local_signals}</strong><em>Open critical/high alert groups</em></article>
        <article><span>Repeated local signals</span><strong>{repeated_local_signals}</strong><em>Open groups repeated 5+ times</em></article>
      </section>

      <section class="cti-panel cti-lifecycle-panel" aria-labelledby="cti-lifecycle-title">
        <header class="cti-section-header">
          <div><span class="cti-kicker">Full lifecycle</span><h3 id="cti-lifecycle-title">Intelligence operating loop</h3></div>
          <p>Each stage must preserve the decision, provenance, uncertainty, owner, and feedback path.</p>
        </header>
        <div class="cti-lifecycle" role="list">
          <article role="listitem"><b>01</b><span>Direction</span><strong>Priority requirements</strong><small>Decision, sponsor, horizon, success</small></article>
          <article role="listitem"><b>02</b><span>Collection</span><strong>Purposeful sourcing</strong><small>Coverage, handling, cadence, gaps</small></article>
          <article role="listitem"><b>03</b><span>Processing</span><strong>Evidence integrity</strong><small>Normalize, dedupe, enrich, expire</small></article>
          <article role="listitem"><b>04</b><span>Analysis</span><strong>Defensible judgment</strong><small>Alternatives, confidence, local relevance</small></article>
          <article role="listitem"><b>05</b><span>Dissemination</span><strong>Owned action</strong><small>Audience, TLP, deadline, validation</small></article>
          <article role="listitem"><b>06</b><span>Feedback</span><strong>Measure change</strong><small>Outcome, source value, refine PIR</small></article>
        </div>
      </section>

      <div class="cti-program-grid">
        <section class="cti-panel" aria-labelledby="cti-direction-title">
          <header class="cti-section-header compact">
            <div><span class="cti-kicker">Direction</span><h3 id="cti-direction-title">Priority intelligence requirement templates</h3></div>
            <span class="cti-neutral-pill">Templates · not active PIRs</span>
          </header>
          <div class="cti-pir-list">
            <article><b>Vulnerability exposure</b><p>Which actively exploited vulnerabilities materially affect monitored technologies and require a patch, mitigation, detection, or accepted-risk decision?</p><span>Consumer: vulnerability + platform owners</span></article>
            <article><b>Adversary behavior</b><p>Which emerging behaviors are observable in Security Onion telemetry, and what detection or hunt should change as a result?</p><span>Consumer: SOC + detection engineering</span></article>
            <article><b>Campaign relevance</b><p>Which campaigns change defensive priorities in the next 30 days based on local assets, exposure, identity, and observed activity?</p><span>Consumer: security leadership + incident response</span></article>
          </div>
          <p class="cti-panel-note">A production PIR register should add sponsor, decision, priority, horizon, cadence, collection gaps, product, success criteria, and review date before these templates become active requirements.</p>
        </section>

        <section class="cti-panel" aria-labelledby="cti-action-title">
          <header class="cti-section-header compact">
            <div><span class="cti-kicker">Last mile</span><h3 id="cti-action-title">Defensive action contract</h3></div>
          </header>
          <div class="cti-action-modes" aria-label="Defensive action modes">
            <span>Block</span><span>Detect</span><span>Hunt</span><span>Enrich</span><span>Patch / mitigate</span><span>Emulate / test</span><span>Watch</span><span>Reject / expire</span>
          </div>
          <ol class="cti-action-checklist">
            <li><b>Evidence</b><span>Source, collection time, provenance, local sighting</span></li>
            <li><b>Assessment</b><span>Facts, assumptions, alternatives, confidence, impact</span></li>
            <li><b>Execution</b><span>Owner, priority, due date, telemetry, rollback, expiry</span></li>
            <li><b>Validation</b><span>Test result, defensive outcome, feedback to requirement</span></li>
          </ol>
          <div class="cti-agent-card"><span>CTI analyst route</span><strong>{model_label}</strong><em>Drafting and summarization only; analyst approval remains required.</em></div>
        </section>
      </div>

      <section class="cti-panel cti-table-panel" aria-labelledby="cti-sources-title">
        <header class="cti-section-header">
          <div><span class="cti-kicker">Collection governance</span><h3 id="cti-sources-title">CTI source portfolio</h3><p>Evaluate relevance, timeliness, reliability, unique yield, overlap, handling, and cost against intelligence requirements.</p></div>
          <div class="cti-table-actions"><label class="cti-search"><span>Search sources</span><input id="cti-source-search" type="search" placeholder="Name, type, owner, requirement"></label><button type="button" class="cti-primary-button" data-cti-add="source">Add source</button></div>
        </header>
        <div class="cti-table-wrap">
          <table class="cti-table cti-source-table">
            <thead><tr><th>Use</th><th>Source</th><th>Collection</th><th>Reliability</th><th>Handling</th><th>Requirements supported</th><th>Governance</th><th><span class="sr-only">Actions</span></th></tr></thead>
            <tbody id="cti-source-rows"><tr><td colspan="8" class="cti-loading-cell">Loading governed sources…</td></tr></tbody>
          </table>
        </div>
        <p class="cti-table-footnote">Credential values are never stored here. A credential reference names a secret held in Onion Sentinel's private environment or secret manager.</p>
      </section>

      <section class="cti-panel cti-table-panel" aria-labelledby="cti-technologies-title">
        <header class="cti-section-header">
          <div><span class="cti-kicker">Local relevance</span><h3 id="cti-technologies-title">Technology intelligence watchlist</h3><p>Track the products and platforms whose advisories, exploitation, dependencies, or behavior can change a local defensive decision.</p></div>
          <div class="cti-table-actions"><label class="cti-search"><span>Search technologies</span><input id="cti-technology-search" type="search" placeholder="Vendor, product, owner, keyword"></label><button type="button" class="cti-primary-button" data-cti-add="technology">Add technology</button></div>
        </header>
        <div class="cti-table-wrap">
          <table class="cti-table cti-technology-table">
            <thead><tr><th>Watch</th><th>Technology</th><th>Priority</th><th>Exposure</th><th>Monitor for</th><th>Requirements</th><th>Ownership / review</th><th><span class="sr-only">Actions</span></th></tr></thead>
            <tbody id="cti-technology-rows"><tr><td colspan="8" class="cti-loading-cell">Loading technology watchlist…</td></tr></tbody>
          </table>
        </div>
        <p class="cti-table-footnote">Watchlist entries express intelligence priority. The Software Inventory remains the evidence source for observed products, versions, and assets.</p>
      </section>

      <div class="cti-program-grid cti-quality-grid">
        <section class="cti-panel" aria-labelledby="cti-quality-title">
          <header class="cti-section-header compact"><div><span class="cti-kicker">Analytic standard</span><h3 id="cti-quality-title">Publication quality gates</h3></div></header>
          <div class="cti-quality-list">
            <span><b>Requirement</b>Named decision and consumer</span>
            <span><b>Evidence</b>Citations, provenance, time, handling</span>
            <span><b>Judgment</b>Confidence, assumptions, alternatives</span>
            <span><b>Relevance</b>Local exposure and sightings</span>
            <span><b>Action</b>Owner, deadline, safety, expiry</span>
            <span><b>Feedback</b>Validated outcome and source value</span>
          </div>
        </section>
        <section class="cti-panel" aria-labelledby="cti-metrics-title">
          <header class="cti-section-header compact"><div><span class="cti-kicker">Program value</span><h3 id="cti-metrics-title">Measure what intelligence changed</h3></div></header>
          <div class="cti-metric-list">
            <span>PIRs answered on time</span><span>Time to operationalize</span><span>Actions with owners</span><span>Expiration compliance</span><span>Detections, hunts, mitigations</span><span>Incidents discovered or scoped faster</span>
          </div>
          <p class="cti-panel-note">Do not use feed count, raw IOC volume, or report volume as headline measures of intelligence effectiveness.</p>
        </section>
      </div>

      <div id="cti-editor" class="cti-modal" hidden>
        <button class="cti-modal-backdrop" type="button" data-cti-close aria-label="Close editor"></button>
        <section class="cti-dialog" role="dialog" aria-modal="true" aria-labelledby="cti-editor-title">
          <header><div><span id="cti-editor-kicker" class="cti-kicker">Collection governance</span><h2 id="cti-editor-title">Add CTI source</h2><p id="cti-editor-description">Store governance metadata and a secret reference—never a credential value.</p></div><button type="button" class="cti-close-button" data-cti-close aria-label="Close editor">×</button></header>
          <form id="cti-editor-form">
            <input id="cti-edit-id" type="hidden">
            <div class="cti-form-banner"><label class="cti-enabled-control"><input id="cti-edit-enabled" type="checkbox" checked><span>Enabled for the CTI program</span></label><span id="cti-editor-status" role="status" aria-live="polite"></span></div>
            <div id="cti-source-fields" class="cti-form-grid">
              <label class="wide"><span>Source name</span><input id="cti-source-name" maxlength="120" required></label>
              <label><span>Source type</span><select id="cti-source-type"><option value="government">Government</option><option value="isac-csirt">ISAC / CSIRT</option><option value="vendor">Vendor</option><option value="commercial">Commercial</option><option value="osint">OSINT</option><option value="stix-taxii">STIX / TAXII</option><option value="internal-telemetry">Internal telemetry</option><option value="incident-response">Incident response</option></select></label>
              <label><span>Acquisition</span><select id="cti-source-acquisition"><option value="api">API</option><option value="rss">RSS</option><option value="taxii">TAXII</option><option value="email">Email</option><option value="web">Web</option><option value="manual">Manual</option><option value="internal">Internal</option></select></label>
              <label class="wide"><span>Endpoint / public URL</span><input id="cti-source-endpoint" type="url" maxlength="500" placeholder="https://example.org/feed (no credentials or query tokens)"></label>
              <label><span>Credential reference</span><input id="cti-source-secret" maxlength="80" pattern="[A-Z][A-Z0-9_]{{2,79}}" placeholder="CTI_VENDOR_API_KEY"></label>
              <label><span>Owner</span><input id="cti-source-owner" maxlength="100" required></label>
              <label><span>Cadence</span><select id="cti-source-cadence"><option value="realtime">Realtime</option><option value="hourly">Hourly</option><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option><option value="on-demand">On demand</option></select></label>
              <label><span>Source reliability</span><select id="cti-source-reliability"><option value="A">A · Completely reliable</option><option value="B">B · Usually reliable</option><option value="C">C · Fairly reliable</option><option value="D">D · Not usually reliable</option><option value="E">E · Unreliable</option><option value="F">F · Cannot be judged</option></select></label>
              <label><span>Handling</span><select id="cti-source-handling"><option value="TLP:CLEAR">TLP:CLEAR</option><option value="TLP:GREEN">TLP:GREEN</option><option value="TLP:AMBER">TLP:AMBER</option><option value="TLP:AMBER+STRICT">TLP:AMBER+STRICT</option><option value="TLP:RED">TLP:RED</option></select></label>
              <label><span>Portfolio disposition</span><select id="cti-source-disposition"><option value="retain">Retain</option><option value="reduce">Reduce</option><option value="replace">Replace</option><option value="remove">Remove</option></select></label>
              <label><span>Next review</span><input id="cti-source-review" type="date"></label>
              <label class="wide"><span>Requirements supported · comma separated</span><input id="cti-source-requirements" maxlength="1200"></label>
              <label class="wide"><span>Analyst notes</span><textarea id="cti-source-notes" maxlength="1200" rows="4"></textarea></label>
            </div>
            <div id="cti-technology-fields" class="cti-form-grid" hidden>
              <label><span>Vendor</span><input id="cti-tech-vendor" maxlength="100" required></label>
              <label><span>Product / component</span><input id="cti-tech-product" maxlength="120" required></label>
              <label><span>Category</span><select id="cti-tech-category"><option value="security-platform">Security platform</option><option value="operating-system">Operating system</option><option value="application">Application</option><option value="cloud-service">Cloud service</option><option value="network">Network</option><option value="development-tool">Development tool</option><option value="library">Library</option><option value="other">Other</option></select></label>
              <label><span>Versions / branch</span><input id="cti-tech-versions" maxlength="180"></label>
              <label class="wide"><span>Deployment scope</span><input id="cti-tech-scope" maxlength="240" placeholder="Assets, service, business unit, or environment"></label>
              <label><span>Business criticality</span><select id="cti-tech-criticality"><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
              <label><span>Intel priority</span><select id="cti-tech-priority"><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
              <label><span>Exposure</span><select id="cti-tech-exposure"><option value="internet-facing">Internet-facing</option><option value="internal">Internal</option><option value="endpoint">Endpoint</option><option value="server">Server</option><option value="cloud">Cloud</option><option value="mixed">Mixed</option><option value="unknown">Unknown</option></select></label>
              <label><span>Owner</span><input id="cti-tech-owner" maxlength="100" required></label>
              <label class="wide"><span>Monitor for · aliases, CPEs, keywords, dependencies</span><input id="cti-tech-monitor" maxlength="1800"></label>
              <label class="wide"><span>Requirements supported · comma separated</span><input id="cti-tech-requirements" maxlength="1200"></label>
              <label><span>Next review</span><input id="cti-tech-review" type="date"></label>
              <label class="wide"><span>Analyst notes</span><textarea id="cti-tech-notes" maxlength="1200" rows="4"></textarea></label>
            </div>
            <footer><button id="cti-delete-entry" type="button" class="cti-danger-button" hidden>Delete</button><span></span><button type="button" class="cti-secondary-button" data-cti-close>Cancel</button><button id="cti-save-entry" type="submit" class="cti-primary-button">Save source</button></footer>
          </form>
        </section>
      </div>
    </section>'''


def render_cyber_threat_intel_page(view: CyberThreatIntelPageViewModel) -> str:
    """Render the decision-led CTI program workspace."""
    return CYBER_THREAT_INTEL_MARKUP.format(
        urgent_local_signals=view.urgent_local_signals,
        repeated_local_signals=view.repeated_local_signals,
        model_label=html.escape(view.model_label),
    )


CYBER_THREAT_INTEL_CSS = '''
<style>
.cti-workspace{display:grid;gap:16px;padding-top:10px}.cti-workspace button,.cti-workspace input,.cti-workspace select,.cti-workspace textarea{font:inherit}.cti-hero{position:relative;display:grid;grid-template-columns:minmax(0,1.35fr) minmax(340px,.65fr);gap:18px;overflow:hidden;border:1px solid rgba(34,211,238,.2);border-radius:14px;padding:24px;background:radial-gradient(circle at 12% 0%,rgba(34,211,238,.12),transparent 38%),linear-gradient(135deg,#0d1a25,#09121b 72%);box-shadow:0 22px 54px rgba(0,0,0,.2),inset 0 1px 0 rgba(255,255,255,.035)}.cti-hero:after{content:'';position:absolute;right:-70px;bottom:-110px;width:280px;height:280px;border:1px solid rgba(34,211,238,.1);border-radius:50%;box-shadow:0 0 0 34px rgba(34,211,238,.025),0 0 0 68px rgba(34,211,238,.018);pointer-events:none}.cti-kicker{display:inline-block;color:#8ff4ff;font-size:10.5px;font-weight:950;text-transform:uppercase;letter-spacing:.14em}.cti-hero h2{margin:9px 0 8px;color:#f5f9ff;font-size:34px;line-height:1.02;letter-spacing:-.035em}.cti-hero-copy>p{max-width:78ch;margin:0;color:#a3b2c4;font-size:14px;line-height:1.62}.cti-hero-meta{display:flex;align-items:center;flex-wrap:wrap;gap:8px 15px;margin-top:17px;color:#8fa1b5;font-size:11.5px}.cti-maturity-pill,.cti-neutral-pill{display:inline-flex;align-items:center;border:1px solid rgba(34,211,238,.28);border-radius:999px;padding:5px 9px;color:#8ff4ff;background:rgba(34,211,238,.055);font-size:9.5px;font-weight:950;text-transform:uppercase;letter-spacing:.08em}.cti-doctrine-card{position:relative;z-index:1;align-self:stretch;border:1px solid rgba(148,163,184,.13);border-radius:11px;padding:16px;background:rgba(6,16,24,.74);box-shadow:inset 3px 0 0 rgba(34,211,238,.45)}.cti-doctrine-card>span{color:#8ff4ff;font-size:10px;font-weight:950;text-transform:uppercase;letter-spacing:.11em}.cti-doctrine-card>strong{display:block;margin-top:8px;color:#f1f7ff;font-size:15px;line-height:1.42}.cti-doctrine-card>p{margin:8px 0 0;color:#93a5b9;font-size:12px;line-height:1.5}.cti-hero-actions{display:flex;gap:8px;margin-top:16px}.cti-primary-button,.cti-secondary-button,.cti-danger-button,.cti-edit-button{min-height:38px;border-radius:8px;padding:8px 12px;font-size:11.5px;font-weight:900;cursor:pointer;transition:border-color .14s,color .14s,background .14s}.cti-primary-button{border:1px solid #67e8f9;color:#061018;background:#8ff4ff}.cti-primary-button:hover,.cti-primary-button:focus-visible{background:#c8fbff;outline:none}.cti-secondary-button,.cti-edit-button{border:1px solid rgba(34,211,238,.28);color:#aef7ff;background:rgba(34,211,238,.05)}.cti-secondary-button:hover,.cti-secondary-button:focus-visible,.cti-edit-button:hover,.cti-edit-button:focus-visible{border-color:#8ff4ff;color:#f4fdff;outline:none}.cti-danger-button{border:1px solid rgba(251,113,133,.46);color:#fb7185;background:rgba(251,113,133,.055)}.cti-danger-button:hover,.cti-danger-button:focus-visible{border-color:#fb7185;background:rgba(251,113,133,.12);outline:none}.cti-workspace button:disabled{cursor:wait;opacity:.58}.cti-page-status{display:flex;align-items:center;gap:9px;min-height:36px;border:1px solid rgba(148,163,184,.11);border-radius:9px;padding:8px 12px;color:#9eb0c3;background:#0b151f;font-size:11.5px}.cti-page-status.ok{border-color:rgba(74,222,128,.18)}.cti-page-status.error{border-color:rgba(251,113,133,.25);color:#ff8ca0}.cti-page-status.warning{border-color:rgba(246,199,109,.22);color:#f6c76d}.cti-status-dot{width:7px;height:7px;flex:0 0 7px;border-radius:50%;background:#22d3ee;box-shadow:0 0 11px rgba(34,211,238,.58)}.cti-page-status.ok .cti-status-dot{background:#4ade80}.cti-page-status.error .cti-status-dot{background:#fb7185}.cti-page-status.warning .cti-status-dot{background:#f6c76d}.cti-page-status a{margin-left:auto;color:#8ff4ff;font-weight:900;text-decoration:none}.cti-kpi-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:8px}.cti-kpi-grid article{min-width:0;border:1px solid rgba(148,163,184,.1);border-radius:9px;padding:12px;background:linear-gradient(180deg,#0d1721,#0a131c)}.cti-kpi-grid span{display:block;color:#93a5b9;font-size:9.5px;font-weight:950;text-transform:uppercase;letter-spacing:.08em}.cti-kpi-grid strong{display:block;margin-top:8px;color:#f7fbff;font-size:24px;line-height:1}.cti-kpi-grid em{display:block;margin-top:7px;color:#788b9f;font-size:10.5px;font-style:normal;line-height:1.3}.cti-panel{min-width:0;border:1px solid rgba(148,163,184,.11);border-radius:11px;padding:16px;background:linear-gradient(180deg,#0d1721,#0a131c);box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}.cti-section-header{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:14px}.cti-section-header.compact{align-items:flex-start}.cti-section-header h3{margin:6px 0 0;color:#f3f8ff;font-size:18px;line-height:1.2;letter-spacing:-.015em}.cti-section-header p{max-width:66ch;margin:5px 0 0;color:#90a2b6;font-size:11.5px;line-height:1.45}.cti-section-header>p{margin:0;text-align:right}.cti-lifecycle{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:7px}.cti-lifecycle article{position:relative;min-width:0;border:1px solid rgba(34,211,238,.1);border-radius:8px;padding:12px 11px;background:#08121b}.cti-lifecycle article:not(:last-child):after{content:'›';position:absolute;right:-7px;top:50%;z-index:2;display:grid;place-items:center;width:14px;height:20px;color:#4ddbea;background:#0b151f;font-size:16px;transform:translateY(-50%)}.cti-lifecycle b{color:#4ddbea;font:900 10px/1 ui-monospace,SFMono-Regular,Menlo,monospace}.cti-lifecycle span{display:block;margin-top:12px;color:#8ff4ff;font-size:9.5px;font-weight:950;text-transform:uppercase;letter-spacing:.08em}.cti-lifecycle strong{display:block;margin-top:5px;color:#edf5ff;font-size:12px;line-height:1.3}.cti-lifecycle small{display:block;margin-top:6px;color:#778b9f;font-size:10px;line-height:1.35}.cti-program-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(320px,.8fr);gap:10px}.cti-pir-list{display:grid;gap:7px}.cti-pir-list article{display:grid;grid-template-columns:180px minmax(0,1fr) 180px;gap:13px;align-items:start;border-top:1px solid rgba(148,163,184,.09);padding:10px 0}.cti-pir-list b{color:#f0f6ff;font-size:12px}.cti-pir-list p{margin:0;color:#aab8c8;font-size:11.5px;line-height:1.48}.cti-pir-list span{color:#7f92a6;font-size:10.5px;line-height:1.4}.cti-panel-note{margin:12px 0 0;border-left:2px solid rgba(246,199,109,.55);padding-left:10px;color:#a6b4c4;font-size:11px;line-height:1.5}.cti-action-modes{display:flex;flex-wrap:wrap;gap:6px}.cti-action-modes span,.cti-metric-list span{border:1px solid rgba(34,211,238,.14);border-radius:999px;padding:5px 8px;color:#a8eaf1;background:rgba(34,211,238,.035);font-size:9.5px;font-weight:850}.cti-action-checklist{display:grid;gap:0;margin:12px 0 0;padding:0;list-style:none}.cti-action-checklist li{display:grid;grid-template-columns:82px minmax(0,1fr);gap:10px;border-top:1px solid rgba(148,163,184,.09);padding:8px 0}.cti-action-checklist b{color:#8ff4ff;font-size:10px;text-transform:uppercase;letter-spacing:.06em}.cti-action-checklist span{color:#99aabd;font-size:11px;line-height:1.35}.cti-agent-card{margin-top:10px;border:1px solid rgba(34,211,238,.14);border-radius:8px;padding:10px;background:#07111a}.cti-agent-card span{color:#7f92a6;font-size:9.5px;font-weight:900;text-transform:uppercase;letter-spacing:.08em}.cti-agent-card strong{display:block;margin-top:5px;color:#eaf6ff;font-size:12px}.cti-agent-card em{display:block;margin-top:5px;color:#8396aa;font-size:10.5px;font-style:normal;line-height:1.4}.cti-table-panel{padding:0;overflow:hidden}.cti-table-panel .cti-section-header{align-items:flex-end;margin:0;padding:16px}.cti-table-actions{display:flex;align-items:flex-end;gap:8px}.cti-search{display:grid;gap:5px;color:#8ea1b6;font-size:9px;font-weight:900;text-transform:uppercase;letter-spacing:.08em}.cti-search input{width:250px;min-height:38px;border:1px solid rgba(34,211,238,.17);border-radius:8px;padding:8px 10px;color:#e7f3ff;background:#071018;outline:none;font-size:11.5px;text-transform:none;letter-spacing:0}.cti-search input:focus{border-color:#67e8f9;box-shadow:0 0 0 3px rgba(34,211,238,.08)}.cti-table-wrap{overflow:auto;border-top:1px solid rgba(148,163,184,.1);border-bottom:1px solid rgba(148,163,184,.09);box-shadow:inset -22px 0 20px -22px rgba(143,244,255,.32)}.cti-table{width:100%;min-width:1260px;border-collapse:collapse}.cti-table th{padding:9px 11px;color:#91a3b6;background:#101b26;font-size:9px;font-weight:950;text-align:left;text-transform:uppercase;letter-spacing:.08em;white-space:nowrap}.cti-table td{padding:11px;border-top:1px solid rgba(148,163,184,.08);color:#cbd8e6;font-size:11px;line-height:1.4;vertical-align:top}.cti-table tbody tr:hover{background:rgba(34,211,238,.025)}.cti-table td:first-child{width:58px}.cti-table td:last-child{width:68px;text-align:right}.cti-table strong{display:block;color:#f2f7fd;font-size:11.5px;line-height:1.32}.cti-table small{display:block;margin-top:4px;color:#8295a9;font-size:10px;line-height:1.35}.cti-table a{display:block;margin-top:4px;color:#8ff4ff;text-decoration:none;font-size:10px}.cti-table a:hover{text-decoration:underline}.cti-source-table td:nth-child(2){width:220px}.cti-source-table td:nth-child(3){width:140px}.cti-source-table td:nth-child(4),.cti-source-table td:nth-child(5){width:90px}.cti-source-table td:nth-child(6){min-width:260px}.cti-source-table td:nth-child(7){width:180px}.cti-technology-table td:nth-child(2){width:225px}.cti-technology-table td:nth-child(3),.cti-technology-table td:nth-child(4){width:105px}.cti-technology-table td:nth-child(5),.cti-technology-table td:nth-child(6){min-width:230px}.cti-technology-table td:nth-child(7){width:180px}.cti-table-pill{display:inline-flex;align-items:center;border:1px solid rgba(34,211,238,.18);border-radius:999px;padding:3px 7px;color:#8ff4ff;background:rgba(34,211,238,.035);font-size:9px;font-weight:950;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}.cti-table-pill.priority-critical{border-color:rgba(251,113,133,.46);color:#ff7890;background:rgba(251,113,133,.06)}.cti-table-pill.priority-high{border-color:rgba(246,199,109,.44);color:#f6c76d;background:rgba(246,199,109,.055)}.cti-table-pill.priority-low{border-color:rgba(148,163,184,.22);color:#9eafc1}.cti-table-pill.overdue{margin-top:5px;border-color:rgba(251,113,133,.42);color:#fb7185}.cti-inline-tags{display:flex;flex-wrap:wrap;gap:4px}.cti-inline-tags span{border:1px solid rgba(148,163,184,.12);border-radius:5px;padding:2px 5px;color:#a8b8c9;background:#0a141d;font-size:9.5px}.cti-loading-cell{padding:22px!important;color:#8397ab!important;text-align:center!important}.cti-table-footnote{margin:0;padding:10px 16px;color:#7f92a6;font-size:10.5px;line-height:1.4}.cti-switch{position:relative;display:inline-flex;width:34px;height:19px}.cti-switch input{position:absolute;opacity:0;pointer-events:none}.cti-switch span{position:absolute;inset:0;border:1px solid rgba(148,163,184,.28);border-radius:999px;background:#111c27;cursor:pointer}.cti-switch span:after{content:'';position:absolute;left:2px;top:2px;width:13px;height:13px;border-radius:50%;background:#8293a6;transition:transform .16s,background .16s}.cti-switch input:checked+span{border-color:rgba(74,222,128,.48);background:rgba(74,222,128,.12)}.cti-switch input:checked+span:after{background:#4ade80;transform:translateX(15px)}.cti-switch input:focus-visible+span{outline:2px solid #8ff4ff;outline-offset:2px}.cti-quality-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.cti-quality-list{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px}.cti-quality-list span{border:1px solid rgba(148,163,184,.1);border-radius:7px;padding:9px;color:#8497aa;background:#08121b;font-size:10px;line-height:1.35}.cti-quality-list b{display:block;margin-bottom:4px;color:#dce8f6;font-size:10.5px}.cti-metric-list{display:flex;flex-wrap:wrap;gap:6px}.cti-modal[hidden]{display:none}.cti-modal{position:fixed;inset:0;z-index:12000;display:grid;place-items:center;padding:18px}.cti-modal-backdrop{position:absolute;inset:0;width:100%;height:100%;border:0;background:rgba(1,7,12,.83);backdrop-filter:blur(5px);cursor:default}.cti-dialog{position:relative;display:grid;grid-template-rows:auto minmax(0,1fr);width:min(880px,100%);max-height:calc(100dvh - 36px);overflow:hidden;border:1px solid rgba(34,211,238,.34);border-radius:13px;background:#0a141e;box-shadow:0 30px 90px rgba(0,0,0,.62)}.cti-dialog>header{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;border-bottom:1px solid rgba(148,163,184,.1);padding:18px 20px}.cti-dialog h2{margin:6px 0 0;color:#f3f8ff;font-size:23px}.cti-dialog header p{margin:6px 0 0;color:#8da0b4;font-size:11.5px}.cti-close-button{display:grid;place-items:center;width:38px;height:38px;flex:0 0 38px;border:1px solid rgba(148,163,184,.2);border-radius:8px;color:#cbd8e6;background:#0d1822;font-size:24px;cursor:pointer}.cti-close-button:hover,.cti-close-button:focus-visible{border-color:#8ff4ff;color:#8ff4ff;outline:none}.cti-dialog form{overflow:auto;padding:16px 20px 20px}.cti-form-banner{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;border:1px solid rgba(148,163,184,.1);border-radius:8px;padding:9px 11px;background:#07111a}.cti-enabled-control{display:flex;align-items:center;gap:8px;color:#dbe7f3;font-size:11.5px;font-weight:800}.cti-enabled-control input{accent-color:#22d3ee}.cti-form-banner>span{color:#f6c76d;font-size:10.5px;text-align:right}.cti-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:11px}.cti-form-grid label{display:grid;gap:6px;min-width:0;color:#91a4b8;font-size:9.5px;font-weight:900;text-transform:uppercase;letter-spacing:.075em}.cti-form-grid label.wide{grid-column:1/-1}.cti-form-grid input,.cti-form-grid select,.cti-form-grid textarea{box-sizing:border-box;width:100%;min-width:0;border:1px solid rgba(34,211,238,.18);border-radius:8px;padding:10px 11px;color:#e4f0fc;background:#071018;outline:none;font-size:11.5px;line-height:1.35;text-transform:none;letter-spacing:0}.cti-form-grid textarea{resize:vertical}.cti-form-grid input:focus,.cti-form-grid select:focus,.cti-form-grid textarea:focus{border-color:#67e8f9;box-shadow:0 0 0 3px rgba(34,211,238,.08)}.cti-dialog footer{display:grid;grid-template-columns:auto 1fr auto auto;gap:8px;align-items:center;margin-top:16px;border-top:1px solid rgba(148,163,184,.1);padding-top:14px}body.cti-modal-open{overflow:hidden}@media(max-width:1280px){.cti-kpi-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.cti-lifecycle{grid-template-columns:repeat(3,minmax(0,1fr))}.cti-lifecycle article:nth-child(3):after{display:none}}@media(max-width:980px){.cti-hero,.cti-program-grid,.cti-quality-grid{grid-template-columns:1fr}.cti-lifecycle{grid-template-columns:repeat(2,minmax(0,1fr))}.cti-lifecycle article:nth-child(3):after{display:grid}.cti-lifecycle article:nth-child(even):after{display:none}.cti-section-header{align-items:flex-start}.cti-table-panel .cti-section-header{align-items:flex-start}.cti-pir-list article{grid-template-columns:150px minmax(0,1fr)}.cti-pir-list article span{grid-column:2}}@media(max-width:720px){.cti-workspace{gap:11px}.cti-hero{padding:17px}.cti-hero h2{font-size:28px}.cti-hero-actions,.cti-table-actions,.cti-section-header,.cti-table-panel .cti-section-header{display:grid;width:100%}.cti-kpi-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.cti-lifecycle{grid-template-columns:1fr}.cti-lifecycle article:after{display:none!important}.cti-pir-list article{grid-template-columns:1fr;gap:5px}.cti-pir-list article span{grid-column:auto}.cti-search input{width:100%}.cti-table-actions .cti-primary-button{width:100%}.cti-quality-list{grid-template-columns:repeat(2,minmax(0,1fr))}.cti-modal{padding:8px}.cti-dialog{max-height:calc(100dvh - 16px)}.cti-dialog>header,.cti-dialog form{padding:14px}.cti-form-grid{grid-template-columns:1fr}.cti-form-grid label.wide{grid-column:auto}.cti-dialog footer{grid-template-columns:1fr 1fr}.cti-dialog footer>span{display:none}.cti-dialog footer button{width:100%}}@media(max-width:460px){.cti-kpi-grid,.cti-quality-list{grid-template-columns:1fr}.cti-dialog footer{grid-template-columns:1fr}.cti-doctrine-card{padding:13px}}
</style>
'''


CYBER_THREAT_INTEL_JS = r'''
<script>
(() => {
  const root = document.querySelector('#cti-workspace');
  if (!root) return;
  const apiPath = '/api/cyber-threat-intel/program';
  const state = {program: null, authenticated: false, editorKind: '', previousFocus: null};
  const byId = id => document.getElementById(id);
  const statusBox = byId('cti-page-status');
  const statusText = byId('cti-page-status-text');
  const adminLink = byId('cti-admin-link');
  const modal = byId('cti-editor');
  const form = byId('cti-editor-form');
  const sourceFields = byId('cti-source-fields');
  const technologyFields = byId('cti-technology-fields');
  const editorStatus = byId('cti-editor-status');
  const saveButton = byId('cti-save-entry');
  const deleteButton = byId('cti-delete-entry');

  const setPageStatus = (message, tone = '') => {
    statusText.textContent = message;
    statusBox.classList.remove('ok', 'warning', 'error');
    if (tone) statusBox.classList.add(tone);
  };
  const labelize = value => String(value || '').replaceAll('-', ' ').replace(/\b\w/g, char => char.toUpperCase());
  const splitList = value => [...new Set(String(value || '').split(',').map(item => item.trim()).filter(Boolean))];
  const today = () => new Date().toISOString().slice(0, 10);
  const reviewNeedsAttention = entry => Boolean(entry.enabled && (!entry.review_date || entry.review_date < today()));
  const cloneProgram = () => JSON.parse(JSON.stringify(state.program));
  const node = (tag, className = '', text = '') => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== '') element.textContent = text;
    return element;
  };
  const addLine = (cell, primary, secondary = '') => {
    cell.append(node('strong', '', primary));
    if (secondary) cell.append(node('small', '', secondary));
    return cell;
  };
  const pill = (text, className = '') => node('span', `cti-table-pill ${className}`.trim(), text);
  const tagList = values => {
    const container = node('div', 'cti-inline-tags');
    (values || []).slice(0, 5).forEach(value => container.append(node('span', '', value)));
    if ((values || []).length > 5) container.append(node('span', '', `+${values.length - 5}`));
    return container;
  };
  const switchControl = (checked, label, onChange) => {
    const wrapper = node('label', 'cti-switch');
    const input = node('input');
    input.type = 'checkbox';
    input.checked = Boolean(checked);
    input.setAttribute('aria-label', label);
    input.addEventListener('change', async () => {
      input.disabled = true;
      try { await onChange(input.checked); }
      catch (_) { input.checked = !input.checked; }
      finally { input.disabled = false; }
    });
    wrapper.append(input, node('span'));
    return wrapper;
  };
  const editButton = (kind, id, label) => {
    const button = node('button', 'cti-edit-button', 'Edit');
    button.type = 'button';
    button.setAttribute('aria-label', `Edit ${label}`);
    button.addEventListener('click', () => requireAdmin(() => openEditor(kind, id)));
    return button;
  };
  const emptyRow = (tbody, columns, text) => {
    tbody.replaceChildren();
    const row = node('tr');
    const cell = node('td', 'cti-loading-cell', text);
    cell.colSpan = columns;
    row.append(cell);
    tbody.append(row);
  };

  const renderSources = () => {
    const tbody = byId('cti-source-rows');
    tbody.replaceChildren();
    const sources = state.program?.sources || [];
    if (!sources.length) { emptyRow(tbody, 8, 'No CTI sources are configured.'); return; }
    sources.forEach(source => {
      const row = node('tr');
      row.dataset.searchText = [source.name, source.source_type, source.acquisition, source.owner, ...(source.requirements || [])].join(' ').toLowerCase();
      const useCell = node('td');
      useCell.append(switchControl(source.enabled, `${source.enabled ? 'Disable' : 'Enable'} ${source.name}`, enabled => toggleEntry('source', source.id, enabled)));
      const sourceCell = addLine(node('td'), source.name, `${labelize(source.source_type)} · ${source.disposition.toUpperCase()}`);
      if (source.endpoint) {
        const link = node('a', '', 'Open source');
        link.href = source.endpoint;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        sourceCell.append(link);
      }
      const collectionCell = addLine(node('td'), labelize(source.acquisition), labelize(source.cadence));
      if (source.credential_reference) collectionCell.append(node('small', '', `Secret ref: ${source.credential_reference}`));
      const reliabilityCell = node('td'); reliabilityCell.append(pill(source.reliability));
      const handlingCell = node('td'); handlingCell.append(pill(source.handling));
      const requirementCell = node('td'); requirementCell.append(tagList(source.requirements));
      const reviewLabel = source.review_date ? `Review ${source.review_date}` : 'Review date missing';
      const governanceCell = addLine(node('td'), source.owner, reviewLabel);
      if (reviewNeedsAttention(source)) governanceCell.append(pill('Review gap', 'overdue'));
      const actionCell = node('td'); actionCell.append(editButton('source', source.id, source.name));
      row.append(useCell, sourceCell, collectionCell, reliabilityCell, handlingCell, requirementCell, governanceCell, actionCell);
      tbody.append(row);
    });
    filterRows('source');
  };

  const renderTechnologies = () => {
    const tbody = byId('cti-technology-rows');
    tbody.replaceChildren();
    const technologies = state.program?.technologies || [];
    if (!technologies.length) { emptyRow(tbody, 8, 'No technologies are on the intelligence watchlist.'); return; }
    technologies.forEach(technology => {
      const row = node('tr');
      row.dataset.searchText = [technology.vendor, technology.product, technology.category, technology.owner, ...(technology.monitor_for || []), ...(technology.requirements || [])].join(' ').toLowerCase();
      const watchCell = node('td');
      watchCell.append(switchControl(technology.enabled, `${technology.enabled ? 'Disable' : 'Enable'} ${technology.vendor} ${technology.product}`, enabled => toggleEntry('technology', technology.id, enabled)));
      const technologyCell = addLine(node('td'), `${technology.vendor} · ${technology.product}`, `${technology.versions || 'Versions not set'} · ${labelize(technology.category)}`);
      const priorityCell = node('td'); priorityCell.append(pill(technology.priority, `priority-${technology.priority}`)); priorityCell.append(node('small', '', `${labelize(technology.criticality)} business criticality`));
      const exposureCell = addLine(node('td'), labelize(technology.exposure), technology.deployment_scope || 'Scope not recorded');
      const monitorCell = node('td'); monitorCell.append(tagList(technology.monitor_for));
      const requirementCell = node('td'); requirementCell.append(tagList(technology.requirements));
      const reviewLabel = technology.review_date ? `Review ${technology.review_date}` : 'Review date missing';
      const governanceCell = addLine(node('td'), technology.owner, reviewLabel);
      if (reviewNeedsAttention(technology)) governanceCell.append(pill('Review gap', 'overdue'));
      const actionCell = node('td'); actionCell.append(editButton('technology', technology.id, `${technology.vendor} ${technology.product}`));
      row.append(watchCell, technologyCell, priorityCell, exposureCell, monitorCell, requirementCell, governanceCell, actionCell);
      tbody.append(row);
    });
    filterRows('technology');
  };

  const renderMetrics = () => {
    const sources = state.program?.sources || [];
    const technologies = state.program?.technologies || [];
    byId('cti-active-sources').textContent = String(sources.filter(item => item.enabled).length);
    byId('cti-active-technologies').textContent = String(technologies.filter(item => item.enabled).length);
    byId('cti-high-priority').textContent = String(technologies.filter(item => item.enabled && ['critical', 'high'].includes(item.priority)).length);
    byId('cti-review-gaps').textContent = String([...sources, ...technologies].filter(reviewNeedsAttention).length);
    byId('cti-last-saved').textContent = state.program?.updated_at ? `Saved ${state.program.updated_at}` : 'Defaults loaded · not yet saved';
  };
  const renderWorkspace = () => { renderMetrics(); renderSources(); renderTechnologies(); };
  const filterRows = kind => {
    const input = byId(kind === 'source' ? 'cti-source-search' : 'cti-technology-search');
    const tbody = byId(kind === 'source' ? 'cti-source-rows' : 'cti-technology-rows');
    const query = String(input?.value || '').trim().toLowerCase();
    [...tbody.querySelectorAll('tr[data-search-text]')].forEach(row => { row.hidden = Boolean(query && !row.dataset.searchText.includes(query)); });
  };

  const loadSession = async () => {
    try {
      const response = await fetch('/api/admin/session-status', {cache: 'no-store', credentials: 'same-origin'});
      const data = await response.json();
      state.authenticated = Boolean(response.ok && data.authenticated);
    } catch (_) { state.authenticated = false; }
    adminLink.hidden = state.authenticated;
  };
  const loadWorkspace = async () => {
    const response = await fetch(apiPath, {cache: 'no-store', credentials: 'same-origin'});
    let data = {};
    try { data = await response.json(); } catch (_) {}
    if (!response.ok || !data.ok || !data.program) throw new Error(data.error || `Workspace load failed with HTTP ${response.status}`);
    state.program = data.program;
    renderWorkspace();
  };
  const initialize = async () => {
    try {
      await Promise.all([loadSession(), loadWorkspace()]);
      if (state.authenticated) setPageStatus('Workspace loaded. Administration is verified for editing.', 'ok');
      else setPageStatus('Workspace loaded read-only. Sign in to Administration to add, edit, remove, or toggle entries.', 'warning');
    } catch (error) {
      setPageStatus(error.message || 'Could not load the CTI workspace.', 'error');
      emptyRow(byId('cti-source-rows'), 8, 'CTI source data is unavailable.');
      emptyRow(byId('cti-technology-rows'), 8, 'Technology watchlist data is unavailable.');
    }
  };
  const requireAdmin = action => {
    if (state.authenticated) return action();
    setPageStatus('Administration sign-in is required before changing CTI program governance.', 'warning');
    adminLink.hidden = false;
    adminLink.focus();
    return Promise.reject(new Error('Administration sign-in is required.'));
  };

  const persist = async (nextProgram, successMessage) => {
    const response = await fetch(apiPath, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-Onion-Sentinel-Request': 'dashboard'},
      body: JSON.stringify({expected_revision: state.program.revision, sources: nextProgram.sources, technologies: nextProgram.technologies}),
    });
    let data = {};
    try { data = await response.json(); } catch (_) {}
    if (!response.ok || !data.ok || !data.program) {
      if (response.status === 403 && data.authentication_required) { state.authenticated = false; adminLink.hidden = false; }
      if (response.status === 409) {
        await loadWorkspace();
        throw new Error(`${data.error || 'The workspace changed.'} The latest revision has been loaded.`);
      }
      throw new Error(data.error || `Save failed with HTTP ${response.status}`);
    }
    state.program = data.program;
    renderWorkspace();
    setPageStatus(successMessage, 'ok');
  };
  const toggleEntry = (kind, id, enabled) => requireAdmin(async () => {
    const next = cloneProgram();
    const list = kind === 'source' ? next.sources : next.technologies;
    const entry = list.find(item => item.id === id);
    if (!entry) return;
    entry.enabled = enabled;
    try { await persist(next, `${kind === 'source' ? 'Source' : 'Technology'} ${enabled ? 'enabled' : 'paused'}.`); }
    catch (error) { renderWorkspace(); setPageStatus(error.message || 'Could not save the change.', 'error'); throw error; }
  });

  const setGroupEnabled = (group, enabled) => {
    group.hidden = !enabled;
    group.querySelectorAll('input,select,textarea').forEach(control => { control.disabled = !enabled; });
  };
  const value = (id, nextValue = undefined) => {
    const control = byId(id);
    if (nextValue !== undefined) control.value = nextValue ?? '';
    return control.value;
  };
  const setEditorStatus = message => { editorStatus.textContent = message || ''; };
  const defaultSource = () => ({id: '', enabled: true, name: '', source_type: 'vendor', acquisition: 'web', endpoint: '', credential_reference: '', owner: 'CTI Program', cadence: 'daily', reliability: 'B', handling: 'TLP:CLEAR', requirements: [], review_date: '', disposition: 'retain', notes: ''});
  const defaultTechnology = () => ({id: '', enabled: true, vendor: '', product: '', category: 'application', versions: '', deployment_scope: '', criticality: 'medium', priority: 'medium', exposure: 'unknown', owner: 'CTI Program', monitor_for: [], requirements: [], review_date: '', notes: ''});
  const openEditor = (kind, id = '') => {
    if (!state.program) return;
    state.editorKind = kind;
    state.previousFocus = document.activeElement;
    const isSource = kind === 'source';
    const list = isSource ? state.program.sources : state.program.technologies;
    const existing = list.find(item => item.id === id);
    const entry = JSON.parse(JSON.stringify(existing || (isSource ? defaultSource() : defaultTechnology())));
    byId('cti-edit-id').value = entry.id || '';
    byId('cti-edit-enabled').checked = entry.enabled !== false;
    byId('cti-editor-kicker').textContent = isSource ? 'Collection governance' : 'Local relevance';
    byId('cti-editor-title').textContent = `${existing ? 'Edit' : 'Add'} ${isSource ? 'CTI source' : 'monitored technology'}`;
    byId('cti-editor-description').textContent = isSource ? 'Store governance metadata and a secret reference—never a credential value.' : 'Define what to monitor and why; observed software remains in Software Inventory.';
    saveButton.textContent = `Save ${isSource ? 'source' : 'technology'}`;
    deleteButton.hidden = !existing;
    setGroupEnabled(sourceFields, isSource);
    setGroupEnabled(technologyFields, !isSource);
    if (isSource) {
      value('cti-source-name', entry.name); value('cti-source-type', entry.source_type); value('cti-source-acquisition', entry.acquisition); value('cti-source-endpoint', entry.endpoint); value('cti-source-secret', entry.credential_reference); value('cti-source-owner', entry.owner); value('cti-source-cadence', entry.cadence); value('cti-source-reliability', entry.reliability); value('cti-source-handling', entry.handling); value('cti-source-disposition', entry.disposition); value('cti-source-review', entry.review_date); value('cti-source-requirements', (entry.requirements || []).join(', ')); value('cti-source-notes', entry.notes);
    } else {
      value('cti-tech-vendor', entry.vendor); value('cti-tech-product', entry.product); value('cti-tech-category', entry.category); value('cti-tech-versions', entry.versions); value('cti-tech-scope', entry.deployment_scope); value('cti-tech-criticality', entry.criticality); value('cti-tech-priority', entry.priority); value('cti-tech-exposure', entry.exposure); value('cti-tech-owner', entry.owner); value('cti-tech-monitor', (entry.monitor_for || []).join(', ')); value('cti-tech-requirements', (entry.requirements || []).join(', ')); value('cti-tech-review', entry.review_date); value('cti-tech-notes', entry.notes);
    }
    setEditorStatus('');
    modal.hidden = false;
    document.body.classList.add('cti-modal-open');
    window.setTimeout(() => (isSource ? byId('cti-source-name') : byId('cti-tech-vendor')).focus(), 0);
  };
  const closeEditor = () => {
    modal.hidden = true;
    document.body.classList.remove('cti-modal-open');
    setEditorStatus('');
    if (state.previousFocus?.focus) state.previousFocus.focus();
  };
  const entryFromForm = () => {
    const id = value('cti-edit-id');
    const enabled = byId('cti-edit-enabled').checked;
    if (state.editorKind === 'source') return {id, enabled, name: value('cti-source-name'), source_type: value('cti-source-type'), acquisition: value('cti-source-acquisition'), endpoint: value('cti-source-endpoint'), credential_reference: value('cti-source-secret'), owner: value('cti-source-owner'), cadence: value('cti-source-cadence'), reliability: value('cti-source-reliability'), handling: value('cti-source-handling'), requirements: splitList(value('cti-source-requirements')), review_date: value('cti-source-review'), disposition: value('cti-source-disposition'), notes: value('cti-source-notes')};
    return {id, enabled, vendor: value('cti-tech-vendor'), product: value('cti-tech-product'), category: value('cti-tech-category'), versions: value('cti-tech-versions'), deployment_scope: value('cti-tech-scope'), criticality: value('cti-tech-criticality'), priority: value('cti-tech-priority'), exposure: value('cti-tech-exposure'), owner: value('cti-tech-owner'), monitor_for: splitList(value('cti-tech-monitor')), requirements: splitList(value('cti-tech-requirements')), review_date: value('cti-tech-review'), notes: value('cti-tech-notes')};
  };

  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!state.authenticated || !state.program) { setEditorStatus('Administration sign-in is required.'); return; }
    const next = cloneProgram();
    const kind = state.editorKind;
    const list = kind === 'source' ? next.sources : next.technologies;
    const entry = entryFromForm();
    const index = list.findIndex(item => item.id === entry.id && entry.id);
    if (index >= 0) list[index] = entry; else list.push(entry);
    saveButton.disabled = true;
    setEditorStatus('Saving…');
    try { await persist(next, `${kind === 'source' ? 'CTI source' : 'Technology watchlist entry'} saved.`); closeEditor(); }
    catch (error) { setEditorStatus(error.message || 'Could not save this entry.'); setPageStatus(error.message || 'Could not save this entry.', 'error'); }
    finally { saveButton.disabled = false; }
  });
  deleteButton.addEventListener('click', async () => {
    const id = value('cti-edit-id');
    if (!id || !state.authenticated) return;
    const label = state.editorKind === 'source' ? value('cti-source-name') : `${value('cti-tech-vendor')} ${value('cti-tech-product')}`.trim();
    if (!window.confirm(`Remove ${label} from the CTI program? This does not delete any source system or software inventory data.`)) return;
    const next = cloneProgram();
    const key = state.editorKind === 'source' ? 'sources' : 'technologies';
    next[key] = next[key].filter(item => item.id !== id);
    deleteButton.disabled = true;
    try { await persist(next, `${state.editorKind === 'source' ? 'CTI source' : 'Technology watchlist entry'} removed.`); closeEditor(); }
    catch (error) { setEditorStatus(error.message || 'Could not remove this entry.'); setPageStatus(error.message || 'Could not remove this entry.', 'error'); }
    finally { deleteButton.disabled = false; }
  });

  root.querySelectorAll('[data-cti-add]').forEach(button => button.addEventListener('click', () => requireAdmin(() => openEditor(button.dataset.ctiAdd)).catch(() => {})));
  root.querySelectorAll('[data-cti-close]').forEach(button => button.addEventListener('click', closeEditor));
  byId('cti-source-search').addEventListener('input', () => filterRows('source'));
  byId('cti-technology-search').addEventListener('input', () => filterRows('technology'));
  document.addEventListener('keydown', event => { if (event.key === 'Escape' && !modal.hidden) closeEditor(); });
  initialize();
})();
</script>
'''


def inject_cyber_threat_intel_assets(text: str) -> str:
    if CYBER_THREAT_INTEL_CSS not in text:
        text = text.replace('</head>', CYBER_THREAT_INTEL_CSS + '</head>', 1)
    if CYBER_THREAT_INTEL_JS not in text:
        text = text.replace('</body>', CYBER_THREAT_INTEL_JS + '</body>', 1)
    return text
