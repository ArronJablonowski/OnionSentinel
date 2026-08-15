"""Truth-preserving Software Inventory page renderer."""
from __future__ import annotations


SOFTWARE_INVENTORY_PAGE_SECTION = r'''
    <section id="software-inventory-view" class="view-section active software-view" aria-label="Software inventory">
      <section class="software-coverage-hero" aria-labelledby="software-coverage-title">
        <div class="software-coverage-copy">
          <span class="software-eyebrow">Inventory coverage</span>
          <h2 id="software-coverage-title">Distinguish endpoint-reported, observed, and inferred evidence</h2>
          <p>Successful endpoint query results can support time-bounded installed-software claims. Network metadata only proves that software presented itself on monitored traffic, while fingerprints remain hypotheses.</p>
        </div>
        <div class="software-coverage-cards" aria-label="Software inventory coverage">
          <article><span>Authoritative denominator</span><strong id="software-denominator">Unknown</strong></article>
          <article><span>Endpoint + Osquery ready</span><strong id="software-osquery-ready-total">Unknown</strong></article>
          <article><span>Fresh endpoint inventories</span><strong id="software-fresh-endpoint-total">0</strong></article>
          <article><span>Network-observed assets</span><strong id="software-network-observed-total">0</strong></article>
          <article><span>Coverage gaps</span><strong id="software-coverage-gap-total">Unknown</strong></article>
        </div>
        <p id="software-coverage-note" class="software-coverage-note" role="status" aria-live="polite">Coverage percentage cannot be calculated without an authoritative LAN denominator.</p>
      </section>

      <section class="software-provenance" aria-label="Evidence provenance and confidence">
        <article>
          <span class="software-tier software-tier-authoritative_endpoint">Endpoint-reported</span>
          <strong>High-confidence installed evidence</strong>
          <span id="software-installed-total" class="software-provenance-count">0 record(s)</span>
          <p>An indexed OSQuery Apps result reports that the endpoint listed this package at observation time. It does not prove a complete endpoint inventory or a current installation.</p>
        </article>
        <article>
          <span class="software-tier software-tier-observed_network">Observed network</span>
          <strong>Medium-confidence observation</strong>
          <span id="software-observed-total" class="software-provenance-count">0 record(s)</span>
          <p>Protocol metadata shows a product or version presenting itself on monitored traffic; it does not prove a current installation.</p>
        </article>
        <article>
          <span class="software-tier software-tier-inferred">Inferred</span>
          <strong>Low or unknown confidence</strong>
          <span id="software-inferred-total" class="software-provenance-count">0 record(s)</span>
          <p>User agents, TLS fingerprints, services, and related clues are hypotheses and never count as installed-software truth.</p>
        </article>
      </section>

      <section class="software-freshness-summary" aria-labelledby="software-freshness-title">
        <div>
          <span class="software-eyebrow">Evidence freshness</span>
          <h2 id="software-freshness-title">Age of the visible evidence</h2>
        </div>
        <div class="software-freshness-cards">
          <article><span>Current</span><strong id="software-current-total">0</strong><small>Seen within 24 hours</small></article>
          <article><span>Recent</span><strong id="software-recent-total">0</strong><small>Seen within 7 days</small></article>
          <article><span>Historical</span><strong id="software-historical-total">0</strong><small>Passive evidence within 30 days</small></article>
          <article><span>Expired</span><strong id="software-expired-total">0</strong><small>Outside its trusted freshness window</small></article>
          <article><span>Conflicting</span><strong id="software-conflicting-total">0</strong><small>Simultaneous version disagreement</small></article>
        </div>
      </section>

      <div id="software-collection-status" class="software-collection-status" role="status" aria-live="polite">Loading collection completeness…</div>
      <ul id="software-warning-list" class="software-warning-list" aria-label="Software inventory warnings" hidden></ul>

      <div class="software-toolbar" aria-label="Software inventory filters">
        <label class="software-search-label">Search
          <input id="software-search" type="search" autocomplete="off" placeholder="Software, version, publisher, or asset">
        </label>
        <label>Evidence
          <select id="software-tier-filter">
            <option value="all">All evidence</option>
            <option value="installed">Endpoint-reported</option>
            <option value="observed">Observed network</option>
            <option value="inferred">Inferred</option>
          </select>
        </label>
        <label>Confidence
          <select id="software-confidence-filter">
            <option value="all">All confidence</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </label>
        <label>Freshness
          <select id="software-freshness-filter">
            <option value="all">All freshness</option>
            <option value="current">Current</option>
            <option value="recent">Recent</option>
            <option value="historical">Historical</option>
            <option value="expired">Expired</option>
          </select>
        </label>
        <label>Platform
          <select id="software-platform-filter">
            <option value="all">All platforms</option>
          </select>
        </label>
        <label>Window
          <select id="software-window-filter">
            <option value="24h" selected>Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
          </select>
        </label>
        <label>Sort
          <select id="software-sort">
            <option value="last_seen" selected>Last seen</option>
            <option value="first_seen">First seen</option>
            <option value="product">Software</option>
            <option value="asset">Asset</option>
            <option value="tier">Evidence tier</option>
            <option value="confidence">Confidence</option>
          </select>
        </label>
        <label>Direction
          <select id="software-direction">
            <option value="desc" selected>Descending</option>
            <option value="asc">Ascending</option>
          </select>
        </label>
        <label>Rows
          <select id="software-page-size">
            <option value="50">50</option>
            <option value="100" selected>100</option>
            <option value="250">250</option>
          </select>
        </label>
        <div class="software-toolbar-actions">
          <button id="software-clear-filters" type="button">Clear filters</button>
          <button id="software-retry" type="button">Retry</button>
        </div>
      </div>

      <div id="software-inventory-status" class="software-status" role="status" aria-live="polite">Loading software evidence…</div>
      <div id="software-inventory-error" class="ir-error" role="alert" hidden></div>

      <div class="software-table-wrap">
        <table class="software-table">
          <thead><tr>
            <th>Asset / host</th><th>Software</th><th>Version</th><th>Evidence tier</th>
            <th>Source / evidence</th><th>Confidence</th><th>Freshness</th>
            <th>First seen</th><th>Last seen</th><th>Collection</th>
          </tr></thead>
          <tbody id="software-table-body"><tr><td colspan="10" class="ir-loading">Loading software evidence…</td></tr></tbody>
        </table>
      </div>
      <div id="software-mobile-list" class="software-mobile-list" aria-label="Software evidence"></div>
      <div class="software-pagination" aria-label="Software inventory pages">
        <button id="software-page-previous" type="button">Previous</button>
        <span id="software-page-summary">Page 1</span>
        <button id="software-page-next" type="button">Next</button>
      </div>
    </section>
    <style>
      .software-view{display:block;min-width:0;padding:0 0 28px}.software-coverage-hero{display:grid;gap:18px;margin-bottom:16px;padding:22px;border:1px solid #184352;border-radius:12px;background:linear-gradient(135deg,#0d1b26,#0a151f);box-shadow:inset 0 1px 0 rgba(255,255,255,.025);overflow:hidden}.software-coverage-copy{max-width:900px}.software-eyebrow{display:block;margin-bottom:6px;color:#75efff;font-size:.72rem;font-weight:950;letter-spacing:.12em;text-transform:uppercase}.software-coverage-copy h2,.software-freshness-summary h2{margin:0;color:#eef5ff;font-size:1.4rem}.software-coverage-copy p{max-width:940px;margin:8px 0 0;color:#9caec2;line-height:1.55}.software-coverage-cards{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}.software-coverage-cards article{min-height:94px;padding:15px 16px;border:1px solid #223341;border-radius:9px;background:#0b1721}.software-coverage-cards span{display:block;color:#9caec2;font-size:.7rem;font-weight:850;text-transform:uppercase}.software-coverage-cards strong{display:block;margin-top:8px;color:#75efff;font-size:1.45rem;overflow-wrap:anywhere}.software-coverage-note{margin:0;padding:11px 13px;border-left:3px solid #ffca67;color:#f5d58b;background:rgba(255,202,103,.06);font-size:.8rem;line-height:1.45}.software-provenance{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:16px}.software-provenance article{padding:14px 15px;border:1px solid #223341;border-radius:9px;background:#0b1721}.software-provenance strong{display:block;margin-top:9px;color:#eef5ff;font-size:.86rem}.software-provenance .software-provenance-count{display:block;margin-top:7px;color:#75efff;font-size:.78rem;font-weight:900}.software-provenance p{margin:5px 0 0;color:#8fa2b8;font-size:.76rem;line-height:1.45}.software-freshness-summary{display:grid;gap:13px;margin-bottom:16px;padding:18px;border:1px solid #223341;border-radius:10px;background:#0a151f}.software-freshness-summary h2{font-size:1.08rem}.software-freshness-cards{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}.software-freshness-cards article{padding:12px 14px;border:1px solid #223341;border-radius:8px;background:#0b1721}.software-freshness-cards span,.software-freshness-cards small{display:block;color:#8fa2b8;font-size:.68rem}.software-freshness-cards span{font-weight:900;text-transform:uppercase}.software-freshness-cards strong{display:block;margin:5px 0;color:#75efff;font-size:1.2rem}.software-tier,.software-confidence,.software-freshness{display:inline-block;padding:3px 7px;border:1px solid currentColor;border-radius:999px;font-size:.62rem;font-weight:950;text-transform:uppercase;white-space:nowrap}.software-tier-authoritative_endpoint,.software-confidence-high,.software-freshness-current{color:#69e89a}.software-tier-observed_network,.software-confidence-medium,.software-freshness-recent{color:#75efff}.software-tier-inferred,.software-confidence-low,.software-freshness-historical{color:#ffca67}.software-confidence-unknown,.software-freshness-expired,.software-freshness-stale,.software-tier-unknown{color:#9caec2}.software-collection-status{margin-bottom:10px;padding:10px 12px;border:1px solid #223341;border-radius:8px;color:#a9bbce;background:#0a151f;font-size:.78rem}.software-collection-status[data-state="partial"],.software-collection-status[data-state="stale"]{border-color:#755d27;color:#f5d58b;background:#211b10}.software-collection-status[data-state="failed"]{border-color:#7f3345;color:#ffb8c3;background:#25131a}.software-warning-list{display:grid;gap:5px;margin:0 0 12px;padding:11px 14px 11px 32px;border:1px solid #755d27;border-radius:8px;color:#f5d58b;background:#211b10;font-size:.78rem;line-height:1.4}.software-toolbar{display:grid;grid-template-columns:minmax(260px,1fr) repeat(4,minmax(132px,170px));gap:10px;align-items:end;margin-bottom:12px}.software-toolbar label{min-width:0;color:#9caec2;font-size:.7rem;font-weight:850;text-transform:uppercase}.software-toolbar input,.software-toolbar select{display:block;width:100%;min-height:44px;margin-top:5px;padding:0 11px;color:#e9f2ff;background:#0b1620;border:1px solid #07566a;border-radius:8px;font:inherit}.software-toolbar input:focus,.software-toolbar select:focus{outline:2px solid rgba(117,239,255,.35);outline-offset:1px}.software-search-label{grid-column:span 2}.software-toolbar-actions{display:flex;gap:8px;align-items:end}.software-toolbar-actions button,.software-pagination button{min-height:44px;padding:0 13px;border:1px solid #07566a;border-radius:8px;color:#e9f2ff;background:#0b1620;font-weight:850;cursor:pointer}.software-toolbar-actions button:hover,.software-toolbar-actions button:focus-visible,.software-pagination button:hover:not(:disabled),.software-pagination button:focus-visible{border-color:#35d9ec;color:#75efff}.software-toolbar-actions button:disabled,.software-pagination button:disabled{opacity:.45;cursor:not-allowed}.software-status{margin:0 0 12px;color:#8fa2b8;font-size:.8rem;line-height:1.45}.software-table-wrap{overflow-x:auto;border:1px solid #223341;border-radius:8px;background:#09131d}.software-table{width:100%;min-width:1480px;border-collapse:collapse;table-layout:fixed}.software-table th,.software-table td{box-sizing:border-box;padding:10px;text-align:left;vertical-align:top;border-bottom:1px solid #1e303d}.software-table th{color:#9caec2;background:#101e2a;font-size:.7rem;text-transform:uppercase}.software-table th:nth-child(1){width:175px}.software-table th:nth-child(2){width:190px}.software-table th:nth-child(3){width:125px}.software-table th:nth-child(4){width:140px}.software-table th:nth-child(5){width:205px}.software-table th:nth-child(6){width:105px}.software-table th:nth-child(7){width:105px}.software-table th:nth-child(8){width:150px}.software-table th:nth-child(9){width:150px}.software-table th:nth-child(10){width:135px}.software-table tbody tr:hover td{background:#0e202b}.software-name{display:block;color:#eef5ff;font-weight:900;overflow-wrap:anywhere}.software-muted{display:block;margin-top:4px;color:#8397ab;font-size:.72rem;line-height:1.4;overflow-wrap:anywhere}.software-code{display:block;color:#d8e7f8;font:700 12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere;white-space:normal}.software-asset-link{color:#75efff;text-decoration:none}.software-asset-link:hover,.software-asset-link:focus-visible{text-decoration:underline}.software-evidence-details{margin-top:8px;border-top:1px solid #1e303d}.software-evidence-details>summary{min-height:44px;display:flex;align-items:center;color:#75efff;font-size:.72rem;font-weight:850;cursor:pointer;list-style:none}.software-evidence-details>summary::-webkit-details-marker{display:none}.software-evidence-details>summary:before{content:"›";display:inline-block;margin-right:7px;font-size:18px;transition:transform .16s ease}.software-evidence-details[open]>summary:before{transform:rotate(90deg)}.software-evidence-grid{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:5px 9px;margin:0;padding:0 0 7px;font-size:.7rem}.software-evidence-grid dt{color:#8397ab;font-weight:850}.software-evidence-grid dd{min-width:0;margin:0;color:#c8d6e6;overflow-wrap:anywhere}.software-pagination{display:flex;align-items:center;justify-content:flex-end;gap:12px;margin-top:12px;color:#9caec2;font-size:.78rem}.software-mobile-list{display:none}.software-mobile-card{min-width:0;border:1px solid #223341;border-radius:10px;background:#0b1721;overflow:hidden}.software-mobile-card>details>summary{display:block;min-height:72px;padding:14px;color:inherit;cursor:pointer;list-style:none}.software-mobile-card>details>summary::-webkit-details-marker{display:none}.software-mobile-top{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}.software-mobile-title{min-width:0}.software-mobile-badges{display:flex;flex-wrap:wrap;gap:6px;margin-top:9px}.software-mobile-detail{padding:13px 14px 15px;border-top:1px solid #1e303d}.software-mobile-detail .software-evidence-grid{font-size:.76rem}.software-mobile-detail .software-asset-link{display:inline-block;margin-bottom:9px}@media(max-width:1200px){.software-coverage-cards{grid-template-columns:repeat(3,minmax(0,1fr))}.software-freshness-cards{grid-template-columns:repeat(2,minmax(0,1fr))}.software-toolbar{grid-template-columns:repeat(3,minmax(0,1fr))}.software-search-label{grid-column:span 2}.software-toolbar-actions{align-self:end}}@media(max-width:900px){.software-coverage-cards,.software-provenance{grid-template-columns:repeat(2,minmax(0,1fr))}.software-provenance article:last-child{grid-column:span 2}.software-toolbar{grid-template-columns:repeat(2,minmax(0,1fr))}.software-search-label{grid-column:1/-1}.software-table-wrap{display:none}.software-mobile-list{display:grid;gap:10px}.software-pagination{justify-content:center}}@media(max-width:560px){.software-coverage-hero{padding:16px}.software-coverage-copy h2{font-size:1.18rem}.software-coverage-cards,.software-provenance,.software-freshness-cards,.software-toolbar{grid-template-columns:1fr}.software-provenance article:last-child,.software-search-label{grid-column:auto}.software-toolbar-actions{display:grid;grid-template-columns:1fr 1fr}.software-toolbar-actions button{width:100%}.software-mobile-top{display:grid}.software-pagination{display:grid;grid-template-columns:1fr auto 1fr}.software-pagination button{padding:0 8px}}
      .software-table{min-width:1710px;table-layout:fixed}.software-table th:nth-child(2){width:420px}.software-table td:nth-child(2) .software-name{white-space:normal;overflow-wrap:anywhere;word-break:normal}
    </style>
    <script>
    (()=> {
      const body=document.getElementById('software-table-body');
      const mobile=document.getElementById('software-mobile-list');
      const status=document.getElementById('software-inventory-status');
      const errorBox=document.getElementById('software-inventory-error');
      const collectionStatus=document.getElementById('software-collection-status');
      const warningList=document.getElementById('software-warning-list');
      const coverageNote=document.getElementById('software-coverage-note');
      const search=document.getElementById('software-search');
      const tier=document.getElementById('software-tier-filter');
      const confidence=document.getElementById('software-confidence-filter');
      const freshness=document.getElementById('software-freshness-filter');
      const platform=document.getElementById('software-platform-filter');
      const timeWindow=document.getElementById('software-window-filter');
      const sort=document.getElementById('software-sort');
      const direction=document.getElementById('software-direction');
      const pageSize=document.getElementById('software-page-size');
      const clearFilters=document.getElementById('software-clear-filters');
      const retry=document.getElementById('software-retry');
      const previousPage=document.getElementById('software-page-previous');
      const nextPage=document.getElementById('software-page-next');
      const pageSummary=document.getElementById('software-page-summary');
      let softwareItems=[],softwareLoadPromise=null,softwareReloadPending=false,softwareSignature='',pageOffset=0,pageMeta={limit:100,offset:0,filtered_total:0,has_more:false},searchTimer=null,lastSuccessfulAt='',lastSuccessfulRequestKey='';
      const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
      const token=value=>String(value??'unknown').toLowerCase().replace(/[^a-z0-9_]+/g,'_').replace(/^_+|_+$/g,'')||'unknown';
      const words=value=>String(value??'unknown').replaceAll('_',' ').replace(/\b\w/g,char=>char.toUpperCase());
      const first=(...values)=>values.find(value=>value!==undefined&&value!==null&&value!=='');
      const number=(...values)=>{const value=first(...values);const parsed=Number(value);return Number.isFinite(parsed)?parsed:0};
      const metric=(value,fallback='0')=>value===undefined||value===null||value===''?fallback:String(value);
      const stableSignature=value=>JSON.stringify(value,(key,item)=>key==='generated_at'||key==='observed_at'?undefined:item);
      const snapshotTime=payload=>String(first(payload?.collection?.last_success_at,payload?.generated_at,''));
      const requestParams=()=>new URLSearchParams({limit:pageSize.value,offset:String(pageOffset),search:search.value.trim(),tier:tier.value,confidence:confidence.value,freshness:freshness.value,platform:platform.value,window:timeWindow.value,sort:sort.value,direction:direction.value});
      const timestamp=value=>{const text=String(value||'').trim();return text?esc(text.replace('T','  ')):'Unknown'};
      const tierKey=value=>{const key=token(value);if(key.includes('authoritative')||key==='installed'||key==='endpoint')return 'authoritative_endpoint';if(key.includes('observed')||key==='network')return 'observed_network';if(key.includes('infer'))return 'inferred';return 'unknown'};
      const tierLabel=value=>({authoritative_endpoint:'Endpoint-reported',observed_network:'Observed network',inferred:'Inferred',unknown:'Unknown evidence'}[tierKey(value)]);
      const sourceLabel=item=>{const source=item?.source;if(source&&typeof source==='object')return String(first(source.label,source.type,source.name,'Unknown source'));return String(first(source,'Unknown source'))};
      const evidenceId=(item,index)=>String(first(item?.evidence_id,`${sourceLabel(item)}:${item?.asset_ref||''}:${item?.product||''}:${item?.version||''}:${index}`));
      const assetDisplay=item=>String(first(item?.asset_label,item?.asset_ref,'Unresolved asset'));
      const collectionLabel=item=>String(first(item?.collection_status,item?.status,'recorded'));
      const conflictState=item=>String(item?.evidence_conflict??'').trim();
      const conflictLabel=item=>conflictState(item)?words(conflictState(item)):'No simultaneous disagreement';
      const filtered=()=>Boolean(search.value.trim()||tier.value!=='all'||confidence.value!=='all'||freshness.value!=='all'||platform.value!=='all'||timeWindow.value!=='24h'||sort.value!=='last_seen'||direction.value!=='desc'||pageSize.value!=='100');
      const emptyMessage=()=>{
        if(tier.value==='installed')return 'No successful endpoint software inventory was collected in this window. This does not mean no software is installed.';
        if(tier.value==='observed')return 'No network-observed software was seen in this window. Passive absence is not evidence of absence.';
        if(tier.value==='inferred')return 'No inferred software evidence was produced in this window. Fingerprint absence is not evidence of software absence.';
        if(filtered())return 'No records match these filters. Clear filters to broaden the view.';
        return 'No software evidence has been collected in this window. Absence is not evidence of absence.';
      };
      const operatingSystem=item=>({type:String(item?.operating_system_type??'').trim(),version:String(item?.operating_system_version??'').trim(),source:String(item?.operating_system_source??'').trim(),confidence:String(item?.operating_system_confidence??'').trim(),observedAt:String(item?.operating_system_observed_at??'').trim(),freshness:String(item?.operating_system_freshness??'').trim(),association:String(item?.operating_system_association??'').trim()});
      const assetHtml=item=>{const assetLabel=String(item?.asset_label??'').trim(),display=assetDisplay(item),refType=token(item?.asset_ref_type),os=operatingSystem(item),freshness=os.freshness?`<span class="software-muted">OS evidence: ${esc(words(os.freshness))}</span>`:'';const label=`<strong class="software-name">${esc(display)}</strong><span class="software-muted">OS: ${esc(os.type||'Not observed')}</span><span class="software-muted">Full version: ${esc(os.version||'Not observed')}</span>${freshness}`;return assetLabel?`<a class="software-asset-link" href="asset-inventory.html?asset=${esc(encodeURIComponent(assetLabel))}">${label}</a>`:`<span>${label}<span class="software-muted">Unresolved ${esc(words(refType))} reference</span></span>`};
      const userAgentEvidence=item=>{const userAgent=String(item?.observed_user_agent??'').trim();return userAgent?`<dt>Observed user-agent</dt><dd><code class="software-code">${esc(userAgent)}</code></dd>`:''};
      const operatingSystemEvidence=item=>{const os=operatingSystem(item),provenance=os.source?[os.source,os.confidence?`${os.confidence} confidence`:''].filter(Boolean).join(' · '):'Not observed',association=os.association==='asset_inventory:unique-host-static-ip'?'Unique Asset Inventory hostname-to-static-IP association':os.association;return `<dt>Operating system type</dt><dd>${esc(os.type||'Not observed')}</dd><dt>Full OS version</dt><dd>${esc(os.version||'Not observed')}</dd><dt>OS evidence</dt><dd>${esc(provenance)}</dd><dt>OS association</dt><dd>${esc(association||'Direct or not observed')}</dd><dt>OS observed</dt><dd>${os.observedAt?timestamp(os.observedAt):'Not observed'}</dd><dt>OS evidence freshness</dt><dd>${esc(os.freshness?words(os.freshness):'Not observed')}</dd>`};
      const evidenceDetails=(item,id,layout)=>`<details class="software-evidence-details" data-software-evidence-id="${esc(id)}" data-software-layout="${esc(layout)}"><summary>Evidence details</summary><dl class="software-evidence-grid"><dt>Evidence ID</dt><dd><code class="software-code">${esc(first(item.evidence_id,'Not supplied'))}</code></dd><dt>Conflict state</dt><dd>${esc(conflictLabel(item))}</dd><dt>Dataset</dt><dd>${esc(first(item.source_dataset,'Not supplied'))}</dd><dt>Category</dt><dd>${esc(first(item.category,'Uncategorized'))}</dd>${operatingSystemEvidence(item)}${userAgentEvidence(item)}<dt>Asset reference type</dt><dd>${esc(first(item.asset_ref_type,'unknown'))}</dd><dt>Asset reference</dt><dd>${esc(first(item.asset_ref,'Not supplied'))}</dd><dt>Observations</dt><dd>${number(item.observation_count)}</dd><dt>Collection state</dt><dd>${esc(words(collectionLabel(item)))}</dd></dl></details>`;
      const row=(item,index)=>{const id=evidenceId(item,index),itemTier=tierKey(item.tier),itemConfidence=token(item.confidence),itemFreshness=token(item.freshness),source=sourceLabel(item);return `<tr data-software-row="${esc(id)}"><td>${assetHtml(item)}</td><td><strong class="software-name">${esc(first(item.product,'Unknown software'))}</strong><span class="software-muted">${esc(first(item.category,'Uncategorized'))}</span></td><td><code class="software-code">${esc(first(item.version,'Unknown version'))}</code></td><td><span class="software-tier software-tier-${esc(itemTier)}">${esc(tierLabel(item.tier))}</span></td><td><strong class="software-name">${esc(source)}</strong><span class="software-muted">${esc(first(item.source_dataset,'Dataset not supplied'))}</span>${evidenceDetails(item,id,'desktop')}</td><td><span class="software-confidence software-confidence-${esc(itemConfidence)}">${esc(words(itemConfidence))}</span></td><td><span class="software-freshness software-freshness-${esc(itemFreshness)}">${esc(words(itemFreshness))}</span></td><td>${timestamp(item.first_seen)}</td><td>${timestamp(item.last_seen)}</td><td><strong class="software-name">${number(item.observation_count)} observation(s)</strong><span class="software-muted">${esc(words(collectionLabel(item)))}</span></td></tr>`};
      const mobileCard=(item,index)=>{const id=evidenceId(item,index),itemTier=tierKey(item.tier),itemConfidence=token(item.confidence),itemFreshness=token(item.freshness);return `<article class="software-mobile-card" data-software-card="${esc(id)}"><details class="software-evidence-details" data-software-evidence-id="${esc(id)}" data-software-layout="mobile"><summary><span class="software-mobile-top"><span class="software-mobile-title"><strong class="software-name">${esc(first(item.product,'Unknown software'))}</strong><span class="software-muted">${esc(first(item.version,'Unknown version'))} · ${esc(assetDisplay(item))}</span></span><span class="software-freshness software-freshness-${esc(itemFreshness)}">${esc(words(itemFreshness))}</span></span><span class="software-mobile-badges"><span class="software-tier software-tier-${esc(itemTier)}">${esc(tierLabel(item.tier))}</span><span class="software-confidence software-confidence-${esc(itemConfidence)}">${esc(words(itemConfidence))}</span></span></summary><div class="software-mobile-detail">${assetHtml(item)}<dl class="software-evidence-grid"><dt>Evidence ID</dt><dd><code class="software-code">${esc(first(item.evidence_id,'Not supplied'))}</code></dd><dt>Conflict state</dt><dd>${esc(conflictLabel(item))}</dd><dt>Source</dt><dd>${esc(sourceLabel(item))}</dd><dt>Dataset</dt><dd>${esc(first(item.source_dataset,'Not supplied'))}</dd><dt>Category</dt><dd>${esc(first(item.category,'Uncategorized'))}</dd>${operatingSystemEvidence(item)}${userAgentEvidence(item)}<dt>First seen</dt><dd>${timestamp(item.first_seen)}</dd><dt>Last seen</dt><dd>${timestamp(item.last_seen)}</dd><dt>Observations</dt><dd>${number(item.observation_count)}</dd><dt>Collection state</dt><dd>${esc(words(collectionLabel(item)))}</dd></dl></div></details></article>`};
      function captureViewState(){
        const expanded=new Set(Array.from(document.querySelectorAll('.software-evidence-details[open]')).map(node=>node.dataset.softwareEvidenceId));
        const active=document.activeElement?.closest?.('[data-software-evidence-id]');
        return {expanded,focusId:active?.dataset.softwareEvidenceId||'',focusLayout:active?.dataset.softwareLayout||''};
      }
      function restoreViewState(viewState){
        document.querySelectorAll('[data-software-evidence-id]').forEach(node=>{if(viewState.expanded?.has(node.dataset.softwareEvidenceId))node.open=true});
        if(!viewState.focusId)return;
        const target=Array.from(document.querySelectorAll('[data-software-evidence-id]')).find(node=>node.dataset.softwareEvidenceId===viewState.focusId&&node.dataset.softwareLayout===viewState.focusLayout);
        target?.querySelector('summary')?.focus({preventScroll:true});
      }
      function renderItems(viewState={expanded:new Set(),focusId:'',focusLayout:''}){
        const message=emptyMessage();
        body.innerHTML=softwareItems.length?softwareItems.map(row).join(''):`<tr><td colspan="10" class="ir-loading">${esc(message)}</td></tr>`;
        mobile.innerHTML=softwareItems.length?softwareItems.map(mobileCard).join(''):`<div class="ir-loading">${esc(message)}</div>`;
        body.dataset.liveRenderVersion=String(Number(body.dataset.liveRenderVersion||0)+1);
        mobile.dataset.liveRenderVersion=String(Number(mobile.dataset.liveRenderVersion||0)+1);
        restoreViewState(viewState);
      }
      function renderCoverage(payload){
        const summary=payload.summary||{},coverage=payload.coverage||{},denominator=coverage.authoritative_denominator,denominatorStatus=token(coverage.denominator_status);
        document.getElementById('software-installed-total').textContent=`${number(summary.installed)} record(s)`;
        document.getElementById('software-observed-total').textContent=`${number(summary.observed)} record(s)`;
        document.getElementById('software-inferred-total').textContent=`${number(summary.inferred)} record(s)`;
        document.getElementById('software-current-total').textContent=number(summary.current);
        document.getElementById('software-recent-total').textContent=number(summary.recent);
        document.getElementById('software-historical-total').textContent=number(summary.historical);
        document.getElementById('software-expired-total').textContent=number(summary.expired);
        document.getElementById('software-conflicting-total').textContent=number(summary.conflicting_records);
        document.getElementById('software-denominator').textContent=metric(denominator,'Unknown');
        document.getElementById('software-osquery-ready-total').textContent=metric(coverage.osquery_ready,'Unknown');
        document.getElementById('software-fresh-endpoint-total').textContent=metric(coverage.fresh_endpoint_inventories);
        document.getElementById('software-network-observed-total').textContent=metric(coverage.network_observed_assets);
        document.getElementById('software-coverage-gap-total').textContent=metric(coverage.coverage_gaps,'Unknown');
        const denominatorNumber=Number(denominator),freshNumber=number(coverage.fresh_endpoint_inventories);
        if(denominatorStatus!=='known'||!Number.isFinite(denominatorNumber)||denominatorNumber<=0){
          coverageNote.textContent='Coverage percentage cannot be calculated without an authoritative LAN denominator. Endpoint, passive, and inferred populations are not interchangeable.';
        }else{
          const percent=Math.min(100,Math.max(0,(freshNumber/denominatorNumber)*100));
          coverageNote.textContent=`Fresh endpoint-reported inventory covers ${freshNumber} of ${denominatorNumber} registered LAN assets (${percent.toFixed(1)}%).`;
        }
        const start=pageMeta.filtered_total?Number(pageMeta.offset||0)+1:0,end=Number(pageMeta.offset||0)+softwareItems.length,total=Number(pageMeta.filtered_total||0),page=Math.floor(Number(pageMeta.offset||0)/Number(pageMeta.limit||100))+1,pages=Math.max(1,Math.ceil(total/Number(pageMeta.limit||100)));
        status.textContent=`Showing ${start}–${end} of ${total} evidence record(s): ${number(summary.products)} product(s), ${number(summary.assets)} asset reference(s), ${number(summary.installed)} installed, ${number(summary.observed)} observed, ${number(summary.inferred)} inferred, ${number(summary.conflicting_records)} conflicting; freshness ${number(summary.current)} current, ${number(summary.recent)} recent, ${number(summary.historical)} historical, ${number(summary.expired)} expired.`;
        pageSummary.textContent=`Page ${page} of ${pages}`;
        previousPage.disabled=Number(pageMeta.offset||0)<=0;
        nextPage.disabled=!pageMeta.has_more;
      }
      function renderCollection(payload){
        const collection=payload.collection||{},state=token(first(collection.status,collection.state,'unknown')),parts=[`Collection: ${words(state)}`];
        if(typeof collection.complete==='boolean')parts.push(collection.complete?'complete snapshot':'incomplete snapshot');
        const collectionWindow=collection.window&&typeof collection.window==='object'?collection.window:{};
        if(collectionWindow.start&&collectionWindow.end)parts.push(`window ${String(collectionWindow.start).replace('T','  ')} to ${String(collectionWindow.end).replace('T','  ')}`);
        const sourceStatuses=collection.source_statuses&&typeof collection.source_statuses==='object'?Object.entries(collection.source_statuses):[];
        sourceStatuses.forEach(([source,value])=>{const sourceParts=[`${words(source)} ${words(first(value?.status,'unknown'))}`];if(value?.freshness)sourceParts.push(words(value.freshness));if(value?.latest_observation_at)sourceParts.push(`latest ${String(value.latest_observation_at).replace('T','  ')}`);parts.push(sourceParts.join(' · '))});
        const last=first(collection.last_success_at,collection.collected_at,collection.observed_at);
        if(last)parts.push(`last success ${String(last).replace('T','  ')}`);
        collectionStatus.textContent=parts.join(' · ');
        const sourceProblem=sourceStatuses.some(([,value])=>{const sourceState=token(first(value?.status,'unknown')),sourceFreshness=token(first(value?.freshness,'unknown'));return Boolean(value?.error)||!['ok','complete','success','successful'].includes(sourceState)||['stale','expired'].includes(sourceFreshness)});
        collectionStatus.dataset.state=state.includes('fail')||state.includes('error')||state.includes('unavailable')||state.includes('missing')?'failed':state.includes('partial')||collection.complete===false||sourceProblem?'partial':state.includes('stale')?'stale':'ok';
        const warnings=Array.isArray(payload.warnings)?payload.warnings.filter(value=>String(value||'').trim()).slice(0,20):[];
        warningList.innerHTML=warnings.map(value=>`<li>${esc(value)}</li>`).join('');
        warningList.hidden=!warnings.length;
      }
      function hydratePlatforms(platforms){
        const options=Array.isArray(platforms)?platforms.filter(value=>String(value||'').trim()).slice(0,100):[];
        if(!options.length)return;
        const selected=platform.value;
        const choices=selected&&selected!=='all'&&!options.some(value=>String(value)===selected)?[selected,...options]:options;
        platform.innerHTML='<option value="all">All platforms</option>'+choices.map(value=>`<option value="${esc(value)}">${esc(value)}</option>`).join('');
        platform.value=selected;
      }
      function load({announce=false}={}){
        if(softwareLoadPromise){
          if(announce)softwareReloadPending=true;
          return softwareLoadPromise;
        }
        softwareLoadPromise=(async()=>{
          const viewState=captureViewState();
          const params=requestParams();
          const requestKey=params.toString();
          retry.disabled=true;
          errorBox.hidden=true;
          if(announce||!softwareSignature)status.textContent=softwareItems.length?'Refreshing software evidence…':'Loading software evidence…';
          try{
            const response=await fetch('/api/software-inventory'+`?${params}`,{cache:'no-store'});
            const payload=await response.json().catch(()=>({ok:false}));
            if(requestKey!==requestParams().toString())return false;
            if(!response.ok||payload.ok===false){
              if(payload&&typeof payload==='object'&&payload.summary&&payload.coverage&&payload.page){
                softwareSignature=stableSignature(payload);
                softwareItems=Array.isArray(payload.items)?payload.items:[];
                pageMeta=payload.page;
                hydratePlatforms(payload.platforms||[]);
                renderCoverage(payload);
                renderCollection(payload);
                renderItems(viewState);
                errorBox.textContent='Software inventory is temporarily unavailable. Retry the request.';
                errorBox.hidden=false;
                return false;
              }
              throw new Error(`HTTP ${response.status}`);
            }
            const nextSignature=stableSignature(payload);
            if(nextSignature===softwareSignature)return false;
            softwareSignature=nextSignature;
            softwareItems=Array.isArray(payload.items)?payload.items:[];
            pageMeta=payload.page||{limit:Number(pageSize.value),offset:pageOffset,filtered_total:softwareItems.length,has_more:false};
            lastSuccessfulAt=snapshotTime(payload);
            lastSuccessfulRequestKey=requestKey;
            hydratePlatforms(payload.platforms||[]);
            renderCoverage(payload);
            renderCollection(payload);
            renderItems(viewState);
            return true;
          }catch(error){
            if(requestKey!==requestParams().toString())return false;
            errorBox.textContent='Software inventory is temporarily unavailable. Retry the request.';
            errorBox.hidden=false;
            collectionStatus.textContent='Collection status unavailable.';
            collectionStatus.dataset.state='failed';
            if(softwareItems.length&&requestKey===lastSuccessfulRequestKey){
              status.textContent=`Showing the last successful software inventory snapshot${lastSuccessfulAt?` from ${lastSuccessfulAt.replace('T','  ')}`:''}.`;
              restoreViewState(viewState);
            }else{
              const message=softwareItems.length
                ?'Software inventory could not be loaded for the selected filters. Previous results are hidden because they belong to a different request.'
                :'Software inventory could not be loaded. No inventory conclusion can be drawn.';
              body.innerHTML=`<tr><td colspan="10" class="ir-loading">${message}</td></tr>`;
              mobile.innerHTML=`<div class="ir-loading">${message}</div>`;
              status.textContent=message;
              previousPage.disabled=true;nextPage.disabled=true;
            }
            return false;
          }finally{
            retry.disabled=false;
            softwareLoadPromise=null;
            if(softwareReloadPending){
              softwareReloadPending=false;
              load({announce:true});
            }
          }
        })();
        return softwareLoadPromise;
      }
      const resetAndLoad=()=>{pageOffset=0;softwareSignature='';load({announce:true})};
      search.addEventListener('input',()=>{window.clearTimeout(searchTimer);searchTimer=window.setTimeout(resetAndLoad,250)});
      [tier,confidence,freshness,platform,timeWindow,sort,direction,pageSize].forEach(control=>control.addEventListener('change',resetAndLoad));
      clearFilters.addEventListener('click',()=>{search.value='';tier.value='all';confidence.value='all';freshness.value='all';platform.value='all';timeWindow.value='24h';sort.value='last_seen';direction.value='desc';pageSize.value='100';resetAndLoad();search.focus()});
      retry.addEventListener('click',()=>{softwareSignature='';load({announce:true})});
      previousPage.addEventListener('click',()=>{pageOffset=Math.max(0,pageOffset-Number(pageSize.value));softwareSignature='';load({announce:true})});
      nextPage.addEventListener('click',()=>{if(pageMeta.has_more){pageOffset+=Number(pageSize.value);softwareSignature='';load({announce:true})}});
      load();
      if(window.OnionSentinelReactiveTables){
        window.OnionSentinelReactiveTables.register('software-inventory-table',load,{intervalMs:60000,revisionKey:'software_inventory'});
      }else{
        window.setInterval(load,60000);
      }
    })();
    </script>'''


def software_inventory_page_section() -> str:
    """Render software evidence without conflating installed, observed, and inferred facts."""
    return SOFTWARE_INVENTORY_PAGE_SECTION
