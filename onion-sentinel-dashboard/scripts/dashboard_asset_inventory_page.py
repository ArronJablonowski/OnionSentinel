"""Authoritative Asset Inventory and DHCP review page renderer."""
from __future__ import annotations


ASSET_INVENTORY_PAGE_SECTION = r'''
    <section id="asset-inventory-view" class="view-section active asset-view" aria-label="Asset inventory">
      <div class="asset-metrics" aria-label="Asset inventory metrics">
        <div><span>Known records</span><strong id="asset-records-total">0</strong></div>
        <div><span>Current assets</span><strong id="asset-current-total">0</strong></div>
        <div><span>Current IPs</span><strong id="asset-ip-total">0</strong></div>
        <div><span>Hostnames</span><strong id="asset-hostname-total">0</strong></div>
        <div><span>Historical</span><strong id="asset-expired-total">0</strong></div>
      </div>
      <div class="asset-toolbar">
        <label class="asset-search-label">Search
          <input id="asset-search" type="search" autocomplete="off" placeholder="Asset, hostname, IP, role, or platform">
        </label>
        <label>Sort
          <select id="asset-sort">
            <option value="asset_id">Asset name</option>
            <option value="criticality">Criticality</option>
            <option value="valid_from">Valid since</option>
            <option value="role">Role</option>
            <option value="platform">Platform</option>
          </select>
        </label>
        <label>Direction
          <select id="asset-direction">
            <option value="asc">Ascending</option>
            <option value="desc">Descending</option>
          </select>
        </label>
        <label>Rows
          <select id="asset-page-size">
            <option value="50">50</option>
            <option value="100" selected>100</option>
            <option value="250">250</option>
            <option value="500">500</option>
          </select>
        </label>
      </div>
      <div id="asset-inventory-status" class="asset-status" role="status" aria-live="polite">Loading authoritative and dynamically observed inventory…</div>
      <div id="asset-inventory-error" class="ir-error" role="alert" hidden></div>
      <div class="asset-table-wrap">
        <table class="asset-table">
          <thead><tr>
            <th>Asset</th><th>State</th><th>Current IP address</th><th>MAC address</th><th>Hostname</th>
            <th>Role / platform</th><th>Criticality</th><th>Confidence</th>
            <th>From</th><th>Until</th><th>Source</th><th>Actions</th>
          </tr></thead>
          <tbody id="asset-table-body"><tr><td colspan="12" class="ir-loading">Loading known assets…</td></tr></tbody>
        </table>
      </div>
      <div class="asset-pagination" aria-label="Asset inventory pages">
        <button id="asset-page-previous" type="button">Previous</button>
        <span id="asset-page-summary">Page 1</span>
        <button id="asset-page-next" type="button">Next</button>
      </div>
      <div class="dhcp-section">
        <div class="dhcp-heading">
          <div>
            <h2>DHCP network discovery</h2>
            <p>Read-only Zeek DHCP observations update current-address display and surface provisional DHCP observations for LAN clients. Candidates and conflicts remain non-authoritative until operator review.</p>
          </div>
          <span id="dhcp-collection-badge" class="asset-state">Loading</span>
        </div>
        <div class="asset-metrics dhcp-metrics" aria-label="DHCP discovery metrics">
          <div><span>Observed identities</span><strong id="dhcp-total">0</strong></div>
          <div><span>Verified matches</span><strong id="dhcp-matches">0</strong></div>
          <div><span>Review candidates</span><strong id="dhcp-candidates">0</strong></div>
          <div><span>Conflicts</span><strong id="dhcp-conflicts">0</strong></div>
          <div><span>Stale</span><strong id="dhcp-stale">0</strong></div>
        </div>
        <div id="dhcp-discovery-status" class="asset-status" role="status" aria-live="polite">Loading DHCP discovery state…</div>
        <div id="dhcp-discovery-error" class="ir-error" role="alert" hidden></div>
        <div class="asset-table-wrap">
          <table class="asset-table dhcp-table">
            <thead><tr>
              <th>Review state</th><th>Current IP address</th><th>DHCP hostname</th>
              <th>MAC address</th><th>Authoritative asset</th><th>Lease / last seen</th>
              <th>Evidence</th><th>Action</th>
            </tr></thead>
            <tbody id="dhcp-table-body"><tr><td colspan="8" class="ir-loading">Loading DHCP observations…</td></tr></tbody>
          </table>
        </div>
      </div>
      <div id="dhcp-review-modal" class="dhcp-review-modal" role="dialog" aria-modal="true" aria-labelledby="dhcp-review-title" hidden>
        <form id="dhcp-review-form" class="dhcp-review-card" novalidate>
          <div class="dhcp-review-heading">
            <div><h2 id="dhcp-review-title">Review DHCP identity</h2><p id="dhcp-review-summary"></p></div>
            <button id="dhcp-review-close" type="button" aria-label="Close review dialog">×</button>
          </div>
          <div id="dhcp-review-error" class="ir-error" role="alert" hidden></div>
          <div id="dhcp-promotion-fields" class="dhcp-review-grid">
            <label>Asset name<input id="dhcp-review-asset-id" maxlength="160" required></label>
            <label>Hostname<input id="dhcp-review-hostname" maxlength="253"></label>
            <label>Role<input id="dhcp-review-role" maxlength="160" required></label>
            <label>Platform<input id="dhcp-review-platform" maxlength="160"></label>
            <label>Criticality<select id="dhcp-review-criticality"><option>unknown</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
          </div>
          <div class="dhcp-review-grid">
            <label>Operator reference<input id="dhcp-review-operator" maxlength="160" placeholder="Name, ticket, or change reference" required></label>
            <label class="dhcp-review-wide">Reason<textarea id="dhcp-review-reason" maxlength="1000" rows="3" required></textarea></label>
            <label id="dhcp-local-mac-field" class="dhcp-review-check" hidden><input id="dhcp-review-local-mac" type="checkbox"> I explicitly accept this locally administered MAC as the reviewed identity.</label>
            <label class="dhcp-review-wide">Type the confirmation shown below<input id="dhcp-review-confirm" maxlength="256" autocomplete="off" required><small id="dhcp-review-confirmation"></small></label>
          </div>
          <p id="dhcp-review-auth" class="dhcp-review-auth"><span id="dhcp-review-auth-status">Operator confirmation is active.</span> <a id="dhcp-review-admin-login" href="/admin/login?resume=asset-review" target="onion-sentinel-admin-auth" rel="noopener" hidden>Sign in to Administration</a> The DHCP observation is revalidated inside the database transaction before any change is committed.</p>
          <div class="dhcp-review-actions"><button id="dhcp-review-cancel" type="button">Cancel</button><button id="dhcp-review-submit" type="submit">Approve</button></div>
        </form>
      </div>
      <div id="asset-review-modal" class="dhcp-review-modal" role="dialog" aria-modal="true" aria-labelledby="asset-review-title" hidden>
        <form id="asset-review-form" class="dhcp-review-card" novalidate>
          <div class="dhcp-review-heading">
            <div><h2 id="asset-review-title">Edit asset</h2><p id="asset-review-summary"></p></div>
            <button id="asset-review-close" type="button" aria-label="Close asset dialog">×</button>
          </div>
          <div id="asset-review-error" class="ir-error" role="alert" hidden></div>
          <div id="asset-edit-fields" class="dhcp-review-grid">
            <label>Asset name<input id="asset-review-asset-id" maxlength="160" readonly></label>
            <label>Role<input id="asset-review-role" maxlength="160" required></label>
            <label class="dhcp-review-wide">IP addresses<input id="asset-review-ips" maxlength="2048" placeholder="Comma-separated IP addresses"></label>
            <label class="dhcp-review-wide">MAC addresses<input id="asset-review-macs" maxlength="2048" placeholder="Comma-separated MAC addresses"></label>
            <label class="dhcp-review-wide">Hostnames<input id="asset-review-hostnames" maxlength="4096" placeholder="Comma-separated hostnames"></label>
            <label>Platform<input id="asset-review-platform" maxlength="160"></label>
            <label>Criticality<select id="asset-review-criticality"><option>unknown</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
            <label>Confidence<select id="asset-review-confidence"><option>unknown</option><option>low</option><option>medium</option><option>high</option></select></label>
          </div>
          <p id="asset-demote-warning" class="asset-demote-warning" hidden>This closes the current authoritative record while retaining its history and audit trail. Its preserved DHCP observation will return to the DHCP review table.</p>
          <div class="dhcp-review-grid">
            <label>Operator reference<input id="asset-review-operator" maxlength="160" placeholder="Name, ticket, or change reference" required></label>
            <label class="dhcp-review-wide">Reason<textarea id="asset-review-reason" maxlength="1000" rows="3" required></textarea></label>
            <label class="dhcp-review-wide">Type the confirmation shown below<input id="asset-review-confirm" maxlength="256" autocomplete="off" required><small id="asset-review-confirmation"></small></label>
          </div>
          <p class="dhcp-review-auth"><span>Operator confirmation is active; Administration sign-in is not required.</span> The database revalidates the current asset version before committing the change.</p>
          <div class="dhcp-review-actions"><button id="asset-review-cancel" type="button">Cancel</button><button id="asset-review-submit" type="submit">Save asset</button></div>
        </form>
      </div>
    </section>
    <style>
      .asset-view{display:block;padding:0 0 28px}.asset-metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin:0 0 16px}.asset-metrics>div{min-height:84px;padding:16px 18px;border:1px solid #223341;border-radius:8px;background:#0d1822}.asset-metrics span{display:block;color:#9caec2;font-size:.76rem;font-weight:800;text-transform:uppercase}.asset-metrics strong{display:block;margin-top:7px;color:#75efff;font-size:1.55rem}.asset-toolbar{display:grid;grid-template-columns:minmax(260px,1fr) 180px 150px 110px;gap:12px;align-items:end;margin-bottom:12px}.asset-toolbar label{color:#9caec2;font-size:.76rem;font-weight:800;text-transform:uppercase}.asset-toolbar input,.asset-toolbar select{display:block;width:100%;min-height:44px;margin-top:5px;padding:0 12px;color:#e9f2ff;background:#0b1620;border:1px solid #07566a;border-radius:8px;font:inherit}.asset-status{margin:0 0 12px;color:#8fa2b8;font-size:.8rem}.asset-table-wrap{overflow-x:auto;border:1px solid #223341;border-radius:8px;background:#09131d}.asset-table{width:100%;min-width:1725px;border-collapse:collapse;table-layout:fixed}.asset-table th,.asset-table td{box-sizing:border-box;padding:9px 10px;text-align:left;vertical-align:top;border-bottom:1px solid #1e303d}.asset-table th{color:#9caec2;background:#101e2a;font-size:.72rem;text-transform:uppercase}.asset-table th:nth-child(1){width:220px}.asset-table th:nth-child(2){width:75px}.asset-table th:nth-child(3){width:145px}.asset-table th:nth-child(4){width:155px}.asset-table th:nth-child(5){width:220px}.asset-table th:nth-child(6){width:155px}.asset-table th:nth-child(7){width:85px}.asset-table th:nth-child(8){width:90px}.asset-table th:nth-child(9){width:118px}.asset-table th:nth-child(10){width:118px}.asset-table th:nth-child(11){width:190px}.asset-table th:nth-child(12){width:150px}.asset-table tbody tr:hover td{background:#0e202b}.asset-pagination{display:flex;align-items:center;justify-content:flex-end;gap:12px;margin:12px 0 0;color:#9caec2;font-size:.78rem}.asset-pagination button{min-width:92px;min-height:38px;border:1px solid #07566a;border-radius:7px;color:#e9f2ff;background:#0b1620;font-weight:800}.asset-pagination button:disabled{opacity:.4;cursor:not-allowed}.asset-name{display:block;color:#eef5ff;font-weight:900;overflow-wrap:anywhere}.asset-table:not(.dhcp-table) td:first-child .asset-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.asset-state{display:inline-block;margin:0;padding:3px 7px;border:1px solid #205069;border-radius:999px;color:#75efff;background:#0a1a24;font-size:.62rem;font-weight:900;text-transform:uppercase}.asset-values{display:grid;gap:3px}.asset-values code{display:block;color:#d8e7f8;font:700 12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere;white-space:normal}.asset-mac{white-space:nowrap!important;overflow-wrap:normal!important}.asset-hostname{color:#69e89a!important;overflow:hidden!important;overflow-wrap:normal!important;text-overflow:ellipsis;white-space:nowrap!important}.asset-muted{display:block;color:#8397ab;font-size:.75rem;line-height:1.4;overflow-wrap:anywhere}.asset-criticality{font-weight:900;text-transform:uppercase}.asset-criticality-critical{color:#ff6681}.asset-criticality-high{color:#ff963e}.asset-criticality-medium{color:#ffca67}.asset-criticality-low{color:#72e99c}.asset-criticality-unknown{color:#9caec2}.asset-empty{color:#8397ab;font-style:italic}.asset-validity{font-variant-numeric:tabular-nums}.asset-row-actions{display:grid;gap:6px}.asset-row-action{min-height:32px;padding:4px 8px;border:1px solid #08708a;border-radius:6px;color:#eaf8ff;background:#0a2530;font-weight:900}.asset-row-action.asset-demote{border-color:#8d3950;color:#ff8da1;background:#28131b}.asset-demote-warning{padding:10px 12px;border:1px solid #8d3950;border-radius:7px;color:#ffb1bf;background:#28131b}.dhcp-section{margin-top:32px;padding-top:24px;border-top:1px solid #223341}.dhcp-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:16px}.dhcp-heading h2{margin:0;color:#eef5ff;font-size:1.15rem}.dhcp-heading p{max-width:820px;margin:6px 0 0;color:#8fa2b8;font-size:.82rem}.dhcp-heading .asset-state{margin:0}.dhcp-table{min-width:1370px}.dhcp-table th:nth-child(1){width:160px}.dhcp-table th:nth-child(2){width:180px}.dhcp-table th:nth-child(3){width:210px}.dhcp-table th:nth-child(4){width:180px}.dhcp-table th:nth-child(5){width:220px}.dhcp-table th:nth-child(6){width:210px}.dhcp-table th:nth-child(7){width:150px}.dhcp-table th:nth-child(8){width:110px}.dhcp-reconciliation{display:inline-block;padding:4px 8px;border:1px solid currentColor;border-radius:999px;font-size:.63rem;font-weight:900;text-transform:uppercase}.dhcp-verified_match{color:#69e89a}.dhcp-candidate{color:#ffca67}.dhcp-conflict{color:#ff6681}.dhcp-stale{display:block;margin-top:7px;color:#ffca67;font-size:.68rem;font-weight:900;text-transform:uppercase}.dhcp-ip{white-space:nowrap!important;overflow-wrap:normal!important}.dhcp-review-button{min-height:34px;width:100%;padding:5px 8px;border:1px solid #08708a;border-radius:6px;color:#eaf8ff;background:#0a2530;font-weight:900}.dhcp-review-button:disabled{opacity:.4;cursor:not-allowed}.dhcp-review-note{display:block;margin-top:5px;color:#8397ab;font-size:.68rem}.dhcp-review-modal{position:fixed;inset:0;z-index:1000;display:grid;place-items:center;padding:20px;background:rgba(2,8,13,.82)}.dhcp-review-modal[hidden]{display:none}.dhcp-review-card{width:min(760px,calc(100vw - 32px));max-height:calc(100vh - 40px);overflow:auto;padding:22px;border:1px solid #17667a;border-radius:10px;background:#0b1721;box-shadow:0 24px 80px #000}.dhcp-review-heading{display:flex;justify-content:space-between;gap:18px}.dhcp-review-heading h2{margin:0;color:#eef5ff}.dhcp-review-heading p{margin:5px 0 16px;color:#8fa2b8}.dhcp-review-heading button{width:38px;height:38px;border:1px solid #315064;border-radius:50%;color:#eef5ff;background:#0b1620;font-size:1.35rem}.dhcp-review-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}.dhcp-review-grid label{color:#9caec2;font-size:.76rem;font-weight:800;text-transform:uppercase}.dhcp-review-grid input,.dhcp-review-grid select,.dhcp-review-grid textarea{box-sizing:border-box;display:block;width:100%;margin-top:5px;padding:9px 11px;border:1px solid #315064;border-radius:7px;color:#eef5ff;background:#07131d;font:inherit}.dhcp-review-wide,.dhcp-review-check{grid-column:1/-1}.dhcp-review-check{display:flex!important;align-items:center;gap:8px;color:#ffca67!important;text-transform:none!important}.dhcp-review-check[hidden]{display:none!important}.dhcp-review-check input{display:inline-block;width:auto;margin:0}.dhcp-review-grid small{display:block;margin-top:5px;color:#75efff;font:700 .72rem/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;text-transform:none}.dhcp-review-auth{color:#8fa2b8;font-size:.76rem}.dhcp-review-auth a{color:#75efff}.dhcp-review-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:16px}.dhcp-review-actions button{min-width:120px;min-height:40px;border:1px solid #08708a;border-radius:7px;color:#eef5ff;background:#0a2530;font-weight:900}.dhcp-review-actions button[type=submit]{color:#061117;background:#75efff}.dhcp-review-actions button:disabled{opacity:.5}@media(max-width:900px){.asset-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.asset-toolbar{grid-template-columns:1fr 1fr}.asset-search-label{grid-column:1/-1}}@media(max-width:560px){.asset-metrics,.asset-toolbar,.dhcp-review-grid{grid-template-columns:1fr}.asset-search-label{grid-column:auto}.dhcp-heading{display:block}.dhcp-heading .asset-state{margin-top:10px}.dhcp-review-wide,.dhcp-review-check{grid-column:auto}}
      .asset-table tr.asset-promoted td{animation:asset-promoted 2.8s ease-out}.dhcp-review-auth.authenticated span{color:#69e89a}.dhcp-review-auth.authenticated a{display:none}.dhcp-review-actions button.asset-demote{border-color:#8d3950;color:#fff;background:#c43f5d}@keyframes asset-promoted{0%{background:#123d38}100%{background:transparent}}
    </style>
    <script>
    (()=> {
      const body=document.getElementById('asset-table-body');
      const search=document.getElementById('asset-search');
      const sort=document.getElementById('asset-sort');
      const direction=document.getElementById('asset-direction');
      const pageSize=document.getElementById('asset-page-size');
      const previousPage=document.getElementById('asset-page-previous');
      const nextPage=document.getElementById('asset-page-next');
      const pageSummary=document.getElementById('asset-page-summary');
      const status=document.getElementById('asset-inventory-status');
      const errorBox=document.getElementById('asset-inventory-error');
      const dhcpBody=document.getElementById('dhcp-table-body');
      const dhcpStatus=document.getElementById('dhcp-discovery-status');
      const dhcpError=document.getElementById('dhcp-discovery-error');
      const dhcpBadge=document.getElementById('dhcp-collection-badge');
      const reviewModal=document.getElementById('dhcp-review-modal');
      const reviewForm=document.getElementById('dhcp-review-form');
      const reviewError=document.getElementById('dhcp-review-error');
      const reviewSubmit=document.getElementById('dhcp-review-submit');
      const reviewPromotionFields=document.getElementById('dhcp-promotion-fields');
      const reviewLocalMacField=document.getElementById('dhcp-local-mac-field');
      const assetReviewModal=document.getElementById('asset-review-modal');
      const assetReviewForm=document.getElementById('asset-review-form');
      const assetReviewError=document.getElementById('asset-review-error');
      const assetReviewSubmit=document.getElementById('asset-review-submit');
      const assetEditFields=document.getElementById('asset-edit-fields');
      const assetDemoteWarning=document.getElementById('asset-demote-warning');
      let assets=[],assetLoadPromise=null,dhcpLoadPromise=null,assetSignature='',dhcpSignature='',requestedAssetApplied=false,pageOffset=0,pageMeta={limit:100,offset:0,filtered_total:0,has_more:false},searchTimer=null;
      let assetItems=new Map(),assetReviewItem=null,assetReviewMode='';
      let dhcpItems=new Map(),reviewItem=null,reviewMode='',adminRequired=false,adminAuthenticated=null,adminPollTimer=null,adminWindow=null,resumeAfterAuth=false,recentlyPromotedAssetId='';
      const requestedAsset=new URLSearchParams(location.search).get('asset');
      if(requestedAsset){search.value=requestedAsset;requestedAssetApplied=true}
      const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
      const stableSignature=value=>JSON.stringify(value,(key,item)=>key==='generated_at'||key==='observed_at'?undefined:item);
      const values=(items,className='')=>Array.isArray(items)&&items.length?`<span class="asset-values">${items.map(value=>`<code class="${className}" title="${esc(value)}">${esc(value)}</code>`).join('')}</span>`:'<span class="asset-empty">Not registered</span>';
      const macValues=item=>{if(Array.isArray(item.mac_addresses)&&item.mac_addresses.length)return `${values(item.mac_addresses,'asset-mac')}<span class="asset-muted">Authoritative inventory</span>`;if(Array.isArray(item.observed_mac_addresses)&&item.observed_mac_addresses.length){const qualifier=item.observed_mac_stale?' · stale':' · review required';return `${values(item.observed_mac_addresses,'asset-mac')}<span class="asset-muted">Observed via DHCP${qualifier}</span>`}if(item.observed_mac_ambiguous)return '<span class="asset-empty">Multiple DHCP identities</span><span class="asset-muted">Review discovery evidence below</span>';return '<span class="asset-empty">Not registered or observed</span>'};
      const timestamp=value=>{const text=String(value||'').trim();return text?esc(text.replace('T','  ')):'Open-ended'};
      const row=item=>{const criticality=String(item.criticality||'unknown').toLowerCase().replace(/[^a-z]/g,'')||'unknown';const dynamic=item.current_ip_source==='zeek-dhcp';const configured=Array.isArray(item.configured_ip_addresses)&&item.configured_ip_addresses.length&&JSON.stringify(item.configured_ip_addresses)!==JSON.stringify(item.ip_addresses)?`<span class="asset-muted">Configured: ${esc(item.configured_ip_addresses.join(', '))}</span>`:'';const promoted=String(item.asset_id||'')===recentlyPromotedAssetId?' class="asset-promoted"':'';return `<tr${promoted} data-asset-id="${esc(item.asset_id)}"><td><strong class="asset-name" title="${esc(item.asset_id)}">${esc(item.asset_id)}</strong></td><td><span class="asset-state">${esc(item.state||'current')}</span></td><td>${values(item.ip_addresses)}${dynamic?'<span class="asset-muted">Current address from passive DHCP</span>':''}${configured}</td><td>${macValues(item)}</td><td>${values(item.hostnames,'asset-hostname')}</td><td><strong class="asset-name">${esc(item.role||'Unspecified role')}</strong><span class="asset-muted">${esc(item.platform||'Platform not registered')}</span></td><td><span class="asset-criticality asset-criticality-${esc(criticality)}">${esc(item.criticality||'unknown')}</span></td><td>${esc(item.confidence||'unknown')}</td><td class="asset-validity">${timestamp(item.valid_from)}</td><td class="asset-validity">${timestamp(item.valid_until)}${item.dhcp_last_seen?`<span class="asset-muted">DHCP last seen ${timestamp(item.dhcp_last_seen)}</span>`:''}</td><td><strong class="asset-name">${esc(item.source_type||'Operator inventory')}</strong><span class="asset-muted">${esc(item.source_ref||'No source reference')}</span></td><td><div class="asset-row-actions"><button class="asset-row-action" type="button" data-asset-edit="${esc(item.asset_id)}">Edit</button><button class="asset-row-action asset-demote" type="button" data-asset-demote="${esc(item.asset_id)}">Demote</button></div></td></tr>`};
      function render(){
        body.innerHTML=assets.length?assets.map(row).join(''):'<tr><td colspan="12" class="ir-loading">No current assets match this search.</td></tr>';
        body.dataset.liveRenderVersion=String(Number(body.dataset.liveRenderVersion||0)+1);
        const start=pageMeta.filtered_total?Number(pageMeta.offset||0)+1:0,end=Number(pageMeta.offset||0)+assets.length,total=Number(pageMeta.filtered_total||0),page=Math.floor(Number(pageMeta.offset||0)/Number(pageMeta.limit||100))+1,pages=Math.max(1,Math.ceil(total/Number(pageMeta.limit||100)));
        status.textContent=`Showing ${start}–${end} of ${total} matching current asset(s). PostgreSQL is authoritative for investigation identity.`;
        pageSummary.textContent=`Page ${page} of ${pages}`;
        previousPage.disabled=Number(pageMeta.offset||0)<=0;
        nextPage.disabled=!pageMeta.has_more;
      }
      function load(){
        if(assetLoadPromise)return assetLoadPromise;
        assetLoadPromise=(async()=>{
          errorBox.hidden=true;
          try{
          const params=new URLSearchParams({limit:pageSize.value,offset:String(pageOffset),search:search.value.trim(),sort:sort.value,direction:direction.value,state:'current'});
          const response=await fetch('/api/asset-inventory'+`?${params}`,{cache:'no-store'});
          const payload=await response.json();
          if(!response.ok||payload.ok===false)throw new Error(payload.error||`HTTP ${response.status}`);
          const nextSignature=stableSignature(payload);
          if(nextSignature===assetSignature)return false;
          assetSignature=nextSignature;
          assets=Array.isArray(payload.assets)?payload.assets:[];
          assetItems=new Map(assets.map(item=>[String(item.asset_id||''),item]));
          pageMeta=payload.page||{limit:Number(pageSize.value),offset:pageOffset,filtered_total:assets.length,has_more:false};
          document.getElementById('asset-records-total').textContent=Number(payload.records_total||0);
          document.getElementById('asset-current-total').textContent=Number(payload.current_asset_count||0);
          document.getElementById('asset-ip-total').textContent=Number(payload.current_ip_count||0);
          document.getElementById('asset-hostname-total').textContent=Number(payload.current_hostname_count||0);
          document.getElementById('asset-expired-total').textContent=Number(payload.state_counts?.expired||0);
          render();
          return true;
          }catch(error){
          errorBox.textContent=`Asset inventory unavailable: ${error.message}`;
          errorBox.hidden=false;
          body.innerHTML='<tr><td colspan="12" class="ir-loading">Known assets could not be loaded.</td></tr>';
          status.textContent='Inventory status unavailable.';
          }finally{assetLoadPromise=null}
        })();
        return assetLoadPromise;
      }
      const dhcpAction=item=>{const state=String(item.reconciliation||'candidate'),authority=item.authoritative_asset||null,configured=authority&&Array.isArray(authority.configured_ip_addresses)?authority.configured_ip_addresses:[],mac=String(item.mac_address||''),scope=String(item.mac_address_scope||'unknown');if(state==='candidate'&&!item.stale&&/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac)&&scope!=='multicast')return `<button class="dhcp-review-button" type="button" data-dhcp-promote="${esc(item.discovery_id)}">Promote</button>`;if(state==='verified_match'&&!item.stale&&authority&&!configured.includes(item.current_ip))return `<button class="dhcp-review-button" type="button" data-dhcp-ip-change="${esc(item.discovery_id)}">Approve IP</button>`;const note=item.stale?'Stale':state==='conflict'?'Resolve conflict':state==='verified_match'?'Already current':'Not eligible';return `<button class="dhcp-review-button" type="button" disabled>${esc(note)}</button>`};
      const dhcpRow=item=>{const state=String(item.reconciliation||'candidate');const authority=item.authoritative_asset;const macScope=String(item.mac_address_scope||'unknown').replaceAll('_',' ');return `<tr data-discovery-id="${esc(item.discovery_id)}"><td><span class="dhcp-reconciliation dhcp-${esc(state)}">${esc(state.replace('_',' '))}</span>${item.stale?'<span class="dhcp-stale">Stale observation</span>':''}<span class="asset-muted">${esc(item.reconciliation_detail||'')}</span></td><td>${values([item.current_ip],'dhcp-ip')}</td><td>${values(item.hostname?[item.hostname]:[],'asset-hostname')}</td><td>${values(item.mac_address?[item.mac_address]:[])}<span class="asset-muted">${esc(macScope)}</span></td><td>${authority?`<strong class="asset-name">${esc(authority.asset_id)}</strong><span class="asset-muted">${esc(authority.hostname||'No authoritative hostname')}</span>`:'<span class="asset-empty">Not registered</span>'}</td><td class="asset-validity"><span class="asset-muted">Lease expires</span>${timestamp(item.lease_expires_at)}<span class="asset-muted">Last seen</span>${timestamp(item.last_seen)}</td><td><strong class="asset-name">${Number(item.observation_count||0)} event(s)</strong><span class="asset-muted">${esc((item.message_types||[]).join(', ')||'Message type unavailable')}</span><span class="asset-muted">${esc((item.sensors||[]).join(', ')||'Sensor unavailable')}</span></td><td>${dhcpAction(item)}</td></tr>`};
      const field=id=>document.getElementById(id);
      const suggestedAssetId=item=>String(item.hostname||`dhcp-${item.discovery_id}`).toLowerCase().replace(/[^a-z0-9._-]+/g,'-').replace(/^-+|-+$/g,'').slice(0,160)||`dhcp-${item.discovery_id}`;
      const reviewAuth=field('dhcp-review-auth');
      const reviewAuthStatus=field('dhcp-review-auth-status');
      const reviewAdminLogin=field('dhcp-review-admin-login');
      function showReviewError(message,focusTarget=null){reviewError.textContent=message;reviewError.hidden=false;focusTarget?.focus()}
      function updateAdminStatus(required,authenticated){adminRequired=required===true;adminAuthenticated=authenticated===true;const ready=!adminRequired||adminAuthenticated;reviewAuth.classList.toggle('authenticated',ready);reviewAuthStatus.textContent=adminRequired?(adminAuthenticated?'Administration session active.':'Administration sign-in required.'):'Operator confirmation is active; Administration sign-in is not required.';reviewAdminLogin.hidden=!adminRequired||adminAuthenticated}
      async function refreshAdminSession(){try{const response=await fetch('/api/admin/session-status',{cache:'no-store',credentials:'same-origin'});const payload=await response.json();updateAdminStatus(payload.required===true,response.ok&&payload.authenticated===true);return !adminRequired||adminAuthenticated}catch(_){updateAdminStatus(false,false);return true}}
      function stopAdminPolling(){if(adminPollTimer){window.clearInterval(adminPollTimer);adminPollTimer=null}}
      function startAdminPolling(){if(adminPollTimer)return;adminPollTimer=window.setInterval(async()=>{if(!reviewItem){stopAdminPolling();return}if(await refreshAdminSession()){stopAdminPolling();try{adminWindow?.close()}catch(_){}if(resumeAfterAuth){resumeAfterAuth=false;await commitReview()}}},1000)}
      function closeReview(){stopAdminPolling();resumeAfterAuth=false;reviewModal.hidden=true;reviewItem=null;reviewMode='';reviewError.hidden=true;reviewForm.reset()}
      function openReview(item,mode){reviewItem=item;reviewMode=mode;reviewForm.reset();reviewError.hidden=true;updateAdminStatus(false,false);const authority=item.authoritative_asset||{};const promotion=mode==='promote';const confirmation=promotion?`PROMOTE:${item.discovery_id}`:`CHANGE-IP:${item.discovery_id}:${authority.asset_id}`;field('dhcp-review-title').textContent=promotion?'Promote DHCP identity':'Approve DHCP IP change';field('dhcp-review-summary').textContent=promotion?`${item.current_ip} · ${item.hostname||'no hostname'} · ${item.mac_address}`:`${authority.asset_id}: ${(authority.configured_ip_addresses||[]).join(', ')||'no current IP'} → ${item.current_ip}`;reviewPromotionFields.hidden=!promotion;reviewPromotionFields.querySelectorAll('input,select').forEach(control=>{control.disabled=!promotion});field('dhcp-review-asset-id').value=promotion?suggestedAssetId(item):String(authority.asset_id||'');field('dhcp-review-hostname').value=String(item.hostname||'');field('dhcp-review-role').value=promotion?'LAN client':String(authority.role||'');field('dhcp-review-platform').value=promotion?'':String(authority.platform||'');field('dhcp-review-criticality').value=String(authority.criticality||'unknown');reviewLocalMacField.hidden=!(promotion&&item.mac_address_scope==='locally_administered');field('dhcp-review-confirmation').textContent=confirmation;field('dhcp-review-confirm').placeholder=confirmation;reviewSubmit.textContent=promotion?'Promote asset':'Approve IP change';reviewSubmit.disabled=false;reviewModal.hidden=false;field('dhcp-review-operator').focus();refreshAdminSession()}
      function reviewPayload(){const authority=reviewItem.authoritative_asset||{};const promotion=reviewMode==='promote';const payload={discovery_id:reviewItem.discovery_id,expected_ip:reviewItem.current_ip,expected_mac:reviewItem.mac_address||'',expected_hostname:String(reviewItem.hostname||'').toLowerCase().replace(/\.$/,''),asset_id:promotion?field('dhcp-review-asset-id').value.trim():authority.asset_id,operator_ref:field('dhcp-review-operator').value.trim(),reason:field('dhcp-review-reason').value.trim(),confirm:field('dhcp-review-confirm').value.trim()};if(promotion)Object.assign(payload,{hostname:field('dhcp-review-hostname').value.trim(),role:field('dhcp-review-role').value.trim(),platform:field('dhcp-review-platform').value.trim(),criticality:field('dhcp-review-criticality').value,accept_locally_administered_mac:field('dhcp-review-local-mac').checked});return payload}
      function validateReview(){const promotion=reviewMode==='promote';const required=promotion?[[field('dhcp-review-asset-id'),'Enter an asset name.'],[field('dhcp-review-role'),'Enter an asset role.']]:[];required.push([field('dhcp-review-operator'),'Enter an operator reference.'],[field('dhcp-review-reason'),'Enter the reason for this inventory change.'],[field('dhcp-review-confirm'),'Type the displayed confirmation exactly.']);for(const [control,message] of required){if(!control.value.trim()){showReviewError(message,control);return false}}const authority=reviewItem.authoritative_asset||{};const expected=promotion?`PROMOTE:${reviewItem.discovery_id}`:`CHANGE-IP:${reviewItem.discovery_id}:${authority.asset_id}`;if(field('dhcp-review-confirm').value.trim()!==expected){showReviewError(`Confirmation must exactly match ${expected}.`,field('dhcp-review-confirm'));return false}if(promotion&&reviewItem.mac_address_scope==='locally_administered'&&!field('dhcp-review-local-mac').checked){showReviewError('Explicitly accept the locally administered MAC before promoting this identity.',field('dhcp-review-local-mac'));return false}return true}
      async function commitReview(){if(!reviewItem)return;reviewError.hidden=true;reviewSubmit.disabled=true;const promotion=reviewMode==='promote';reviewSubmit.textContent=promotion?'Promoting…':'Approving…';try{const endpoint=promotion?'/api/assets/promote-dhcp':'/api/assets/approve-dhcp-ip-change';const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json','X-Onion-Sentinel-Request':'dashboard'},credentials:'same-origin',body:JSON.stringify(reviewPayload())});const result=await response.json();if(response.status===403&&result.authentication_required===true){updateAdminStatus(true,false);resumeAfterAuth=true;startAdminPolling();showReviewError('Administration sign-in is required. Sign in using the link below; this change will resume automatically.');return}if(!response.ok||result.ok===false)throw new Error(result.error||`HTTP ${response.status}`);const promotedAssetId=String(result.asset_id||reviewItem.authoritative_asset?.asset_id||'');recentlyPromotedAssetId=promotedAssetId;closeReview();pageOffset=0;assetSignature='';dhcpSignature='';await Promise.all([load(),loadDhcp()]);const promotedRow=document.querySelector(`[data-asset-id="${CSS.escape(promotedAssetId)}"]`);promotedRow?.scrollIntoView({behavior:'smooth',block:'center'});status.textContent=`${promotedAssetId} was added to the authoritative Asset Inventory. ${status.textContent}`}catch(error){showReviewError(`Asset review was not committed: ${error.message}`)}finally{reviewSubmit.disabled=false;if(!reviewModal.hidden)reviewSubmit.textContent=reviewMode==='promote'?'Promote asset':'Approve IP change'}}
      async function submitReview(event){event.preventDefault();if(!reviewItem||!validateReview())return;reviewError.hidden=true;if(adminRequired&&adminAuthenticated!==true){resumeAfterAuth=true;adminWindow=window.open('/admin/login?resume=asset-review','onion-sentinel-admin-auth','popup,width=520,height=700');startAdminPolling();showReviewError('Administration sign-in is required. Complete sign-in in the Administration window; if it did not open, use the sign-in link below. This change will resume automatically.');return}await commitReview()}
      const splitIdentifiers=value=>String(value||'').split(/[,\n]/).map(item=>item.trim()).filter((item,index,list)=>item&&list.indexOf(item)===index);
      function showAssetReviewError(message,focusTarget=null){assetReviewError.textContent=message;assetReviewError.hidden=false;focusTarget?.focus()}
      function closeAssetReview(){assetReviewModal.hidden=true;assetReviewItem=null;assetReviewMode='';assetReviewError.hidden=true;assetReviewForm.reset()}
      function openAssetReview(item,mode){
        assetReviewItem=item;
        assetReviewMode=mode;
        assetReviewForm.reset();
        assetReviewError.hidden=true;
        const demoting=mode==='demote';
        const confirmation=`${demoting?'DEMOTE':'EDIT'}:${item.asset_id}`;
        field('asset-review-title').textContent=demoting?'Demote asset to DHCP review':'Edit authoritative asset';
        field('asset-review-summary').textContent=demoting?`${item.asset_id} will leave the authoritative table and return to DHCP review.`:`Update ${item.asset_id} without losing its prior version.`;
        assetEditFields.hidden=demoting;
        assetEditFields.querySelectorAll('input,select').forEach(control=>{control.disabled=demoting});
        assetDemoteWarning.hidden=!demoting;
        field('asset-review-asset-id').value=String(item.asset_id||'');
        field('asset-review-role').value=String(item.role||'');
        field('asset-review-ips').value=(item.ip_addresses||[]).join(', ');
        field('asset-review-macs').value=(item.mac_addresses||[]).join(', ');
        field('asset-review-hostnames').value=(item.hostnames||[]).join(', ');
        field('asset-review-platform').value=String(item.platform||'');
        field('asset-review-criticality').value=String(item.criticality||'unknown');
        field('asset-review-confidence').value=String(item.confidence||'unknown');
        field('asset-review-confirmation').textContent=confirmation;
        field('asset-review-confirm').placeholder=confirmation;
        assetReviewSubmit.textContent=demoting?'Demote asset':'Save asset';
        assetReviewSubmit.classList.toggle('asset-demote',demoting);
        assetReviewSubmit.disabled=false;
        assetReviewModal.hidden=false;
        field('asset-review-operator').focus();
      }
      function assetReviewPayload(){
        const payload={
          asset_id:assetReviewItem.asset_id,
          expected_valid_from:assetReviewItem.valid_from,
          operator_ref:field('asset-review-operator').value.trim(),
          reason:field('asset-review-reason').value.trim(),
          confirm:field('asset-review-confirm').value.trim(),
        };
        if(assetReviewMode==='edit')Object.assign(payload,{
          ip_addresses:splitIdentifiers(field('asset-review-ips').value),
          mac_addresses:splitIdentifiers(field('asset-review-macs').value),
          hostnames:splitIdentifiers(field('asset-review-hostnames').value),
          role:field('asset-review-role').value.trim(),
          platform:field('asset-review-platform').value.trim(),
          criticality:field('asset-review-criticality').value,
          confidence:field('asset-review-confidence').value,
        });
        return payload;
      }
      function validateAssetReview(){
        const required=[[field('asset-review-operator'),'Enter an operator reference.'],[field('asset-review-reason'),'Enter the reason for this asset change.'],[field('asset-review-confirm'),'Type the displayed confirmation exactly.']];
        if(assetReviewMode==='edit')required.unshift([field('asset-review-role'),'Enter an asset role.']);
        for(const [control,message] of required){if(!control.value.trim()){showAssetReviewError(message,control);return false}}
        if(assetReviewMode==='edit'&&!splitIdentifiers(field('asset-review-ips').value).length&&!splitIdentifiers(field('asset-review-macs').value).length&&!splitIdentifiers(field('asset-review-hostnames').value).length){showAssetReviewError('Retain at least one IP address, MAC address, or hostname.',field('asset-review-ips'));return false}
        const expected=`${assetReviewMode==='demote'?'DEMOTE':'EDIT'}:${assetReviewItem.asset_id}`;
        if(field('asset-review-confirm').value.trim()!==expected){showAssetReviewError(`Confirmation must exactly match ${expected}.`,field('asset-review-confirm'));return false}
        return true;
      }
      async function submitAssetReview(event){
        event.preventDefault();
        if(!assetReviewItem||!validateAssetReview())return;
        const demoting=assetReviewMode==='demote';
        const changedAssetId=String(assetReviewItem.asset_id||'');
        assetReviewError.hidden=true;
        assetReviewSubmit.disabled=true;
        assetReviewSubmit.textContent=demoting?'Demoting…':'Saving…';
        try{
          const response=await fetch(demoting?'/api/assets/demote':'/api/assets/update',{method:'POST',headers:{'Content-Type':'application/json','X-Onion-Sentinel-Request':'dashboard'},credentials:'same-origin',body:JSON.stringify(assetReviewPayload())});
          const result=await response.json();
          if(!response.ok||result.ok===false)throw new Error(result.error||`HTTP ${response.status}`);
          const returnedDiscovery=Array.isArray(result.discovery_ids)?String(result.discovery_ids[0]||''):'';
          closeAssetReview();
          recentlyPromotedAssetId=demoting?'':changedAssetId;
          assetSignature='';
          dhcpSignature='';
          await Promise.all([load(),loadDhcp()]);
          if(demoting&&assets.length===0&&pageOffset>0){pageOffset=Math.max(0,pageOffset-Number(pageSize.value));assetSignature='';await load()}
          const changedRow=demoting&&returnedDiscovery?document.querySelector(`[data-discovery-id="${CSS.escape(returnedDiscovery)}"]`):document.querySelector(`[data-asset-id="${CSS.escape(changedAssetId)}"]`);
          changedRow?.scrollIntoView({behavior:'smooth',block:'center'});
          status.textContent=demoting?`${changedAssetId} was demoted from the authoritative inventory and returned to DHCP review. ${status.textContent}`:`${changedAssetId} was updated. ${status.textContent}`;
        }catch(error){
          showAssetReviewError(`Asset change was not committed: ${error.message}`);
        }finally{
          assetReviewSubmit.disabled=false;
          if(!assetReviewModal.hidden)assetReviewSubmit.textContent=assetReviewMode==='demote'?'Demote asset':'Save asset';
        }
      }
      function loadDhcp(){
        if(dhcpLoadPromise)return dhcpLoadPromise;
        dhcpLoadPromise=(async()=>{
          dhcpError.hidden=true;
          try{
          const response=await fetch('/api/dhcp-asset-discovery',{cache:'no-store'});
          const payload=await response.json();
          if(!response.ok||payload.ok===false)throw new Error(payload.error||`HTTP ${response.status}`);
          const nextSignature=stableSignature(payload);
          if(nextSignature===dhcpSignature)return false;
          dhcpSignature=nextSignature;
          const items=Array.isArray(payload.observations)?payload.observations:[];
          dhcpItems=new Map(items.map(item=>[String(item.discovery_id||''),item]));
          const counts=payload.counts||{};
          document.getElementById('dhcp-total').textContent=Number(counts.total||0);
          document.getElementById('dhcp-matches').textContent=Number(counts.verified_match||0);
          document.getElementById('dhcp-candidates').textContent=Number(counts.candidate||0);
          document.getElementById('dhcp-conflicts').textContent=Number(counts.conflict||0);
          document.getElementById('dhcp-stale').textContent=Number(counts.stale||0);
          const collection=payload.collection||{},collectionState=String(collection.status||'unknown'),backfill=payload.backfill||{};
          dhcpBadge.textContent=collectionState.replace('_',' ');
          const last=collection.last_success_at?` Last successful collection: ${collection.last_success_at}.`:' No successful collection has been recorded.';
          const warning=collection.last_error?` ${collection.last_error}`:'';
          const history=backfill.last_success_at?` Historical backfill: ${backfill.status||'ok'}, through ${backfill.covered_through||backfill.requested_end}.`:' Historical backfill has not run.';
          dhcpStatus.textContent=`Collector status: ${collectionState}.${last}${history}${warning}`;
          dhcpBody.innerHTML=items.length?items.map(dhcpRow).join(''):'<tr><td colspan="8" class="ir-loading">No DHCP identities have been observed yet. The restricted relay collector may still need to be enabled.</td></tr>';
          dhcpBody.dataset.liveRenderVersion=String(Number(dhcpBody.dataset.liveRenderVersion||0)+1);
          await load();
          return true;
          }catch(error){
          dhcpError.textContent=`DHCP discovery unavailable: ${error.message}`;
          dhcpError.hidden=false;
          dhcpBadge.textContent='unavailable';
          dhcpStatus.textContent='DHCP collection status unavailable.';
          dhcpBody.innerHTML='<tr><td colspan="8" class="ir-loading">DHCP observations could not be loaded.</td></tr>';
          }finally{dhcpLoadPromise=null}
        })();
        return dhcpLoadPromise;
      }
      const resetAndLoad=()=>{pageOffset=0;assetSignature='';load()};
      search.addEventListener('input',render);
      search.addEventListener('input',()=>{window.clearTimeout(searchTimer);searchTimer=window.setTimeout(resetAndLoad,250)});
      sort.addEventListener('change',resetAndLoad);direction.addEventListener('change',resetAndLoad);pageSize.addEventListener('change',resetAndLoad);
      previousPage.addEventListener('click',()=>{pageOffset=Math.max(0,pageOffset-Number(pageSize.value));assetSignature='';load()});
      nextPage.addEventListener('click',()=>{if(pageMeta.has_more){pageOffset+=Number(pageSize.value);assetSignature='';load()}});
      body.addEventListener('click',event=>{const edit=event.target.closest('[data-asset-edit]'),demote=event.target.closest('[data-asset-demote]'),id=edit?.dataset.assetEdit||demote?.dataset.assetDemote,item=assetItems.get(String(id||''));if(item)openAssetReview(item,demote?'demote':'edit')});
      dhcpBody.addEventListener('click',event=>{const promote=event.target.closest('[data-dhcp-promote]'),change=event.target.closest('[data-dhcp-ip-change]'),id=promote?.dataset.dhcpPromote||change?.dataset.dhcpIpChange,item=dhcpItems.get(String(id||''));if(item)openReview(item,promote?'promote':'ip_change')});
      reviewForm.addEventListener('submit',submitReview);
      assetReviewForm.addEventListener('submit',submitAssetReview);
      reviewAdminLogin.addEventListener('click',startAdminPolling);
      field('dhcp-review-close').addEventListener('click',closeReview);
      field('dhcp-review-cancel').addEventListener('click',closeReview);
      field('asset-review-close').addEventListener('click',closeAssetReview);
      field('asset-review-cancel').addEventListener('click',closeAssetReview);
      reviewModal.addEventListener('click',event=>{if(event.target===reviewModal)closeReview()});
      assetReviewModal.addEventListener('click',event=>{if(event.target===assetReviewModal)closeAssetReview()});
      document.addEventListener('keydown',event=>{if(event.key==='Escape'&&!reviewModal.hidden)closeReview();else if(event.key==='Escape'&&!assetReviewModal.hidden)closeAssetReview()});
      load();loadDhcp();
      const assetLiveRefresh=async()=>{const results=await Promise.all([load(),loadDhcp()]);return results.some(Boolean)};
      const assetCanRefresh=()=>reviewModal.hidden&&assetReviewModal.hidden;
      if(window.OnionSentinelReactiveTables){
        window.OnionSentinelReactiveTables.register('asset-inventory-tables',assetLiveRefresh,{intervalMs:60000,when:assetCanRefresh,revisionKey:'asset_inventory'});
        window.OnionSentinelReactiveTables.register('dhcp-asset-discovery',loadDhcp,{intervalMs:60000,when:assetCanRefresh,revisionKey:'dhcp_asset_discovery'});
      }else{
        window.setInterval(()=>{if(assetCanRefresh())assetLiveRefresh()},60000);
      }
    })();
    </script>'''


def asset_inventory_page_section() -> str:
    """Render current authoritative asset-to-address assignments."""
    return ASSET_INVENTORY_PAGE_SECTION
