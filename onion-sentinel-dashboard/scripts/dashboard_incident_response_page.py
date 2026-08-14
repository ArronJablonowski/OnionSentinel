"""Pure Incident Responder page renderer and bounded browser client."""
from __future__ import annotations


INCIDENT_RESPONSE_MARKUP = r'''
    <section id="incident-response-view" class="view-section active ir-view" aria-label="Incident response cases">
      <div class="ir-metrics" aria-label="Incident response metrics">
        <div><span>Total cases</span><strong id="ir-total">0</strong></div>
        <div><span>Open</span><strong id="ir-open">0</strong></div>
        <div><span>Analyzing</span><strong id="ir-analyzing">0</strong></div>
        <div><span>Analyzed</span><strong id="ir-analyzed">0</strong></div>
        <div><span>Failed</span><strong id="ir-failed">0</strong></div>
      </div>
      <div class="ir-toolbar">
        <button id="ir-reanalyze-all" class="ir-reanalyze-all" type="button">Reanalyze all cases</button>
        <label>Status
          <select id="ir-status-filter">
            <option value="all">All cases</option>
            <option value="open">Open</option>
            <option value="in_progress">In progress</option>
            <option value="resolved">Resolved</option>
          </select>
        </label>
        <label>Rows
          <select id="ir-page-size">
            <option>10</option><option selected>25</option><option>50</option><option>100</option>
          </select>
        </label>
      </div>
      <section id="ir-reanalysis-progress" class="ir-reanalysis-progress" aria-live="polite" hidden></section>
      <div id="ir-error" class="ir-error" role="alert" hidden></div>
      <div class="ir-table-wrap">
        <table class="ir-table">
          <colgroup>
            <col class="ir-col-expand"><col class="ir-col-case">
            <col class="ir-col-escalated"><col class="ir-col-alert">
            <col class="ir-col-assessment"><col class="ir-col-network">
            <col class="ir-col-count"><col class="ir-col-agent">
            <col class="ir-col-actions">
          </colgroup>
          <thead><tr>
            <th aria-label="Expand"></th>
            <th><button class="ir-sort" type="button" data-ir-sort="status">Case</button></th>
            <th><button class="ir-sort" type="button" data-ir-sort="escalated">Escalated</button></th>
            <th><button class="ir-sort" type="button" data-ir-sort="alert">Alert</button></th>
            <th>Assessment</th>
            <th><button class="ir-sort" type="button" data-ir-sort="source">Network path</button></th>
            <th><button class="ir-sort" type="button" data-ir-sort="count">Count</button></th>
            <th><button class="ir-sort" type="button" data-ir-sort="agent">Agent</button></th>
            <th>Actions</th>
          </tr></thead>
          <tbody id="ir-table-body"><tr><td colspan="9" class="ir-loading">Loading incident cases...</td></tr></tbody>
        </table>
      </div>
      <div id="ir-mobile-list" class="ir-mobile-list" aria-label="Incident response cases"></div>
      <div class="ir-pagination">
        <button id="ir-previous" type="button">Previous</button>
        <span id="ir-page-label">Page 1 of 1</span>
        <button id="ir-next" type="button">Next</button>
      </div>
    </section>
'''


INCIDENT_RESPONSE_CSS = r'''    <style>
      .ir-sort{display:inline-flex;align-items:center;gap:5px;padding:4px 2px;color:inherit;background:none;border:0;font:inherit;text-transform:inherit;cursor:pointer}.ir-sort:hover,.ir-sort:focus-visible{color:#75efff}.ir-sort[aria-sort="ascending"]:after{content:"▲";font-size:.62rem}.ir-sort[aria-sort="descending"]:after{content:"▼";font-size:.62rem}
      .ir-view{display:block;padding:0 0 28px}.ir-metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin:0 0 16px}.ir-metrics>div{min-height:84px;padding:16px 18px;border:1px solid #223341;background:#0d1822;border-radius:8px}.ir-metrics span{display:block;color:#9caec2;font-size:.76rem;font-weight:800;text-transform:uppercase}.ir-metrics strong{display:block;margin-top:7px;color:#75efff;font-size:1.55rem}.ir-toolbar{display:flex;justify-content:flex-end;gap:14px;align-items:end;margin:0 0 12px}.ir-toolbar label{color:#9caec2;font-size:.76rem;font-weight:800;text-transform:uppercase}.ir-toolbar select{display:block;min-height:44px;margin-top:5px;padding:0 38px 0 12px;color:#e9f2ff;background:#0b1620;border:1px solid #07566a;border-radius:8px}.ir-reanalyze-all,.ir-reanalyze-case{min-height:40px;padding:0 12px;color:#dffbff;background:#0a1a24;border:1px solid #08758c;border-radius:8px;font-weight:850;cursor:pointer}.ir-reanalyze-all{min-height:44px;margin-right:auto}.ir-reanalyze-all:hover,.ir-reanalyze-case:hover{border-color:#35d9ec;color:#75efff}.ir-reanalyze-all:disabled,.ir-reanalyze-case:disabled{opacity:.55;cursor:wait}.ir-reanalyze-case{display:block;min-height:32px;margin-top:8px;padding:4px 8px;font-size:.7rem}.ir-reanalysis-progress{display:grid;gap:9px;margin:0 0 12px;padding:13px 15px;border:1px solid #185367;border-radius:8px;background:#0b1b26}.ir-reanalysis-progress strong{color:#eef5ff}.ir-reanalysis-identifiers,.ir-reanalysis-counts{display:flex;flex-wrap:wrap;gap:7px 14px;color:#a9bbce;font-size:.78rem}.ir-reanalysis-counts b{color:#75efff}.ir-error{margin:0 0 12px;padding:12px 14px;color:#ffb8c3;background:#25131a;border:1px solid #7f3345;border-radius:8px}.ir-table-wrap{overflow-x:auto;border:1px solid #223341;border-radius:8px;background:#09131d}.ir-table{width:100%;min-width:1510px;border-collapse:collapse;table-layout:fixed}.ir-table col.ir-col-expand{width:60px}.ir-table col.ir-col-status{width:112px}.ir-table col.ir-col-severity{width:128px}.ir-table col.ir-col-escalated{width:264px}.ir-table col.ir-col-alert{width:auto}.ir-table col.ir-col-source{width:152px}.ir-table col.ir-col-destination{width:152px}.ir-table col.ir-col-destination-port{width:118px}.ir-table col.ir-col-count{width:76px}.ir-table col.ir-col-agent{width:148px}.ir-table th,.ir-table td{padding:14px 12px;text-align:left;border-bottom:1px solid #1e303d;vertical-align:middle}.ir-table th{color:#9caec2;background:#101e2a;font-size:.75rem;text-transform:uppercase}.ir-table th:first-child,.ir-case-row td:first-child{padding-left:8px;padding-right:8px;text-align:center}.ir-table th:nth-child(9),.ir-case-row td:nth-child(9){text-align:center}.ir-case-row{cursor:pointer}.ir-case-row:hover td,.ir-case-row:focus-within td{background:#0e202b}.ir-expand{width:40px;height:40px;border:1px solid #07566a;border-radius:7px;background:#0a1a24;color:#75efff;cursor:pointer}.ir-alert-title{display:block;color:#eef5ff;line-height:1.35;overflow-wrap:anywhere}.ir-muted{display:block;margin-top:4px;color:#8fa2b8;font-size:.8rem;line-height:1.35}.ir-escalated{white-space:nowrap;font-variant-numeric:tabular-nums;color:#c8d6e6}.ir-code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#d8e7f8;white-space:nowrap}.ir-status,.ir-agent{display:inline-block;white-space:nowrap;font-size:.72rem;font-weight:900;text-transform:uppercase}.ir-status-open,.ir-agent-queued{color:#ffcb67}.ir-status-in_progress,.ir-agent-analyzing{color:#75efff}.ir-status-resolved,.ir-agent-analyzed{color:#69e89a}.ir-agent-failed{color:#ff7088}.ir-severity-critical{color:#ff6681}.ir-severity-high{color:#ff963e}.ir-severity-medium{color:#ffca67}.ir-severity-low{color:#72e99c}.ir-severity-informational{color:#75efff}.ir-detail-row td{padding:0;background:#07111a;text-align:left}.ir-detail-shell,.ir-detail-content{text-align:left}.ir-detail-shell{padding:18px 20px 24px;border-left:3px solid #1fc7dc}.ir-investigation-report,.ir-query-audit{margin-bottom:14px;padding:18px;border:1px solid #184352;border-radius:8px;background:#0c1924}.ir-investigation-report>h3,.ir-query-audit>h3{margin:0 0 12px;color:#eef5ff}.ir-analysis-meta{display:flex;flex-wrap:wrap;gap:8px 18px;margin-bottom:14px;color:#9caec2;font-size:.83rem}.ir-report-subsection{padding:14px 0;border-top:1px solid #19313d}.ir-report-subsection h4{margin:0 0 8px;color:#eef5ff}.ir-report-subsection p,.ir-report-list{margin:0;color:#c6d3e2;line-height:1.55;white-space:pre-wrap}.ir-report-list{padding-left:22px}.ir-timeline-wrap{max-width:100%;overflow-x:auto}.ir-timeline-table{width:100%;min-width:920px;border-collapse:collapse;table-layout:auto}.ir-timeline-table th,.ir-timeline-table td{padding:10px;text-align:left;vertical-align:top;border-bottom:1px solid #1e303d}.ir-timeline-table th{color:#9caec2;background:#101e2a}.ir-query-record{padding:0;border-top:1px solid #19313d}.ir-query-details>summary{position:relative;display:grid;gap:4px;min-height:64px;padding:14px 44px 14px 4px;color:#eef5ff;cursor:pointer;list-style:none}.ir-query-details>summary>span{min-width:0;overflow-wrap:anywhere}.ir-query-details>summary::-webkit-details-marker{display:none}.ir-query-details>summary:after{content:"›";position:absolute;right:14px;top:50%;color:#75efff;font-size:26px;line-height:1;transform:translateY(-50%);transition:transform .16s ease}.ir-query-details[open]>summary:after{transform:translateY(-50%) rotate(90deg)}.ir-query-details>summary:hover,.ir-query-details>summary:focus-visible{background:rgba(34,211,238,.045)}.ir-query-summary-title{color:#eef5ff;font-size:.94rem;font-weight:850}.ir-query-summary-purpose{color:#a9bbce;font-size:.8rem;line-height:1.4}.ir-query-summary-finding{color:#75efff;font-size:.77rem;font-weight:750;line-height:1.35}.ir-query-record-content{padding:2px 4px 16px}.ir-query-record h4,.ir-query-record h5{margin:0 0 9px;color:#eef5ff}.ir-query-record h5{margin-top:14px;color:#9caec2}.ir-query-meta{display:flex;flex-wrap:wrap;gap:7px 16px;color:#9caec2;font-size:.82rem}.ir-query-code-heading{display:flex;align-items:center;gap:10px;margin-top:14px}.ir-query-code-heading h5{flex:1 1 auto;min-width:0;margin:0}.ir-query-copy{min-height:34px;padding:6px 11px;border:1px solid #07566a;border-radius:7px;color:#d9f7fb;background:#071722;font-size:.76rem;font-weight:850;cursor:pointer}.ir-query-copy:hover,.ir-query-copy:focus-visible{border-color:#1fc7dc;color:#75efff}.ir-query-copy:disabled{opacity:.72;cursor:wait}.ir-copy-feedback{min-width:76px;color:#9caec2;font-size:.75rem;font-weight:800}.ir-copy-feedback:empty{display:none}.ir-copy-feedback[data-state="success"]{color:#69e89a}.ir-copy-feedback[data-state="error"]{color:#ff7088}.ir-query-code{max-width:100%;max-height:420px;margin:8px 0 0;padding:13px;overflow:auto;color:#d8e7f8;background:#061019;border:1px solid #1d3442;border-radius:7px;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre}.ir-prior-ai{margin:0;padding:0;border:1px solid #223341;border-radius:8px;background:#0c1924;overflow:hidden}.ir-prior-ai>summary{min-height:52px;padding:15px 18px;color:#eef5ff;font-weight:800;cursor:pointer}.ir-prior-ai[open]>summary{border-bottom:1px solid #223341}.ir-prior-analysis{padding:4px 18px 16px}.ir-analysis-empty{color:#9caec2}.ir-loading{text-align:center!important;color:#9caec2}.ir-pagination{display:flex;justify-content:flex-end;align-items:center;gap:12px;padding:14px 0}.ir-pagination button{min-height:44px;padding:0 16px;color:#e8f1fc;background:#0b1620;border:1px solid #07566a;border-radius:8px}.ir-pagination button:disabled{opacity:.45}.ir-mobile-list{display:none}.ir-mobile-card{border:1px solid #223341;border-radius:8px;background:#0b1721;overflow:hidden}.ir-mobile-toggle{width:100%;min-height:76px;padding:14px;text-align:left;color:inherit;background:none;border:0}.ir-mobile-top{display:flex;justify-content:space-between;gap:12px;margin-bottom:8px}.ir-mobile-detail{padding:0 14px 16px;border-top:1px solid #1e303d;text-align:left}.ir-mobile-list{gap:10px}
      .ir-table{min-width:1220px}.ir-table col.ir-col-expand{width:48px}.ir-table col.ir-col-case{width:94px}.ir-table col.ir-col-escalated{width:150px}.ir-table col.ir-col-alert{width:auto}.ir-table col.ir-col-assessment{width:190px}.ir-table col.ir-col-network{width:300px}.ir-table col.ir-col-count{width:58px}.ir-table col.ir-col-agent{width:108px}.ir-table col.ir-col-actions{width:112px}.ir-table th,.ir-table td{padding:13px 10px}.ir-case-row td{background:#09141d}.ir-case-row:nth-of-type(4n+1) td{background:#0a1620}.ir-case-cell{display:grid;gap:7px;align-content:center}.ir-case-cell .ir-status{width:max-content}.ir-case-cell .ir-severity-label{font-size:.68rem;font-weight:900;letter-spacing:.04em;text-transform:uppercase}.ir-escalated{white-space:nowrap}.ir-escalated-date,.ir-escalated-time{display:block;font-variant-numeric:tabular-nums}.ir-escalated-date{color:#d7e3ef;font-weight:780}.ir-escalated-time{margin-top:3px;color:#8397ab;font-size:.75rem}.ir-assessment-cell .review-badge-row{margin:0;align-items:flex-start}.ir-table td.ir-network-cell{padding-left:6px;padding-right:6px}.ir-network-path{display:grid;grid-template-columns:minmax(0,1fr) 14px minmax(0,1fr);gap:3px;align-items:start}.ir-network-endpoint{min-width:0}.ir-network-label{display:block;margin-bottom:3px;color:#73879a;font-size:.62rem;font-weight:900;letter-spacing:.05em;text-transform:uppercase}.ir-network-value{display:block;color:#d8e7f8;font:700 11.5px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere;white-space:normal}.ir-network-hostname{display:block;margin-top:4px;color:#69e89a;font-size:.68rem;font-weight:800;line-height:1.3;overflow-wrap:anywhere}.ir-network-hostname.ir-network-ambiguous{color:#ffcb67}.ir-network-arrow{margin-top:15px;color:#35d9ec;text-align:center;line-height:1.35}.ir-count-value{display:inline-grid;min-width:34px;height:28px;padding:0 7px;place-items:center;border:1px solid #214153;border-radius:999px;color:#dffaff;background:#0b1e29;font-weight:900}.ir-agent-cell{display:grid;gap:5px;justify-items:start}.ir-agent-model{max-width:100%;overflow:hidden;color:#8195aa;font:10.5px/1.3 ui-monospace,SFMono-Regular,Menlo,monospace;text-overflow:ellipsis;white-space:nowrap}.ir-actions-cell{display:grid;gap:7px}.ir-actions-cell .review-action-button,.ir-actions-cell .ir-reanalyze-case{width:100%;min-height:32px;margin:0;padding:5px 7px;font-size:.68rem}.ir-agent{white-space:normal;line-height:1.35}.ir-agent-analysis_failed{color:#ff7088}.ir-agent-review_failed{color:#ffb15c}.ir-agent-refresh_failed{color:#ffcb67}
      .ir-agent-skipped{color:#ffcb67}
      @media(max-width:900px){.ir-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.ir-metrics>div:last-child{grid-column:span 2}.ir-toolbar{justify-content:space-between}.ir-table-wrap{display:none}.ir-mobile-list{display:grid}.ir-detail-shell{padding:14px 0}.ir-pagination{justify-content:center}}
      @media(max-width:480px){.ir-metrics{gap:8px}.ir-metrics>div{min-height:72px;padding:12px}.ir-toolbar{align-items:stretch}.ir-toolbar label{flex:1}.ir-toolbar select{width:100%}}
    </style>
'''


INCIDENT_RESPONSE_JS = r'''    <script>
    (() => {
      const body=document.getElementById('ir-table-body');
      const mobile=document.getElementById('ir-mobile-list');
      if(!body||!mobile)return;
      const filter=document.getElementById('ir-status-filter');
      const pageSize=document.getElementById('ir-page-size');
      const previous=document.getElementById('ir-previous');
      const next=document.getElementById('ir-next');
      const pageLabel=document.getElementById('ir-page-label');
      const errorBox=document.getElementById('ir-error');
      const reanalyzeAll=document.getElementById('ir-reanalyze-all');
      const reanalysisProgress=document.getElementById('ir-reanalysis-progress');
      let page=1,pages=1,incidents=[],openCase='',sortKey='priority',sortDirection='desc',loadPromise=null,incidentSignature='',reanalysisSignature='';
      const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
      const severity=item=>String(item.triage_level||item.severity_label||'informational').toLowerCase().replace(/[^a-z]/g,'')||'informational';
      const label=value=>String(value||'unknown').replaceAll('_',' ');
      const escalatedHtml=value=>{const text=String(value||'').trim();if(!text)return '<span class="ir-escalated-date">n/a</span>';const match=text.match(/^(\d{4}-\d{2}-\d{2})[ T]+(\d{2}:\d{2}:\d{2})(.*)$/);return match?`<span class="ir-escalated-date">${esc(match[1])}</span><span class="ir-escalated-time">${esc(match[2]+match[3])}</span>`:`<span class="ir-escalated-date">${esc(text)}</span>`};
      const assetIdentityHtml=asset=>{const status=String(asset?.status||'unmapped');if(status==='resolved'&&asset.hostname)return `<span class="ir-network-hostname" title="Asset ${esc(asset.asset_id||'')} · ${esc(asset.confidence||'unknown')} confidence">${esc(asset.hostname)}</span>`;if(status==='ambiguous')return '<span class="ir-network-hostname ir-network-ambiguous" title="Multiple active inventory records claim this address">Ambiguous mapping</span>';return ''};
      const networkHtml=item=>{const source=item.source_ip||'n/a',destination=item.destination_ip||'n/a',port=item.destination_port;return `<div class="ir-network-path"><span class="ir-network-endpoint"><span class="ir-network-label">Source</span><code class="ir-network-value" title="${esc(source)}">${esc(source)}</code>${assetIdentityHtml(item.source_asset)}</span><span class="ir-network-arrow" aria-hidden="true">→</span><span class="ir-network-endpoint"><span class="ir-network-label">Destination</span><code class="ir-network-value" title="${esc(destination)}${port?':'+esc(port):''}">${esc(destination)}${port?`:${esc(port)}`:''}</code>${assetIdentityHtml(item.destination_asset)}</span></div>`};
      const reviewBadges=item=>{const finalStatus=String(item.final_review_status||'unreviewed'),statusClass=finalStatus==='disputed_pending_human'?'disputed':finalStatus==='model_consensus'?'consensus':finalStatus,statusLabel=finalStatus==='disputed_pending_human'?'Disputed':finalStatus==='review_required_failed'?'Review failed':finalStatus==='model_consensus'?'Models agree':finalStatus==='review_completed_not_authorized'?'Review complete · human decision':finalStatus==='reviewer_advisory'?'Reviewer advisory':finalStatus==='adjudicated'?'Adjudicated':'Unreviewed',reviewerError=String(item.reviewer_error||''),freshness=String(item.freshness_status||'not_analyzed'),coverage=String(item.coverage_status||'unknown'),confidence=String(item.effective_confidence||item.analysis_confidence||'');return `<span class="review-badge-row"><span class="review-badge review-badge-${esc(statusClass)}"${reviewerError?` title="${esc(reviewerError)}"`:''}>${esc(statusLabel)}</span><span class="review-badge review-freshness-${esc(freshness)}">Freshness: ${esc(label(freshness))}</span><span class="review-badge review-coverage-${esc(coverage)}">Coverage: ${esc(label(coverage))}</span>${confidence?`<span class="review-badge review-badge-confidence">Confidence: ${esc(confidence)}</span>`:''}</span>`};
      const queryPurposes={
        alert_context:'Review the triggering detection and its immediate alert context.',
        network_flow:'Review related network connections and traffic metadata.',
        dns_activity:'Review DNS activity related to the alert observables.',
        osquery_history:'Review prior OSquery evidence associated with the alert.',
        cross_sensor_timeline:'Correlate related activity across available sensors.',
        system_inventory:'Review the target system inventory.',
        logged_in_users:'Review users currently logged in to the target.',
        listening_ports:'Review listening network services on the target.',
        process_inventory:'Review running processes on the target.',
        installed_packages:'Review installed software packages on the target.',
        scheduled_tasks:'Review scheduled tasks on the target.',
        startup_items:'Review configured startup items on the target.',
      };
      const queryPack=heading=>{
        const text=String(heading?.textContent||'').trim();
        const separator=text.indexOf(':');
        return (separator>=0?text.slice(separator+1):text).trim()||'evidence_pack';
      };
      const queryPurpose=pack=>{
        const normalized=String(pack||'evidence_pack').trim().toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'');
        return queryPurposes[normalized]||`Review ${label(normalized||'evidence')} evidence.`;
      };
      const queryMetaValue=(meta,name)=>{
        const wanted=String(name||'').toLowerCase();
        const entry=[...(meta?.querySelectorAll('span')||[])].find(node=>String(node.querySelector('b')?.textContent||'').replace(':','').trim().toLowerCase()===wanted);
        if(!entry)return '';
        const clone=entry.cloneNode(true);
        clone.querySelector('b')?.remove();
        return String(clone.textContent||'').trim();
      };
      const queryFinding=(record,meta)=>{
        const linked=String(record?.dataset?.queryFinding||'').trim();
        const status=queryMetaValue(meta,'Status');
        const hits=queryMetaValue(meta,'Hits');
        const rows=queryMetaValue(meta,'Rows');
        const records=queryMetaValue(meta,'Records');
        const countText=hits||rows||records;
        const countMatch=countText.match(/(\d+)\s+total\s*\/\s*(\d+)\s+returned/i);
        const recordMatch=countText.match(/(\d+)\s+scanned\s*\/\s*(\d+)\s+returned/i);
        const unit=hits?'hits':rows?'rows':'records';
        const parts=[];
        if(countMatch)parts.push(`${countMatch[1]} total ${unit}; ${countMatch[2]} returned.`);
        else if(recordMatch)parts.push(`${recordMatch[1]} ${unit} scanned; ${recordMatch[2]} returned.`);
        else if(countText)parts.push(`${countText}.`);
        if(status)parts.push(`Status: ${status}.`);
        if(record.querySelector('.ir-query-error'))parts.push('The query recorded an error.');
        const resultSummary=parts.join(' ')||'No query result summary was recorded.';
        return linked
          ? `${resultSummary} Responder finding: ${linked}`
          : `${resultSummary} No query-linked responder finding was recorded.`;
      };
      async function copyExactQuery(value){
        if(navigator.clipboard?.writeText){
          try{await navigator.clipboard.writeText(value);return}catch(_){}
        }
        const field=document.createElement('textarea');
        field.value=value;
        field.setAttribute('readonly','');
        field.setAttribute('aria-hidden','true');
        field.style.position='fixed';
        field.style.left='-10000px';
        field.style.top='0';
        field.style.opacity='0';
        document.body.appendChild(field);
        field.focus();
        field.select();
        field.setSelectionRange(0,field.value.length);
        let copied=false;
        try{copied=Boolean(document.execCommand?.('copy'))}finally{field.remove()}
        if(!copied)throw new Error('Clipboard copy is unavailable');
      }
      function addQueryCopyControl(pre,title){
        if(pre.dataset.copyEnhanced==='true')return;
        const code=pre.querySelector('code');
        const heading=pre.previousElementSibling;
        if(!code||!heading?.matches('h5'))return;
        const headingText=String(heading.textContent||'').trim();
        if(!/^(OQL|KQL|Elasticsearch Query DSL|OSquery SQL|Structured PCAP\/Zeek request)\b/i.test(headingText))return;
        pre.dataset.copyEnhanced='true';
        const toolbar=document.createElement('div');
        toolbar.className='ir-query-code-heading';
        heading.before(toolbar);
        const button=document.createElement('button');
        button.type='button';
        button.className='ir-query-copy';
        button.textContent='Copy';
        button.setAttribute('aria-label',`Copy ${headingText} for ${title}`);
        const feedback=document.createElement('span');
        feedback.className='ir-copy-feedback';
        feedback.setAttribute('role','status');
        feedback.setAttribute('aria-live','polite');
        toolbar.append(heading,button,feedback);
        button.addEventListener('click',async event=>{
          event.preventDefault();
          event.stopPropagation();
          const previousTimer=Number(button.dataset.resetTimer||0);
          if(previousTimer)window.clearTimeout(previousTimer);
          button.disabled=true;
          button.textContent='Copying…';
          feedback.textContent='';
          delete feedback.dataset.state;
          try{
            await copyExactQuery(code.textContent||'');
            button.textContent='Copied';
            feedback.textContent='Copied exact query.';
            feedback.dataset.state='success';
          }catch(_){
            button.textContent='Try again';
            feedback.textContent='Copy failed — select and copy the query manually.';
            feedback.dataset.state='error';
          }finally{
            button.disabled=false;
            button.dataset.resetTimer=String(window.setTimeout(()=>{
              button.textContent='Copy';
              feedback.textContent='';
              delete feedback.dataset.state;
              delete button.dataset.resetTimer;
            },2400));
          }
        });
      }
      function enhanceIncidentQueryAudit(root){
        root.querySelectorAll('.ir-query-record').forEach(record=>{
          if(record.dataset.queryEnhanced==='true')return;
          const heading=record.querySelector(':scope > h4');
          const meta=record.querySelector(':scope > .ir-query-meta');
          if(!heading)return;
          record.dataset.queryEnhanced='true';
          const title=String(heading.textContent||'Query audit').trim();
          const pack=queryPack(heading);
          const details=document.createElement('details');
          details.className='ir-query-details';
          const summary=document.createElement('summary');
          const summaryTitle=document.createElement('span');
          summaryTitle.className='ir-query-summary-title';
          summaryTitle.textContent=title;
          const summaryPurpose=document.createElement('span');
          summaryPurpose.className='ir-query-summary-purpose';
          summaryPurpose.textContent=String(record.dataset.queryPurpose||'').trim()||queryPurpose(pack);
          const summaryFinding=document.createElement('span');
          summaryFinding.className='ir-query-summary-finding';
          summaryFinding.textContent=queryFinding(record,meta);
          summary.append(summaryTitle,summaryPurpose,summaryFinding);
          const content=document.createElement('div');
          content.className='ir-query-record-content';
          [...record.childNodes].forEach(node=>{if(node!==heading)content.appendChild(node)});
          heading.remove();
          details.append(summary,content);
          record.appendChild(details);
          content.querySelectorAll('pre.ir-query-code').forEach(pre=>addQueryCopyControl(pre,title));
        });
      }
      const reviewButton=item=>{const analysisId=item.analysis_id||'';return `<button class="review-action-button" type="button" data-adjudicate="${esc(item.dashboard_group_id||'')}" data-review-case="${esc(item.case_id||'')}" data-analysis-id="${esc(analysisId)}" data-primary-outcome="${esc(item.primary_outcome||item.detection_outcome||'')}" data-event-status="${esc(item.primary_event_status||'')}" data-detection-validity="${esc(item.primary_detection_validity||'')}" data-activity-disposition="${esc(item.primary_activity_disposition||'')}" data-handling="${esc(item.primary_handling||'')}" data-duplicate-of="${esc(item.primary_duplicate_of||'')}" ${analysisId?'':'disabled title="Run an analysis before recording an analyst decision"'}>Review</button>`};
      const reanalysisButton=item=>`<button class="ir-reanalyze-case" type="button" data-reanalyze-case="${esc(item.case_id||'')}" title="Queue a fresh case-bound Incident Responder investigation">Reanalyze</button>`;
      const caseSummary=item=>item.status==='resolved'&&item.resolution_reason?`Resolved: ${item.resolution_reason}${item.resolved_by?` · ${item.resolved_by}`:''}${item.resolved_at?` · ${item.resolved_at}`:''}`:(item.reason||'Escalated for incident response');
      const rowHtml=item=>{const level=severity(item),agentState=item.agent_display_status||item.agent_status,agentLabel=item.agent_display_label||label(item.agent_status);return `<tr class="ir-case-row" tabindex="0" data-case-id="${esc(item.case_id)}" data-final-review-status="${esc(item.final_review_status||'unreviewed')}"><td><button class="ir-expand" type="button" aria-expanded="false" aria-label="Expand incident case">&#9662;</button></td><td><div class="ir-case-cell"><span class="ir-status ir-status-${esc(item.status)}">${esc(label(item.status))}</span><span class="ir-severity-label ir-severity-${esc(level)}">${esc(level)}</span></div></td><td class="ir-escalated" title="${esc(item.escalated_at||'')}">${escalatedHtml(item.escalated_at)}</td><td><strong class="ir-alert-title">${esc(item.rule_name||'Security Onion alert')}</strong><span class="ir-muted">${esc(caseSummary(item))}</span></td><td class="ir-assessment-cell">${reviewBadges(item)}</td><td class="ir-network-cell">${networkHtml(item)}</td><td><span class="ir-count-value">${Number(item.seen_count||0)}</span></td><td><div class="ir-agent-cell"><span class="ir-agent ir-agent-${esc(agentState)}">${esc(agentLabel)}</span>${item.analysis_model?`<span class="ir-agent-model" title="${esc(item.analysis_model)}">${esc(item.analysis_model)}</span>`:''}</div></td><td><div class="ir-actions-cell">${reviewButton(item)}${reanalysisButton(item)}</div></td></tr><tr class="ir-detail-row" data-detail-for="${esc(item.case_id)}" hidden><td colspan="9"><div class="ir-detail-shell"><div class="ir-detail-content">Loading case evidence...</div></div></td></tr>`};
      const mobileHtml=item=>{const level=severity(item),agentState=item.agent_display_status||item.agent_status,agentLabel=item.agent_display_label||label(item.agent_status),sourceHost=item.source_asset?.status==='resolved'?` (${item.source_asset.hostname})`:'',destinationHost=item.destination_asset?.status==='resolved'?` (${item.destination_asset.hostname})`:'';return `<article class="ir-mobile-card" data-mobile-case="${esc(item.case_id)}" data-final-review-status="${esc(item.final_review_status||'unreviewed')}"><button class="ir-mobile-toggle" type="button" aria-expanded="false"><span class="ir-mobile-top"><span class="ir-status ir-severity-${esc(level)}">${esc(level)}</span><span class="ir-agent ir-agent-${esc(agentState)}">${esc(agentLabel)}</span></span><strong class="ir-alert-title">${esc(item.rule_name||'Security Onion alert')}</strong><span class="ir-muted">${esc(caseSummary(item))} | ${esc(item.source_ip||'n/a')}${esc(sourceHost)} &gt; ${esc(item.destination_ip||'n/a')}${item.destination_port?':'+esc(item.destination_port):''}${esc(destinationHost)} | ${Number(item.seen_count||0)} alert(s)</span>${reviewBadges(item)}</button><div class="ir-mobile-detail" hidden><div class="ir-mobile-review-action">${reviewButton(item)}${reanalysisButton(item)}</div><div class="ir-detail-content">Loading case evidence...</div></div></article>`};
      function renderReanalysisProgress(run){
        if(!reanalysisProgress)return;
        if(!run){reanalysisProgress.hidden=true;reanalysisProgress.innerHTML='';return}
        const counts=run.counts||{};
        reanalysisProgress.hidden=false;
        reanalysisProgress.innerHTML=`<strong>Incident reanalysis: ${esc(label(run.status||'queued'))}</strong><div class="ir-reanalysis-identifiers"><span>Run <code>${esc(run.run_id||'n/a')}</code></span><span>Release <code>${esc(run.release_id||'unversioned')}</code></span><span>Scope ${esc(label(run.scope||'unknown'))}</span><span>Total ${Number(run.total_count||0)}</span></div><div class="ir-reanalysis-counts"><span><b>${Number(counts.queued||0)}</b> queued</span><span><b>${Number(counts.running||0)}</b> running</span><span><b>${Number(counts.completed||0)}</b> completed</span><span><b>${Number(counts.failed||0)}</b> failed</span><span><b>${Number(counts.skipped||0)}</b> skipped</span></div>`;
      }
      async function loadReanalysisProgress(runId=''){
        try{
          const query=runId?`?run_id=${encodeURIComponent(runId)}`:'';
          const response=await fetch(`/api/soc-incidents/reanalysis-runs${query}`,{cache:'no-store'});
          const payload=await response.json();
          if(!response.ok||payload.ok===false)throw new Error(payload.error||`HTTP ${response.status}`);
          const latestRun=payload.latest_run||null;
          const nextSignature=JSON.stringify(latestRun);
          if(nextSignature===reanalysisSignature)return false;
          reanalysisSignature=nextSignature;
          renderReanalysisProgress(latestRun);
          return true;
        }catch(error){
          if(reanalysisProgress){reanalysisProgress.hidden=false;reanalysisProgress.textContent=`Reanalysis progress unavailable: ${error.message}`}
          return null;
        }
      }
      async function queueCaseReanalysis(caseId,button){
        if(!caseId||button?.disabled)return;
        if(button){button.disabled=true;button.textContent='Queuing…'}
        try{
          const response=await fetch(`/api/soc-incidents/${encodeURIComponent(caseId)}/reanalyze`,{method:'POST',headers:{'Content-Type':'application/json','X-Onion-Sentinel-Request':'dashboard'},body:JSON.stringify({requested_by:'dashboard',reason:'Analyst requested fresh Incident Responder analysis'})});
          const payload=await response.json();
          if(!response.ok||payload.ok===false)throw new Error(payload.error||`HTTP ${response.status}`);
          await Promise.all([load(),loadReanalysisProgress(payload.run_id||'')]);
        }catch(error){
          errorBox.textContent=`Case reanalysis could not be queued: ${error.message}`;errorBox.hidden=false;
        }finally{if(button){button.disabled=false;button.textContent='Reanalyze'}}
      }
      async function queueAllReanalysis(){
        if(!reanalyzeAll||reanalyzeAll.disabled)return;
        if(!window.confirm('Queue a fresh Incident Responder investigation for every stored case?'))return;
        reanalyzeAll.disabled=true;reanalyzeAll.textContent='Queuing all…';
        try{
          const response=await fetch('/api/soc-incidents/reanalyze-all',{method:'POST',headers:{'Content-Type':'application/json','X-Onion-Sentinel-Request':'dashboard'},body:JSON.stringify({requested_by:'dashboard',reason:'Analyst requested fresh analysis of all incident cases'})});
          const payload=await response.json();
          if(!response.ok||payload.ok===false)throw new Error(payload.error||`HTTP ${response.status}`);
          await Promise.all([load(),loadReanalysisProgress(payload.run_id||'')]);
        }catch(error){
          errorBox.textContent=`Bulk reanalysis could not be queued: ${error.message}`;errorBox.hidden=false;
        }finally{reanalyzeAll.disabled=false;reanalyzeAll.textContent='Reanalyze all cases'}
      }
      async function loadDetail(item,targets){
        if(targets.every(target=>target.dataset.loaded==='true'))return;
        targets.forEach(target=>{target.innerHTML='Loading case evidence...'});
        try{
          const response=await fetch(`/api/soc-incidents/${encodeURIComponent(item.case_id)}/detail`,{cache:'no-store'});
          const payload=await response.json();
          if(!response.ok||payload.ok===false)throw new Error(payload.error||`HTTP ${response.status}`);
          const html=`${payload.incident_html||'<section class="ir-investigation-report"><h3>Incident Response Investigation</h3><p>No responder report is available.</p></section>'}<details class="ir-prior-ai"><summary>AI Analysis Output</summary>${payload.prior_ai_html||'<div class="ir-prior-analysis"><p>No prior SOC AI analysis is available.</p></div>'}</details>`;
          targets.forEach(target=>{target.innerHTML=html;enhanceIncidentQueryAudit(target);target.dataset.loaded='true'});
        }catch(error){targets.forEach(target=>{target.innerHTML=`<div class="ir-error">Unable to load case evidence: ${esc(error.message)}</div>`})}
      }
      async function toggleCase(caseId){
        const item=incidents.find(candidate=>candidate.case_id===caseId);if(!item)return;
        const row=document.querySelector(`[data-detail-for="${CSS.escape(caseId)}"]`);
        const desktopButton=document.querySelector(`[data-case-id="${CSS.escape(caseId)}"] .ir-expand`);
        const card=document.querySelector(`[data-mobile-case="${CSS.escape(caseId)}"]`);
        const mobileDetail=card?.querySelector('.ir-mobile-detail');
        const mobileButton=card?.querySelector('.ir-mobile-toggle');
        const opening=openCase!==caseId;
        document.querySelectorAll('.ir-detail-row').forEach(node=>node.hidden=true);
        document.querySelectorAll('.ir-mobile-detail').forEach(node=>node.hidden=true);
        document.querySelectorAll('.ir-expand,.ir-mobile-toggle').forEach(node=>node.setAttribute('aria-expanded','false'));
        openCase=opening?caseId:'';
        if(!opening)return;
        if(row)row.hidden=false;if(mobileDetail)mobileDetail.hidden=false;
        desktopButton?.setAttribute('aria-expanded','true');mobileButton?.setAttribute('aria-expanded','true');
        const targets=[row?.querySelector('.ir-detail-content'),mobileDetail?.querySelector('.ir-detail-content')].filter(Boolean);
        await loadDetail(item,targets);
      }
      function render(payload){
        const expandedCase=openCase;
        const anchorRow=[...body.querySelectorAll('.ir-case-row')].find(row=>row.getBoundingClientRect().bottom>Math.max(0,document.querySelector('.ir-table-wrap')?.getBoundingClientRect().top||0));
        const anchor=anchorRow?{caseId:anchorRow.dataset.caseId,top:anchorRow.getBoundingClientRect().top}:null;
        const active=document.activeElement;
        const activeCase=active?.closest?.('[data-case-id],[data-mobile-case]');
        const focusState=activeCase?{caseId:activeCase.dataset.caseId||activeCase.dataset.mobileCase,selector:active.matches('.ir-expand')?'.ir-expand':active.matches('.ir-mobile-toggle')?'.ir-mobile-toggle':active.matches('.review-action-button')?'.review-action-button':active.matches('.ir-reanalyze-case')?'.ir-reanalyze-case':''}:null;
        const detailSource=expandedCase?document.querySelector(`[data-detail-for="${CSS.escape(expandedCase)}"] .ir-detail-content`):null;
        const savedDetail=detailSource?.dataset.loaded==='true'?detailSource.innerHTML:'';
        incidents=Array.isArray(payload.incidents)?payload.incidents:[];pages=Math.max(1,Number(payload.pages||1));page=Math.min(Math.max(1,Number(payload.page||1)),pages);openCase='';
        sortKey=String(payload.sort||sortKey);sortDirection=String(payload.direction||sortDirection)==='asc'?'asc':'desc';
        document.querySelectorAll('[data-ir-sort]').forEach(button=>{const active=button.dataset.irSort===sortKey;if(active)button.setAttribute('aria-sort',sortDirection==='asc'?'ascending':'descending');else button.removeAttribute('aria-sort')});
        const status=payload.status_counts||{},agent=payload.agent_status_counts||{};
        document.getElementById('ir-total').textContent=Number(payload.total||0);
        document.getElementById('ir-open').textContent=Number(status.open||0);
        document.getElementById('ir-analyzing').textContent=Number(agent.analyzing||0);
        document.getElementById('ir-analyzed').textContent=Number(agent.analyzed||0);
        document.getElementById('ir-failed').textContent=Number(agent.failed||0);
        body.innerHTML=incidents.length?incidents.map(rowHtml).join(''):'<tr><td colspan="9" class="ir-loading">No incident cases match this view.</td></tr>';
        mobile.innerHTML=incidents.length?incidents.map(mobileHtml).join(''):'<div class="ir-loading">No incident cases match this view.</div>';
        body.dataset.liveRenderVersion=String(Number(body.dataset.liveRenderVersion||0)+1);
        mobile.dataset.liveRenderVersion=String(Number(mobile.dataset.liveRenderVersion||0)+1);
        pageLabel.textContent=`Page ${page} of ${pages} | ${Number(payload.total||0)} case(s)`;previous.disabled=page<=1;next.disabled=page>=pages;
        if(expandedCase&&incidents.some(item=>item.case_id===expandedCase)){
          if(savedDetail)document.querySelectorAll(`[data-detail-for="${CSS.escape(expandedCase)}"] .ir-detail-content,[data-mobile-case="${CSS.escape(expandedCase)}"] .ir-detail-content`).forEach(target=>{target.innerHTML=savedDetail;target.dataset.loaded='true'});
          void toggleCase(expandedCase);
        }
        if(anchor)requestAnimationFrame(()=>{const restored=body.querySelector(`[data-case-id="${CSS.escape(anchor.caseId)}"]`);if(restored)window.scrollBy(0,restored.getBoundingClientRect().top-anchor.top)});
        if(focusState?.selector)requestAnimationFrame(()=>{const restored=document.querySelector(`[data-case-id="${CSS.escape(focusState.caseId)}"] ${focusState.selector},[data-mobile-case="${CSS.escape(focusState.caseId)}"] ${focusState.selector}`);restored?.focus({preventScroll:true})});
      }
      function load(){
        if(loadPromise)return loadPromise;
        loadPromise=(async()=>{
          errorBox.hidden=true;
          try{
            const params=new URLSearchParams({page:String(page),per_page:pageSize.value,status:filter.value,sort:sortKey,direction:sortDirection});
            const response=await fetch(`/api/soc-incidents?${params}`,{cache:'no-store'});const payload=await response.json();
            if(!response.ok||payload.ok===false)throw new Error(payload.error||`HTTP ${response.status}`);
            const nextSignature=JSON.stringify(payload);
            if(nextSignature===incidentSignature)return false;
            incidentSignature=nextSignature;
            render(payload);
            return true;
          }catch(error){errorBox.textContent=`Incident Response queue unavailable: ${error.message}`;errorBox.hidden=false;body.innerHTML='<tr><td colspan="9" class="ir-loading">Incident cases could not be loaded.</td></tr>';mobile.innerHTML=''}
          finally{loadPromise=null}
        })();
        return loadPromise;
      }
      document.getElementById('incident-response-view').addEventListener('click',event=>{const reanalysis=event.target.closest('[data-reanalyze-case]');if(reanalysis){event.preventDefault();event.stopPropagation();queueCaseReanalysis(reanalysis.dataset.reanalyzeCase,reanalysis);return}const row=event.target.closest('.ir-case-row');const card=event.target.closest('.ir-mobile-card');if(row)toggleCase(row.dataset.caseId);else if(card&&event.target.closest('.ir-mobile-toggle'))toggleCase(card.dataset.mobileCase)});
      document.getElementById('incident-response-view').addEventListener('keydown',event=>{const row=event.target.closest('.ir-case-row');if(row&&(event.key==='Enter'||event.key===' ')){event.preventDefault();toggleCase(row.dataset.caseId)}});
      document.addEventListener('onion-sentinel:adjudicated',event=>{if(event.detail?.caseId){document.querySelectorAll('.ir-detail-content').forEach(target=>delete target.dataset.loaded);load()}});
      document.querySelectorAll('[data-ir-sort]').forEach(button=>button.addEventListener('click',()=>{const nextSort=button.dataset.irSort||'updated';if(sortKey===nextSort)sortDirection=sortDirection==='asc'?'desc':'asc';else{sortKey=nextSort;sortDirection=['alert','source','destination','status','agent'].includes(nextSort)?'asc':'desc'}page=1;load()}));
      filter.addEventListener('change',()=>{page=1;load()});pageSize.addEventListener('change',()=>{page=1;load()});previous.addEventListener('click',()=>{if(page>1){page-=1;load()}});next.addEventListener('click',()=>{if(page<pages){page+=1;load()}});reanalyzeAll?.addEventListener('click',queueAllReanalysis);load();loadReanalysisProgress();
      const incidentLiveRefresh=async()=>{const results=await Promise.all([load(),loadReanalysisProgress()]);return results.some(Boolean)};
      const incidentCanRefresh=()=>document.getElementById('analyst-adjudication-modal')?.hidden!==false;
      if(window.OnionSentinelReactiveTables){
        window.OnionSentinelReactiveTables.register('incident-response-cases',incidentLiveRefresh,{intervalMs:60000,when:incidentCanRefresh,revisionKey:'incidents'});
      }else{
        window.setInterval(()=>{if(incidentCanRefresh())incidentLiveRefresh()},60000);
      }
    })();
    </script>'''


def incident_response_page_section() -> str:
    """Render the API-backed Incident Responder case queue."""
    return INCIDENT_RESPONSE_MARKUP + INCIDENT_RESPONSE_CSS + INCIDENT_RESPONSE_JS
