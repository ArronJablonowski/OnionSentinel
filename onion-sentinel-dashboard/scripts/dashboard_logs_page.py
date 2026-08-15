"""Onion Sentinel application-log page renderer."""
from __future__ import annotations


LOGS_PAGE_SECTION = r'''
    <section id="application-logs-view" class="view-section active logs-view" aria-label="Onion Sentinel application logs">
      <section class="logs-hero" aria-labelledby="logs-overview-title">
        <div class="logs-hero-copy">
          <span class="logs-eyebrow">Runtime observability</span>
          <h2 id="logs-overview-title">Inspect local application logs without loading whole files</h2>
          <p>Review allowlisted Onion Sentinel application, worker, collector, and maintenance logs. File contents are retrieved only when a log is expanded, bounded to the selected number of newest lines, and redacted by the server.</p>
        </div>
        <div class="logs-guardrail">
          <strong>Administration access required</strong>
          <span>Paths and file metadata remain visible only through the fixed catalog. Log requests cannot supply an arbitrary filesystem path.</span>
        </div>
        <div class="logs-summary" aria-label="Local log inventory summary">
          <article><span>Catalog entries</span><strong id="logs-catalog-count">0</strong></article>
          <article><span>Current files</span><strong id="logs-existing-count">0</strong></article>
          <article><span>Active size</span><strong id="logs-active-size">0 B</strong></article>
          <article><span>Retained footprint</span><strong id="logs-retained-size">0 B</strong></article>
        </div>
      </section>

      <section class="logs-workspace" aria-labelledby="logs-files-title">
        <div class="logs-workspace-heading">
          <div>
            <span class="logs-eyebrow">Allowlisted files</span>
            <h2 id="logs-files-title">Onion Sentinel log catalog</h2>
          </div>
          <button id="logs-refresh-catalog" class="logs-button" type="button" aria-label="Refresh local log metadata"><span aria-hidden="true">↻</span> Refresh catalog</button>
        </div>
        <div class="logs-toolbar" aria-label="Log catalog filters">
          <label class="logs-search-label">Search logs
            <input id="logs-search" type="search" autocomplete="off" placeholder="Name, path, category, or purpose">
          </label>
          <label>Category
            <select id="logs-category-filter"><option value="all">All categories</option></select>
          </label>
        </div>
        <div id="logs-catalog-status" class="logs-catalog-status" role="status" aria-live="polite">Loading the local log catalog…</div>
        <div id="logs-catalog-error" class="logs-error" role="alert" hidden></div>
        <div id="application-log-list" class="logs-list" aria-label="Application log files" aria-busy="true"></div>
      </section>

      <aside class="logs-scope-note" aria-labelledby="logs-scope-title">
        <div class="logs-scope-icon" aria-hidden="true">i</div>
        <div>
          <h2 id="logs-scope-title">Local file boundary</h2>
          <p>This page intentionally excludes Docker's internal <code>json-file</code> logs and Relay journald records because they are not local Onion Sentinel regular files. Use <code>docker logs</code> on the Mac Studio or <code>journalctl</code> on the Relay for those sources.</p>
        </div>
      </aside>
    </section>
    <style>
      .logs-view{display:grid;gap:16px;min-width:0;padding:0 0 28px}.logs-hero,.logs-workspace,.logs-scope-note{border:1px solid rgba(34,211,238,.18);border-radius:12px;background:linear-gradient(180deg,rgba(13,27,38,.97),rgba(8,18,27,.97));box-shadow:inset 0 1px 0 rgba(255,255,255,.03)}.logs-hero{display:grid;grid-template-columns:minmax(0,1fr) minmax(260px,380px);gap:18px;padding:22px}.logs-hero-copy{min-width:0}.logs-eyebrow{display:block;margin-bottom:6px;color:#75efff;font-size:.72rem;font-weight:950;letter-spacing:.12em;text-transform:uppercase}.logs-hero h2,.logs-workspace h2,.logs-scope-note h2{margin:0;color:#eef5ff;letter-spacing:-.025em}.logs-hero h2{max-width:760px;font-size:1.55rem;line-height:1.16}.logs-hero-copy p{max-width:880px;margin:9px 0 0;color:#9caec2;font-size:.86rem;line-height:1.58}.logs-guardrail{display:flex;flex-direction:column;justify-content:center;gap:7px;padding:15px 16px;border:1px solid rgba(255,202,103,.25);border-radius:10px;background:rgba(255,202,103,.055)}.logs-guardrail strong{color:#f5d58b;font-size:.82rem}.logs-guardrail span{color:#b7a987;font-size:.75rem;line-height:1.48}.logs-summary{grid-column:1/-1;display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.logs-summary article{min-width:0;padding:13px 15px;border:1px solid #223b49;border-radius:9px;background:#0a1721}.logs-summary span{display:block;color:#8fa2b8;font-size:.67rem;font-weight:900;letter-spacing:.04em;text-transform:uppercase}.logs-summary strong{display:block;margin-top:6px;color:#75efff;font-size:1.28rem;overflow-wrap:anywhere}.logs-workspace{padding:18px}.logs-workspace-heading{display:flex;align-items:end;justify-content:space-between;gap:16px;margin-bottom:14px}.logs-workspace h2{font-size:1.18rem}.logs-button{min-height:42px;border:1px solid #12667a;border-radius:9px;padding:0 13px;color:#e8f3ff;background:#0a1721;font:inherit;font-size:.78rem;font-weight:900;cursor:pointer}.logs-button:hover,.logs-button:focus-visible{border-color:#75efff;color:#75efff;box-shadow:0 0 16px rgba(34,211,238,.12)}.logs-button:disabled{opacity:.48;cursor:wait}.logs-toolbar{display:grid;grid-template-columns:minmax(260px,1fr) minmax(180px,260px);gap:10px;margin-bottom:12px}.logs-toolbar label,.log-view-toolbar label{min-width:0;color:#9caec2;font-size:.68rem;font-weight:900;letter-spacing:.035em;text-transform:uppercase}.logs-toolbar input,.logs-toolbar select,.log-view-toolbar select{display:block;width:100%;min-height:44px;margin-top:5px;border:1px solid #07566a;border-radius:8px;padding:0 11px;color:#e9f2ff;background:#09151f;font:inherit;font-size:.78rem}.logs-toolbar input:focus,.logs-toolbar select:focus,.log-view-toolbar select:focus{outline:2px solid rgba(117,239,255,.34);outline-offset:1px}.logs-catalog-status{margin:0 0 12px;color:#8fa2b8;font-size:.78rem;line-height:1.45}.logs-error{margin:0 0 12px;padding:12px 14px;border:1px solid rgba(251,113,133,.38);border-radius:9px;color:#ffb8c3;background:rgba(251,113,133,.07);font-size:.78rem;line-height:1.5}.logs-error a,.log-sign-in{margin-left:5px;color:#75efff;font-weight:900}.logs-list{display:grid;gap:10px}.logs-list[aria-busy="true"]{min-height:110px}.logs-empty{padding:24px;border:1px dashed #294452;border-radius:10px;color:#8fa2b8;background:#09151f;text-align:center;font-size:.82rem}.log-card{border:1px solid #223b49;border-radius:10px;background:#09151f;overflow:hidden;transition:border-color .16s ease,box-shadow .16s ease}.log-card[open]{border-color:rgba(34,211,238,.42);box-shadow:0 0 0 1px rgba(34,211,238,.08),0 12px 30px rgba(0,0,0,.2)}.log-card>summary{display:grid;grid-template-columns:minmax(260px,1fr) minmax(330px,.95fr);gap:16px;align-items:center;min-height:88px;padding:14px 16px;cursor:pointer;list-style:none;background:#0b1923}.log-card>summary::-webkit-details-marker{display:none}.log-card>summary:focus-visible{outline:2px solid #75efff;outline-offset:-3px}.log-file-main{display:grid;grid-template-columns:28px minmax(0,1fr);gap:11px;align-items:start;min-width:0}.log-expand-icon{width:28px;height:28px;display:grid;place-items:center;border:1px solid rgba(34,211,238,.26);border-radius:8px;color:#75efff;background:rgba(34,211,238,.055);font-size:19px;line-height:1;transition:transform .16s ease}.log-card[open] .log-expand-icon{transform:rotate(90deg)}.log-file-copy{min-width:0}.log-title-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.log-file-title{color:#eef5ff;font-size:.9rem;font-weight:950}.log-category{display:inline-flex;align-items:center;border:1px solid rgba(117,239,255,.22);border-radius:999px;padding:3px 7px;color:#75efff;background:rgba(34,211,238,.045);font-size:.58rem;font-weight:950;letter-spacing:.06em;text-transform:uppercase}.log-description{display:block;margin-top:5px;color:#8fa2b8;font-size:.73rem;line-height:1.38}.log-file-path{display:block;max-width:100%;margin-top:6px;color:#a9bbce;font:700 .72rem/1.4 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;overflow-wrap:anywhere}.log-summary-facts{display:grid;grid-template-columns:minmax(92px,.6fr) minmax(170px,1.25fr);gap:8px}.log-summary-fact{min-width:0;padding:8px 10px;border:1px solid #203541;border-radius:8px;background:rgba(6,15,23,.7)}.log-summary-fact span{display:block;color:#7f93a8;font-size:.58rem;font-weight:950;letter-spacing:.065em;text-transform:uppercase}.log-summary-fact strong{display:block;margin-top:4px;color:#dce8f6;font-size:.7rem;line-height:1.35;overflow-wrap:anywhere}.log-summary-fact.log-missing strong{color:#ffca67}.log-card-body{display:grid;gap:12px;padding:14px 16px 16px;border-top:1px solid #1d3441}.log-view-toolbar{display:grid;grid-template-columns:minmax(230px,1fr) 130px repeat(3,auto);gap:10px;align-items:end}.log-view-toolbar .logs-button{min-height:44px}.log-member-path{min-height:18px;color:#8498ac;font:700 .68rem/1.4 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;overflow-wrap:anywhere}.log-view-status{min-height:19px;color:#93a7bc;font-size:.72rem;line-height:1.4}.log-view-status[data-state="error"]{color:#fb9aaa}.log-view-status[data-state="loading"]{color:#75efff}.log-viewer{position:relative;min-height:180px;max-height:560px;overflow:auto;border:1px solid #1f3947;border-radius:9px;background:#050d14;box-shadow:inset 0 0 26px rgba(0,0,0,.28)}.log-viewer pre{min-width:max-content;margin:0;padding:14px;color:#d7e6f6;font:12px/1.58 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;white-space:pre;tab-size:2}.log-viewer-empty{display:grid;place-items:center;min-height:180px;padding:18px;color:#7890a5;text-align:center;font-size:.76rem}.logs-scope-note{display:flex;gap:13px;padding:16px 18px}.logs-scope-icon{width:30px;height:30px;display:grid;place-items:center;flex:0 0 30px;border:1px solid rgba(117,239,255,.28);border-radius:999px;color:#75efff;background:rgba(34,211,238,.06);font-weight:950}.logs-scope-note h2{font-size:.92rem}.logs-scope-note p{max-width:1050px;margin:5px 0 0;color:#8fa2b8;font-size:.76rem;line-height:1.52}.logs-scope-note code{color:#c9dae9;background:transparent}@media(max-width:980px){.logs-hero{grid-template-columns:1fr}.logs-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.log-card>summary{grid-template-columns:1fr}.log-view-toolbar{grid-template-columns:minmax(200px,1fr) 120px}.log-view-toolbar .logs-button{grid-column:1/-1;width:max-content}}@media(max-width:680px){.logs-hero,.logs-workspace{padding:15px}.logs-summary{grid-template-columns:1fr 1fr}.logs-toolbar{grid-template-columns:1fr}.logs-workspace-heading{align-items:flex-start;flex-direction:column}.log-card>summary{min-height:0;padding:13px}.log-summary-facts{grid-template-columns:1fr}.log-view-toolbar{grid-template-columns:1fr}.log-view-toolbar .logs-button{grid-column:auto;width:100%}.log-viewer{max-height:460px}.log-viewer pre{font-size:11px}.logs-scope-note{padding:14px}}@media(max-width:390px){.logs-summary{grid-template-columns:1fr}.log-file-main{grid-template-columns:24px minmax(0,1fr)}.log-expand-icon{width:24px;height:24px}.logs-button{width:100%}}
    </style>
    <script>
    (() => {
      const CATALOG_ENDPOINT='/api/application-logs';
      const list=document.getElementById('application-log-list');
      if(!list)return;
      const search=document.getElementById('logs-search');
      const categoryFilter=document.getElementById('logs-category-filter');
      const refreshCatalog=document.getElementById('logs-refresh-catalog');
      const catalogStatus=document.getElementById('logs-catalog-status');
      const catalogError=document.getElementById('logs-catalog-error');
      const catalogCount=document.getElementById('logs-catalog-count');
      const existingCount=document.getElementById('logs-existing-count');
      const activeSize=document.getElementById('logs-active-size');
      const retainedSize=document.getElementById('logs-retained-size');
      let logs=[];
      let generatedAt='';
      let catalogRequest=null;

      const node=(tag,className,text)=>{
        const element=document.createElement(tag);
        if(className)element.className=className;
        if(text!==undefined&&text!==null)element.textContent=String(text);
        return element;
      };
      const number=value=>{const parsed=Number(value);return Number.isFinite(parsed)&&parsed>0?parsed:0};
      const formatBytes=value=>{
        let bytes=number(value);
        const units=['B','KiB','MiB','GiB','TiB'];
        let index=0;
        while(bytes>=1024&&index<units.length-1){bytes/=1024;index+=1}
        const digits=index===0?0:bytes>=100?0:bytes>=10?1:2;
        return `${bytes.toFixed(digits)} ${units[index]}`;
      };
      const timestamp=value=>{
        const raw=String(value??'').trim();
        if(!raw)return '';
        const parsed=new Date(raw);
        return Number.isNaN(parsed.getTime())?raw:parsed.toLocaleString();
      };
      const policyText=(value,fallback)=>{
        if(typeof value==='string'&&value.trim())return value.trim();
        if(value&&typeof value==='object'){
          for(const key of ['summary','label','description']){
            const candidate=String(value[key]??'').trim();
            if(candidate)return candidate;
          }
          const parts=[];
          if(value.kind)parts.push(String(value.kind).replaceAll('_',' '));
          if(number(value.max_bytes))parts.push(`at ${formatBytes(value.max_bytes)}`);
          if(number(value.backups))parts.push(`${number(value.backups)} backup${number(value.backups)===1?'':'s'}`);
          if(number(value.days))parts.push(`${number(value.days)} day${number(value.days)===1?'':'s'}`);
          if(parts.length)return parts.join(' · ');
        }
        return fallback;
      };
      const logMembers=item=>{
        if(Array.isArray(item?.members)&&item.members.length)return item.members.filter(member=>member&&typeof member==='object');
        if(item?.exists)return [{id:'current',label:'Current file',path:item.path,size_bytes:item.size_bytes,modified_at:item.modified_at}];
        return [];
      };
      const signInNotice=(target,message)=>{
        target.replaceChildren();
        target.appendChild(node('span','',message));
        const link=node('a','log-sign-in','Sign in to Administration');
        link.href='/admin/login?resume=logs';
        link.target='onion-sentinel-admin-auth';
        link.rel='noopener';
        target.appendChild(link);
      };
      const showCatalogError=(message,adminRequired=false)=>{
        catalogError.hidden=false;
        if(adminRequired)signInNotice(catalogError,message);
        else catalogError.replaceChildren(node('span','',message));
      };
      const categoryLabel=value=>String(value??'Uncategorized').trim()||'Uncategorized';
      const hydrateCategories=()=>{
        const selected=categoryFilter.value||'all';
        const categories=[...new Set(logs.map(item=>categoryLabel(item.category)))].sort((left,right)=>left.localeCompare(right));
        const options=[node('option','', 'All categories')];
        options[0].value='all';
        categories.forEach(category=>{const option=node('option','',category);option.value=category;options.push(option)});
        categoryFilter.replaceChildren(...options);
        categoryFilter.value=categories.includes(selected)?selected:'all';
      };
      const updateMemberPath=view=>{
        const selected=view.members.find(member=>String(member.id??'')===view.memberSelect.value)||view.members[0];
        view.memberPath.textContent=selected?String(selected.path??view.item.path??''):'No readable file member is available.';
      };
      const contentStatus=(data,selectedLines)=>{
        const parts=[];
        const returned=number(data.line_count);
        parts.push(returned?`${returned} newest line${returned===1?'':'s'}`:`Newest ${selectedLines} lines requested`);
        if(number(data.returned_bytes))parts.push(formatBytes(data.returned_bytes));
        if(number(data.file_size_bytes))parts.push(`${formatBytes(data.file_size_bytes)} file`);
        if(data.truncated===true)parts.push('older content remains');
        if(data.redacted===true)parts.push('secret fields redacted');
        if(data.modified_at)parts.push(`modified ${timestamp(data.modified_at)}`);
        if(data.has_newer===true)parts.push('newer page available');
        return parts.join(' · ');
      };
      async function loadLog(view){
        if(!view.members.length){
          view.status.dataset.state='error';
          view.status.textContent='This log does not currently have a readable file member.';
          view.viewer.replaceChildren(node('div','log-viewer-empty','No log output is available.'));
          return false;
        }
        const requestId=(view.requestId||0)+1;
        view.requestId=requestId;
        const member=view.memberSelect.value;
        const selectedLines=Number(view.linesSelect.value||200);
        const query=new URLSearchParams({member,lines:String(selectedLines)});
        if(Number.isInteger(view.before))query.set('before',String(view.before));
        view.reload.disabled=true;
        view.older.disabled=true;
        view.newest.disabled=true;
        view.memberSelect.disabled=true;
        view.linesSelect.disabled=true;
        view.status.dataset.state='loading';
        view.status.textContent='Loading the newest bounded log lines…';
        view.viewer.replaceChildren(node('div','log-viewer-empty','Loading log output…'));
        try{
          const response=await fetch(`${CATALOG_ENDPOINT}/${encodeURIComponent(String(view.item.id??''))}?${query.toString()}`,{cache:'no-store',credentials:'same-origin'});
          const data=await response.json().catch(()=>({ok:false,error:`HTTP ${response.status}`}));
          if(requestId!==view.requestId)return false;
          if(response.status===403){
            view.status.dataset.state='error';
            signInNotice(view.status,'Administration sign-in is required to view log contents.');
            view.viewer.replaceChildren(node('div','log-viewer-empty','Log contents remain protected until an Administration session is active.'));
            return false;
          }
          if(!response.ok||data.ok===false)throw new Error(String(data.error||`HTTP ${response.status}`));
          const content=String(data.content??'');
          const pre=node('pre');
          const code=node('code','',content||'The selected log file is empty.');
          pre.appendChild(code);
          view.viewer.replaceChildren(pre);
          view.status.dataset.state='ready';
          view.status.textContent=contentStatus(data,selectedLines);
          view.nextBefore=Number.isInteger(data.next_before)?Number(data.next_before):null;
          view.older.disabled=data.has_older!==true||!Number.isInteger(view.nextBefore);
          view.newest.disabled=!Number.isInteger(view.before);
          view.loaded=true;
          return true;
        }catch(error){
          if(requestId!==view.requestId)return false;
          view.status.dataset.state='error';
          view.status.textContent=`Log output could not be loaded: ${String(error?.message||error||'Unknown error')}`;
          view.viewer.replaceChildren(node('div','log-viewer-empty','No log conclusion can be drawn from an unavailable response.'));
          return false;
        }finally{
          if(requestId===view.requestId){
            view.reload.disabled=false;
            view.older.disabled=!Number.isInteger(view.nextBefore);
            view.newest.disabled=!Number.isInteger(view.before);
            view.memberSelect.disabled=view.members.length<=1;
            view.linesSelect.disabled=false;
          }
        }
      }
      const buildCard=item=>{
        const details=node('details','log-card');
        details.dataset.logId=String(item.id??'');
        const summary=node('summary');
        const main=node('span','log-file-main');
        main.appendChild(node('span','log-expand-icon','›'));
        const copy=node('span','log-file-copy');
        const titleRow=node('span','log-title-row');
        titleRow.appendChild(node('strong','log-file-title',String(item.label??item.id??'Unnamed log')));
        titleRow.appendChild(node('span','log-category',categoryLabel(item.category)));
        copy.appendChild(titleRow);
        if(item.description)copy.appendChild(node('span','log-description',item.description));
        copy.appendChild(node('code','log-file-path',String(item.path??'Path unavailable')));
        main.appendChild(copy);
        summary.appendChild(main);
        const facts=node('span','log-summary-facts');
        const sizeFact=node('span',`log-summary-fact${item.exists?'':' log-missing'}`);
        sizeFact.appendChild(node('span','',item.exists?'Current size':'File state'));
        sizeFact.appendChild(node('strong','',item.exists?formatBytes(item.size_bytes):'Not present'));
        const rotationFact=node('span','log-summary-fact');
        rotationFact.appendChild(node('span','','Rotation'));
        rotationFact.appendChild(node('strong','',policyText(item.rotation,'No automatic rotation configured')));
        facts.append(sizeFact,rotationFact);
        summary.appendChild(facts);
        details.appendChild(summary);

        const body=node('div','log-card-body');
        const toolbar=node('div','log-view-toolbar');
        const memberLabel=node('label','','File member');
        const memberSelect=node('select');
        memberSelect.setAttribute('aria-label',`File member for ${String(item.label??item.id??'log')}`);
        const members=logMembers(item);
        members.forEach((member,index)=>{
          const label=String(member.label??(index===0?'Current file':`Member ${index+1}`));
          const option=node('option','',`${label} · ${formatBytes(member.size_bytes)}`);
          option.value=String(member.id??index);
          memberSelect.appendChild(option);
        });
        if(!members.length){const option=node('option','','No readable members');option.value='';memberSelect.appendChild(option)}
        memberSelect.disabled=members.length<=1;
        memberLabel.appendChild(memberSelect);
        const linesLabel=node('label','','Lines');
        const linesSelect=node('select');
        linesSelect.setAttribute('aria-label',`Lines to show for ${String(item.label??item.id??'log')}`);
        [100,200,500].forEach(value=>{const option=node('option','',String(value));option.value=String(value);option.selected=value===200;linesSelect.appendChild(option)});
        linesLabel.appendChild(linesSelect);
        const reload=node('button','logs-button','Reload latest');
        reload.type='button';
        const older=node('button','logs-button','Older page');
        older.type='button';
        older.disabled=true;
        const newest=node('button','logs-button','Newest page');
        newest.type='button';
        newest.disabled=true;
        toolbar.append(memberLabel,linesLabel,reload,older,newest);
        const memberPath=node('div','log-member-path');
        const status=node('div','log-view-status','Expand this section to load the newest 200 lines.');
        status.setAttribute('role','status');
        status.setAttribute('aria-live','polite');
        const viewer=node('div','log-viewer');
        viewer.tabIndex=0;
        viewer.setAttribute('aria-label',`Log output for ${String(item.label??item.id??'log')}`);
        viewer.appendChild(node('div','log-viewer-empty','Log output loads only when this section is expanded.'));
        const retention=node('div','log-view-status',`Owner: ${policyText(item.owner,'Unassigned')} · Path class: ${policyText(item.path_class,'Unclassified')} · Maximum active size: ${formatBytes(item.maximum_size_bytes)} · Compression: ${policyText(item.compression,'none')} · Retention: ${policyText(item.retention,'No explicit retention configured')} · Disk pressure: ${policyText(item.disk_pressure,'No explicit disk-pressure policy')}${number(item.retained_size_bytes)>number(item.size_bytes)?` · ${formatBytes(item.retained_size_bytes)} across retained members`:''}${number(item.omitted_member_count)?` · ${number(item.omitted_member_count)} older member${number(item.omitted_member_count)===1?'':'s'} omitted from this bounded catalog`:''}`);
        body.append(toolbar,memberPath,status,viewer,retention);
        details.appendChild(body);
        const view={item,details,members,memberSelect,linesSelect,reload,older,newest,memberPath,status,viewer,loaded:false,requestId:0,before:null,nextBefore:null};
        updateMemberPath(view);
        details.addEventListener('toggle',()=>{if(details.open&&!view.loaded)void loadLog(view)});
        memberSelect.addEventListener('change',()=>{view.loaded=false;view.before=null;view.nextBefore=null;updateMemberPath(view);if(details.open)void loadLog(view)});
        linesSelect.addEventListener('change',()=>{view.loaded=false;view.before=null;view.nextBefore=null;if(details.open)void loadLog(view)});
        reload.addEventListener('click',()=>{view.loaded=false;view.before=null;view.nextBefore=null;void loadLog(view)});
        older.addEventListener('click',()=>{if(!Number.isInteger(view.nextBefore))return;view.loaded=false;view.before=view.nextBefore;void loadLog(view)});
        newest.addEventListener('click',()=>{view.loaded=false;view.before=null;view.nextBefore=null;void loadLog(view)});
        return details;
      };
      const updateSummary=()=>{
        catalogCount.textContent=String(logs.length);
        existingCount.textContent=String(logs.filter(item=>item.exists===true).length);
        activeSize.textContent=formatBytes(logs.reduce((total,item)=>total+number(item.size_bytes),0));
        retainedSize.textContent=formatBytes(logs.reduce((total,item)=>total+number(item.retained_size_bytes||item.size_bytes),0));
      };
      const render=()=>{
        const query=String(search.value||'').trim().toLowerCase();
        const category=categoryFilter.value||'all';
        const filtered=logs.filter(item=>{
          const matchesCategory=category==='all'||categoryLabel(item.category)===category;
          const haystack=[item.label,item.description,item.path,item.category,item.format].map(value=>String(value??'')).join(' ').toLowerCase();
          return matchesCategory&&(!query||haystack.includes(query));
        });
        const fragment=document.createDocumentFragment();
        filtered.forEach(item=>fragment.appendChild(buildCard(item)));
        if(!filtered.length)fragment.appendChild(node('div','logs-empty',logs.length?'No logs match the selected filters.':'No allowlisted local log files were returned.'));
        list.replaceChildren(fragment);
        list.setAttribute('aria-busy','false');
        const generated=generatedAt?` · catalog generated ${timestamp(generatedAt)}`:'';
        catalogStatus.textContent=`Showing ${filtered.length} of ${logs.length} log catalog entr${logs.length===1?'y':'ies'}${generated}. Expand a log to request its bounded, redacted tail.`;
      };
      async function loadCatalog(){
        if(catalogRequest)return catalogRequest;
        catalogRequest=(async()=>{
          refreshCatalog.disabled=true;
          list.setAttribute('aria-busy','true');
          catalogError.hidden=true;
          catalogStatus.textContent=logs.length?'Refreshing local log metadata…':'Loading the local log catalog…';
          try{
            const response=await fetch(CATALOG_ENDPOINT,{cache:'no-store',credentials:'same-origin'});
            const data=await response.json().catch(()=>({ok:false,error:`HTTP ${response.status}`}));
            if(response.status===403){
              logs=[];generatedAt='';updateSummary();hydrateCategories();render();
              showCatalogError('Administration sign-in is required to inspect Onion Sentinel logs.',true);
              catalogStatus.textContent='Log catalog access is protected.';
              return false;
            }
            if(!response.ok||data.ok===false)throw new Error(String(data.error||`HTTP ${response.status}`));
            logs=(Array.isArray(data.logs)?data.logs:Array.isArray(data.items)?data.items:[]).filter(item=>item&&typeof item==='object'&&String(item.id??'').trim());
            logs.sort((left,right)=>categoryLabel(left.category).localeCompare(categoryLabel(right.category))||String(left.label??left.id).localeCompare(String(right.label??right.id)));
            generatedAt=String(data.generated_at??'');
            updateSummary();hydrateCategories();render();
            return true;
          }catch(error){
            list.setAttribute('aria-busy','false');
            showCatalogError(`Log catalog could not be loaded: ${String(error?.message||error||'Unknown error')}`);
            catalogStatus.textContent=logs.length?'Showing the previous log catalog after a refresh failure.':'No log metadata is available.';
            if(!logs.length)list.replaceChildren(node('div','logs-empty','The local log catalog is unavailable. No log conclusion can be drawn.'));
            return false;
          }finally{
            refreshCatalog.disabled=false;
            catalogRequest=null;
          }
        })();
        return catalogRequest;
      }
      search.addEventListener('input',render);
      categoryFilter.addEventListener('change',render);
      refreshCatalog.addEventListener('click',loadCatalog);
      void loadCatalog();
    })();
    </script>'''


def logs_page_section() -> str:
    """Render an admin-only, bounded viewer for allowlisted local log files."""
    return LOGS_PAGE_SECTION
