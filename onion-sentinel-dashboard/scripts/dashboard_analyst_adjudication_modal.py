"""Shared analyst-adjudication dialog for SOC alerts and incidents."""
from __future__ import annotations


ANALYST_ADJUDICATION_MODAL_HTML = r'''
<style>
.review-badge-row,.analyst-review-badges{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.review-badge{display:inline-flex;align-items:center;min-height:24px;padding:3px 8px;border:1px solid #29404f;border-radius:999px;color:#a9bbce;background:#0a1721;font-size:10px;font-weight:850;line-height:1.2;text-transform:uppercase;letter-spacing:.04em}
.review-badge-disputed,.review-badge-review_required_failed,.review-freshness-stale,.review-coverage-gaps{border-color:rgba(255,112,136,.55);color:#ff8da1;background:rgba(255,112,136,.08)}
.review-badge-adjudicated,.review-freshness-current,.review-coverage-complete{border-color:rgba(105,232,154,.48);color:#69e89a;background:rgba(105,232,154,.07)}
.review-badge-consensus,.review-badge-reviewer_advisory{border-color:rgba(117,239,255,.42);color:#75efff;background:rgba(117,239,255,.06)}
.review-badge-unreviewed,.review-freshness-not_analyzed,.review-coverage-unknown{color:#9caec2}
.review-badge-confidence{border-color:rgba(246,199,109,.42);color:#f6c76d}
.analyst-review-panel{display:grid;gap:14px;margin:0 0 18px;padding:17px;border:1px solid #214151;border-radius:10px;background:linear-gradient(145deg,#0d1b26,#0a151f)}
.analyst-review-panel.review-status-disputed_pending_human,.analyst-review-panel.review-status-review_required_failed{border-color:rgba(255,112,136,.62);box-shadow:inset 3px 0 0 #ff7088}
.analyst-review-heading{display:flex;justify-content:space-between;gap:14px;align-items:flex-start}.analyst-review-heading h3{margin:3px 0 0;color:#eef5ff;font-size:1rem}.analyst-review-eyebrow{color:#75efff;font-size:.69rem;font-weight:900;text-transform:uppercase;letter-spacing:.1em}
.analyst-review-comparison{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.analyst-review-comparison>div{display:grid;gap:4px;padding:10px;border:1px solid #1d3442;border-radius:8px;background:#07131c}.analyst-review-comparison b{color:#9caec2;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em}.analyst-review-comparison span{color:#eef5ff}
.analyst-review-empty{margin:0;color:#9caec2}.analyst-review-failure{margin:0;padding:10px;border:1px solid rgba(255,112,136,.45);border-radius:8px;color:#ffd3dc;background:rgba(255,112,136,.07);overflow-wrap:anywhere}.analyst-adjudication-summary{padding:11px;border:1px solid rgba(105,232,154,.35);border-radius:8px;background:rgba(105,232,154,.055);color:#d8e7f8}.analyst-adjudication-summary p{margin:7px 0}.analyst-adjudication-summary small{color:#9caec2}
.analyst-adjudicate-button,.review-action-button{width:max-content;min-height:38px;padding:8px 12px;border:1px solid #087087;border-radius:8px;color:#dffaff;background:#071722;font-weight:850;cursor:pointer}.analyst-adjudicate-button:hover,.review-action-button:hover{border-color:#24cce2;color:#75efff}.review-action-button:disabled,[data-review-blocked="true"]{opacity:.45;cursor:not-allowed}
.analyst-adjudication-dialog{width:min(720px,calc(100vw - 36px));border-color:rgba(34,211,238,.42)!important}.analyst-adjudication-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.analyst-adjudication-grid label,.analyst-resolution-fields label{display:grid;gap:6px;color:#aebdce;font-size:12px;font-weight:800}.analyst-adjudication-grid .full{grid-column:1/-1}.analyst-adjudication-grid select,.analyst-adjudication-grid input,.analyst-adjudication-grid textarea,.analyst-resolution-fields textarea{width:100%;border:1px solid #29404f;border-radius:8px;padding:10px;color:#e7f1fc;background:#07131c;font:13px/1.4 inherit}.analyst-adjudication-grid textarea,.analyst-resolution-fields textarea{min-height:78px;resize:vertical}.analyst-resolve-toggle{display:flex!important;grid-template-columns:auto 1fr!important;align-items:center;gap:9px!important;margin-top:12px}.analyst-resolve-toggle input{width:auto}.analyst-resolution-fields{display:grid;gap:7px;margin-top:10px}.analyst-adjudication-status{min-height:20px;margin:10px 0 0!important;color:#9caec2!important}.analyst-adjudication-status[data-state="error"]{color:#ff8da1!important}
@media(max-width:640px){.analyst-adjudication-grid,.analyst-review-comparison{grid-template-columns:1fr}.analyst-adjudication-grid .full{grid-column:auto}.analyst-review-heading{display:grid}}
</style>
<div id="analyst-adjudication-modal" class="modal-backdrop" hidden>
  <form id="analyst-adjudication-form" class="modal-card analyst-adjudication-dialog" role="dialog" aria-modal="true" aria-labelledby="analyst-adjudication-title">
    <h2 id="analyst-adjudication-title">Record analyst decision</h2>
    <p>Record an append-only human decision for the current analysis. This decision becomes the final outcome for this analysis revision.</p>
    <div class="analyst-adjudication-grid">
      <label>Final outcome
        <select id="analyst-outcome" required>
          <option value="">Select an outcome</option>
          <option value="true_positive_malicious">True positive — malicious</option>
          <option value="true_positive_suspicious">True positive — suspicious</option>
          <option value="true_positive_authorized_benign">True positive — authorized benign</option>
          <option value="false_positive_logic_rule">False positive — rule logic</option>
          <option value="false_positive_data_parser">False positive — parser/data</option>
          <option value="false_positive_bad_intel_ioc">False positive — bad intel/IOC</option>
          <option value="false_negative">False negative</option>
          <option value="duplicate">Duplicate</option>
          <option value="informational_no_action">Informational — no action</option>
          <option value="inconclusive">Inconclusive</option>
        </select>
      </label>
      <label>Confidence
        <select id="analyst-confidence" required>
          <option value="">Select confidence</option>
          <option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option>
        </select>
      </label>
      <label>Event status
        <select id="analyst-event-status">
          <option value="">Not explicitly adjudicated</option>
          <option value="observed">Observed</option>
          <option value="not_observed">Not observed</option>
          <option value="unknown">Unknown</option>
        </select>
      </label>
      <label>Detection validity
        <select id="analyst-detection-validity">
          <option value="">Not explicitly adjudicated</option>
          <option value="matched_intent">Matched intent</option>
          <option value="logic_error">Logic error</option>
          <option value="parser_error">Parser error</option>
          <option value="intel_error">Intel/IOC error</option>
          <option value="not_applicable">Not applicable</option>
          <option value="unknown">Unknown</option>
        </select>
      </label>
      <label>Activity disposition
        <select id="analyst-activity-disposition">
          <option value="">Not explicitly adjudicated</option>
          <option value="malicious">Malicious</option>
          <option value="suspicious">Suspicious</option>
          <option value="authorized_benign">Authorized benign</option>
          <option value="benign">Benign</option>
          <option value="unknown">Unknown</option>
        </select>
      </label>
      <label>Handling
        <select id="analyst-handling">
          <option value="">Not explicitly adjudicated</option>
          <option value="contain">Contain</option>
          <option value="escalate">Escalate</option>
          <option value="investigate">Investigate</option>
          <option value="monitor">Monitor</option>
          <option value="no_action">No action</option>
        </select>
      </label>
      <label class="full">Duplicate of
        <input id="analyst-duplicate-of" maxlength="256" placeholder="Alert/group identifier, or leave blank">
      </label>
      <label class="full">Rationale
        <textarea id="analyst-rationale" maxlength="4000" required placeholder="Why this is the appropriate final decision"></textarea>
      </label>
      <label>Evidence gap
        <textarea id="analyst-evidence-gap" maxlength="4000" placeholder="What evidence remains unavailable or uncertain"></textarea>
      </label>
      <label>Next action
        <textarea id="analyst-next-action" maxlength="4000" placeholder="Recommended follow-up or control action"></textarea>
      </label>
      <label class="full">Reviewer
        <input id="analyst-reviewer" maxlength="100" required autocomplete="name" placeholder="Analyst name or handle">
      </label>
    </div>
    <div id="analyst-resolution-control" hidden>
      <label class="analyst-resolve-toggle"><input id="analyst-resolve-case" type="checkbox"> Resolve this incident case with the decision</label>
      <div id="analyst-resolution-fields" class="analyst-resolution-fields" hidden>
        <label>Case resolution reason
          <textarea id="analyst-resolution-reason" maxlength="2000" placeholder="Why the incident can be closed"></textarea>
        </label>
      </div>
    </div>
    <p id="analyst-adjudication-status" class="analyst-adjudication-status" role="status" aria-live="polite"></p>
    <div class="modal-actions">
      <button id="cancel-analyst-adjudication" class="modal-button" type="button">Cancel</button>
      <button id="save-analyst-adjudication" class="modal-button primary" type="submit">Save analyst decision</button>
    </div>
  </form>
</div>
<script>
(() => {
  const modal=document.getElementById('analyst-adjudication-modal');
  const form=document.getElementById('analyst-adjudication-form');
  if(!modal||!form)return;
  const outcome=document.getElementById('analyst-outcome');
  const confidence=document.getElementById('analyst-confidence');
  const eventStatus=document.getElementById('analyst-event-status');
  const detectionValidity=document.getElementById('analyst-detection-validity');
  const activityDisposition=document.getElementById('analyst-activity-disposition');
  const handling=document.getElementById('analyst-handling');
  const duplicateOf=document.getElementById('analyst-duplicate-of');
  const rationale=document.getElementById('analyst-rationale');
  const evidenceGap=document.getElementById('analyst-evidence-gap');
  const nextAction=document.getElementById('analyst-next-action');
  const reviewer=document.getElementById('analyst-reviewer');
  const resolutionControl=document.getElementById('analyst-resolution-control');
  const resolveCase=document.getElementById('analyst-resolve-case');
  const resolutionFields=document.getElementById('analyst-resolution-fields');
  const resolutionReason=document.getElementById('analyst-resolution-reason');
  const status=document.getElementById('analyst-adjudication-status');
  const save=document.getElementById('save-analyst-adjudication');
  let context={},saving=false;
  const setKnownValue=(field,value)=>{const wanted=String(value??'');field.value=[...field.options].some(option=>option.value===wanted)?wanted:''};
  const close=(force=false)=>{
    if(saving&&!force)return;
    modal.hidden=true;context={};status.textContent='';delete status.dataset.state;
    resolveCase.checked=false;resolutionReason.required=false;resolutionReason.disabled=true;
    resolutionFields.hidden=true;
  };
  window.OnionSentinelAdjudication={
    open(options={}){
      if(saving)return;
      context={groupId:String(options.groupId||''),caseId:String(options.caseId||''),analysisId:String(options.analysisId||'')};
      form.reset();
      const primary=String(options.primaryOutcome||'');
      outcome.value=[...outcome.options].some(option=>option.value===primary)?primary:'';
      setKnownValue(eventStatus,options.eventStatus);
      setKnownValue(detectionValidity,options.detectionValidity);
      setKnownValue(activityDisposition,options.activityDisposition);
      setKnownValue(handling,options.handling);
      duplicateOf.value=String(options.duplicateOf||'');
      try{reviewer.value=localStorage.getItem('onion-sentinel-analyst-reviewer')||''}catch(_){}
      resolutionControl.hidden=!context.caseId;
      resolveCase.checked=false;
      resolutionReason.required=false;
      resolutionReason.disabled=true;
      resolutionFields.hidden=true;
      status.textContent=context.analysisId?'Decision will apply to the displayed analysis revision.':'The server will bind this decision to the current analysis revision.';
      delete status.dataset.state;
      modal.hidden=false;
      window.setTimeout(()=>outcome.focus(),25);
    }
  };
  resolveCase.addEventListener('change',()=>{resolutionFields.hidden=!resolveCase.checked;resolutionReason.required=resolveCase.checked;resolutionReason.disabled=!resolveCase.checked});
  document.getElementById('cancel-analyst-adjudication')?.addEventListener('click',close);
  modal.addEventListener('click',event=>{if(event.target===modal)close()});
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&!modal.hidden)close()});
  form.addEventListener('submit',async event=>{
    event.preventDefault();
    if(saving||(!context.groupId&&!context.caseId))return;
    const submissionContext={...context};
    saving=true;save.disabled=true;status.textContent='Saving append-only analyst decision…';delete status.dataset.state;
    const payload={
      analysis_id:submissionContext.analysisId,
      outcome_override:outcome.value,
      confidence:confidence.value,
      event_status:eventStatus.value||null,
      detection_validity:detectionValidity.value||null,
      activity_disposition:activityDisposition.value||null,
      handling:handling.value||null,
      duplicate_of:duplicateOf.value.trim()||null,
      rationale:rationale.value.trim(),
      evidence_gap:evidenceGap.value.trim(),
      next_action:nextAction.value.trim(),
      reviewer:reviewer.value.trim(),
      resolve_case:Boolean(submissionContext.caseId&&resolveCase.checked),
      case_resolution_reason:resolutionReason.value.trim(),
    };
    const endpoint=submissionContext.caseId
      ? `/api/soc-incidents/${encodeURIComponent(submissionContext.caseId)}/adjudicate`
      : `/api/soc-alerts/${encodeURIComponent(submissionContext.groupId)}/adjudicate`;
    try{
      const response=await fetch(endpoint,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-Onion-Sentinel-Request':'dashboard'},body:JSON.stringify(payload)});
      const result=await response.json().catch(()=>({}));
      if(!response.ok||result.ok===false)throw new Error(result.error||`HTTP ${response.status}`);
      try{localStorage.setItem('onion-sentinel-analyst-reviewer',reviewer.value.trim())}catch(_){}
      const detail={...submissionContext,result};
      saving=false;
      close(true);
      document.dispatchEvent(new CustomEvent('onion-sentinel:adjudicated',{detail}));
    }catch(error){
      status.textContent=`Decision was not saved: ${error.message}`;
      status.dataset.state='error';
    }finally{saving=false;save.disabled=false}
  });
})();
</script>'''


def analyst_adjudication_modal_html() -> str:
    """Return the shared SOC/Incident analyst-decision dialog and client."""
    return ANALYST_ADJUDICATION_MODAL_HTML
