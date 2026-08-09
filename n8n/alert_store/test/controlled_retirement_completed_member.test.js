'use strict';
const assert=require('node:assert/strict');const test=require('node:test');
const {createControlledRetirementCompletedMember}=require('../services/controlled_retirement_completed_member');
function fixture(){
 const analysis={analysis_id:'analysis-1',group_id:'group-1',alert_id:'alert-1',agent_role:'incident-responder',generated_at:'time',response_json:'{"_analysis_provider":"ollama"}',model:'model',model_path:'local',detection_outcome:'tp',confidence:'high'};
 const runCase={case_id:'case-1',group_id:'group-1',dashboard_group_id:'dash-1',representative_alert_id:'alert-1',status:'completed',skip_reason:null,latest_error:null,latest_attempt_id:'attempt-1',analysis_id:'analysis-1',completed_at:'time',executed_model:'model',executed_provider:'ollama',executed_model_path:'local',result_generated_at:'time'};
 const attempt={attempt_id:'attempt-1',run_id:'run-1',case_id:'case-1',group_id:'group-1',durable_attempt_count:1,status:'completed',latest_error:null,analysis_id:'analysis-1',completed_at:'time',executed_model:'model',executed_provider:'ollama',executed_model_path:'local',result_generated_at:'time'};
 const reviewer={group_id:'group-1',alert_id:'alert-1',agent_role:'incident-responder',status:'completed',reviewer_error:null,generated_at:'time',primary_model:'model',primary_model_path:'local',primary_outcome:'tp',primary_confidence:'high',reviewer_model:'reviewer',reviewer_runtime_seconds:1};
 const incident={group_id:'group-1',dashboard_group_id:'dash-1',representative_alert_id:'alert-1',agent_status:'analyzed',latest_analysis_id:'analysis-1',latest_model:'model',latest_generated_at:'time'};
 return {analysis,runCase,attempt,reviewer,incident}; }
function owner(f){let gets=[f.analysis,f.reviewer,f.incident];return createControlledRetirementCompletedMember({all:async(sql)=>sql.includes('run_cases')?[f.runCase]:[f.attempt],get:async()=>gets.shift(),parseJsonObject:JSON.parse,incidentAnalysisProvider:(_p,v)=>v,completedJobLifecycleValid:()=>true,projectCompleted:(v)=>v,conflict:(m)=>new Error(m)});}
const identity={retired_release_id:'release-1',cohort_id:'cohort-1'};const member={rank:1,dispatch_id:'dispatch-1'};
const payload={case_id:'case-1',stable_group_id:'group-1',dashboard_group_id:'dash-1',representative_alert_id:'alert-1',stable_group_key:'key'};
const job={status:'completed',attempt_count:1,lease_token:null,lease_expires_at:null,last_error:null,rerun_requested:0};
const run={run_id:'run-1',release_id:'release-1',scope:'single_case',status:'completed',total_count:1,controlled_dispatch_id:'dispatch-1',completed_at:'time'};
const receipt={ok:true,run_id:'run-1',case_id:'case-1',cohort_id:'cohort-1',dispatch_id:'dispatch-1',release_id:'release-1',scope:'single_case',total_count:1,representative_alert_id:'alert-1',stable_group_id:'group-1',stable_group_key:'key'};
test('exact completed primary reviewer lineage projects once',async()=>{const v=await owner(fixture()).project(identity,member,job,payload,run,receipt);assert.equal(v.analysis.analysis_id,'analysis-1');});
test('missing reviewer fails exact lineage proof',async()=>{const f=fixture();f.reviewer=null;await assert.rejects(owner(f).project(identity,member,job,payload,run,receipt),/not one exact completed/);});
test('provider mismatch fails exact lineage proof',async()=>{const f=fixture();f.attempt.executed_provider='other';await assert.rejects(owner(f).project(identity,member,job,payload,run,receipt),/not one exact completed/);});
test('negative reviewer runtime fails exact lineage proof',async()=>{const f=fixture();f.reviewer.reviewer_runtime_seconds=-1;await assert.rejects(owner(f).project(identity,member,job,payload,run,receipt),/not one exact completed/);});
