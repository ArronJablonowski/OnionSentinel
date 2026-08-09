'use strict';
const assert=require('node:assert/strict'); const test=require('node:test');
const {createControlledRetirementProjections}=require('../lib/controlled_retirement_projections');
const p=createControlledRetirementProjections({rawSha256:(v)=>`raw:${v}`,sha256:(v)=>`json:${JSON.stringify(v)}`,
 safeString:(v,m)=>String(v??'').trim().slice(0,m),parseTimestamp:(v)=>v?new Date(v):null});
test('dispatch census binds completed target and absent ranks',()=>assert.deepEqual(p.orderedDispatches({completed_dispatch_ids:['a'],dispatch_id:'b',absent_dispatch_ids:['c'],member_rank:2}),[
 {rank:1,dispatch_id:'a',expected_state:'completed'},{rank:2,dispatch_id:'b',expected_state:'target'},{rank:3,dispatch_id:'c',expected_state:'absent'}]));
test('error projection hashes raw and bounded normalized forms',()=>{assert.deepEqual(p.error(null),{raw_sha256:null,normalized_sha256:null});assert.deepEqual(p.error(' x '),{raw_sha256:'raw: x ',normalized_sha256:'raw:x'});});
test('job projection never exposes lease token or raw payload',()=>{const value=p.job({id:'7',payload_json:'secret',lease_token:'token',last_error:'failure'});assert.equal(value.payload_sha256,'raw:secret');assert.equal(value.lease_token_present,true);assert.equal('lease_token' in value,false);});
test('lifecycle requires monotonic complete timestamps',()=>{assert.equal(p.completedLifecycleValid({requested_at:'2026-01-01',processing_started_at:'2026-01-02',completed_at:'2026-01-03',last_completed_at:'2026-01-04',updated_at:'2026-01-05'}),true);assert.equal(p.completedLifecycleValid({requested_at:'2026-01-02',processing_started_at:'2026-01-01'}),false);});
test('reviewer runtime is stringified for cross-language canonical receipts',()=>{assert.equal(p.reviewer({reviewer_runtime_seconds:1}).reviewer_runtime_seconds,'1');assert.equal(p.reviewer({reviewer_runtime_seconds:null}).reviewer_runtime_seconds,null);});
