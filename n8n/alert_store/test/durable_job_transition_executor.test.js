'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createDurableJobTransitionExecutor} = require('../services/durable_job_transition_executor');

function conflict(message) { const error = new Error(message); error.statusCode = 409; return error; }

function harness({mode = true, claim = null, getResults = [], transitions = []} = {}) {
  const gets = [], runs = [], queueCalls = [], signals = [], metrics = [];
  const pendingGets = [...getResults], pendingTransitions = [...transitions];
  const owner = createDurableJobTransitionExecutor({
    controlledEvaluationMode: mode, parseClaimIdentity: () => claim,
    stableGroupIdPattern: /^group-[a-z]+$/, identityConflict: conflict,
    get: async (sql, params) => { gets.push({sql, params}); return pendingGets.shift(); },
    run: async (sql, params) => { runs.push({sql, params}); return {changes: 1}; },
    safeString: (value, max) => String(value ?? '').trim().slice(0, max),
    incidentReanalysisJobPayload: (row) => row?.payload || {},
    controlledRuntimeReleaseId: () => 'release-1', incidentReanalysisAttemptId: () => 'attempt-1',
    aiAnalysisLeaseSeconds: 60, nowUtc: () => '2026-08-09  12:00:00Z', nowMs: () => 0,
    durableJobs: () => ({transition: async (...args) => {
      queueCalls.push(args); return pendingTransitions.shift() || {updated: false};
    }}),
    pipelineMetrics: () => ({record: async (...args) => metrics.push(args)}),
    retireCompletedIncidentReanalysisJob: async () => false,
    retireSupersededIncidentReanalysisJob: async () => false,
    updateIncidentReanalysisProgress: async () => null,
    signalAiWorkers: async (reason) => signals.push(reason),
  });
  return {gets, runs, queueCalls, signals, metrics, owner};
}

const exactClaim = {jobId: 7, representativeAlertId: 'alert-one',
  stableGroupKey: 'key:one', dispatchId: 'dispatch-one',
  expectedAssignedRoute: 'route:primary', expectedReviewerRoute: 'route:reviewer',
  reviewerRequired: true};
const frozenPayload = {alert_id: 'alert-one', representative_alert_id: 'alert-one',
  group_id: 'group-one', stable_group_id: 'group-one', stable_group_key: 'key:one',
  dispatch_id: 'dispatch-one', expected_assigned_route: 'route:primary',
  expected_reviewer_route: 'route:reviewer', reviewer_required: true,
  release_id: 'release-1', agent_role: 'soc-analyst'};

test('ordinary transition delegates directly and preserves response envelope', async () => {
  const env = harness({mode: false, transitions: [{updated: false, leaseToken: 'x'}]});
  assert.deepEqual(await env.owner.transition('public_enrichment', 'alert-1', 'failed'),
    {updated: false, resolvedKey: 'alert-1', leaseToken: 'x', claim: null});
  assert.equal(env.queueCalls.length, 1);
});

test('invalid exact claim transition fails before database reads', async () => {
  const env = harness({claim: exactClaim});
  await assert.rejects(env.owner.transition('ai_analysis', 'group-one', 'failed'),
    (error) => error.message === 'controlled durable job claim is not valid for this transition');
  assert.equal(env.gets.length, 0);
});

test('processing exact claim replays the same token and revives only expiry', async () => {
  const candidate = {id: 7, status: 'processing', rerun_requested: 0,
    lease_token: 'lease-one', payload_json: '{}', payload: frozenPayload};
  const env = harness({claim: exactClaim, getResults: [candidate,
    {stable_group_id: 'group-one', stable_group_key: 'key:one'}]});
  const result = await env.owner.transition('ai_analysis', 'group-one', 'processing');
  assert.equal(result.idempotentClaim, true);
  assert.equal(result.leaseToken, 'lease-one');
  assert.equal(env.queueCalls.length, 0);
  assert.match(env.runs[0].sql, /SET lease_expires_at = \?, updated_at = \?/);
});

test('legacy group alias retries an unchanged transition at stable identity', async () => {
  const env = harness({getResults: [{stable_group_id: 'group-one'},
    {id: 9, status: 'failed', attempt_count: 1, payload: {}}],
    transitions: [{updated: false}, {updated: true}]});
  const result = await env.owner.transition('ai_analysis', 'legacy', 'failed');
  assert.equal(result.updated, true);
  assert.equal(result.resolvedKey, 'group-one');
  assert.equal(env.queueCalls.length, 2);
});

test('updated AI processing returns exact durable snapshot and records metric', async () => {
  const job = {id: 9, status: 'processing', attempt_count: 2,
    updated_at: 'time', payload: {group_id: 'group-one'}};
  const env = harness({getResults: [job], transitions: [{updated: true, leaseToken: 'lease'}]});
  const result = await env.owner.transition('ai_analysis', 'group-one', 'processing');
  assert.deepEqual(result.claim, {job_type: 'ai_analysis', dedupe_key: 'group-one',
    payload: {group_id: 'group-one'}});
  assert.equal(env.metrics[0][1], 'started');
});

test('incident severity retirement projects a skipped case with its policy reason', async () => {
  const reason = 'automatic incident response skipped: low is below configured high threshold';
  const job = {id: 9, status: 'failed', attempt_count: 1, updated_at: 'time', payload: {}};
  const env = harness({mode: false, getResults: [job, {case_id: 'case-one'}],
    transitions: [{updated: true}]});
  await env.owner.transition(
    'incident_response_analysis', 'group-one', 'failed', reason, 'lease-one', false,
  );
  const caseUpdate = env.runs.find(({sql}) => /SET agent_status/.test(sql));
  assert.deepEqual(caseUpdate.params, ['skipped', reason, '2026-08-09  12:00:00Z', 'case-one']);
});
