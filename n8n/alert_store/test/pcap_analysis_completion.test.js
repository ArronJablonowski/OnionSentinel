'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createPcapAnalysisCompletion} = require('../services/pcap_analysis_completion');

function harness({row = {}, changes = 1, campaign = null, matches = true} = {}) {
  const calls = [];
  const completion = createPcapAnalysisCompletion({
    run: async (sql, params) => { calls.push({name: 'run', sql, params}); return {changes}; },
    get: async (sql, params) => { calls.push({name: 'get', sql, params}); return row; },
    safeString: (value, max) => String(value ?? '').trim().slice(0, max),
    nowUtc: () => '2026-08-09  12:00:00Z',
    recordMetric: async (...args) => calls.push({name: 'metric', args}),
    matchesAnalysis: (level) => { calls.push({name: 'matches', level}); return matches; },
    authorizedCampaignForAlertId: async (alertId) => {
      calls.push({name: 'campaign', alertId}); return campaign;
    },
    enqueueAiJob: async (...args) => calls.push({name: 'enqueue', args}),
    severityRank: {critical: 4, high: 3, informational: 0},
  });
  return {calls, completion};
}

test('validation and fulfilled ownership fail closed before downstream work', async () => {
  const env = harness({changes: 0});
  await assert.rejects(env.completion.complete({}), /request_id is required/);
  await assert.rejects(
    env.completion.complete({request_id: 'p1', status: 'unknown'}),
    /processing, completed, or failed/,
  );
  await assert.rejects(
    env.completion.complete({request_id: 'p1', status: 'processing'}),
    /fulfilled PCAP request not found/,
  );
  assert.equal(env.calls.some(({name}) => name === 'metric'), false);
});

test('processing updates attempt state and records stable analysis identity only', async () => {
  const env = harness({row: {
    analysis_attempt_count: 2, analysis_started_at: 'start', artifact_size_bytes: 42,
  }});
  const result = await env.completion.complete({request_id: 'p1', status: 'processing'});
  assert.equal(result.wake_ai_analysis, false);
  assert.match(env.calls[0].sql, /analysis_attempt_count = analysis_attempt_count/);
  assert.equal(env.calls.find(({name}) => name === 'metric').args[1], 'started');
  assert.equal(env.calls.some(({name}) => name === 'enqueue'), false);
});

test('completed evidence below policy does not invent an AI job', async () => {
  const env = harness({row: {queue_group_id: 'g1', triage_level: 'low'}, matches: false});
  const result = await env.completion.complete({request_id: 'p1', status: 'completed'});
  assert.equal(result.wake_ai_analysis, false);
  assert.equal(env.calls.some(({name}) => name === 'campaign'), false);
  assert.equal(env.calls.some(({name}) => name === 'enqueue'), false);
});

test('incident-response-only campaigns suppress duplicate AI work', async () => {
  const env = harness({
    row: {queue_group_id: 'g1', triage_level: 'high', alert_id: 'a1'},
    campaign: {campaign_id: 'campaign-1', investigation_mode: 'incident_response_only'},
  });
  const result = await env.completion.complete({request_id: 'p1', status: 'completed'});
  assert.equal(result.ai_analysis_coalesced_campaign, 'campaign-1');
  assert.equal(result.wake_ai_analysis, false);
  assert.equal(env.calls.some(({name}) => name === 'enqueue'), false);
});

test('eligible completion enqueues exact durable identity before returning wake intent', async () => {
  const env = harness({row: {
    queue_group_id: 'g1', queue_group_key: 'stable-g1', triage_level: 'high',
    alert_id: 'a1', analysis_attempt_count: 3, artifact_size_bytes: 64,
  }});
  const result = await env.completion.complete({request_id: 'p1', status: 'completed'});
  assert.equal(result.wake_ai_analysis, true);
  const enqueue = env.calls.find(({name}) => name === 'enqueue');
  assert.deepEqual(enqueue.args, [
    'g1',
    {group_id: 'g1', group_key: 'stable-g1', representative_alert_id: 'a1'},
    {priority: 3, maxAttempts: 8},
  ]);
  assert.equal(env.calls.at(-1).name, 'metric');
  assert.match(env.calls.at(-1).args[3].eventKey, /g1:pcap:p1:3$/);
});
