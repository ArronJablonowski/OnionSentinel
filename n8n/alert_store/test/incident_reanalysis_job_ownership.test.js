'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createIncidentReanalysisJobOwnership,
} = require('../services/incident_reanalysis_job_ownership');

function owner(overrides = {}) {
  const writes = [];
  const service = createIncidentReanalysisJobOwnership({
    safeString: (value) => String(value || '').trim(),
    validCaseId: (value) => (/^case-/.test(String(value || '')) ? value : ''),
    get: async () => null,
    all: async () => [],
    run: async (sql, params) => { writes.push({sql, params}); return {changes: 1}; },
    nowUtc: () => 'time',
    sha256Text: () => 'a'.repeat(64),
    refreshRun: async () => undefined,
    ...overrides,
  });
  return {service, writes};
}

function job(status = 'pending') {
  return {
    id: 7,
    status,
    payload_json: JSON.stringify({
      manual_reanalysis: true,
      reanalysis_run_id: 'run-1',
      case_id: 'case-1',
    }),
  };
}

test('parses only object job payloads and never throws on malformed JSON', () => {
  const {service} = owner();
  assert.deepEqual(service.jobPayload({payload_json: '{bad'}), {});
  assert.deepEqual(service.jobPayload({payload_json: '[]'}), {});
  assert.equal(service.jobPayload(job()).case_id, 'case-1');
});

test('derives a one-way bounded attempt identity without retaining the lease', () => {
  const {service} = owner();
  assert.equal(service.attemptId('secret-lease'), `ira-${'a'.repeat(40)}`);
  assert.equal(service.attemptId(''), '');
});

test('preserves explicit and route-derived analysis providers', () => {
  const {service} = owner();
  assert.equal(service.analysisProvider('ollama'), 'ollama');
  assert.equal(service.analysisProvider('hermes-agent'), 'openai-codex');
  assert.equal(service.analysisProvider('ollama', 'Observed'), 'observed');
});

test('retires a completed manual job with exact payload compare-and-set', async () => {
  const {service, writes} = owner({get: async () => ({analysis_id: 'analysis-1'})});
  assert.equal(await service.retireCompleted(job()), true);
  assert.equal(writes.length, 1);
  assert.match(writes[0].sql, /payload_json = \?/);
});

test('does not retire an unproven or non-pending superseded job', async () => {
  const {service, writes} = owner({get: async () => ({present: 1})});
  assert.equal(await service.retireSuperseded(job('processing')), false);
  assert.equal(writes.length, 0);
});
