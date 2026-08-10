'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const definitions = require('../lib/controlled_retirement_identity');
const {createControlledRetirementReplay} = require('../services/controlled_retirement_replay');

const identity = {
  case_id: 'case-1',
  cohort_id: 'cohort-1',
  dispatch_id: 'dispatch-1',
  reanalysis_run_id: 'irr-run-1',
  job_id: 7,
};

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function receipt() {
  const value = Object.fromEntries(definitions.RECEIPT_FIELDS.map((field) => [field, false]));
  Object.assign(value, {
    case_agent_status: 'failed',
    idempotent: true,
    identity,
    lineage_after_sha256: 'hash',
    lineage_before_sha256: 'hash',
    ok: true,
    receipt_sha256: 'hash',
    retirement_id: 'retirement-1',
    schema: definitions.RECEIPT_SCHEMA,
    status: 'retired',
    target_after: {state: 'retired'},
    target_before: {state: 'pending'},
  });
  return value;
}

function owner(rows = []) {
  return createControlledRetirementReplay({
    all: async () => rows,
    get: async () => null,
    eventType: definitions.EVENT_TYPE,
    receiptFields: definitions.RECEIPT_FIELDS,
    receiptSchema: definitions.RECEIPT_SCHEMA,
    dispatchIdPattern: /^hash$/,
    parseJsonObject: JSON.parse,
    canonicalJsonText: canonical,
    sha256: () => 'hash',
    projectJob: (value) => value,
    projectCensus: async () => ({members: []}),
    conflict: (message) => new Error(message),
  });
}

test('validates the exact bounded retirement receipt schema', () => {
  const value = receipt();
  assert.equal(owner().validateReceipt(value, identity, 'retirement-1'), value);
});

test('rejects an extra retirement receipt field', () => {
  const value = {...receipt(), unexpected: true};
  assert.throws(
    () => owner().validateReceipt(value, identity, 'retirement-1'),
    /receipt identity changed/,
  );
});

test('replays one canonical matching receipt', async () => {
  const value = receipt();
  const result = await owner([{id: 1, detail_json: canonical(value)}]).replay(
    identity,
    'retirement-1',
  );
  assert.deepEqual(result, value);
});

test('rejects multiple matching retirement lineage events', async () => {
  const value = receipt();
  const row = {id: 1, detail_json: canonical(value)};
  await assert.rejects(
    owner([row, {...row, id: 2}]).replay(identity, 'retirement-1'),
    /retirement lineage is ambiguous/,
  );
});
