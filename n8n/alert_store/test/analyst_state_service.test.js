'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAnalystStateService} = require('../services/analyst_state_service');

function harness() {
  const calls = [];
  const operation = (name) => async (value) => {
    calls.push({name, value});
    return {name, value};
  };
  const service = createAnalystStateService({
    analystStatusSnapshot: operation('statusSnapshot'),
    updateAnalystStatus: operation('putStatus'),
    analystAdjudicationSnapshot: operation('adjudicationSnapshot'),
    recordAnalystAdjudication: operation('recordAdjudication'),
    updateIncidentCaseStatus: operation('putIncidentStatus'),
    withWriteGate: async (callback) => {
      calls.push({name: 'writeGate:begin'});
      const result = await callback();
      calls.push({name: 'writeGate:end'});
      return result;
    },
    withTransaction: async (callback) => {
      calls.push({name: 'transaction:begin'});
      const result = await callback();
      calls.push({name: 'transaction:end'});
      return result;
    },
  });
  return {calls, service};
}

test('preserves direct status and adjudication read operations', async () => {
  const env = harness();
  const query = new URLSearchParams('group_id=abcdef123456');
  await env.service.statusSnapshot();
  await env.service.putStatus({status: 'open'});
  await env.service.adjudicationSnapshot(query);
  assert.deepEqual(env.calls, [
    {name: 'statusSnapshot', value: undefined},
    {name: 'putStatus', value: {status: 'open'}},
    {name: 'adjudicationSnapshot', value: query},
  ]);
});

test('owns the write gate and transaction around adjudication and incident writes', async () => {
  for (const [method, operation] of [
    ['recordAdjudication', 'recordAdjudication'],
    ['putIncidentStatus', 'putIncidentStatus'],
  ]) {
    const env = harness();
    const payload = {id: method};
    assert.deepEqual(await env.service[method](payload), {name: operation, value: payload});
    assert.deepEqual(env.calls.map(({name}) => name), [
      'writeGate:begin',
      'transaction:begin',
      operation,
      'transaction:end',
      'writeGate:end',
    ]);
  }
});
