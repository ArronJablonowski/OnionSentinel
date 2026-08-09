'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createPcapService} = require('../services/pcap_service');

function harness({wakePcap = false, wakeAi = false, failCommit = false} = {}) {
  const calls = [];
  const operation = (name, result = {ok: true}) => async (value) => {
    calls.push({name, value});
    return {...result};
  };
  const service = createPcapService({
    withWriteGate: async (callback) => {
      calls.push({name: 'gate:begin'});
      const result = await callback();
      calls.push({name: 'gate:end'});
      return result;
    },
    withTransaction: async (callback) => {
      calls.push({name: 'transaction:begin'});
      const result = await callback();
      if (failCommit) throw new Error('commit failed');
      calls.push({name: 'transaction:commit'});
      return result;
    },
    createRequest: operation('createRequest'),
    listRequests: operation('listRequests', {ok: true, requests: []}),
    claimRequest: operation('claimRequest'),
    completeRequest: operation('completeRequest', {ok: true, wake_pcap_analysis: wakePcap}),
    updateTransferProgress: operation('updateTransferProgress'),
    retryRequest: operation('retryRequest'),
    completeAnalysis: operation('completeAnalysis', {ok: true, wake_ai_analysis: wakeAi}),
    requeueRequests: operation('requeueRequests'),
    signalPcapWorker: async (reason) => calls.push({name: 'signalPcapWorker', value: reason}),
    signalAiWorkers: async (reason) => calls.push({name: 'signalAiWorkers', value: reason}),
  });
  return {calls, service};
}

test('owns the write gate for every PCAP mutation and leaves listing read-only', async () => {
  const cases = [
    ['request', 'createRequest'],
    ['claim', 'claimRequest'],
    ['progress', 'updateTransferProgress'],
    ['retry', 'retryRequest'],
    ['requeue', 'requeueRequests'],
  ];
  for (const [method, operation] of cases) {
    const env = harness();
    await env.service[method]({request_id: 'pcap-1'});
    assert.deepEqual(env.calls.map(({name}) => name), [
      'gate:begin', operation, 'gate:end',
    ]);
  }
  const env = harness();
  const query = new URLSearchParams('status=pending');
  await env.service.list(query);
  assert.deepEqual(env.calls, [{name: 'listRequests', value: query}]);
});

test('signals the PCAP worker only after committed transfer metadata and hides wake state', async () => {
  const env = harness({wakePcap: true});
  assert.deepEqual(await env.service.complete({request_id: 'pcap-1'}), {ok: true});
  assert.deepEqual(env.calls.map(({name}) => name), [
    'gate:begin', 'completeRequest', 'gate:end', 'signalPcapWorker',
  ]);
  assert.equal(env.calls.at(-1).value, 'pcap-transfer-completed');

  const quiet = harness();
  assert.deepEqual(await quiet.service.complete({}), {ok: true});
  assert.equal(quiet.calls.some(({name}) => name === 'signalPcapWorker'), false);
});

test('commits analysis status before waking AI and hides internal wake state', async () => {
  const env = harness({wakeAi: true});
  assert.deepEqual(await env.service.analysisStatus({request_id: 'pcap-1'}), {ok: true});
  assert.deepEqual(env.calls.map(({name}) => name), [
    'gate:begin', 'transaction:begin', 'completeAnalysis',
    'transaction:commit', 'gate:end', 'signalAiWorkers',
  ]);
  assert.equal(env.calls.at(-1).value, 'pcap-analysis-completed');
});

test('a failed analysis-status commit never wakes AI workers', async () => {
  const env = harness({wakeAi: true, failCommit: true});
  await assert.rejects(env.service.analysisStatus({}), /commit failed/);
  assert.equal(env.calls.some(({name}) => name === 'signalAiWorkers'), false);
});
