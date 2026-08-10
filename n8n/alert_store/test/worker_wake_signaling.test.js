'use strict';

const assert = require('node:assert/strict');
const nodePath = require('node:path');
const test = require('node:test');
const {createWorkerWakeSignaling} = require('../services/worker_wake_signaling');

function owner({controlled = false, wakePaths = ['/run/ai-one.wake', '/run/ai-two.wake'],
  mkdir, writeFile} = {}) {
  const calls = [];
  const errors = [];
  const service = createWorkerWakeSignaling({
    fs: {promises: {
      mkdir: mkdir || (async (...args) => calls.push({name: 'mkdir', args})),
      writeFile: writeFile || (async (...args) => calls.push({name: 'writeFile', args})),
    }},
    path: nodePath,
    nowUtc: () => '2026-08-10T02:00:00Z',
    isControlledEvaluation: () => controlled,
    aiAnalysisWakePaths: wakePaths,
    logError: (message) => errors.push(message),
  });
  return {calls, errors, service};
}

test('empty wake path is a no-op', async () => {
  const {calls, service} = owner();
  assert.equal(await service.signalWorker('', 'alert-committed'), false);
  assert.deepEqual(calls, []);
});

test('wake file preserves modes, encoding, timestamp, sanitization, and event bound', async () => {
  const {calls, service} = owner();
  const eventName = 'AI ready!?/'.repeat(10);
  assert.equal(await service.signalWorker('/run/nested/ai.wake', eventName), true);
  assert.deepEqual(calls[0], {name: 'mkdir',
    args: ['/run/nested', {recursive: true, mode: 0o700}]});
  const expectedEvent = eventName.replace(/[^a-z0-9_-]/gi, '-').slice(0, 64);
  assert.deepEqual(calls[1], {name: 'writeFile', args: [
    '/run/nested/ai.wake', `2026-08-10T02:00:00Z ${expectedEvent}\n`,
    {encoding: 'utf8', mode: 0o600},
  ]});
  assert.equal(expectedEvent.length, 64);
});

test('missing event name retains the work-available fallback', async () => {
  const {calls, service} = owner();
  await service.signalWorker('/run/ai.wake');
  assert.equal(calls[1].args[1], '2026-08-10T02:00:00Z work-available\n');
});

test('filesystem failure is non-fatal and retains the diagnostic', async () => {
  const failure = new Error('read-only filesystem');
  const {errors, service} = owner({mkdir: async () => { throw failure; }});
  assert.equal(await service.signalWorker('/run/ai.wake', 'alert-committed'), false);
  assert.deepEqual(errors, [
    '2026-08-10T02:00:00Z worker wake signal failed for alert-committed: read-only filesystem',
  ]);
});

test('controlled evaluation suppresses all AI wake writes', async () => {
  const {calls, service} = owner({controlled: true});
  assert.equal(await service.signalAiWorkers('alert-committed'), false);
  assert.deepEqual(calls, []);
});

test('AI fan-out attempts every path and succeeds when any write succeeds', async () => {
  const writes = [];
  const {errors, service} = owner({writeFile: async (wakePath) => {
    writes.push(wakePath);
    if (wakePath.endsWith('one.wake')) throw new Error('first unavailable');
  }});
  assert.equal(await service.signalAiWorkers('ai-lease-recovered'), true);
  assert.deepEqual(writes, ['/run/ai-one.wake', '/run/ai-two.wake']);
  assert.equal(errors.length, 1);
});

test('AI fan-out returns false when every wake write fails', async () => {
  const {errors, service} = owner({writeFile: async () => { throw new Error('unavailable'); }});
  assert.equal(await service.signalAiWorkers('alert-committed'), false);
  assert.equal(errors.length, 2);
});

test('empty AI wake path collection remains a false no-op', async () => {
  const {calls, service} = owner({wakePaths: []});
  assert.equal(await service.signalAiWorkers('alert-committed'), false);
  assert.deepEqual(calls, []);
});
