'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAlertIngestService} = require('../services/alert_ingest_service');

function harness({heartbeat = false, storeResult = {ok: true, stored: true}} = {}) {
  const calls = [];
  const metrics = {
    ingest_requests: 0,
    ingest_latency_ms_total: 10,
    ingest_latency_ms_max: 3,
  };
  let clock = 100;
  const service = createAlertIngestService({
    metrics,
    now: () => {
      const value = clock;
      clock += 7;
      return value;
    },
    readJsonBody: async (request) => {
      calls.push({name: 'readJsonBody', request});
      return {alert_id: 'alert-1'};
    },
    writeBeacon: (...args) => {
      calls.push({name: 'beacon', args});
      return {path: '/bounded/beacon'};
    },
    isRelayHeartbeat: () => heartbeat,
    assertDiskWriteAdmission: (reason) => calls.push({name: 'disk', reason}),
    storeAlert: async (alert) => {
      calls.push({name: 'storeAlert', alert});
      return storeResult;
    },
  });
  return {calls, metrics, service};
}

test('counts intake before parsing and records storage latency and beacon order', async () => {
  const env = harness();
  const request = {url: '/alert'};
  assert.deepEqual(await env.service.ingest(request), {ok: true, stored: true});
  assert.equal(env.metrics.ingest_requests, 1);
  assert.equal(env.metrics.ingest_latency_ms_total, 17);
  assert.equal(env.metrics.ingest_latency_ms_max, 7);
  assert.deepEqual(env.calls.map(({name}) => name), [
    'readJsonBody', 'beacon', 'disk', 'storeAlert', 'beacon',
  ]);
  assert.equal(env.calls[1].args[0], 'received');
  assert.equal(env.calls.at(-1).args[0], 'stored');
});

test('accepts relay heartbeat before disk admission or persistent storage', async () => {
  const env = harness({heartbeat: true});
  assert.deepEqual(await env.service.ingest({}), {
    ok: true,
    status: 'heartbeat',
    stored: false,
    beacon: {path: '/bounded/beacon'},
  });
  assert.deepEqual(env.calls.map(({name}) => name), [
    'readJsonBody', 'beacon', 'beacon',
  ]);
  assert.equal(env.metrics.ingest_requests, 1);
  assert.equal(env.metrics.ingest_latency_ms_total, 10);
});

test('a body parse failure still counts the attempted intake without storage latency', async () => {
  const metrics = {ingest_requests: 0, ingest_latency_ms_total: 0, ingest_latency_ms_max: 0};
  const expected = new Error('malformed JSON');
  const service = createAlertIngestService({
    metrics,
    now: () => 1,
    readJsonBody: async () => { throw expected; },
    writeBeacon: () => {},
    isRelayHeartbeat: () => false,
    assertDiskWriteAdmission: () => {},
    storeAlert: async () => ({ok: true}),
  });
  await assert.rejects(service.ingest({}), expected);
  assert.equal(metrics.ingest_requests, 1);
  assert.equal(metrics.ingest_latency_ms_total, 0);
});
