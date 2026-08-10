'use strict';

const assert = require('node:assert/strict');
const nodePath = require('node:path');
const test = require('node:test');
const {createBeaconPersistence} = require('../services/beacon_persistence');

const generatedAt = '2026-08-10T02:00:00Z';
const currentMs = Date.parse(generatedAt);

function memoryFs(initial = {}, failDestinations = []) {
  const files = new Map(Object.entries(initial));
  const calls = [];
  return {
    files,
    calls,
    mkdirSync: (...args) => calls.push({name: 'mkdirSync', args}),
    writeFileSync: (...args) => {
      calls.push({name: 'writeFileSync', args});
      files.set(args[0], args[1]);
    },
    renameSync: (source, destination) => {
      calls.push({name: 'renameSync', args: [source, destination]});
      if (failDestinations.includes(destination)) throw new Error('rename unavailable');
      files.set(destination, files.get(source));
      files.delete(source);
    },
    readFileSync: (filePath) => {
      calls.push({name: 'readFileSync', args: [filePath, 'utf8']});
      if (!files.has(filePath)) throw new Error('missing');
      return files.get(filePath);
    },
  };
}

function parseTimestamp(value) {
  const parsed = new Date(String(value || '').replace('  ', 'T'));
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function nestedField(value, dottedPath) {
  return dottedPath.split('.').reduce((item, key) => item?.[key] ?? null, value);
}

function integerField(value) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 65535 ? parsed : null;
}

function nonNegativeIntegerField(value) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

function owner({initial, failDestinations, beaconPaths = ['/state/n8n-beacon.json'],
  historyPaths = []} = {}) {
  const fs = memoryFs(initial, failDestinations);
  const errors = [];
  const service = createBeaconPersistence({
    fs,
    path: nodePath,
    processId: 321,
    beaconPaths,
    beaconHistoryPaths: historyPaths,
    nowUtc: () => generatedAt,
    dateNow: () => currentMs,
    parseProjectTimestamp: parseTimestamp,
    nestedField,
    integerField,
    nonNegativeIntegerField,
    logError: (message) => errors.push(message),
  });
  return {errors, fs, service};
}

function storedJson(fs, filePath) {
  return JSON.parse(fs.files.get(filePath));
}

test('atomic JSON writes use a same-directory PID temp file and rename last', () => {
  const {fs, service} = owner();
  service.writeJsonAtomic('/state/value.json', {ok: true});
  assert.deepEqual(fs.calls, [
    {name: 'mkdirSync', args: ['/state', {recursive: true}]},
    {name: 'writeFileSync', args: ['/state/.value.json.321.tmp', '{\n  "ok": true\n}\n', 'utf8']},
    {name: 'renameSync', args: ['/state/.value.json.321.tmp', '/state/value.json']},
  ]);
});

test('PCAP workflow projection preserves bounds and numeric normalization', () => {
  const {service} = owner();
  assert.equal(service.boundedPcapWorkflowState(null), null);
  assert.equal(service.boundedPcapWorkflowState([]), null);
  const state = service.boundedPcapWorkflowState({
    state: 's'.repeat(70), deferred: 1, reason: 'r'.repeat(310), metric: 'm'.repeat(70),
    observed_percent: '2.5', threshold_percent: '', telemetry_age_seconds: 'invalid',
    processed: '4', operational_failures: -1,
  });
  assert.equal(state.state.length, 64);
  assert.equal(state.reason.length, 300);
  assert.equal(state.metric.length, 64);
  assert.deepEqual({...state, state: '', reason: '', metric: ''}, {
    state: '', deferred: true, reason: '', metric: '', observed_percent: 2.5,
    threshold_percent: null, telemetry_age_seconds: null, processed: 4,
    operational_failures: 0,
  });
});

test('received beacon preserves public projection and skips history and PCAP state', () => {
  const {fs, service} = owner();
  const payload = service.writeBeacon('received', {
    message_type: 'alert', source: 'relay', alert_count: '3', dropped_alert_count: 'bad',
    alert_id: 'source-id', rule_name: 'source-rule', source: {ip: '10.0.0.1'},
    destination: {ip: '10.0.0.2', port: '443'}, component: 'pcap_broker',
    pcap_workflow: {state: 'ready'},
  }, {alert: {alert_id: 'result-id', rule_name: 'result-rule'}, ok: false});
  assert.equal(payload.status, 'received');
  assert.equal(payload.ok, false);
  assert.equal(payload.alert_id, 'source-id');
  assert.equal(payload.rule_name, 'source-rule');
  assert.equal(payload.source_ip, '10.0.0.1');
  assert.equal(payload.destination_ip, '10.0.0.2');
  assert.equal(payload.destination_port, 443);
  assert.equal(payload.alert_count, 3);
  assert.equal(payload.dropped_alert_count, null);
  assert.deepEqual([...fs.files.keys()], ['/state/n8n-beacon.json']);
});

test('non-received PCAP beacon writes one bounded state and one deduplicated history per directory', () => {
  const {fs, service} = owner({
    beaconPaths: ['/state/beacon-one.json', '/state/beacon-two.json'],
    historyPaths: ['/state/n8n-beacon-history.json'],
  });
  service.writeBeacon('stored', {component: 'pcap_broker', relay_host: 'r'.repeat(140),
    pcap_workflow: {state: 'complete', processed: 2}}, {ok: true, status: 'stored'});
  const state = storedJson(fs, '/state/pcap-workflow-state.json');
  assert.equal(state.relay_host.length, 128);
  assert.deepEqual(state.pcap_workflow, {state: 'complete', deferred: false, reason: '',
    metric: '', observed_percent: null, threshold_percent: null,
    telemetry_age_seconds: null, processed: 2, operational_failures: 0});
  const history = storedJson(fs, '/state/n8n-beacon-history.json');
  assert.equal(history.length, 1);
  assert.equal(history[0].history_recorded_at, generatedAt);
  assert.equal(fs.calls.filter(({name, args}) => name === 'renameSync'
    && args[1] === '/state/pcap-workflow-state.json').length, 1);
});

test('history removes expired records, keeps the latest 1000, then appends', () => {
  const historyPath = '/history/custom.json';
  const recent = Array.from({length: 1002}, (_, index) => ({
    generated_at: '2026-08-09T02:00:00Z', index,
  }));
  const {fs, service} = owner({historyPaths: [historyPath], initial: {
    [historyPath]: JSON.stringify([{generated_at: '2026-08-01T00:00:00Z'}, ...recent]),
  }});
  service.appendN8nBeaconHistory({generated_at: generatedAt, stage: 'stored'});
  const history = storedJson(fs, historyPath);
  assert.equal(history.length, 1001);
  assert.equal(history[0].index, 2);
  assert.equal(history.at(-1).stage, 'stored');
});

test('corrupt and non-array history fall back to one new entry', () => {
  for (const initialValue of ['{broken', '{"not":"an array"}']) {
    const historyPath = '/history/custom.json';
    const {fs, service} = owner({historyPaths: [historyPath], initial: {
      [historyPath]: initialValue,
    }});
    service.appendN8nBeaconHistory({generated_at: generatedAt, stage: 'error'});
    assert.equal(storedJson(fs, historyPath).length, 1);
  }
});

test('a beacon-path failure is logged and does not block later outputs', () => {
  const {errors, fs, service} = owner({
    beaconPaths: ['/failed/beacon.json', '/healthy/beacon.json'],
    failDestinations: ['/failed/beacon.json'],
  });
  const payload = service.writeBeacon('received', {}, null, new Error('ingest failed'));
  assert.equal(payload.ok, false);
  assert.equal(payload.status, 'error');
  assert.equal(payload.error, 'ingest failed');
  assert.equal(storedJson(fs, '/healthy/beacon.json').stage, 'received');
  assert.deepEqual(errors, [
    'Unable to write n8n beacon /failed/beacon.json: rename unavailable',
  ]);
});

test('history path order is configured first then unique derived paths', () => {
  const {service} = owner({
    beaconPaths: ['/a/beacon.json', '/b/beacon.json', '/a/second.json'],
    historyPaths: ['/custom/history.json', '/a/n8n-beacon-history.json'],
  });
  assert.deepEqual(service.n8nBeaconHistoryPaths(), [
    '/custom/history.json', '/a/n8n-beacon-history.json', '/b/n8n-beacon-history.json',
  ]);
});
