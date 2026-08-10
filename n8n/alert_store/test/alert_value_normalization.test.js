'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const values = require('../lib/alert_value_normalization');

test('relay heartbeat recognition remains exact and bounded', () => {
  assert.equal(values.isRelayHeartbeat({message_type: 'relay_heartbeat'}), true);
  assert.equal(values.isRelayHeartbeat({message_type: 'relay_health_recovery'}), true);
  assert.equal(values.isRelayHeartbeat({message_type: 'Relay_Heartbeat'}), false);
  assert.equal(values.isRelayHeartbeat(null), false);
});

test('nested fields preserve nullish leaves and stop at non-objects', () => {
  const payload = {source: {ip: '10.0.0.1', port: 0, enabled: false, empty: ''}};
  assert.equal(values.nestedField(payload, 'source.ip'), '10.0.0.1');
  assert.equal(values.nestedField(payload, 'source.port'), 0);
  assert.equal(values.nestedField(payload, 'source.enabled'), false);
  assert.equal(values.nestedField(payload, 'source.empty'), '');
  assert.equal(values.nestedField(payload, 'source.missing'), null);
  assert.equal(values.nestedField({source: false}, 'source.ip'), null);
});

test('port integer accepts numeric values only inside 0 through 65535', () => {
  for (const [input, expected] of [[0, 0], [false, 0], ['443', 443], [65535, 65535]]) {
    assert.equal(values.integerField(input), expected);
  }
  for (const input of [null, undefined, '', -1, 1.5, 65536, 'invalid']) {
    assert.equal(values.integerField(input), null);
  }
});

test('non-negative integer requires a safe integer', () => {
  for (const [input, expected] of [[0, 0], [false, 0], ['4', 4],
    [Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]]) {
    assert.equal(values.nonNegativeIntegerField(input), expected);
  }
  for (const input of [null, undefined, '', -1, 1.5, Number.MAX_SAFE_INTEGER + 1, 'bad']) {
    assert.equal(values.nonNegativeIntegerField(input), null);
  }
});

test('enrichment companion projection keeps exact fields and defaults', () => {
  const alert = {message: 'event', tags: ['tag'], dns: {question: 'example.test'},
    enrichment: {external_intel: {verdict: 'clean'}}, ignored: 'full alert only'};
  assert.deepEqual(values.enrichmentRecord(alert), {
    message: 'event', tags: ['tag'], labels: {}, ecs: {}, agent: {}, log: {},
    dns: {question: 'example.test'}, http: {}, url: {}, tls: {}, file: {}, process: {},
    user: {}, related: {}, threat: {}, zeek: {}, suricata: {}, security_onion: {},
    external_intel: {verdict: 'clean'},
  });
  assert.equal(Object.hasOwn(values.enrichmentRecord(alert), 'ignored'), false);
});

test('triage normalization preserves levels, info alias, fallback, and unknown', () => {
  assert.equal(values.normalizeTriageLevel(' HIGH '), 'high');
  assert.equal(values.normalizeTriageLevel('info'), 'informational');
  assert.equal(values.normalizeTriageLevel('invalid', ' CRITICAL '), 'critical');
  assert.equal(values.normalizeTriageLevel('', 'info'), 'informational');
  assert.equal(values.normalizeTriageLevel('invalid', 'also-invalid'), 'unknown');
});

test('safe strings trim, collapse whitespace, stringify nullish, and bound output', () => {
  assert.equal(values.safeString('  alpha\n\t beta  '), 'alpha beta');
  assert.equal(values.safeString(null), '');
  assert.equal(values.safeString(42), '42');
  assert.equal(values.safeString('abcdef', 4), 'abcd');
});

test('safe file tokens retain allowed characters and bounded fallback behavior', () => {
  assert.equal(values.safeFileToken(' ..Alert name / evidence!!.json.. '),
    'Alert-name-evidence-.json');
  assert.equal(values.safeFileToken('...'), 'artifact');
  assert.equal(values.safeFileToken('...', 'fallback'), 'fallback');
  assert.ok(values.safeFileToken('a'.repeat(200)).length <= 180);
});

test('parsed JSON accepts only serialized non-array objects', () => {
  assert.deepEqual(values.parseJsonObject('{"ok":true}'), {ok: true});
  for (const input of [null, '', '{broken', '[]', 'null', '1', '"text"', {ok: true}]) {
    assert.deepEqual(values.parseJsonObject(input), {});
  }
});
