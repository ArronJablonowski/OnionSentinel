'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createScoringRulesRuntime,
  defaultScoringRules,
} = require('../lib/scoring_rules_runtime');

function fixture({contents = '{}', failure = null, path = '/config/scoring_rules.json'} = {}) {
  const reads = [];
  const errors = [];
  const runtime = createScoringRulesRuntime({
    fs: {
      readFileSync: (...args) => {
        reads.push(args);
        if (failure) throw failure;
        return contents;
      },
    },
    scoringRulesPath: path,
    logError: (message) => errors.push(message),
  });
  return {errors, reads, runtime};
}

test('default rules preserve the exact production scoring fallback', () => {
  assert.deepEqual(defaultScoringRules(), {
    thresholds: {medium_min: 40, high_min: 70, critical_min: 85},
    severity_base: {
      critical: 85, high: 70, medium: 45, low: 25,
      numeric_4_or_more: 75, numeric_3: 60, numeric_2: 45,
      numeric_1: 25, default: 30,
    },
    infrastructure_ips: ['192.168.1.7', '10.77.7.225'],
    direction_adjustments: {
      inbound: 15, outbound: 10, internal: 3, external: 0, unknown: 0,
    },
    infrastructure_adjustments: {destination: 15, source: 5},
    keyword_adjustments: [], rule_adjustments: [], pair_adjustments: [],
    drop_rules: [], suppress_rules: [],
  });
});

test('empty configuration reads exact UTF-8 path and retains all defaults', () => {
  const {errors, reads, runtime} = fixture();
  assert.deepEqual(runtime.load(), defaultScoringRules());
  assert.deepEqual(reads, [['/config/scoring_rules.json', 'utf8']]);
  assert.deepEqual(errors, []);
});

test('configured values retain shallow top-level override semantics', () => {
  const configured = {
    thresholds: {critical_min: 99},
    infrastructure_ips: ['10.0.0.5'],
    drop_rules: [{name: 'configured drop'}],
    custom_extension: {enabled: true},
  };
  const {runtime} = fixture({contents: JSON.stringify(configured)});
  const loaded = runtime.load();
  assert.deepEqual(loaded.thresholds, {critical_min: 99});
  assert.deepEqual(loaded.infrastructure_ips, ['10.0.0.5']);
  assert.deepEqual(loaded.drop_rules, [{name: 'configured drop'}]);
  assert.deepEqual(loaded.custom_extension, {enabled: true});
  assert.deepEqual(loaded.severity_base, defaultScoringRules().severity_base);
});

test('missing file preserves defaults and emits the exact bounded diagnostic', () => {
  const failure = new Error('ENOENT');
  const {errors, runtime} = fixture({failure, path: '/missing/rules.json'});
  assert.deepEqual(runtime.load(), defaultScoringRules());
  assert.deepEqual(errors, [
    'Unable to load scoring rules from /missing/rules.json: ENOENT',
  ]);
});

test('invalid JSON preserves defaults and reports the parser failure', () => {
  const {errors, runtime} = fixture({contents: '{invalid'});
  assert.deepEqual(runtime.load(), defaultScoringRules());
  assert.equal(errors.length, 1);
  assert.match(errors[0], /^Unable to load scoring rules from \/config\/scoring_rules\.json:/);
  assert.match(errors[0], /JSON|property|position|expected/i);
});

test('each fallback load owns independent mutable nested values', () => {
  const first = fixture({failure: new Error('missing')}).runtime.load();
  const second = fixture({failure: new Error('missing')}).runtime.load();
  first.thresholds.medium_min = 1;
  first.infrastructure_ips.push('127.0.0.1');
  assert.equal(second.thresholds.medium_min, 40);
  assert.deepEqual(second.infrastructure_ips, ['192.168.1.7', '10.77.7.225']);
});
