'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createScoringPolicy} = require('../lib/scoring_policy');

const rules = {
  thresholds: {medium_min: 40, high_min: 70, critical_min: 85},
  severity_base: {
    critical: 85,
    high: 70,
    medium: 45,
    low: 25,
    numeric_4_or_more: 75,
    numeric_3: 60,
    numeric_2: 45,
    numeric_1: 25,
    default: 30,
  },
  infrastructure_ips: ['10.77.7.225'],
  direction_adjustments: {
    inbound: 15, outbound: 10, internal: 3, external: 0, unknown: 0,
  },
  infrastructure_adjustments: {destination: 15, source: 5},
  keyword_adjustments: [
    {keywords: ['malware'], score_delta: 7, reason: 'malware wording'},
    {
      name: 'informational or low severity',
      keywords: [],
      score_delta: -6,
      reason: 'configured low severity adjustment',
    },
  ],
  rule_adjustments: [
    {rule_contains: 'known benign', score_delta: -90, reason: 'known benign rule'},
  ],
  pair_adjustments: [],
  drop_rules: [{name: 'drop heartbeat', rule_contains: 'heartbeat'}],
  filter_rules: {drop_alerts: [{reason: 'drop scanner', keywords: ['scanner-noise']}]},
  suppress_rules: [{
    name: 'repeat C2',
    levels: ['high'],
    keywords: ['command and control'],
    key_fields: ['triage.level', 'rule_name', 'source.ip'],
  }],
};

function nestedField(value, dottedPath) {
  return dottedPath.split('.').reduce(
    (current, part) => (current && typeof current === 'object'
      ? current[part] : undefined),
    value,
  );
}

const policy = createScoringPolicy({rules, nestedField});

test('preserves IPv4 validation, private ranges, and traffic directions', () => {
  assert.deepEqual(policy.parseIpv4('192.168.1.7'), [192, 168, 1, 7]);
  for (const invalid of [null, '192.168.1', '192.168.1.256', 'x.1.2.3']) {
    assert.equal(policy.parseIpv4(invalid), null);
  }
  for (const privateIp of ['10.0.0.1', '172.16.0.1', '172.31.255.1', '192.168.1.1', '100.64.0.1', '127.0.0.1']) {
    assert.equal(policy.isPrivateIpv4(privateIp), true, privateIp);
  }
  assert.equal(policy.isPrivateIpv4('172.32.0.1'), false);
  assert.equal(policy.trafficDirection('198.51.100.1', '10.0.0.1'), 'inbound');
  assert.equal(policy.trafficDirection('10.0.0.1', '198.51.100.1'), 'outbound');
  assert.equal(policy.trafficDirection('10.0.0.1', '192.168.1.1'), 'internal');
  assert.equal(policy.trafficDirection('198.51.100.1', '203.0.113.2'), 'external');
  assert.equal(policy.trafficDirection('', ''), 'unknown');
});

test('preserves deterministic scoring, routing, infrastructure, and reasons', () => {
  const result = policy.scoreAlert({
    severity_label: 'medium',
    rule_name: 'Malware callback',
    source: {ip: '198.51.100.2'},
    destination: {ip: '10.77.7.225'},
  });
  assert.deepEqual(result, {
    score: 82,
    level: 'high',
    routing: 'analyst-review-immediate',
    traffic_direction: 'inbound',
    source_is_private: false,
    destination_is_private: true,
    source_is_infrastructure: false,
    destination_is_infrastructure: true,
    reasons: [
      'base severity score 45',
      'public-to-private inbound traffic',
      'destination is monitored infrastructure',
      'malware wording',
    ],
  });
});

test('preserves low adjustment, rule clamps, and numeric severity fallback', () => {
  const low = policy.scoreAlert({
    severity_label: 'low',
    rule_name: 'Known Benign chatter',
    source: {ip: '10.0.0.1'},
    destination: {ip: '10.0.0.2'},
  });
  assert.equal(low.score, 0);
  assert.equal(low.level, 'low');
  assert.deepEqual(low.reasons, [
    'base severity score 25',
    'internal private traffic',
    'configured low severity adjustment',
    'known benign rule',
  ]);
  assert.equal(policy.scoreAlert({severity: 4}).score, 75);
});

test('preserves drop and suppression policy matching and stable keys', () => {
  assert.equal(policy.ruleName({}), 'unnamed policy rule');
  assert.equal(policy.findDropRule({rule_name: 'Relay heartbeat'})?.name, 'drop heartbeat');
  assert.equal(policy.findDropRule({rule_name: 'scanner-noise event'})?.reason, 'drop scanner');
  assert.equal(policy.findDropRule({rule_name: 'ordinary'}), null);

  const alert = {
    rule_name: 'Command and Control detected',
    triage: {level: 'high'},
    source: {ip: '192.0.2.4'},
  };
  const suppress = policy.findSuppressRule(alert);
  assert.equal(suppress?.name, 'repeat C2');
  assert.equal(
    policy.suppressionKey(suppress, alert),
    'triage.level=high|rule_name=Command and Control detected|source.ip=192.0.2.4',
  );
  assert.equal(policy.findSuppressRule({...alert, triage: {level: 'medium'}}), null);
});
