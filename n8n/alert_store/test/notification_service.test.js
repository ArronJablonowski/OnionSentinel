'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createNotificationService} = require('../services/notification_service');

function createHarness(overrides = {}) {
  const reads = [...(overrides.reads || [])];
  const writes = [];
  const service = createNotificationService({
    nestedField: (value, dottedPath) => dottedPath.split('.').reduce(
      (current, key) => current?.[key], value,
    ),
    normalizeTimestampValue: (value) => value,
    formatProjectTimestamp: (value) => value.toISOString(),
    nowUtc: () => '2026-08-09 22:15:00+00:00',
    get: async () => reads.shift() || null,
    run: async (sql, params) => writes.push({sql, params}),
    all: async () => [{status: 'pending', count: 2}, {status: 'failed', count: 1}],
    withSqliteWriteGate: async (task) => task(),
    withImmediateTransaction: async (task) => task(),
    botToken: 'configured-token',
    chatId: 'configured-chat',
    alertLevels: new Set(['critical', 'high']),
    cooldownSeconds: 900,
    outboxBaseRetrySeconds: 30,
    outboxMaxRetrySeconds: 3600,
    outboxMaxAttempts: 8,
    outboxAutostart: false,
    controlledEvaluationMode: false,
    nowMs: () => Date.parse('2026-08-09T22:15:00Z'),
    ...overrides.dependencies,
  });
  return {service, writes};
}

const alert = {
  alert_id: 'sensor:event:123456789012345678901',
  rule_name: 'Rule <One>',
  timestamp: '2026-08-09T22:14:00Z',
  source: {ip: '198.51.100.1'},
  destination: {ip: '203.0.113.2'},
  triage: {
    level: 'critical',
    score: 99,
    routing: 'immediate',
    traffic_direction: 'inbound',
    reasons: ['base severity score 80', 'public exploit <match>'],
  },
};

test('preserves stable cooldown keys and bounded escaped phone text', () => {
  const {service} = createHarness();
  assert.equal(
    service.notificationKey(alert),
    'critical|Rule <One>|198.51.100.1|203.0.113.2',
  );
  const formatted = service.formatTelegramAlert(alert, {});
  assert.match(formatted, /\[CRITICAL\] Security Onion Alert/);
  assert.match(formatted, /Rule &lt;One&gt;/);
  assert.match(formatted, /public exploit &lt;match&gt;/);
  assert.match(formatted, /Alert ID: 123456789012345678\.\.\./);
});

test('preserves duplicate, suppression, disabled, and level skip decisions', async () => {
  const {service} = createHarness();
  assert.equal((await service.queueTelegramNotification(alert, {}, false, '')).status, 'skipped_duplicate');
  assert.deepEqual(
    await service.queueTelegramNotification(alert, {}, true, '', {
      status: 'suppressed', key: 'k', rule: 'r', ttl_seconds: 60, seen_count: 3,
    }),
    {
      channel: 'telegram', status: 'skipped_suppression', suppression_key: 'k',
      suppression_rule: 'r', suppression_ttl_seconds: 60, suppression_seen_count: 3,
    },
  );
  const disabled = createHarness({dependencies: {botToken: ''}}).service;
  assert.equal((await disabled.queueTelegramNotification(alert, {}, true, '')).status, 'disabled');
  const low = {...alert, triage: {...alert.triage, level: 'low'}};
  assert.equal(
    (await service.queueTelegramNotification(low, {}, true, '')).status,
    'skipped_level',
  );
});

test('checks cooldown and pending intent before one durable enqueue', async () => {
  const cooldown = createHarness({reads: [{last_sent: '2026-08-09T22:10:00Z'}]}).service;
  assert.equal(
    (await cooldown.queueTelegramNotification(
      alert, {}, true, '2026-08-09T22:15:00Z',
    )).status,
    'skipped_cooldown',
  );
  const pending = createHarness({reads: [null, {id: 42}]}).service;
  assert.equal(
    (await pending.queueTelegramNotification(
      alert, {}, true, '2026-08-09T22:15:00Z',
    )).status,
    'skipped_pending',
  );
  const {service, writes} = createHarness({reads: [null, null]});
  assert.equal(
    (await service.queueTelegramNotification(
      alert, {}, true, '2026-08-09T22:15:00Z',
    )).status,
    'queued',
  );
  assert.equal(writes.length, 1);
  assert.match(writes[0].sql, /INSERT INTO notification_outbox/);
  assert.doesNotMatch(writes[0].params[6], /configured-token/);
});

test('keeps retries bounded and controlled evaluation network-disabled', async () => {
  const {service, writes} = createHarness();
  assert.equal(service.outboxRetryTimestamp(1), '2026-08-09T22:15:30.000Z');
  await service.failTelegramOutboxItem({id: 7, attempt_count: 8}, new Error('bounded'));
  assert.equal(writes[0].params[0], 'failed');
  assert.equal(writes[0].params[2], 'bounded');
  const controlled = createHarness({
    dependencies: {controlledEvaluationMode: true},
  }).service;
  await assert.rejects(
    controlled.postTelegramMessage('do not send'),
    /disabled in controlled evaluation mode/,
  );
  assert.deepEqual(await service.telegramOutboxSnapshot(), {pending: 2, failed: 1});
});
