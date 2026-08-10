'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createNotificationEnrichmentSchema,
} = require('../services/notification_enrichment_schema');

function owner() {
  const events = [];
  const service = createNotificationEnrichmentSchema({
    run: async (sql, params = []) => {
      events.push({type: 'run', sql: sql.replace(/\s+/g, ' ').trim(), params});
    },
    nowUtc: () => '2026-08-10T00:00:00Z',
    installEnrichmentCache: async () => events.push({type: 'cache'}),
  });
  return {events, service};
}

test('installs notification, suppression, cache, and rate-limit owners in order', async () => {
  const {events, service} = owner();
  await service.install();
  const notification = events.findIndex((event) => event.sql?.includes('notification_log'));
  const outbox = events.findIndex((event) => event.sql?.includes('TABLE IF NOT EXISTS notification_outbox'));
  const suppression = events.findIndex((event) => event.sql?.includes('suppression_log'));
  const cache = events.findIndex((event) => event.type === 'cache');
  const rateLimit = events.findIndex((event) => event.sql?.includes('enrichment_rate_limit'));
  assert(notification >= 0 && notification < outbox && outbox < suppression
    && suppression < cache && cache < rateLimit);
});

test('recovers only interrupted delivery claims after indexes are available', async () => {
  const {events, service} = owner();
  await service.install();
  const dueIndex = events.findIndex((event) => event.sql?.includes('idx_notification_outbox_due'));
  const keyIndex = events.findIndex((event) => event.sql?.includes('idx_notification_outbox_key'));
  const recovery = events.findIndex((event) => event.sql?.startsWith('UPDATE notification_outbox'));
  assert(dueIndex >= 0 && dueIndex < keyIndex && keyIndex < recovery);
  assert.deepEqual(events[recovery], {
    type: 'run',
    sql: "UPDATE notification_outbox SET status = 'pending', updated_at = ? WHERE status = 'delivering'",
    params: ['2026-08-10T00:00:00Z'],
  });
});

test('does not invoke wall clock before the outbox recovery statement', async () => {
  let clockReads = 0;
  const statements = [];
  const service = createNotificationEnrichmentSchema({
    run: async (sql, params = []) => statements.push({sql, params, clockReads}),
    nowUtc: () => { clockReads += 1; return 'time'; },
    installEnrichmentCache: async () => undefined,
  });
  await service.install();
  assert.equal(clockReads, 1);
  const recovery = statements.find((entry) => entry.sql.startsWith('UPDATE notification_outbox'));
  assert.deepEqual(recovery.params, ['time']);
  assert.equal(recovery.clockReads, 1);
});
