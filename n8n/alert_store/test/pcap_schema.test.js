'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createPcapSchema} = require('../services/pcap_schema');

function owner() {
  const events = [];
  const service = createPcapSchema({
    run: async (sql) => events.push({type: 'run', sql: sql.replace(/\s+/g, ' ').trim()}),
    ensureColumn: async (table, name, definition) => {
      events.push({type: 'column', table, name, definition});
    },
    backfillOutcomes: async () => events.push({type: 'outcomes'}),
  });
  return {events, service};
}

test('retains all additive PCAP compatibility columns in exact order', async () => {
  const {events, service} = owner();
  await service.install();
  assert.deepEqual(events.filter((event) => event.type === 'column').map((event) => event.name), [
    'claimed_at', 'completed_at', 'diagnostics_json', 'analysis_status',
    'analysis_attempt_count', 'analysis_error', 'analysis_started_at',
    'analysis_completed_at', 'outcome', 'transfer_stage', 'transfer_bytes',
    'transfer_total_bytes', 'transfer_progress_at', 'transfer_duration_seconds',
    'transfer_attempt_count', 'transfer_retry_count', 'transfer_last_error',
    'transfer_last_failed_stage', 'next_attempt_at',
  ]);
});

test('runs duration and outcome backfills before creating lookup indexes', async () => {
  const {events, service} = owner();
  await service.install();
  const duration = events.findIndex((event) => event.sql?.startsWith('UPDATE pcap_requests'));
  const outcomes = events.findIndex((event) => event.type === 'outcomes');
  const firstIndex = events.findIndex((event) => event.sql?.startsWith('CREATE INDEX'));
  assert(duration >= 0 && duration < outcomes && outcomes < firstIndex);
  assert(events[duration].sql.includes('transfer_duration_seconds IS NULL'));
  assert(events[duration].sql.includes('claimed_at IS NOT NULL'));
  assert(events[duration].sql.includes('completed_at IS NOT NULL'));
});

test('retains retry, completion, alert, and group lookup indexes', async () => {
  const {events, service} = owner();
  await service.install();
  const indexes = events.filter((event) => event.sql?.startsWith('CREATE INDEX'))
    .map((event) => event.sql);
  assert.equal(indexes.length, 5);
  for (const name of ['idx_pcap_requests_status_created',
    'idx_pcap_requests_status_next_attempt', 'idx_pcap_requests_completed_at',
    'idx_pcap_requests_alert_id', 'idx_pcap_requests_group_id']) {
    assert(indexes.some((sql) => sql.includes(name)));
  }
});
