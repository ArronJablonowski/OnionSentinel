'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAiReviewSchema} = require('../services/ai_review_schema');

function owner() {
  const events = [];
  const service = createAiReviewSchema({
    run: async (sql) => events.push({type: 'run', sql: sql.replace(/\s+/g, ' ').trim()}),
    ensureColumn: async (table, name, definition) => {
      events.push({type: 'column', table, name, definition});
    },
  });
  return {events, service};
}

test('installs review, adjudication, analyst, and correlation schemas in order', async () => {
  const {events, service} = owner();
  await service.install();
  const sql = events.filter((event) => event.type === 'run').map((event) => event.sql);
  const positions = ['ai_second_opinion_runs', 'ai_disagreement_adjudication_runs',
    'analyst_adjudications', 'alert_correlations']
    .map((table) => sql.findIndex((statement) => statement.includes(`TABLE IF NOT EXISTS ${table}`)));
  assert(positions.every((position) => position >= 0));
  assert.deepEqual([...positions].sort((left, right) => left - right), positions);
});

test('retains additive reviewer and analyst compatibility columns', async () => {
  const {events, service} = owner();
  await service.install();
  assert.deepEqual(
    events.filter((event) => event.type === 'column').map(({table, name}) => [table, name]),
    [
      ['ai_second_opinion_runs', 'reviewer_error'],
      ['analyst_adjudications', 'event_status'],
      ['analyst_adjudications', 'detection_validity'],
      ['analyst_adjudications', 'activity_disposition'],
      ['analyst_adjudications', 'handling'],
      ['analyst_adjudications', 'duplicate_of'],
    ],
  );
});

test('retains pairwise correlation identity and bidirectional lookup indexes', async () => {
  const {events, service} = owner();
  await service.install();
  const sql = events.filter((event) => event.type === 'run').map((event) => event.sql);
  assert(sql.some((statement) => statement.includes('PRIMARY KEY (source_group_id, related_group_id)')));
  assert(sql.some((statement) => statement.includes('idx_alert_correlations_related')));
  assert(sql.some((statement) => statement.includes('idx_alert_correlations_source')));
});
