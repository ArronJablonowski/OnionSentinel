'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createIncidentAnalysisSchema} = require('../services/incident_analysis_schema');

function owner() {
  const events = [];
  const service = createIncidentAnalysisSchema({
    run: async (sql) => events.push({type: 'run', sql: sql.replace(/\s+/g, ' ').trim()}),
    ensureColumn: async (table, name, definition) => {
      events.push({type: 'column', table, name, definition});
    },
  });
  return {events, service};
}

test('installs analysis, incident, reanalysis, and attempt owners in dependency order', async () => {
  const {events, service} = owner();
  await service.install();
  const sql = events.filter((event) => event.type === 'run').map((event) => event.sql);
  const positions = [
    'CREATE TABLE IF NOT EXISTS ai_analysis_runs',
    'CREATE TABLE IF NOT EXISTS incident_response_cases',
    'CREATE TABLE IF NOT EXISTS incident_response_events',
    'CREATE TABLE IF NOT EXISTS incident_reanalysis_runs',
    'CREATE TABLE IF NOT EXISTS incident_reanalysis_run_cases',
    'CREATE TABLE IF NOT EXISTS incident_reanalysis_attempts',
  ].map((needle) => sql.findIndex((statement) => statement.includes(needle)));
  assert(positions.every((position) => position >= 0));
  assert.deepEqual([...positions].sort((left, right) => left - right), positions);
});

test('retains additive compatibility columns in exact order', async () => {
  const {events, service} = owner();
  await service.install();
  assert.deepEqual(
    events.filter((event) => event.type === 'column')
      .map(({table, name, definition}) => [table, name, definition]),
    [
      ['ai_analysis_runs', 'agent_role', "TEXT NOT NULL DEFAULT 'soc-analyst'"],
      ['incident_response_cases', 'resolution_reason', 'TEXT'],
      ['incident_response_cases', 'resolved_at', 'TEXT'],
      ['incident_response_cases', 'resolved_by', 'TEXT'],
      ['incident_reanalysis_runs', 'controlled_dispatch_id', 'TEXT'],
      ['incident_reanalysis_runs', 'controlled_receipt_json', 'TEXT'],
      ['incident_reanalysis_run_cases', 'latest_attempt_id', 'TEXT'],
      ['incident_reanalysis_run_cases', 'analysis_id', 'TEXT'],
      ['incident_reanalysis_run_cases', 'executed_model', 'TEXT'],
      ['incident_reanalysis_run_cases', 'executed_provider', 'TEXT'],
      ['incident_reanalysis_run_cases', 'executed_model_path', 'TEXT'],
      ['incident_reanalysis_run_cases', 'result_generated_at', 'TEXT'],
    ],
  );
});

test('retains partial uniqueness for dispatch and immutable result ownership', async () => {
  const {events, service} = owner();
  await service.install();
  const indexes = events.filter((event) => event.type === 'run').map((event) => event.sql);
  assert(indexes.some((sql) => sql.includes('idx_incident_reanalysis_runs_controlled_dispatch')
    && sql.includes('WHERE controlled_dispatch_id IS NOT NULL')));
  assert(indexes.some((sql) => sql.includes('idx_incident_reanalysis_attempts_analysis')
    && sql.includes('WHERE analysis_id IS NOT NULL')));
});
