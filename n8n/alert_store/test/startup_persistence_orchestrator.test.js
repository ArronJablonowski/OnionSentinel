'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  STEP_NAMES,
  createStartupPersistenceOrchestrator,
} = require('../services/startup_persistence_orchestrator');

function owner(overrides = {}) {
  const events = [];
  const dependencies = Object.fromEntries(
    STEP_NAMES.map((name) => [name, async () => events.push(name)]),
  );
  const service = createStartupPersistenceOrchestrator({...dependencies, ...overrides});
  return {events, service};
}

test('retains exact durable, shadow, recovery, metrics, and backfill order', async () => {
  const {events, service} = owner();
  await service.initialize();
  assert.deepEqual(events, STEP_NAMES);
});

test('does not reconcile immutable attempts before durable lease recovery installs', async () => {
  const {events, service} = owner();
  await service.initialize();
  assert(events.indexOf('installDurableJobs')
    < events.indexOf('reconcileRecoveredIncidentAttempts'));
  assert(events.indexOf('initializePostgresShadowProjector')
    < events.indexOf('reconcileRecoveredIncidentAttempts'));
});

test('fails closed without running later owners after a startup failure', async () => {
  const events = [];
  const failure = new Error('shadow install failed');
  const {service} = owner({
    initializeDurableJobs: async () => events.push('initializeDurableJobs'),
    installDurableJobs: async () => events.push('installDurableJobs'),
    initializePostgresShadowOutbox: async () => events.push('initializePostgresShadowOutbox'),
    installPostgresShadowOutbox: async () => { events.push('installPostgresShadowOutbox'); throw failure; },
    initializePostgresShadowProjector: async () => events.push('unexpected'),
  });
  await assert.rejects(service.initialize(), (error) => error === failure);
  assert.deepEqual(events, [
    'initializeDurableJobs', 'installDurableJobs',
    'initializePostgresShadowOutbox', 'installPostgresShadowOutbox',
  ]);
});

test('requires every persistence owner at composition time', () => {
  const dependencies = Object.fromEntries(STEP_NAMES.map((name) => [name, async () => undefined]));
  delete dependencies.installPipelineMetrics;
  assert.throws(
    () => createStartupPersistenceOrchestrator(dependencies),
    /installPipelineMetrics must be a function/,
  );
});
