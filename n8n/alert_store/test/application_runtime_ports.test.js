'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createApplicationRuntimePorts,
} = require('../composition/application_runtime_ports');

function createFixture() {
  const calls = [];
  const callable = (name, result) => (...args) => {
    calls.push([name, args]);
    return result;
  };
  const durable = {
    install: callable('durable.install'),
    enqueue: callable('durable.enqueue'),
    completePendingByDedupeKeys: callable('durable.complete'),
  };
  const metrics = {
    install: callable('metrics.install'),
    record: callable('metrics.record'),
  };
  const outbox = {install: callable('outbox.install')};
  const mutable = {
    durableJobs: callable('owner.durable', durable),
    pipelineMetrics: callable('owner.metrics', metrics),
    postgresShadowOutbox: callable('owner.outbox', outbox),
    initializeDurableJobs: callable('initialize.durable'),
    initializePostgresShadowOutbox: callable('initialize.outbox'),
    initializePostgresShadowProjector: callable('initialize.projector'),
    initializePipelineMetrics: callable('initialize.metrics'),
  };
  const domain = new Proxy({
    enrichmentCache: {install: callable('cache.install')},
    pcapRequestRepository: {
      backfillOutcomes: callable('pcap.backfill'),
      createRequest: callable('pcap.create'),
    },
  }, {
    get: (target, key) => target[key] || callable(`domain.${String(key)}`),
  });
  const lifecycle = new Proxy({}, {
    get: (target, key) => callable(`lifecycle.${String(key)}`),
  });
  return {calls, mutable, domain, lifecycle};
}

test('fails closed when a required owner section is absent', () => {
  assert.throws(
    () => createApplicationRuntimePorts({mutable: {}}),
    /domain application runtime ports section is required/,
  );
});

test('construction is lazy and service ports resolve current mutable owners', () => {
  const fixture = createFixture();
  const ports = createApplicationRuntimePorts(fixture);
  assert.deepEqual(fixture.calls, []);
  ports.services.enqueueJob('ai_analysis', {alert_id: 'a1'});
  ports.services.recordMetric('ai_analysis', 'enqueued');
  ports.services.createPcapRequest({request_id: 'p1'});
  assert.deepEqual(fixture.calls.map(([name]) => name), [
    'owner.durable', 'durable.enqueue',
    'owner.metrics', 'metrics.record',
    'pcap.create',
  ]);
});

test('lifecycle ports retain initialization and install delegation order', () => {
  const fixture = createFixture();
  const ports = createApplicationRuntimePorts(fixture);
  ports.lifecycle.initializeDurableJobs();
  ports.lifecycle.installDurableJobs();
  ports.lifecycle.initializePostgresShadowOutbox();
  ports.lifecycle.installPostgresShadowOutbox();
  ports.lifecycle.initializePipelineMetrics();
  ports.lifecycle.installPipelineMetrics();
  ports.lifecycle.reconcileRecoveredIncidentAttempts();
  assert.deepEqual(fixture.calls.map(([name]) => name), [
    'initialize.durable', 'owner.durable', 'durable.install',
    'initialize.outbox', 'owner.outbox', 'outbox.install',
    'initialize.metrics', 'owner.metrics', 'metrics.install',
    'lifecycle.reconcileRecoveredIncidentAttempts',
  ]);
});
