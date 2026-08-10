'use strict';

function requireSection(options, name) {
  const section = options && options[name];
  if (!section || typeof section !== 'object') {
    throw new Error(`${name} application runtime ports section is required`);
  }
  return section;
}

function createApplicationRuntimePorts(options = {}) {
  const mutable = requireSection(options, 'mutable');
  const domain = requireSection(options, 'domain');
  const lifecycle = requireSection(options, 'lifecycle');

  return {
    services: {
      installEnrichmentCache: () => domain.enrichmentCache.install(),
      backfillPcapOutcomes: () => domain.pcapRequestRepository.backfillOutcomes(),
      completePendingJobs: (...args) => (
        mutable.durableJobs().completePendingByDedupeKeys(...args)
      ),
      resolveDashboardAlertGroup: domain.resolveDashboardAlertGroup,
      randomUUID: domain.randomUUID,
      rebuildGroupSummaries: domain.rebuildGroupSummariesUnlocked,
      createPcapRequest: (...args) => domain.pcapRequestRepository.createRequest(...args),
      queueIncidentResponseForGroup: domain.queueIncidentResponseForGroup,
      persistStableIdentity: domain.persistStableIdentity,
      refreshGroupSummary: domain.refreshGroupSummary,
      queueNotification: domain.queueNotification,
      enqueueJob: (...args) => mutable.durableJobs().enqueue(...args),
      recordMetric: (...args) => mutable.pipelineMetrics().record(...args),
      signalAiWorkers: domain.signalAiWorkers,
      drainNotificationOutbox: domain.drainNotificationOutbox,
      drainEnrichmentJobs: domain.drainEnrichmentJobs,
      drainPostCommitJobs: domain.drainPostCommitJobs,
    },
    lifecycle: {
      initializeDurableJobs: mutable.initializeDurableJobs,
      installDurableJobs: () => mutable.durableJobs().install(),
      initializePostgresShadowOutbox: mutable.initializePostgresShadowOutbox,
      installPostgresShadowOutbox: () => mutable.postgresShadowOutbox().install(),
      initializePostgresShadowProjector: mutable.initializePostgresShadowProjector,
      reconcileRecoveredIncidentAttempts: lifecycle.reconcileRecoveredIncidentAttempts,
      initializePipelineMetrics: mutable.initializePipelineMetrics,
      installPipelineMetrics: () => mutable.pipelineMetrics().install(),
      backfillStableGroupIdentity: lifecycle.backfillStableGroupIdentity,
      rebuildAlertGroupSummaries: lifecycle.rebuildAlertGroupSummaries,
      refreshGroupAliases: lifecycle.refreshGroupAliases,
    },
  };
}

module.exports = {createApplicationRuntimePorts};
