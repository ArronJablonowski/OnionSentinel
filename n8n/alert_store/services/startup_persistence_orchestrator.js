'use strict';

const STEP_NAMES = Object.freeze([
  'initializeDurableJobs',
  'installDurableJobs',
  'initializePostgresShadowOutbox',
  'installPostgresShadowOutbox',
  'initializePostgresShadowProjector',
  'reconcileRecoveredIncidentAttempts',
  'initializePipelineMetrics',
  'installPipelineMetrics',
  'backfillStableGroupIdentity',
  'backfillAuthorizedActivityCampaigns',
  'reconcileAuthorizedActivityBacklog',
  'backfillAlertObservables',
  'rebuildAlertGroupSummaries',
  'refreshGroupAliases',
]);

function createStartupPersistenceOrchestrator(dependencies) {
  for (const name of STEP_NAMES) {
    if (typeof dependencies?.[name] !== 'function') {
      throw new TypeError(`${name} must be a function`);
    }
  }

  async function initialize() {
    for (const name of STEP_NAMES) await dependencies[name]();
  }

  return {initialize};
}

module.exports = {STEP_NAMES, createStartupPersistenceOrchestrator};
