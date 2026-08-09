'use strict';

function createDurableJobRecovery({
  durableJobs,
  withWriteGate,
  withTransaction,
  reconcileIncidentAttempts,
  reconcileAuthorizedActivity,
  nowUtc,
  warn,
  signalAiWorkers,
  drainEnrichmentJobs,
  drainPostCommitJobs,
}) {
  for (const [name, value] of Object.entries({
    withWriteGate, withTransaction, reconcileIncidentAttempts,
    reconcileAuthorizedActivity, nowUtc, warn, signalAiWorkers,
    drainEnrichmentJobs, drainPostCommitJobs,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  if (typeof durableJobs !== 'function') throw new TypeError('durableJobs must be a function');
  let active = false;

  async function recover() {
    if (active) return;
    const queue = durableJobs();
    if (!queue || typeof queue.recoverExpired !== 'function') return;
    active = true;
    try {
      const summary = await withWriteGate(() => withTransaction(async () => {
        const recovered = await queue.recoverExpired();
        recovered.reanalysis_attempts = await reconcileIncidentAttempts();
        if (recovered.job_types?.ai_analysis || recovered.job_types?.incident_response_analysis) {
          recovered.authorized_activity = await reconcileAuthorizedActivity();
        }
        return recovered;
      }));
      if (!summary.recovered && !summary.failed && !summary.reanalysis_attempts) return;
      warn(`${nowUtc()} durable job lease recovery: ${JSON.stringify(summary)}`);
      if (summary.job_types.ai_analysis || summary.job_types.incident_response_analysis) {
        void signalAiWorkers('ai-lease-recovered');
      }
      if (summary.job_types.public_enrichment) void drainEnrichmentJobs();
      if (summary.job_types.n8n_post_commit) void drainPostCommitJobs();
    } finally {
      active = false;
    }
  }

  return {recover};
}

module.exports = {createDurableJobRecovery};
