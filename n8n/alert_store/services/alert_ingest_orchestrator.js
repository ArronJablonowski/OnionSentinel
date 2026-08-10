'use strict';

function createAlertIngestOrchestrator({
  scoreAlert,
  withWriteGate,
  withTransaction,
  storeUnlocked,
  queueNotification,
  nowUtc,
  buildPostCommitPayload,
  enqueueJob,
  recordMetric,
  severityRank,
  postCommitMaxAttempts,
  hasUsableExternalIntel,
  nestedField,
  enrichmentMaxAttempts,
  groupKeyFromRow,
  groupIdFromKey,
  matchesAnalysis,
  signalAiWorkers,
  drainNotificationOutbox,
  drainEnrichmentJobs,
  drainPostCommitJobs,
}) {
  const functions = {scoreAlert, withWriteGate, withTransaction, storeUnlocked,
    queueNotification, nowUtc, buildPostCommitPayload, enqueueJob, recordMetric,
    hasUsableExternalIntel, nestedField, groupKeyFromRow, groupIdFromKey,
    matchesAnalysis, signalAiWorkers, drainNotificationOutbox,
    drainEnrichmentJobs, drainPostCommitJobs};
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function priority(level) {
    return severityRank[String(level || 'informational').toLowerCase()] ?? 0;
  }

  async function enqueuePostCommit(rawAlert, stored) {
    if (stored.status !== 'accepted' || !stored.stored || !stored.alert?.alert_id) return;
    const payload = buildPostCommitPayload(rawAlert, stored);
    await enqueueJob('n8n_post_commit', stored.alert.alert_id, payload, {
      priority: priority(stored.alert.triage_level),
      maxAttempts: postCommitMaxAttempts,
    });
    await recordMetric('n8n_post_commit', 'enqueued', stored.alert.alert_id, {
      eventKey: `n8n_post_commit:enqueued:${stored.alert.alert_id}`,
      sizeBytes: Buffer.byteLength(JSON.stringify(payload)),
    });
  }

  async function enqueueEnrichment(alert, stored) {
    const admitted = !stored.campaign
      || stored.campaign.member_ordinal <= stored.campaign.enrichment_sample_limit;
    if (!stored.alert?.alert_id || stored.status === 'dropped'
      || hasUsableExternalIntel(alert) || !admitted) return false;
    const level = String(stored.alert.triage_level
      || nestedField(alert, 'triage.level') || 'informational').toLowerCase();
    await enqueueJob('public_enrichment', stored.alert.alert_id, {
      alert_id: stored.alert.alert_id,
    }, {priority: priority(level), maxAttempts: enrichmentMaxAttempts});
    await recordMetric('public_enrichment', 'enqueued', stored.alert.alert_id, {
      eventKey: `public_enrichment:enqueued:${stored.alert.alert_id}:${stored.alert.seen_count || 1}`,
    });
    return true;
  }

  async function enqueueAnalysis(stored, enrichmentQueued) {
    if (!stored.alert?.alert_id || ['dropped', 'suppressed'].includes(stored.status)) return false;
    const groupKey = stored.alert.stable_group_key || groupKeyFromRow(stored.alert);
    const groupId = stored.alert.stable_group_id || groupIdFromKey(groupKey);
    const level = String(stored.alert.triage_level || 'informational').toLowerCase();
    const campaignOwnsIncident = stored.campaign?.investigation_mode === 'incident_response_only';
    let wake = false;
    if (matchesAnalysis(level) && !campaignOwnsIncident) {
      await enqueueJob('ai_analysis', groupId, {
        group_id: groupId,
        group_key: groupKey,
        representative_alert_id: stored.alert.alert_id,
      }, {priority: priority(level), maxAttempts: 8});
      await recordMetric('ai_analysis', 'enqueued', groupId, {
        eventKey: `ai_analysis:enqueued:${groupId}:${stored.alert.seen_count || 1}`,
      });
      // Enrichment normally supplies committed evidence first. Launchd remains
      // the bounded fallback if that worker never wakes AI.
      wake = !enrichmentQueued;
    }
    return wake || stored.incident?.status === 'queued';
  }

  async function store(rawAlert) {
    const alert = {...rawAlert, triage: scoreAlert(rawAlert)};
    let wakeAiAfterCommit = false;
    const result = await withWriteGate(() => withTransaction(async () => {
      const stored = await storeUnlocked(alert);
      if (!stored.ok) return stored;
      stored.notification = await queueNotification(
        alert,
        stored.alert,
        stored.stored,
        nowUtc(),
        stored.filter,
      );
      await enqueuePostCommit(rawAlert, stored);
      const enrichmentQueued = await enqueueEnrichment(alert, stored);
      wakeAiAfterCommit = await enqueueAnalysis(stored, enrichmentQueued);
      await recordMetric('alert_ingest', 'completed', stored.alert?.alert_id || 'unknown', {
        eventKey: `alert_ingest:completed:${stored.alert?.alert_id || 'unknown'}:${stored.alert?.seen_count || 1}`,
        sizeBytes: Buffer.byteLength(JSON.stringify(rawAlert || {})),
      });
      return stored;
    }));
    if (!result.ok) return result;
    if (wakeAiAfterCommit) void signalAiWorkers('alert-committed');
    // Network/provider work deliberately begins only after SQLite commit.
    void drainNotificationOutbox();
    void drainEnrichmentJobs();
    void drainPostCommitJobs();
    return result;
  }

  return {store};
}

module.exports = {createAlertIngestOrchestrator};
