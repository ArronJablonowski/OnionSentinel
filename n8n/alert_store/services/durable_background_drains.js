'use strict';

function createDurableBackgroundDrains({
  durableJobs,
  withWriteTransaction,
  get,
  run,
  enrichAlert,
  enrichmentRecord,
  jsonText,
  indexAlertObservables,
  groupKeyFromRow,
  groupIdFromKey,
  authorizedCampaignForAlertId,
  matchesAnalysis,
  severityRank,
  recordMetric,
  signalAiWorkers,
  requestJson,
  safeString,
  enrichmentTimeoutMs,
  n8nPostCommitUrl,
  n8nPostCommitToken,
  n8nPostCommitTimeoutMs,
  n8nPostCommitBaseRetrySeconds,
}) {
  let enrichmentActive = false;
  let postCommitActive = false;

  function postCommitResult(body) {
    const candidates = Array.isArray(body) ? body : [body];
    for (const candidate of candidates) {
      if (!candidate || typeof candidate !== 'object') continue;
      const payload = candidate.json && typeof candidate.json === 'object'
        ? candidate.json
        : candidate;
      if (
        payload.ok === false
        || ['rejected', 'error'].includes(String(payload.status || '').toLowerCase())
      ) {
        return {
          ok: false,
          reason: safeString(payload.reason || payload.error || payload.status, 500),
        };
      }
      if (payload.report_written === true) return {ok: true, payload};
    }
    return {
      ok: false,
      reason: 'n8n did not confirm the committed alert report write',
    };
  }

  async function claim(queue, jobType, leaseSeconds) {
    return withWriteTransaction(() => queue.claim(jobType, leaseSeconds));
  }

  async function persistEnrichmentSuccess(queue, job, result) {
    let wakeAi = false;
    await withWriteTransaction(async () => {
      await run(
        'UPDATE alerts SET enrichment_json = ?, alert_json = ? WHERE alert_id = ?',
        [
          jsonText(enrichmentRecord(result.alert)),
          jsonText(result.alert),
          job.payload.alert_id,
        ],
      );
      const updatedRow = await get(
        'SELECT * FROM alerts WHERE alert_id = ?',
        [job.payload.alert_id],
      );
      if (updatedRow) {
        await indexAlertObservables(result.alert, updatedRow);
        const groupKey = updatedRow.stable_group_key || groupKeyFromRow(updatedRow);
        const groupId = updatedRow.stable_group_id || groupIdFromKey(groupKey);
        const level = String(
          updatedRow.triage_level || 'informational',
        ).toLowerCase();
        const campaign = await authorizedCampaignForAlertId(updatedRow.alert_id);
        if (
          matchesAnalysis(level)
          && campaign?.investigation_mode !== 'incident_response_only'
        ) {
          await queue.enqueue('ai_analysis', groupId, {
            group_id: groupId,
            group_key: groupKey,
            representative_alert_id: updatedRow.alert_id,
          }, {priority: severityRank[level] ?? 0, maxAttempts: 8});
          await recordMetric('ai_analysis', 'enqueued', groupId, {
            eventKey: `ai_analysis:enqueued:${groupId}:enrichment:${job.id}:${job.attempt_count}`,
          });
          wakeAi = true;
        }
      }
      const completed = await queue.complete(job);
      if (completed) {
        await recordMetric('public_enrichment', 'completed', job.payload.alert_id, {
          eventKey: `public_enrichment:completed:${job.id}:${job.attempt_count}`,
          sizeBytes: Buffer.byteLength(
            JSON.stringify(enrichmentRecord(result.alert) || {}),
          ),
        });
      }
    });
    if (wakeAi) void signalAiWorkers('enrichment-completed');
  }

  async function persistEnrichmentFailure(queue, job, error) {
    let exhausted = false;
    await withWriteTransaction(async () => {
      await queue.fail(job, error.message);
      const failedJob = await get(
        'SELECT status FROM durable_jobs WHERE id = ?',
        [job.id],
      );
      exhausted = failedJob?.status === 'failed';
      await recordMetric('public_enrichment', 'failed', job.payload.alert_id, {
        eventKey: `public_enrichment:failed:${job.id}:${job.attempt_count}`,
      });
    });
    if (exhausted) void signalAiWorkers('enrichment-exhausted');
  }

  async function drainEnrichment() {
    if (enrichmentActive) return;
    const queue = durableJobs();
    if (!queue) return;
    enrichmentActive = true;
    try {
      const job = await claim(
        queue,
        'public_enrichment',
        Math.ceil(enrichmentTimeoutMs * 20 / 1000),
      );
      if (!job) return;
      try {
        const row = await get(
          'SELECT alert_json FROM alerts WHERE alert_id = ?',
          [job.payload.alert_id],
        );
        if (!row) throw new Error('alert no longer exists');
        const alert = JSON.parse(row.alert_json);
        const result = await enrichAlert(alert);
        if (!result.ok || !result.alert) {
          throw new Error(result.reason || 'enrichment returned no alert');
        }
        await persistEnrichmentSuccess(queue, job, result);
      } catch (error) {
        await persistEnrichmentFailure(queue, job, error);
      }
    } finally {
      enrichmentActive = false;
    }
  }

  async function persistPostCommitSuccess(queue, job) {
    await withWriteTransaction(async () => {
      const completed = await queue.complete(job);
      if (completed) {
        await recordMetric('n8n_post_commit', 'completed', job.dedupe_key, {
          eventKey: `n8n_post_commit:completed:${job.id}:${job.attempt_count}`,
          sizeBytes: Buffer.byteLength(JSON.stringify(job.payload || {})),
        });
      }
    });
  }

  async function persistPostCommitFailure(queue, job, error) {
    await withWriteTransaction(async () => {
      await queue.fail(job, error.message, n8nPostCommitBaseRetrySeconds);
      await recordMetric('n8n_post_commit', 'failed', job.dedupe_key, {
        eventKey: `n8n_post_commit:failed:${job.id}:${job.attempt_count}`,
      });
    });
  }

  async function drainPostCommit() {
    if (postCommitActive) return;
    const queue = durableJobs();
    if (!queue || !n8nPostCommitUrl || !n8nPostCommitToken) return;
    postCommitActive = true;
    try {
      const job = await claim(
        queue,
        'n8n_post_commit',
        Math.ceil(n8nPostCommitTimeoutMs * 3 / 1000),
      );
      if (!job) return;
      try {
        const response = await requestJson({
          method: 'POST',
          url: n8nPostCommitUrl,
          headers: {'X-Relay-Token': n8nPostCommitToken},
          body: job.payload,
          timeoutMs: n8nPostCommitTimeoutMs,
        });
        const result = postCommitResult(response.body);
        if (
          response.statusCode < 200
          || response.statusCode >= 300
          || !result.ok
        ) {
          throw new Error(
            result.reason || `n8n returned HTTP ${response.statusCode}`,
          );
        }
        await persistPostCommitSuccess(queue, job);
      } catch (error) {
        await persistPostCommitFailure(queue, job, error);
      }
    } finally {
      postCommitActive = false;
    }
  }

  return {drainEnrichment, drainPostCommit, postCommitResult};
}

module.exports = {createDurableBackgroundDrains};
