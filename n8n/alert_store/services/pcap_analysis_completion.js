'use strict';

function createPcapAnalysisCompletion({
  run,
  get,
  safeString,
  nowUtc,
  recordMetric,
  matchesAnalysis,
  authorizedCampaignForAlertId,
  enqueueAiJob,
  severityRank,
}) {
  for (const [name, value] of Object.entries({
    run,
    get,
    safeString,
    nowUtc,
    recordMetric,
    matchesAnalysis,
    authorizedCampaignForAlertId,
    enqueueAiJob,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function complete(payload) {
    const requestId = safeString(payload?.request_id, 64);
    if (!requestId) throw new Error('request_id is required');
    const status = safeString(payload?.status, 32).toLowerCase();
    if (!['processing', 'completed', 'failed'].includes(status)) {
      throw new Error('analysis status must be processing, completed, or failed');
    }
    const now = nowUtc();
    const result = await run(
      `UPDATE pcap_requests SET analysis_status = ?,
         analysis_attempt_count = analysis_attempt_count + CASE WHEN ? = 'processing' THEN 1 ELSE 0 END,
         analysis_error = ?,
         analysis_started_at = CASE WHEN ? = 'processing' THEN COALESCE(analysis_started_at, ?) ELSE analysis_started_at END,
         analysis_completed_at = CASE WHEN ? IN ('completed', 'failed') THEN ? ELSE NULL END,
         updated_at = ?
       WHERE request_id = ? AND status = 'fulfilled'`,
      [status, status, safeString(payload?.error, 1000) || null, status, now, status, now, now, requestId],
    );
    if (result.changes !== 1) throw new Error('fulfilled PCAP request not found');
    const row = await get(
      `SELECT p.artifact_size_bytes, p.analysis_attempt_count, p.analysis_started_at,
              p.analysis_completed_at, p.alert_id,
              COALESCE(a.stable_group_id, ga.stable_group_id, p.group_id) AS queue_group_id,
              COALESCE(a.stable_group_key, ga.stable_group_key, p.group_key, g.group_key) AS queue_group_key,
              COALESCE(a.triage_level, g.triage_level, 'informational') AS triage_level
       FROM pcap_requests p
       LEFT JOIN alerts a ON a.alert_id = p.alert_id
       LEFT JOIN alert_group_alias ga ON ga.legacy_group_id = p.group_id
       LEFT JOIN alert_group_summary g ON g.group_id = p.group_id
       WHERE p.request_id = ?`,
      [requestId],
    );
    const eventType = status === 'processing' ? 'started' : status;
    await recordMetric('pcap_analysis', eventType, requestId, {
      eventKey: `pcap_analysis:${eventType}:${requestId}:${row?.analysis_attempt_count || 0}:${row?.analysis_completed_at || row?.analysis_started_at || now}`,
      sizeBytes: row?.artifact_size_bytes || 0,
    });
    let wakeAiAnalysis = false;
    if (status === 'completed' && row?.queue_group_id && matchesAnalysis(row.triage_level)) {
      const campaign = await authorizedCampaignForAlertId(row.alert_id);
      if (campaign?.investigation_mode === 'incident_response_only') {
        return {
          ok: true,
          request_id: requestId,
          analysis_status: status,
          wake_ai_analysis: false,
          ai_analysis_coalesced_campaign: campaign.campaign_id,
        };
      }
      const groupId = String(row.queue_group_id);
      const groupKey = String(row.queue_group_key || groupId);
      const level = String(row.triage_level || 'informational').toLowerCase();
      await enqueueAiJob(groupId, {
        group_id: groupId,
        group_key: groupKey,
        representative_alert_id: row.alert_id || null,
      }, {priority: severityRank[level] ?? 0, maxAttempts: 8});
      await recordMetric('ai_analysis', 'enqueued', groupId, {
        eventKey: `ai_analysis:enqueued:${groupId}:pcap:${requestId}:${row.analysis_attempt_count || 0}`,
        sizeBytes: row.artifact_size_bytes || 0,
      });
      wakeAiAnalysis = true;
    }
    return {
      ok: true,
      request_id: requestId,
      analysis_status: status,
      wake_ai_analysis: wakeAiAnalysis,
    };
  }

  return {complete};
}

module.exports = {createPcapAnalysisCompletion};
