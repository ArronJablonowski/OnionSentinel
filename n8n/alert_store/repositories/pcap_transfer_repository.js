'use strict';

const PCAP_TRANSFER_STAGES = new Set([
  'claimed', 'exporting', 'security_onion_to_relay', 'relay_to_mac', 'verifying',
]);

function createPcapTransferRepository({
  get,
  run,
  safeString,
  nonNegativeIntegerField,
  nowUtc,
  formatProjectTimestamp,
  pcapRequestFromRow,
  classifyPcapOutcome,
  pcapOutcomes,
  pipelineMetrics,
  claimLeaseSeconds,
  maxAttempts,
  maxRetrySeconds,
  nowMs = () => Date.now(),
}) {
  for (const [name, value] of Object.entries({
    get,
    run,
    safeString,
    nonNegativeIntegerField,
    nowUtc,
    formatProjectTimestamp,
    pcapRequestFromRow,
    classifyPcapOutcome,
    nowMs,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  if (!pcapOutcomes || typeof pcapOutcomes.has !== 'function') {
    throw new TypeError('pcapOutcomes must provide has');
  }
  if (!pipelineMetrics || typeof pipelineMetrics.record !== 'function') {
    throw new TypeError('pipelineMetrics.record must be a function');
  }

  async function requeueStaleClaims() {
    const cutoff = formatProjectTimestamp(new Date(nowMs() - claimLeaseSeconds * 1000));
    const now = nowUtc();
    await run(
      `
        UPDATE pcap_requests
        SET status = CASE WHEN transfer_attempt_count >= ? THEN 'failed' ELSE 'pending' END,
            outcome = CASE WHEN transfer_attempt_count >= ? THEN 'timeout' ELSE outcome END,
            relay_host = NULL,
            claimed_at = NULL,
            error = 'requeued after stale relay claim lease expired',
            transfer_retry_count = transfer_retry_count + 1,
            transfer_last_error = 'relay claim lease expired without progress',
            transfer_last_failed_stage = COALESCE(transfer_stage, 'claimed'),
            next_attempt_at = CASE WHEN transfer_attempt_count >= ? THEN NULL ELSE ? END,
            completed_at = CASE WHEN transfer_attempt_count >= ? THEN ? ELSE NULL END,
            updated_at = ?
        WHERE status = 'claimed'
          AND COALESCE(transfer_progress_at, claimed_at, updated_at, created_at) < ?
      `,
      [maxAttempts, maxAttempts, maxAttempts, now, maxAttempts, now, now, cutoff],
    );
  }

  async function claimRequest(payload) {
    const requestId = safeString(payload?.request_id, 64);
    if (!requestId) throw new Error('request_id is required');
    const relayHost = safeString(payload?.relay_host || 'relay', 120);
    const now = nowUtc();
    const existing = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
    if (!existing) throw new Error('pcap request not found');
    if (existing.status !== 'pending') {
      return {ok: true, claimed: false, status: existing.status, request: pcapRequestFromRow(existing)};
    }
    if (existing.next_attempt_at && Date.parse(existing.next_attempt_at) > nowMs()) {
      return {ok: true, claimed: false, status: existing.status, request: pcapRequestFromRow(existing)};
    }
    const claimResult = await run(
      `
        UPDATE pcap_requests
        SET status = 'claimed',
            relay_host = ?,
            error = NULL,
            claimed_at = ?,
            transfer_stage = COALESCE(transfer_stage, 'claimed'),
            transfer_progress_at = ?,
            transfer_attempt_count = transfer_attempt_count + 1,
            next_attempt_at = NULL,
            updated_at = ?
        WHERE request_id = ?
          AND status = 'pending'
          AND (next_attempt_at IS NULL OR datetime(next_attempt_at) <= datetime(?))
      `,
      [relayHost, now, now, now, requestId, now],
    );
    const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
    return {
      ok: true,
      claimed: claimResult.changes === 1,
      status: row.status,
      request: pcapRequestFromRow(row),
    };
  }

  async function updateTransferProgress(payload) {
    const requestId = safeString(payload?.request_id, 64);
    if (!requestId) throw new Error('request_id is required');
    const stage = safeString(payload?.stage, 64).toLowerCase();
    if (!PCAP_TRANSFER_STAGES.has(stage)) throw new Error('invalid PCAP transfer stage');
    const transferredBytes = nonNegativeIntegerField(payload?.transferred_bytes) || 0;
    const totalBytes = nonNegativeIntegerField(payload?.total_bytes) || 0;
    if (totalBytes && transferredBytes > totalBytes) {
      throw new Error('transferred_bytes cannot exceed total_bytes');
    }
    const now = nowUtc();
    const result = await run(
      `UPDATE pcap_requests
       SET transfer_stage = ?,
           transfer_bytes = ?,
           transfer_total_bytes = CASE WHEN ? > 0 THEN ? ELSE transfer_total_bytes END,
           transfer_progress_at = ?,
           updated_at = ?
       WHERE request_id = ? AND status = 'claimed'`,
      [stage, transferredBytes, totalBytes, totalBytes, now, now, requestId],
    );
    if (result.changes !== 1) throw new Error('claimed PCAP request not found');
    return {
      ok: true,
      request_id: requestId,
      stage,
      transferred_bytes: transferredBytes,
      total_bytes: totalBytes,
      progress_at: now,
    };
  }

  async function retryRequest(payload) {
    const requestId = safeString(payload?.request_id, 64);
    if (!requestId) throw new Error('request_id is required');
    const existing = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
    if (!existing) throw new Error('pcap request not found');
    if (existing.status === 'pending') {
      return {ok: true, retry_scheduled: true, exhausted: false, request: pcapRequestFromRow(existing)};
    }
    if (existing.status !== 'claimed') {
      return {ok: true, retry_scheduled: false, exhausted: false, request: pcapRequestFromRow(existing)};
    }

    const error = safeString(payload?.error, 1000) || 'transient PCAP transfer failure';
    const requestedStage = safeString(payload?.stage, 64).toLowerCase();
    const failedStage = PCAP_TRANSFER_STAGES.has(requestedStage)
      ? requestedStage
      : (existing.transfer_stage || 'claimed');
    const requestedDelay = nonNegativeIntegerField(payload?.retry_after_seconds) || 0;
    const retryAfterSeconds = Math.min(maxRetrySeconds, requestedDelay);
    const attempts = Number(existing.transfer_attempt_count || 0);
    const exhausted = attempts >= maxAttempts;
    const now = nowUtc();
    const nextAttemptAt = exhausted
      ? null
      : formatProjectTimestamp(new Date(nowMs() + retryAfterSeconds * 1000));
    const outcome = classifyPcapOutcome('failed', error, payload?.diagnostics || {}) || 'failed';
    const diagnostics = payload?.diagnostics && typeof payload.diagnostics === 'object' && !Array.isArray(payload.diagnostics)
      ? JSON.stringify(payload.diagnostics).slice(0, 12000)
      : null;

    await run(
      `UPDATE pcap_requests
       SET status = ?,
           outcome = ?,
           relay_host = NULL,
           claimed_at = NULL,
           completed_at = ?,
           error = ?,
           diagnostics_json = CASE WHEN ? IS NOT NULL THEN ? ELSE diagnostics_json END,
           transfer_retry_count = transfer_retry_count + 1,
           transfer_last_error = ?,
           transfer_last_failed_stage = ?,
           next_attempt_at = ?,
           updated_at = ?
       WHERE request_id = ? AND status = 'claimed'`,
      [
        exhausted ? 'failed' : 'pending',
        exhausted ? outcome : null,
        exhausted ? now : null,
        exhausted ? error : `retry scheduled after ${failedStage} failure: ${error}`,
        diagnostics,
        diagnostics,
        error,
        failedStage,
        nextAttemptAt,
        now,
        requestId,
      ],
    );
    const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
    const eventType = exhausted ? 'failed' : 'deferred';
    await pipelineMetrics.record('pcap_transfer', eventType, requestId, {
      eventKey: `pcap_transfer:${eventType}:${requestId}:${attempts}:${now}`,
    });
    return {
      ok: true,
      retry_scheduled: !exhausted,
      exhausted,
      max_attempts: maxAttempts,
      request: pcapRequestFromRow(row),
    };
  }

  async function completeRequest(payload) {
    const requestId = safeString(payload?.request_id, 64);
    if (!requestId) throw new Error('request_id is required');
    const requestedStatus = safeString(payload?.status, 32).toLowerCase();
    if (!['fulfilled', 'failed', 'rejected'].includes(requestedStatus)) {
      throw new Error('status must be fulfilled, failed, or rejected');
    }
    const now = nowUtc();
    const artifactPath = safeString(payload?.artifact_path, 1024) || null;
    const artifactSha256 = safeString(payload?.artifact_sha256, 128) || null;
    const artifactSizeBytes = nonNegativeIntegerField(payload?.artifact_size_bytes);
    const relayHost = safeString(payload?.relay_host, 120) || null;
    const error = safeString(payload?.error, 500) || null;
    const diagnostics = payload?.diagnostics && typeof payload.diagnostics === 'object' && !Array.isArray(payload.diagnostics)
      ? JSON.stringify(payload.diagnostics).slice(0, 12000)
      : null;
    const requestedOutcome = safeString(payload?.outcome, 64).toLowerCase();
    const classifiedOutcome = classifyPcapOutcome(requestedStatus, error, payload?.diagnostics || {});
    const outcome = pcapOutcomes.has(requestedOutcome) && requestedOutcome !== 'failed'
      ? requestedOutcome
      : classifiedOutcome || requestedOutcome;
    if (requestedStatus === 'fulfilled' && (!artifactPath || !artifactSha256 || !artifactSizeBytes)) {
      throw new Error('fulfilled pcap request requires artifact_path, artifact_sha256, and artifact_size_bytes');
    }
    await run(
      `
        UPDATE pcap_requests
        SET status = ?,
            relay_host = COALESCE(?, relay_host),
            artifact_path = ?,
            artifact_sha256 = ?,
            artifact_size_bytes = ?,
            error = ?,
            outcome = ?,
            diagnostics_json = ?,
            analysis_status = CASE WHEN ? = 'fulfilled' THEN 'pending' ELSE 'not_ready' END,
            analysis_error = NULL,
            analysis_started_at = NULL,
            analysis_completed_at = NULL,
            transfer_stage = ?,
            transfer_bytes = CASE WHEN ? = 'fulfilled' THEN ? ELSE transfer_bytes END,
            transfer_total_bytes = CASE WHEN ? = 'fulfilled' THEN ? ELSE transfer_total_bytes END,
            transfer_progress_at = ?,
            next_attempt_at = NULL,
            transfer_duration_seconds = CASE
              WHEN claimed_at IS NULL THEN NULL
              ELSE MAX(
                0,
                CAST(ROUND(
                  (julianday(replace(?, '  ', 'T')) -
                   julianday(replace(claimed_at, '  ', 'T'))) * 86400
                ) AS INTEGER)
              )
            END,
            completed_at = ?,
            updated_at = ?
        WHERE request_id = ?
      `,
      [
        requestedStatus,
        relayHost,
        artifactPath,
        artifactSha256,
        artifactSizeBytes,
        requestedStatus === 'fulfilled' ? null : error,
        outcome || null,
        requestedStatus === 'fulfilled' ? null : diagnostics,
        requestedStatus,
        requestedStatus,
        requestedStatus,
        artifactSizeBytes,
        requestedStatus,
        artifactSizeBytes,
        now,
        now,
        now,
        now,
        requestId,
      ],
    );
    const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
    if (!row) throw new Error('pcap request not found');
    const eventType = requestedStatus === 'fulfilled' ? 'completed' : 'failed';
    await pipelineMetrics.record('pcap_transfer', eventType, requestId, {
      eventKey: `pcap_transfer:${eventType}:${requestId}:${row.claimed_at || row.created_at}`,
      sizeBytes: row.artifact_size_bytes || 0,
    });
    return {
      ok: true,
      status: row.status,
      request: pcapRequestFromRow(row),
      wake_pcap_analysis: requestedStatus === 'fulfilled',
    };
  }

  return {
    requeueStaleClaims,
    claimRequest,
    updateTransferProgress,
    retryRequest,
    completeRequest,
  };
}

module.exports = {createPcapTransferRepository};
