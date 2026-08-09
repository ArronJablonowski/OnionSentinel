'use strict';

function createPcapRequestRepository({
  get,
  all,
  run,
  safeString,
  parseJsonObject,
  jsonText,
  nowUtc,
  pcapCandidateFromRow,
  normalizePcapRequest,
  pcapRetentionError,
  pcapRequestFromRow,
  classifyPcapOutcome,
  recordMetric,
  readCaptureLossThreshold,
  requeueStaleClaims,
  priorityMaxWaitSeconds,
  captureRetentionSeconds,
  nowMs = () => Date.now(),
}) {
  for (const [name, value] of Object.entries({
    get,
    all,
    run,
    safeString,
    parseJsonObject,
    jsonText,
    nowUtc,
    pcapCandidateFromRow,
    normalizePcapRequest,
    pcapRetentionError,
    pcapRequestFromRow,
    classifyPcapOutcome,
    recordMetric,
    readCaptureLossThreshold,
    requeueStaleClaims,
    nowMs,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function candidateFromPayload(payload) {
    if (payload.alert_id) {
      const row = await get('SELECT * FROM alerts WHERE alert_id = ?', [String(payload.alert_id)]);
      if (row) return pcapCandidateFromRow(row);
    }
    if (payload.group_id) {
      const row = await get('SELECT * FROM alert_group_summary WHERE group_id = ?', [String(payload.group_id)]);
      if (row) {
        if (row.representative_alert_id) {
          const representative = await get('SELECT * FROM alerts WHERE alert_id = ?', [row.representative_alert_id]);
          if (representative) return pcapCandidateFromRow(representative);
        }
        const newest = await get(`
          SELECT *
          FROM alerts
          WHERE COALESCE(
            NULLIF(suppression_key, ''),
            COALESCE(triage_level, 'unknown-level') || '|' ||
            COALESCE(rule_name, 'unknown-rule') || '|' ||
            COALESCE(source_ip, 'unknown-source') || '|' ||
            COALESCE(destination_ip, 'unknown-destination') || '|' ||
            COALESCE(filter_status, 'accepted')
          ) = ?
          ORDER BY last_seen DESC
          LIMIT 1
        `, [row.group_key]);
        if (newest) return pcapCandidateFromRow(newest);
        return pcapCandidateFromRow(row);
      }
    }
    return {};
  }

  async function backfillOutcomes() {
    const rows = await all("SELECT request_id, status, error, diagnostics_json FROM pcap_requests WHERE outcome IS NULL OR outcome = '' OR outcome = 'failed'");
    for (const row of rows) {
      const outcome = classifyPcapOutcome(row.status, row.error, parseJsonObject(row.diagnostics_json));
      if (outcome) await run('UPDATE pcap_requests SET outcome = ? WHERE request_id = ?', [outcome, row.request_id]);
    }
  }

  async function createRequest(payload) {
    const candidate = await candidateFromPayload(payload);
    const normalized = normalizePcapRequest(payload, candidate);
    const now = nowUtc();
    const retentionError = pcapRetentionError(normalized.last_seen);
    const initialStatus = retentionError ? 'rejected' : 'pending';
    await run(
      `
        INSERT INTO pcap_requests (
          request_id, status, alert_id, group_id, group_key, first_seen, last_seen,
          source_ip, source_port, destination_ip, destination_port, network_protocol,
          transport_protocol, community_id, requested_by, reason, max_window_seconds,
          error, outcome, request_json, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(request_id) DO UPDATE SET
          status = excluded.status,
          reason = excluded.reason,
          requested_by = excluded.requested_by,
          max_window_seconds = excluded.max_window_seconds,
          request_json = excluded.request_json,
          claimed_at = NULL,
          completed_at = NULL,
          error = NULL,
          artifact_path = NULL,
          artifact_sha256 = NULL,
          artifact_size_bytes = NULL,
          transfer_stage = NULL,
          transfer_bytes = 0,
          transfer_total_bytes = 0,
          transfer_progress_at = NULL,
          transfer_duration_seconds = NULL,
          transfer_attempt_count = 0,
          transfer_retry_count = 0,
          transfer_last_error = NULL,
          transfer_last_failed_stage = NULL,
          next_attempt_at = NULL,
          outcome = excluded.outcome,
          updated_at = excluded.updated_at
      `,
      [
        normalized.request_id,
        initialStatus,
        normalized.alert_id,
        normalized.group_id,
        normalized.group_key,
        normalized.first_seen,
        normalized.last_seen,
        normalized.source_ip,
        normalized.source_port,
        normalized.destination_ip,
        normalized.destination_port,
        normalized.network_protocol,
        normalized.transport_protocol,
        normalized.community_id,
        normalized.requested_by,
        normalized.reason,
        normalized.max_window_seconds,
        retentionError || null,
        retentionError ? 'expired' : null,
        jsonText(normalized),
        now,
        now,
      ],
    );
    const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [normalized.request_id]);
    const eventType = initialStatus === 'pending' ? 'enqueued' : 'failed';
    await recordMetric('pcap_transfer', eventType, normalized.request_id, {
      eventKey: `pcap_transfer:${eventType}:${normalized.request_id}:${row.updated_at}`,
    });
    return {
      ok: true,
      status: row.status,
      request: pcapRequestFromRow(row),
      execution: {
        enabled: false,
        reason: 'PCAP fulfillment is intentionally brokered by the relay/Security Onion forced-command path, not by alert-store.',
      },
    };
  }

  async function rejectExpiredPending() {
    if (!captureRetentionSeconds) return;
    const cutoff = new Date(nowMs() - captureRetentionSeconds * 1000).toISOString();
    const now = nowUtc();
    await run(
      `
        UPDATE pcap_requests
        SET status = 'rejected',
            outcome = 'expired',
            error = ?,
            completed_at = ?,
            updated_at = ?
        WHERE status = 'pending'
          AND last_seen IS NOT NULL
          AND datetime(replace(last_seen, '  ', 'T')) < datetime(?)
      `,
      [`PCAP request exceeds configured capture retention (${captureRetentionSeconds}s)`, now, now, cutoff],
    );
  }

  async function listRequests(query = new URLSearchParams()) {
    const allowed = new Set(['pending', 'claimed', 'fulfilled', 'failed', 'rejected']);
    const requestedStatus = safeString(query.get('status'), 32).toLowerCase();
    const status = allowed.has(requestedStatus) ? requestedStatus : '';
    const limit = Math.min(100, Math.max(1, Number(query.get('limit') || 25) || 25));
    await rejectExpiredPending();
    await requeueStaleClaims();
    const rows = status
      ? await all(
        `
          SELECT p.*
          FROM pcap_requests AS p
          LEFT JOIN alert_group_summary AS g ON g.group_id = p.group_id
          WHERE p.status = ?
            AND (p.status <> 'pending' OR p.next_attempt_at IS NULL OR datetime(p.next_attempt_at) <= datetime(?))
          ORDER BY
            CASE lower(COALESCE(g.triage_level, ''))
              WHEN 'critical' THEN 2 WHEN 'high' THEN 1 ELSE 0
            END DESC,
            CASE WHEN lower(COALESCE(g.triage_level, '')) NOT IN ('critical', 'high')
              AND CAST(strftime('%s', replace(?, '  ', 'T')) AS INTEGER)
                - CAST(strftime('%s', replace(p.created_at, '  ', 'T')) AS INTEGER) >= ?
              THEN 1 ELSE 0
            END DESC,
            CASE WHEN lower(COALESCE(g.triage_level, '')) NOT IN ('critical', 'high')
              AND CAST(strftime('%s', replace(?, '  ', 'T')) AS INTEGER)
                - CAST(strftime('%s', replace(p.created_at, '  ', 'T')) AS INTEGER) >= ?
              THEN datetime(replace(p.created_at, '  ', 'T')) ELSE NULL
            END ASC,
            CASE lower(COALESCE(g.triage_level, ''))
              WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
              WHEN 'low' THEN 1 WHEN 'informational' THEN 0 WHEN 'info' THEN 0 ELSE -1
            END DESC,
            CASE WHEN ? > 0 AND p.last_seen IS NOT NULL
              THEN datetime(replace(p.last_seen, '  ', 'T'), '+' || ? || ' seconds')
              ELSE datetime(p.created_at, '+100 years')
            END ASC,
            p.created_at DESC
          LIMIT ?
        `,
        [status, nowUtc(), nowUtc(), priorityMaxWaitSeconds,
          nowUtc(), priorityMaxWaitSeconds,
          captureRetentionSeconds, captureRetentionSeconds, limit],
      )
      : await all('SELECT * FROM pcap_requests ORDER BY created_at DESC LIMIT ?', [limit]);
    return {
      ok: true,
      status: status || 'all',
      requests: rows.map(pcapRequestFromRow),
      policy: {capture_loss_threshold_percent: readCaptureLossThreshold()},
    };
  }

  async function requeueRequests(payload) {
    const requestIds = Array.isArray(payload?.request_ids)
      ? [...new Set(payload.request_ids.map((value) => safeString(value, 64)).filter(Boolean))].slice(0, 500)
      : [];
    if (!requestIds.length) throw new Error('request_ids must contain at least one PCAP request id');
    const now = nowUtc();
    const placeholders = requestIds.map(() => '?').join(', ');
    await run(
      `UPDATE pcap_requests
       SET status = 'pending', outcome = NULL, relay_host = NULL, claimed_at = NULL,
           completed_at = NULL, error = 'requeued after PCAP capture-selection upgrade',
           diagnostics_json = NULL, transfer_stage = NULL, transfer_bytes = 0,
           transfer_total_bytes = 0, transfer_progress_at = NULL,
           transfer_duration_seconds = NULL, transfer_attempt_count = 0,
           transfer_retry_count = 0, transfer_last_error = NULL,
           transfer_last_failed_stage = NULL, next_attempt_at = NULL, updated_at = ?
       WHERE status = 'failed' AND request_id IN (${placeholders})`,
      [now, ...requestIds],
    );
    const rows = await all(`SELECT * FROM pcap_requests WHERE request_id IN (${placeholders})`, requestIds);
    return {ok: true, requests: rows.map(pcapRequestFromRow)};
  }

  return {backfillOutcomes, candidateFromPayload, createRequest, listRequests, requeueRequests};
}

module.exports = {createPcapRequestRepository};
