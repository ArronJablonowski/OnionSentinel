'use strict';

const crypto = require('crypto');

const PCAP_OUTCOMES = new Set([
  'captured', 'no_packets_available', 'expired', 'oversize', 'timeout',
  'transport_failed', 'checksum_failed', 'rejected', 'failed',
]);

function createPcapPolicy({
  safeString,
  parseJsonObject,
  nestedField,
  integerField,
  normalizeTimestampValue,
  defaultWindowSeconds,
  maxWindowSeconds,
  captureRetentionSeconds,
  nowMs = () => Date.now(),
}) {
  for (const [name, value] of Object.entries({
    safeString,
    parseJsonObject,
    nestedField,
    integerField,
    normalizeTimestampValue,
    nowMs,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function pcapRequestId(seed) {
    return crypto.createHash('sha256').update(JSON.stringify(seed)).digest('hex').slice(0, 16);
  }

  function pcapCandidateFromRow(row) {
    if (!row) return {};
    const alertJson = parseJsonObject(row.alert_json);
    const rawEventJson = parseJsonObject(row.raw_event_json);
    const captureFile =
      nestedField(rawEventJson, 'suricata.capture_file') ||
      nestedField(rawEventJson, 'message.capture_file') ||
      nestedField(alertJson, 'suricata.capture_file') ||
      nestedField(alertJson, 'capture_file') ||
      null;
    return {
      alert_id: row.alert_id || row.representative_alert_id || null,
      group_id: row.group_id || null,
      group_key: row.group_key || null,
      event_timestamp: row.timestamp || null,
      first_seen: row.first_seen || row.timestamp || null,
      last_seen: row.last_seen || row.timestamp || null,
      source_ip: row.source_ip || nestedField(alertJson, 'source.ip') || nestedField(rawEventJson, 'source.ip') || null,
      source_port: integerField(row.source_port ?? nestedField(alertJson, 'source.port') ?? nestedField(rawEventJson, 'source.port')),
      destination_ip: row.destination_ip || nestedField(alertJson, 'destination.ip') || nestedField(rawEventJson, 'destination.ip') || null,
      destination_port: integerField(row.destination_port ?? nestedField(alertJson, 'destination.port') ?? nestedField(rawEventJson, 'destination.port')),
      network_protocol: row.network_protocol || nestedField(alertJson, 'network.protocol') || nestedField(rawEventJson, 'network.protocol') || null,
      transport_protocol: row.transport_protocol || nestedField(alertJson, 'network.transport') || nestedField(rawEventJson, 'network.transport') || null,
      community_id: nestedField(alertJson, 'network.community_id') || nestedField(rawEventJson, 'network.community_id') || null,
      capture_file: captureFile,
    };
  }

  function normalizePcapRequest(payload, candidate = {}) {
    const merged = {...candidate, ...(payload || {})};
    const reason = safeString(merged.reason, 240);
    if (!reason) throw new Error('pcap request reason is required');
    const sourceIp = safeString(merged.source_ip, 64);
    const destinationIp = safeString(merged.destination_ip, 64);
    if (!sourceIp || !destinationIp) throw new Error('pcap request requires source_ip and destination_ip');
    // Exact representative alerts are anchored to their immutable event time.
    // Ingestion and group rollup clocks can move when old events are replayed.
    const selectedEventTimestamp = normalizeTimestampValue(
      candidate.event_timestamp || candidate.timestamp,
    );
    const firstSeen = selectedEventTimestamp || normalizeTimestampValue(
      merged.first_seen || merged.timestamp || merged.last_seen,
    );
    const lastSeen = selectedEventTimestamp || normalizeTimestampValue(
      merged.last_seen || merged.timestamp || merged.first_seen,
    );
    if (!firstSeen || !lastSeen) throw new Error('pcap request requires first_seen and last_seen timestamps');
    const requestedWindow = Number(merged.max_window_seconds || defaultWindowSeconds);
    const boundedWindowSeconds = Math.min(
      maxWindowSeconds,
      Math.max(30, Number.isFinite(requestedWindow) ? Math.round(requestedWindow) : defaultWindowSeconds),
    );
    const request = {
      alert_id: safeString(merged.alert_id, 512) || null,
      group_id: safeString(merged.group_id, 64) || null,
      group_key: safeString(merged.group_key, 512) || null,
      first_seen: firstSeen,
      last_seen: lastSeen,
      source_ip: sourceIp,
      source_port: integerField(merged.source_port),
      destination_ip: destinationIp,
      destination_port: integerField(merged.destination_port),
      network_protocol: safeString(merged.network_protocol, 32) || null,
      transport_protocol: safeString(merged.transport_protocol, 32).toLowerCase() || null,
      community_id: safeString(merged.community_id, 128) || null,
      capture_file: safeString(merged.capture_file, 512) || null,
      requested_by: safeString(merged.requested_by || 'soc-analyst', 80),
      reason,
      max_window_seconds: boundedWindowSeconds,
      require_source_port: Boolean(merged.require_source_port),
    };
    request.request_id = pcapRequestId({
      alert_id: request.alert_id,
      group_id: request.group_id,
      first_seen: request.first_seen,
      last_seen: request.last_seen,
      source_ip: request.source_ip,
      source_port: request.source_port,
      destination_ip: request.destination_ip,
      destination_port: request.destination_port,
      community_id: request.community_id,
      capture_file: request.capture_file,
      reason: request.reason,
    });
    return request;
  }

  function pcapRetentionError(lastSeen) {
    if (!captureRetentionSeconds || !lastSeen) return null;
    const occurredAt = Date.parse(String(lastSeen).replace('  ', 'T'));
    if (!Number.isFinite(occurredAt)) return null;
    const ageSeconds = Math.floor((nowMs() - occurredAt) / 1000);
    if (ageSeconds <= captureRetentionSeconds) return null;
    return `PCAP request exceeds configured capture retention (${captureRetentionSeconds}s)`;
  }

  function classifyPcapOutcome(status, error, diagnostics = {}) {
    const state = String(status || '').toLowerCase();
    const detail = `${String(error || '')} ${JSON.stringify(diagnostics || {})}`.toLowerCase();
    if (state === 'fulfilled') return 'captured';
    if (detail.includes('no matching packet')) return 'no_packets_available';
    if (detail.includes('capture retention') || detail.includes('expired')) return 'expired';
    if (detail.includes('exceed') && (detail.includes('size') || detail.includes('artifact'))) return 'oversize';
    if (detail.includes('timeout') || detail.includes('timed out')) return 'timeout';
    if (detail.includes('sha256') || detail.includes('checksum')) return 'checksum_failed';
    if (detail.includes('rsync') || detail.includes('artifact upload') || detail.includes('connection') || detail.includes('ssh')) {
      return 'transport_failed';
    }
    if (state === 'rejected') return 'rejected';
    return state === 'failed' ? 'failed' : '';
  }

  function pcapRequestFromRow(row) {
    const requestJson = parseJsonObject(row.request_json);
    return {
      request_id: row.request_id,
      status: row.status,
      alert_id: row.alert_id,
      group_id: row.group_id,
      group_key: row.group_key,
      first_seen: row.first_seen,
      last_seen: row.last_seen,
      source_ip: row.source_ip,
      source_port: row.source_port,
      destination_ip: row.destination_ip,
      destination_port: row.destination_port,
      network_protocol: row.network_protocol,
      transport_protocol: row.transport_protocol,
      community_id: row.community_id,
      capture_file: requestJson.capture_file || null,
      requested_by: row.requested_by,
      reason: row.reason,
      max_window_seconds: row.max_window_seconds,
      require_source_port: Boolean(requestJson.require_source_port),
      relay_host: row.relay_host,
      artifact_path: row.artifact_path,
      artifact_sha256: row.artifact_sha256,
      artifact_size_bytes: row.artifact_size_bytes,
      error: row.error,
      outcome: row.outcome || classifyPcapOutcome(row.status, row.error, parseJsonObject(row.diagnostics_json)),
      diagnostics: parseJsonObject(row.diagnostics_json),
      analysis_status: row.analysis_status || 'not_ready',
      analysis_attempt_count: Number(row.analysis_attempt_count || 0),
      analysis_error: row.analysis_error || null,
      analysis_started_at: row.analysis_started_at || null,
      analysis_completed_at: row.analysis_completed_at || null,
      transfer_stage: row.transfer_stage || null,
      transfer_bytes: Number(row.transfer_bytes || 0),
      transfer_total_bytes: Number(row.transfer_total_bytes || 0),
      transfer_progress_at: row.transfer_progress_at || null,
      transfer_duration_seconds: row.transfer_duration_seconds == null
        ? null
        : Number(row.transfer_duration_seconds),
      transfer_attempt_count: Number(row.transfer_attempt_count || 0),
      transfer_retry_count: Number(row.transfer_retry_count || 0),
      transfer_last_error: row.transfer_last_error || null,
      transfer_last_failed_stage: row.transfer_last_failed_stage || null,
      next_attempt_at: row.next_attempt_at || null,
      created_at: row.created_at,
      claimed_at: row.claimed_at,
      completed_at: row.completed_at,
      updated_at: row.updated_at,
    };
  }

  return {
    pcapOutcomes: PCAP_OUTCOMES,
    pcapRequestId,
    pcapCandidateFromRow,
    normalizePcapRequest,
    pcapRetentionError,
    pcapRequestFromRow,
    classifyPcapOutcome,
  };
}

module.exports = {createPcapPolicy};
