'use strict';

function createAutomaticResponseRouting({
  nestedField, readPolicy, matchesPcap, matchesIncident, groupKeyFromRow,
  groupIdFromKey, get, run, parseJsonObject, jsonText, nowUtc,
  createPcapRequest, pcapRequestDefaultWindowSeconds,
  queueIncidentResponseForGroup, severityRank,
}) {
  const functions = {nestedField, readPolicy, matchesPcap, matchesIncident,
    groupKeyFromRow, groupIdFromKey, get, run, parseJsonObject, jsonText, nowUtc,
    createPcapRequest, queueIncidentResponseForGroup};
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  if (!severityRank || typeof severityRank !== 'object') {
    throw new TypeError('severityRank must be an object');
  }

  function skipStatus(storedRow, inserted, suppression) {
    if (!inserted) return {status: 'skipped_duplicate'};
    if (!storedRow || ['suppressed', 'dropped'].includes(
      String(storedRow.filter_status || '').toLowerCase(),
    )) return {status: 'skipped_filter'};
    if (suppression?.status === 'suppressed') return {status: 'skipped_suppression'};
    return null;
  }

  function triageLevel(alert, storedRow) {
    return String(
      nestedField(alert, 'triage.level') || storedRow.triage_level || '',
    ).toLowerCase();
  }

  async function queuePcap(alert, storedRow, inserted, suppression, campaign = null) {
    const skipped = skipStatus(storedRow, inserted, suppression);
    if (skipped) return skipped;
    const level = triageLevel(alert, storedRow);
    const threshold = readPolicy().soc_analyst_pcap_min_severity;
    if (!matchesPcap(level)) {
      return {status: 'skipped_level', triage_level: level, threshold};
    }
    if (campaign && campaign.member_ordinal > campaign.pcap_sample_limit) {
      return {status: 'coalesced_campaign', campaign_id: campaign.campaign_id,
        representative_group_id: campaign.representative_group_id,
        sample_limit: campaign.pcap_sample_limit,
        member_ordinal: campaign.member_ordinal, triage_level: level, threshold};
    }
    try {
      const groupId = groupIdFromKey(groupKeyFromRow(storedRow));
      const stableId = storedRow.stable_group_id || groupId;
      const existingPending = await get(
        `SELECT p.* FROM pcap_requests p
         LEFT JOIN alert_group_alias a ON a.legacy_group_id = p.group_id
         WHERE COALESCE(a.stable_group_id, p.group_id) = ? AND p.status = 'pending'
         ORDER BY p.created_at DESC LIMIT 1`,
        [stableId],
      );
      if (existingPending) {
        const payload = parseJsonObject(existingPending.request_json);
        payload.last_seen = storedRow.last_seen || payload.last_seen;
        payload.alert_id = storedRow.alert_id || payload.alert_id;
        await run(
          `UPDATE pcap_requests SET alert_id = ?, last_seen = ?, request_json = ?,
             reason = ?, updated_at = ? WHERE request_id = ? AND status = 'pending'`,
          [storedRow.alert_id, storedRow.last_seen, jsonText(payload),
            `Coalesced automatic PCAP request for ${level} alert group`, nowUtc(),
            existingPending.request_id],
        );
        return {status: 'coalesced', request_id: existingPending.request_id,
          group_id: groupId, triage_level: level, threshold};
      }
      const result = await createPcapRequest({group_id: groupId,
        alert_id: storedRow.alert_id, requested_by: 'alert-store-auto-pcap',
        reason: `Automatic PCAP request for ${level} alert`,
        max_window_seconds: pcapRequestDefaultWindowSeconds});
      return {status: result.request?.status || 'pending',
        request_id: result.request?.request_id || null, group_id: groupId,
        triage_level: level, threshold};
    } catch (error) {
      return {status: 'failed', reason: error.message, triage_level: level, threshold};
    }
  }

  async function queueIncident(alert, storedRow, inserted, suppression, campaign = null) {
    const skipped = skipStatus(storedRow, inserted, suppression);
    if (skipped) return skipped;
    const level = triageLevel(alert, storedRow);
    const threshold = readPolicy().soc_analyst_incident_min_severity;
    if (!matchesIncident(level)) {
      return {status: 'skipped_level', triage_level: level, threshold};
    }
    if (campaign && !campaign.is_representative) {
      const representative = await get(
        `SELECT case_id, dashboard_group_id, representative_alert_id
         FROM incident_response_cases WHERE group_id = ?`,
        [campaign.representative_group_id],
      );
      return {status: 'coalesced_campaign', campaign_id: campaign.campaign_id,
        campaign_member_count: campaign.member_count,
        representative_group_id: campaign.representative_group_id,
        representative_alert_id: campaign.representative_alert_id,
        case_id: representative?.case_id || null, triage_level: level, threshold};
    }
    try {
      const dashboardGroupId = groupIdFromKey(groupKeyFromRow(storedRow));
      const result = await queueIncidentResponseForGroup({dashboardGroupId,
        representative: storedRow, requestedBy: 'alert-store-auto-incident',
        reason: `Automatic incident response for ${level} alert at configured ${threshold} threshold`,
        relatedLimit: 250, pcapAnalysisLimit: 25, manualReanalysis: false,
        eventType: 'auto_escalated', priority: 100 + (severityRank[level] ?? 0)});
      return {...result, triage_level: level, threshold};
    } catch (error) {
      error.statusCode = Number(error.statusCode || 503);
      throw error;
    }
  }

  return {queuePcap, queueIncident};
}

module.exports = {createAutomaticResponseRouting};
