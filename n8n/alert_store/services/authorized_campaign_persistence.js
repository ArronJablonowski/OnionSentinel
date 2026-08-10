'use strict';

function createAuthorizedCampaignPersistence({
  all, get, run, withImmediateTransaction, policy, matchAuthorizedActivity,
  parseJsonObject, normalizeTimestampValue, nowUtc, jsonText, integerField,
  completePendingJobs, stableGroupKey, stableGroupId, buildAlertObservables,
  extractAlertIndicators,
}) {
  const functions = {all, get, run, withImmediateTransaction, matchAuthorizedActivity,
    parseJsonObject, normalizeTimestampValue, nowUtc, jsonText, integerField,
    completePendingJobs, stableGroupKey, stableGroupId, buildAlertObservables,
    extractAlertIndicators};
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  let reconciliation = {
    status: 'not_run', campaigns: 0, ai_jobs_coalesced: 0,
    incident_jobs_coalesced: 0, incident_cases_resolved_as_duplicates: 0,
    pcap_requests_rejected_above_sample_limit: 0,
  };

  function reconciliationState() {
    return {...reconciliation};
  }

  function campaignProjection(campaign, admission, alertId, ordinal) {
    return {
      campaign_id: campaign.campaign_id,
      policy_id: campaign.policy_id,
      bucket_start: campaign.bucket_start,
      bucket_end: campaign.bucket_end,
      representative_alert_id: campaign.representative_alert_id,
      representative_group_id: campaign.representative_group_id,
      member_count: Number(campaign.member_count || 0),
      distinct_target_count: Number(campaign.distinct_target_count || 0),
      member_ordinal: Number(ordinal?.count || 0),
      is_representative: campaign.representative_alert_id === alertId,
      investigation_mode: admission.investigation_mode,
      pcap_sample_limit: Number(admission.pcap_sample_limit || 0),
      enrichment_sample_limit: Number(admission.enrichment_sample_limit || 0),
    };
  }

  async function memberOrdinal(campaignId, observedAt, alertId) {
    return get(
      `SELECT COUNT(*) AS count
       FROM authorized_activity_campaign_members
       WHERE campaign_id = ?
         AND (observed_at < ? OR (observed_at = ? AND alert_id <= ?))`,
      [campaignId, observedAt, observedAt, alertId],
    );
  }

  async function recordCampaign(alert, row, inserted = true) {
    if (!inserted || !row?.alert_id || !row?.stable_group_id) return null;
    const matchedPolicy = matchAuthorizedActivity(policy, alert, row);
    if (!matchedPolicy) return null;
    const existing = await get(
      `SELECT campaign.*, member.observed_at
       FROM authorized_activity_campaign_members AS member
       JOIN authorized_activity_campaigns AS campaign
         ON campaign.campaign_id = member.campaign_id
       WHERE member.alert_id = ? LIMIT 1`,
      [row.alert_id],
    );
    if (existing) {
      return campaignProjection(
        existing,
        parseJsonObject(existing.policy_json),
        row.alert_id,
        await memberOrdinal(existing.campaign_id, existing.observed_at, row.alert_id),
      );
    }
    const observedAt = normalizeTimestampValue(
      alert?.timestamp || row.timestamp || row.last_seen || row.first_seen,
    ) || row.last_seen || row.first_seen || nowUtc();
    const timestamp = nowUtc();
    const policyEvidence = {
      ...matchedPolicy.authorization,
      policy_id: matchedPolicy.id,
      source_ips: matchedPolicy.source_ips,
      destination_ips: matchedPolicy.destination_ips,
      rule_ids: matchedPolicy.rule_ids,
      source_ports: matchedPolicy.source_ports,
      destination_ports: matchedPolicy.destination_ports,
      destination_port_ranges: matchedPolicy.destination_port_ranges,
      transport_protocols: matchedPolicy.transport_protocols,
      authorization_start: matchedPolicy.authorization_start,
      authorization_end: matchedPolicy.authorization_end,
    };
    const admission = {
      investigation_mode: matchedPolicy.investigation_mode,
      window_seconds: matchedPolicy.window_seconds,
      pcap_sample_limit: matchedPolicy.pcap_sample_limit,
      enrichment_sample_limit: matchedPolicy.enrichment_sample_limit,
      reconcile_existing_pending: matchedPolicy.reconcile_existing_pending,
    };
    await run(
      `INSERT OR IGNORE INTO authorized_activity_campaigns (
         campaign_id, campaign_key, policy_id, representative_alert_id,
         representative_group_id, bucket_start, bucket_end, first_seen,
         last_seen, member_count, distinct_target_count, authorization_json,
         policy_json, created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?)`,
      [matchedPolicy.campaign_id, matchedPolicy.campaign_key, matchedPolicy.id,
        row.alert_id, row.stable_group_id, matchedPolicy.bucket_start,
        matchedPolicy.bucket_end, observedAt, observedAt, jsonText(policyEvidence),
        jsonText(admission), timestamp, timestamp],
    );
    await run(
      `INSERT OR IGNORE INTO authorized_activity_campaign_members (
         campaign_id, alert_id, stable_group_id, destination_ip,
         destination_port, observed_at, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [matchedPolicy.campaign_id, row.alert_id, row.stable_group_id,
        row.destination_ip || null, integerField(row.destination_port), observedAt, timestamp],
    );
    await run(
      `UPDATE authorized_activity_campaigns
       SET representative_alert_id = (
             SELECT alert_id FROM authorized_activity_campaign_members
             WHERE campaign_id = ? ORDER BY observed_at ASC, alert_id ASC LIMIT 1),
           representative_group_id = (
             SELECT stable_group_id FROM authorized_activity_campaign_members
             WHERE campaign_id = ? ORDER BY observed_at ASC, alert_id ASC LIMIT 1),
           first_seen = (SELECT MIN(observed_at) FROM authorized_activity_campaign_members
             WHERE campaign_id = ?),
           last_seen = (SELECT MAX(observed_at) FROM authorized_activity_campaign_members
             WHERE campaign_id = ?),
           member_count = (SELECT COUNT(*) FROM authorized_activity_campaign_members
             WHERE campaign_id = ?),
           distinct_target_count = (
             SELECT COUNT(DISTINCT COALESCE(destination_ip, '') || ':' || COALESCE(destination_port, ''))
             FROM authorized_activity_campaign_members WHERE campaign_id = ?),
           updated_at = ?
       WHERE campaign_id = ?`,
      [matchedPolicy.campaign_id, matchedPolicy.campaign_id, matchedPolicy.campaign_id,
        matchedPolicy.campaign_id, matchedPolicy.campaign_id, matchedPolicy.campaign_id,
        timestamp, matchedPolicy.campaign_id],
    );
    const campaign = await get(
      'SELECT * FROM authorized_activity_campaigns WHERE campaign_id = ?',
      [matchedPolicy.campaign_id],
    );
    return campaignProjection(
      campaign,
      admission,
      row.alert_id,
      await memberOrdinal(matchedPolicy.campaign_id, observedAt, row.alert_id),
    );
  }

  async function backfillCampaigns() {
    const enabled = (policy?.policies || []).filter((item) => item.enabled === true);
    if (!enabled.length) return 0;
    const starts = enabled.map((item) => Date.parse(item.authorization_start)).filter(Number.isFinite);
    const ends = enabled.map((item) => Date.parse(item.authorization_end)).filter(Number.isFinite);
    if (!starts.length || !ends.length) return 0;
    const earliest = new Date(Math.min(...starts)).toISOString();
    const latest = new Date(Math.max(...ends)).toISOString();
    const pageSize = 128;
    let lastRowId = 0;
    let matched = 0;
    while (true) {
      const rows = await all(
        `SELECT rowid AS backfill_rowid,
                alert_id, first_seen, last_seen, timestamp, rule_id,
                source_ip, source_port, destination_ip, destination_port,
                network_protocol, transport_protocol, stable_group_id, alert_json
         FROM alerts
         WHERE rowid > ?
           AND stable_group_id IS NOT NULL AND stable_group_id <> ''
           AND COALESCE(filter_status, 'accepted') IN ('accepted', 'escalated', 'duplicate')
           AND julianday(replace(COALESCE(timestamp, first_seen), '  ', 'T'))
               BETWEEN julianday(?) AND julianday(?)
           AND NOT EXISTS (
             SELECT 1 FROM authorized_activity_campaign_members AS member
             WHERE member.alert_id = alerts.alert_id)
         ORDER BY rowid ASC LIMIT ?`,
        [lastRowId, earliest, latest, pageSize],
      );
      if (!rows.length) break;
      lastRowId = Number(rows[rows.length - 1].backfill_rowid || lastRowId);
      await withImmediateTransaction(async () => {
        for (const row of rows) {
          if (await recordCampaign(parseJsonObject(row.alert_json), row, true)) matched += 1;
        }
      });
      if (rows.length < pageSize) break;
    }
    return matched;
  }

  async function campaignForAlertId(alertId) {
    if (!alertId) return null;
    const row = await get(
      `SELECT campaign.campaign_id, campaign.policy_id,
              campaign.representative_alert_id, campaign.representative_group_id,
              campaign.member_count, campaign.distinct_target_count, campaign.policy_json
       FROM authorized_activity_campaign_members AS member
       JOIN authorized_activity_campaigns AS campaign
         ON campaign.campaign_id = member.campaign_id
       WHERE member.alert_id = ? ORDER BY campaign.bucket_start DESC LIMIT 1`,
      [alertId],
    );
    return row ? {...row, ...parseJsonObject(row.policy_json)} : null;
  }

  async function reconcileCampaign(campaign, summary) {
    const admission = parseJsonObject(campaign.policy_json);
    if (admission.investigation_mode !== 'incident_response_only'
      || admission.reconcile_existing_pending !== true) return;
    const representativeCase = await get(
      'SELECT case_id FROM incident_response_cases WHERE group_id = ?',
      [campaign.representative_group_id],
    );
    if (!representativeCase?.case_id) return;
    summary.campaigns += 1;
    const members = await all(
      `SELECT stable_group_id, alert_id, observed_at
       FROM authorized_activity_campaign_members
       WHERE campaign_id = ? ORDER BY observed_at ASC, alert_id ASC`,
      [campaign.campaign_id],
    );
    const groupIds = [...new Set(members.map((item) => item.stable_group_id).filter(Boolean))];
    const duplicateIds = groupIds.filter((id) => id !== campaign.representative_group_id);
    summary.ai_jobs_coalesced += await completePendingJobs('ai_analysis', groupIds);
    summary.incident_jobs_coalesced += await completePendingJobs(
      'incident_response_analysis', duplicateIds,
    );
    for (let offset = 0; offset < duplicateIds.length; offset += 500) {
      const chunk = duplicateIds.slice(offset, offset + 500);
      const placeholders = chunk.map(() => '?').join(', ');
      const pendingCases = await all(
        `SELECT case_id, group_id FROM incident_response_cases
         WHERE group_id IN (${placeholders})
           AND agent_status = 'queued' AND status <> 'resolved'`,
        chunk,
      );
      const resolvedAt = nowUtc();
      const reason = `Coalesced into authorized activity campaign ${campaign.campaign_id}; representative case ${representativeCase.case_id}`;
      const updated = await run(
        `UPDATE incident_response_cases
         SET status = 'resolved', agent_status = 'analyzed', updated_at = ?,
             resolution_reason = ?, resolved_at = ?,
             resolved_by = 'authorized-activity-policy', latest_error = NULL
         WHERE group_id IN (${placeholders})
           AND agent_status = 'queued' AND status <> 'resolved'`,
        [resolvedAt, reason, resolvedAt, ...chunk],
      );
      summary.incident_cases_resolved_as_duplicates += Number(updated.changes || 0);
      for (const incident of pendingCases) {
        await run(
          `INSERT INTO incident_response_events
             (case_id, event_type, actor, detail_json, created_at)
           VALUES (?, 'campaign_coalesced', 'authorized-activity-policy', ?, ?)`,
          [incident.case_id, jsonText({campaign_id: campaign.campaign_id,
            representative_case_id: representativeCase.case_id,
            representative_group_id: campaign.representative_group_id,
            resolution: 'duplicate_authorized_campaign_member'}), resolvedAt],
        );
      }
    }
    const sampleLimit = Math.max(0, Number(admission.pcap_sample_limit || 0));
    const rejectedAt = nowUtc();
    const rejected = await run(
      `UPDATE pcap_requests
       SET status = 'rejected', outcome = 'rejected',
           error = ?, completed_at = ?, updated_at = ?
       WHERE status = 'pending'
         AND alert_id IN (
           SELECT alert_id FROM authorized_activity_campaign_members
           WHERE campaign_id = ? ORDER BY observed_at ASC, alert_id ASC
           LIMIT -1 OFFSET ?)`,
      [`Coalesced above the ${sampleLimit}-capture authorized campaign sample limit`,
        rejectedAt, rejectedAt, campaign.campaign_id, sampleLimit],
    );
    summary.pcap_requests_rejected_above_sample_limit += Number(rejected.changes || 0);
  }

  async function reconcileBacklog() {
    const summary = {status: 'ok', campaigns: 0, ai_jobs_coalesced: 0,
      incident_jobs_coalesced: 0, incident_cases_resolved_as_duplicates: 0,
      pcap_requests_rejected_above_sample_limit: 0, completed_at: nowUtc()};
    for (const campaign of await all(
      'SELECT * FROM authorized_activity_campaigns ORDER BY bucket_start ASC',
    )) await reconcileCampaign(campaign, summary);
    summary.completed_at = nowUtc();
    reconciliation = summary;
    return summary;
  }

  async function indexObservables(alert, row) {
    if (!row?.alert_id) return 0;
    const identity = {...row, rule_id: alert?.rule_id || row.rule_id};
    const groupKey = row.stable_group_key || stableGroupKey(identity);
    const groupId = row.stable_group_id || stableGroupId(identity);
    const observables = buildAlertObservables(alert, row, extractAlertIndicators);
    await run('DELETE FROM alert_observables WHERE alert_id = ?', [row.alert_id]);
    for (const observable of observables) {
      await run(
        `INSERT INTO alert_observables (
           group_id, group_key, alert_id, observable_type, observable_value,
           role, source, first_seen, last_seen, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [groupId, groupKey, row.alert_id, observable.observable_type,
          observable.observable_value, observable.role, observable.source,
          row.first_seen || null, row.last_seen || row.timestamp || null, nowUtc()],
      );
    }
    return observables.length;
  }

  async function backfillObservables() {
    const pending = await all(`
      SELECT a.* FROM alerts AS a
      WHERE NOT EXISTS (
        SELECT 1 FROM alert_observables AS observable WHERE observable.alert_id = a.alert_id)
         OR (
           instr(COALESCE(a.alert_json, ''), '"community_id"') > 0
           AND NOT EXISTS (
             SELECT 1 FROM alert_observables AS observable
             WHERE observable.alert_id = a.alert_id
               AND observable.observable_type = 'community_id'))
      ORDER BY a.last_seen ASC
    `);
    if (!pending.length) return 0;
    await withImmediateTransaction(async () => {
      for (const item of pending) {
        await indexObservables(parseJsonObject(item.alert_json), item);
      }
    });
    return pending.length;
  }

  return {recordCampaign, backfillCampaigns, campaignForAlertId, reconcileBacklog,
    reconciliationState, indexObservables, backfillObservables};
}

module.exports = {createAuthorizedCampaignPersistence};
