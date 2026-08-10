'use strict';

function createAlertPersistence({
  currentGroupKey, nowUtc, findDropRule, nestedField, ruleName,
  normalizeTimestampValue, integerField, jsonText, enrichmentRecord, run, get,
  applySuppression, persistStableIdentity, indexObservables, recordCampaign,
  groupKeyFromRow, refreshGroupSummary, queueAutomaticPcap, queueAutomaticIncident,
}) {
  const functions = {currentGroupKey, nowUtc, findDropRule, nestedField, ruleName,
    normalizeTimestampValue, integerField, jsonText, enrichmentRecord, run, get,
    applySuppression, persistStableIdentity, indexObservables, recordCampaign,
    groupKeyFromRow, refreshGroupSummary, queueAutomaticPcap, queueAutomaticIncident};
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function dropped(alert, alertId, rule) {
    return {
      ok: true, status: 'dropped', stored: false,
      alert: {alert_id: alertId, rule_name: alert.rule_name || null,
        event_dataset: alert.event_dataset || null,
        source_ip: nestedField(alert, 'source.ip'),
        destination_ip: nestedField(alert, 'destination.ip'),
        triage_score: nestedField(alert, 'triage.score'),
        triage_level: nestedField(alert, 'triage.level'), routing: 'dropped'},
      triage: {...alert.triage, routing: 'dropped',
        reasons: [...(alert.triage.reasons || []), `dropped by policy: ${ruleName(rule)}`]},
      filter: {status: 'dropped', rule: ruleName(rule),
        reason: rule.reason || 'matched drop rule'},
      notification: {channel: 'telegram', status: 'skipped_filter'},
    };
  }

  function insertParams(alert, alertId, timestamp) {
    return {$alert_id: alertId, $first_seen: timestamp, $last_seen: timestamp,
      $timestamp: normalizeTimestampValue(alert.timestamp),
      $rule_name: alert.rule_name || null, $event_dataset: alert.event_dataset || null,
      $severity: alert.severity ?? null, $severity_label: alert.severity_label || null,
      $source_ip: nestedField(alert, 'source.ip'),
      $source_port: integerField(nestedField(alert, 'source.port')),
      $destination_ip: nestedField(alert, 'destination.ip'),
      $destination_port: integerField(nestedField(alert, 'destination.port')),
      $network_protocol: nestedField(alert, 'network.protocol'),
      $transport_protocol: nestedField(alert, 'network.transport')
        || nestedField(alert, 'network.iana_number'),
      $traffic_direction: nestedField(alert, 'triage.traffic_direction'),
      $triage_score: nestedField(alert, 'triage.score'),
      $triage_level: nestedField(alert, 'triage.level'),
      $routing: nestedField(alert, 'triage.routing'), $filter_status: 'accepted',
      $filter_reason: null, $suppression_key: null,
      $raw_event_json: jsonText(nestedField(alert, 'security_onion.raw_event')),
      $enrichment_json: jsonText(enrichmentRecord(alert)), $alert_json: jsonText(alert)};
  }

  async function insertAlert(params) {
    return run(`
      INSERT OR IGNORE INTO alerts (
        alert_id, first_seen, last_seen, seen_count, timestamp,
        rule_name, event_dataset, severity, severity_label,
        source_ip, source_port, destination_ip, destination_port,
        network_protocol, transport_protocol, traffic_direction, triage_score,
        triage_level, routing, filter_status, filter_reason,
        suppression_key, raw_event_json, enrichment_json, alert_json)
      VALUES (
        $alert_id, $first_seen, $last_seen, 1, $timestamp,
        $rule_name, $event_dataset, $severity, $severity_label,
        $source_ip, $source_port, $destination_ip, $destination_port,
        $network_protocol, $transport_protocol, $traffic_direction, $triage_score,
        $triage_level, $routing, $filter_status, $filter_reason,
        $suppression_key, $raw_event_json, $enrichment_json, $alert_json)
    `, params);
  }

  async function updateDuplicate(alert, params, timestamp) {
    await run(`
      UPDATE alerts
      SET last_seen = $last_seen, seen_count = seen_count + 1,
          source_port = $source_port, destination_port = $destination_port,
          network_protocol = $network_protocol, transport_protocol = $transport_protocol,
          traffic_direction = $traffic_direction, triage_score = $triage_score,
          triage_level = $triage_level, routing = $routing,
          filter_status = $filter_status, filter_reason = $filter_reason,
          suppression_key = $suppression_key, raw_event_json = $raw_event_json,
          enrichment_json = $enrichment_json, alert_json = $alert_json
      WHERE alert_id = $alert_id`,
    {$last_seen: timestamp, $source_port: params.$source_port,
      $destination_port: params.$destination_port, $network_protocol: params.$network_protocol,
      $transport_protocol: params.$transport_protocol,
      $traffic_direction: nestedField(alert, 'triage.traffic_direction'),
      $triage_score: nestedField(alert, 'triage.score'),
      $triage_level: nestedField(alert, 'triage.level'),
      $routing: nestedField(alert, 'triage.routing'), $filter_status: 'duplicate',
      $filter_reason: null, $suppression_key: null,
      $raw_event_json: params.$raw_event_json, $enrichment_json: params.$enrichment_json,
      $alert_json: params.$alert_json, $alert_id: params.$alert_id});
  }

  async function updateSuppression(alert, alertId, suppression) {
    await run(`
      UPDATE alerts
      SET source_port = $source_port, destination_port = $destination_port,
          network_protocol = $network_protocol, transport_protocol = $transport_protocol,
          routing = $routing, filter_status = $filter_status,
          filter_reason = $filter_reason, suppression_key = $suppression_key,
          raw_event_json = $raw_event_json, enrichment_json = $enrichment_json,
          alert_json = $alert_json
      WHERE alert_id = $alert_id`,
    {$source_port: integerField(nestedField(alert, 'source.port')),
      $destination_port: integerField(nestedField(alert, 'destination.port')),
      $network_protocol: nestedField(alert, 'network.protocol'),
      $transport_protocol: nestedField(alert, 'network.transport')
        || nestedField(alert, 'network.iana_number'),
      $routing: nestedField(alert, 'triage.routing'), $filter_status: suppression.status,
      $filter_reason: suppression.reason || null, $suppression_key: suppression.key || null,
      $raw_event_json: jsonText(nestedField(alert, 'security_onion.raw_event')),
      $enrichment_json: jsonText(enrichmentRecord(alert)), $alert_json: jsonText(alert),
      $alert_id: alertId});
  }

  async function storedRow(alertId) {
    return get(`
      SELECT alert_id, first_seen, last_seen, seen_count, timestamp,
             rule_name, event_dataset, severity, severity_label,
             source_ip, source_port, destination_ip, destination_port,
             network_protocol, transport_protocol, traffic_direction, triage_score,
             triage_level, routing, filter_status, filter_reason, suppression_key
      FROM alerts WHERE alert_id = ?`, [alertId]);
  }

  async function store(alert) {
    const alertId = alert.alert_id;
    if (!alertId) return {ok: false, status: 'rejected', reason: 'missing alert_id'};
    const previousGroupKey = await currentGroupKey(alertId);
    const timestamp = nowUtc();
    const dropRule = findDropRule(alert);
    if (dropRule) return dropped(alert, alertId, dropRule);
    const params = insertParams(alert, alertId, timestamp);
    const inserted = (await insertAlert(params)).changes === 1;
    const suppression = inserted
      ? await applySuppression(alert, timestamp) : {status: 'not_applicable'};
    if (suppression.status === 'suppressed') {
      alert.triage = {...alert.triage, routing: 'suppressed',
        reasons: [...(alert.triage.reasons || []),
          `suppressed by policy: ${suppression.rule}`]};
    }
    if (suppression.status === 'escalated') {
      alert.triage = {...alert.triage, reasons: [...(alert.triage.reasons || []),
        `suppression escalation threshold reached: ${suppression.seen_count} in window`]};
    }
    if (!inserted) await updateDuplicate(alert, params, timestamp);
    else if (['suppressed', 'escalated'].includes(suppression.status)) {
      await updateSuppression(alert, alertId, suppression);
    }
    const row = await storedRow(alertId);
    Object.assign(row, await persistStableIdentity(alertId, row, alert));
    await indexObservables(alert, row);
    const campaign = await recordCampaign(alert, row, inserted);
    const nextGroupKey = groupKeyFromRow(row);
    if (previousGroupKey && previousGroupKey !== nextGroupKey) {
      await refreshGroupSummary(previousGroupKey);
    }
    await refreshGroupSummary(nextGroupKey);
    const pcap = await queueAutomaticPcap(alert, row, inserted, suppression, campaign);
    const incident = await queueAutomaticIncident(alert, row, inserted, suppression, campaign);
    return {ok: true,
      status: inserted
        ? (suppression.status === 'suppressed' ? 'suppressed' : 'accepted')
        : 'already_seen',
      stored: inserted, alert: row, triage: alert.triage, filter: suppression,
      campaign, pcap, incident,
      notification: {channel: 'telegram', status: 'pending'}};
  }

  return {store};
}

module.exports = {createAlertPersistence};
