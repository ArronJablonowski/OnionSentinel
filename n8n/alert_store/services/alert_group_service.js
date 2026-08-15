'use strict';

function createAlertGroupService({
  all,
  get,
  run,
  withImmediateTransaction,
  withSqliteWriteGate,
  nowUtc,
  normalizeTriageLevel,
  alertGroupId,
  alertGroupKeySql,
}) {
  for (const [name, value] of Object.entries({
    all,
    get,
    run,
    withImmediateTransaction,
    withSqliteWriteGate,
    nowUtc,
    normalizeTriageLevel,
    alertGroupId,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  if (typeof alertGroupKeySql !== 'string' || !alertGroupKeySql.trim()) {
    throw new TypeError('alertGroupKeySql must be a non-empty string');
  }

  async function refreshGroupAliases() {
    const groups = await all(`
      SELECT g.group_id AS legacy_group_id, a.stable_group_id, a.stable_group_key
      FROM alert_group_summary g JOIN alerts a ON a.alert_id = g.representative_alert_id
      WHERE a.stable_group_id IS NOT NULL AND a.stable_group_key IS NOT NULL
    `);
    if (!groups.length) return 0;
    await withImmediateTransaction(async () => {
      for (const item of groups) {
        await run(
          `INSERT INTO alert_group_alias (legacy_group_id, stable_group_id, stable_group_key, updated_at)
           VALUES (?, ?, ?, ?) ON CONFLICT(legacy_group_id) DO UPDATE SET
           stable_group_id = excluded.stable_group_id,
           stable_group_key = excluded.stable_group_key,
           updated_at = excluded.updated_at`,
          [item.legacy_group_id, item.stable_group_id, item.stable_group_key, nowUtc()],
        );
      }
    });
    return groups.length;
  }

  function alertGroupKeyFromRow(row) {
    if (!row) return '';
    if (row.suppression_key) return String(row.suppression_key);
    return [
      normalizeTriageLevel(row.triage_level, row.severity_label),
      row.rule_name || 'unknown-rule',
      row.source_ip || 'unknown-source',
      row.destination_ip || 'unknown-destination',
      row.filter_status || 'accepted',
    ].join('|');
  }

  async function currentAlertGroupKey(alertId) {
    const row = await get(
      `SELECT ${alertGroupKeySql} AS group_key FROM alerts WHERE alert_id = ?`,
      [alertId],
    );
    return row?.group_key || '';
  }

  async function removeEmptyGroup(groupId) {
    await run('DELETE FROM alert_group_summary WHERE group_id = ?', [groupId]);
    await run('DELETE FROM alert_group_alias WHERE legacy_group_id = ?', [groupId]);
  }

  async function refreshAlertGroupSummary(groupKey) {
    if (!groupKey) return;
    const aggregate = await get(
      `
        SELECT COUNT(*) AS raw_alert_count,
               COALESCE(SUM(MAX(1, COALESCE(seen_count, 1))), 0) AS total_seen_count,
               MIN(first_seen) AS first_seen,
               MAX(last_seen) AS last_seen
        FROM alerts
        WHERE ${alertGroupKeySql} = ?
      `,
      [groupKey],
    );
    const groupId = alertGroupId(groupKey);
    if (!aggregate || Number(aggregate.raw_alert_count || 0) === 0) {
      await removeEmptyGroup(groupId);
      return;
    }
    const representative = await get(
      `
        SELECT alert_id, timestamp, rule_name, event_dataset, severity, severity_label,
               source_ip, source_port, destination_ip, destination_port,
               network_protocol, transport_protocol, traffic_direction, triage_score,
               triage_level, routing, filter_status, filter_reason, suppression_key
        FROM alerts
        WHERE ${alertGroupKeySql} = ?
        ORDER BY replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC,
                 alert_id DESC
        LIMIT 1
      `,
      [groupKey],
    );
    if (!representative) {
      await removeEmptyGroup(groupId);
      return;
    }
    await run(
      `
        INSERT INTO alert_group_summary (
          group_id, group_key, representative_alert_id, first_seen, last_seen,
          raw_alert_count, total_seen_count, timestamp, rule_name, event_dataset,
          severity, severity_label, source_ip, source_port, destination_ip,
          destination_port, network_protocol, transport_protocol, traffic_direction,
          triage_score, triage_level, routing, filter_status, filter_reason,
          suppression_key, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(group_id) DO UPDATE SET
          group_key = excluded.group_key,
          representative_alert_id = excluded.representative_alert_id,
          first_seen = excluded.first_seen,
          last_seen = excluded.last_seen,
          raw_alert_count = excluded.raw_alert_count,
          total_seen_count = excluded.total_seen_count,
          timestamp = excluded.timestamp,
          rule_name = excluded.rule_name,
          event_dataset = excluded.event_dataset,
          severity = excluded.severity,
          severity_label = excluded.severity_label,
          source_ip = excluded.source_ip,
          source_port = excluded.source_port,
          destination_ip = excluded.destination_ip,
          destination_port = excluded.destination_port,
          network_protocol = excluded.network_protocol,
          transport_protocol = excluded.transport_protocol,
          traffic_direction = excluded.traffic_direction,
          triage_score = excluded.triage_score,
          triage_level = excluded.triage_level,
          routing = excluded.routing,
          filter_status = excluded.filter_status,
          filter_reason = excluded.filter_reason,
          suppression_key = excluded.suppression_key,
          updated_at = excluded.updated_at
      `,
      [
        groupId,
        groupKey,
        representative.alert_id,
        aggregate.first_seen,
        aggregate.last_seen,
        Number(aggregate.raw_alert_count || 0),
        Number(aggregate.total_seen_count || 0),
        representative.timestamp,
        representative.rule_name,
        representative.event_dataset,
        representative.severity,
        representative.severity_label,
        representative.source_ip,
        representative.source_port,
        representative.destination_ip,
        representative.destination_port,
        representative.network_protocol,
        representative.transport_protocol,
        representative.traffic_direction,
        representative.triage_score,
        normalizeTriageLevel(representative.triage_level, representative.severity_label),
        representative.routing,
        representative.filter_status,
        representative.filter_reason,
        representative.suppression_key,
        nowUtc(),
      ],
    );
    const stableIdentity = await get(
      'SELECT stable_group_id, stable_group_key FROM alerts WHERE alert_id = ?',
      [representative.alert_id],
    );
    if (stableIdentity?.stable_group_id && stableIdentity?.stable_group_key) {
      await run(
        `INSERT INTO alert_group_alias (legacy_group_id, stable_group_id, stable_group_key, updated_at)
         VALUES (?, ?, ?, ?) ON CONFLICT(legacy_group_id) DO UPDATE SET
         stable_group_id = excluded.stable_group_id,
         stable_group_key = excluded.stable_group_key,
         updated_at = excluded.updated_at`,
        [groupId, stableIdentity.stable_group_id, stableIdentity.stable_group_key, nowUtc()],
      );
    }
  }

  async function rebuildAlertGroupSummariesUnlocked() {
    const groups = await all(`
      WITH ranked AS (
        SELECT ${alertGroupKeySql} AS group_key,
               alert_id, first_seen, last_seen, timestamp, rule_name, event_dataset,
               severity, severity_label, source_ip, source_port, destination_ip,
               destination_port, network_protocol, transport_protocol,
               traffic_direction, triage_score, triage_level, routing,
               filter_status, filter_reason, suppression_key,
               COUNT(*) OVER (PARTITION BY ${alertGroupKeySql}) AS raw_alert_count,
               SUM(MAX(1, COALESCE(seen_count, 1))) OVER (PARTITION BY ${alertGroupKeySql}) AS total_seen_count,
               MIN(first_seen) OVER (PARTITION BY ${alertGroupKeySql}) AS group_first_seen,
               MAX(last_seen) OVER (PARTITION BY ${alertGroupKeySql}) AS group_last_seen,
               ROW_NUMBER() OVER (
                 PARTITION BY ${alertGroupKeySql}
                 ORDER BY replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC,
                          alert_id DESC
               ) AS representative_rank
        FROM alerts
      )
      SELECT * FROM ranked WHERE representative_rank = 1
    `);
    await withImmediateTransaction(async () => {
      await run('DELETE FROM alert_group_summary');
      for (const row of groups) {
        await run(
          `
            INSERT INTO alert_group_summary (
              group_id, group_key, representative_alert_id, first_seen, last_seen,
              raw_alert_count, total_seen_count, timestamp, rule_name, event_dataset,
              severity, severity_label, source_ip, source_port, destination_ip,
              destination_port, network_protocol, transport_protocol, traffic_direction,
              triage_score, triage_level, routing, filter_status, filter_reason,
              suppression_key, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `,
          [
            alertGroupId(row.group_key), row.group_key, row.alert_id,
            row.group_first_seen, row.group_last_seen,
            Number(row.raw_alert_count || 0), Number(row.total_seen_count || 0),
            row.timestamp, row.rule_name, row.event_dataset, row.severity,
            row.severity_label, row.source_ip, row.source_port, row.destination_ip,
            row.destination_port, row.network_protocol, row.transport_protocol,
            row.traffic_direction, row.triage_score,
            normalizeTriageLevel(row.triage_level, row.severity_label), row.routing,
            row.filter_status, row.filter_reason, row.suppression_key, nowUtc(),
          ],
        );
      }
    });
    return {ok: true, status: 'group_summary_rebuilt', groups: groups.length};
  }

  async function rebuildAlertGroupSummaries() {
    return withSqliteWriteGate(rebuildAlertGroupSummariesUnlocked);
  }

  return {
    refreshGroupAliases,
    alertGroupKeyFromRow,
    currentAlertGroupKey,
    refreshAlertGroupSummary,
    rebuildAlertGroupSummariesUnlocked,
    rebuildAlertGroupSummaries,
  };
}

module.exports = {createAlertGroupService};
