'use strict';

function createPostCommitPayload({nowUtc, nestedField}) {
  if (typeof nowUtc !== 'function') throw new TypeError('nowUtc must be a function');
  if (typeof nestedField !== 'function') {
    throw new TypeError('nestedField must be a function');
  }

  function build(rawAlert, stored) {
    const row = stored.alert || {};
    const triage = stored.triage || {};
    const filter = stored.filter || {status: stored.status || 'unknown'};
    const notification = stored.notification || {status: 'unknown'};
    const routing = stored.status === 'already_seen'
      ? 'duplicate-suppressed'
      : (triage.routing || row.routing || 'unknown');
    const committedAt = nowUtc();
    return {
      ok: true,
      stage: 'alert-store-post-commit',
      status: stored.status,
      stored: Boolean(stored.stored),
      original_alert: rawAlert,
      alert_id: row.alert_id || rawAlert.alert_id,
      rule_name: row.rule_name || rawAlert.rule_name || null,
      event_dataset: row.event_dataset || rawAlert.event_dataset || null,
      severity: row.severity ?? rawAlert.severity ?? null,
      severity_label: row.severity_label || rawAlert.severity_label || null,
      source_ip: row.source_ip || nestedField(rawAlert, 'source.ip'),
      destination_ip: row.destination_ip || nestedField(rawAlert, 'destination.ip'),
      traffic_direction: triage.traffic_direction || row.traffic_direction || null,
      triage_score: triage.score ?? row.triage_score ?? null,
      triage_level: triage.level || row.triage_level || null,
      routing,
      triage_reasons: triage.reasons || [],
      filter_status: filter.status || row.filter_status || null,
      filter_reason: filter.reason || row.filter_reason || null,
      suppression_key: filter.key || row.suppression_key || null,
      suppression_rule: filter.rule || null,
      notification_channel: notification.channel || 'telegram',
      notification_status: notification.status,
      first_seen: row.first_seen || null,
      last_seen: row.last_seen || null,
      seen_count: row.seen_count || null,
      authorized_activity_campaign: stored.campaign || null,
      should_write_report: stored.status === 'accepted' && Boolean(stored.stored),
      report_decision: 'write_markdown_report',
      report_job_id: `alert-report:${row.alert_id || rawAlert.alert_id}`,
      committed_at: committedAt,
    };
  }

  return {build};
}

module.exports = {createPostCommitPayload};
