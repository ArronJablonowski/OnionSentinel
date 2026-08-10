'use strict';

function createSuppressionPersistence({
  findSuppressRule, stableGroupId, nestedField, pendingHumanReview,
  suppressionKey, ruleName, get, run, secondsSince,
}) {
  const functions = {findSuppressRule, stableGroupId, nestedField, pendingHumanReview,
    suppressionKey, ruleName, get, run, secondsSince};
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function candidateIdentity(alert) {
    return stableGroupId({rule_id: alert.rule_id, rule_name: alert.rule_name,
      event_dataset: alert.event_dataset, source_ip: nestedField(alert, 'source.ip'),
      destination_ip: nestedField(alert, 'destination.ip'),
      destination_port: nestedField(alert, 'destination.port'),
      network_protocol: nestedField(alert, 'network.protocol'),
      transport_protocol: nestedField(alert, 'network.transport')
        || nestedField(alert, 'network.iana_number')});
  }

  async function resetWindow(rule, key, now, ttlSeconds, escalationThreshold) {
    await run(`
      INSERT INTO suppression_log (
        suppression_key, rule_name, reason, window_start, last_seen,
        seen_count, suppressed_count, escalated_count, ttl_seconds,
        escalation_threshold)
      VALUES (?, ?, ?, ?, ?, 1, 0, 0, ?, ?)
      ON CONFLICT(suppression_key) DO UPDATE SET
        rule_name = excluded.rule_name, reason = excluded.reason,
        window_start = excluded.window_start, last_seen = excluded.last_seen,
        seen_count = 1, suppressed_count = 0, escalated_count = 0,
        ttl_seconds = excluded.ttl_seconds,
        escalation_threshold = excluded.escalation_threshold`,
    [key, ruleName(rule), rule.reason || null, now, now, ttlSeconds, escalationThreshold]);
    return {status: 'accepted', key, rule: ruleName(rule), reason: rule.reason || null,
      ttl_seconds: ttlSeconds, seen_count: 1};
  }

  async function apply(alert, now) {
    const rule = findSuppressRule(alert);
    if (!rule) return {status: 'accepted'};
    if (await pendingHumanReview(candidateIdentity(alert))) {
      return {status: 'accepted',
        reason: 'automatic suppression blocked pending explicit analyst adjudication',
        review_status: 'pending_human_review'};
    }
    const key = suppressionKey(rule, alert);
    const ttlSeconds = Number(rule.ttl_seconds || rule.suppress_seconds || 1800);
    const escalationThreshold = Number(rule.escalation_threshold || 0);
    const existing = await get(
      'SELECT * FROM suppression_log WHERE suppression_key = ?', [key],
    );
    if (!existing || secondsSince(existing.window_start, now) >= ttlSeconds) {
      return resetWindow(rule, key, now, ttlSeconds, escalationThreshold);
    }
    const nextSeenCount = Number(existing.seen_count || 0) + 1;
    const escalated = escalationThreshold > 0
      && nextSeenCount % escalationThreshold === 0;
    await run(`
      UPDATE suppression_log
      SET last_seen = ?, seen_count = seen_count + 1,
          suppressed_count = suppressed_count + ?,
          escalated_count = escalated_count + ?
      WHERE suppression_key = ?`,
    [now, escalated ? 0 : 1, escalated ? 1 : 0, key]);
    return {status: escalated ? 'escalated' : 'suppressed', key,
      rule: ruleName(rule), reason: rule.reason || null, ttl_seconds: ttlSeconds,
      escalation_threshold: escalationThreshold || null, seen_count: nextSeenCount};
  }

  return {apply};
}

module.exports = {createSuppressionPersistence};
