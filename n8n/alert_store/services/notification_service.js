'use strict';

function createNotificationService({
  nestedField,
  normalizeTimestampValue,
  formatProjectTimestamp,
  nowUtc,
  get,
  run,
  all,
  withSqliteWriteGate,
  withImmediateTransaction,
  botToken,
  chatId,
  alertLevels,
  cooldownSeconds,
  outboxBaseRetrySeconds,
  outboxMaxRetrySeconds,
  outboxMaxAttempts,
  outboxAutostart,
  controlledEvaluationMode,
  httpsRequest = require('https').request,
  nowMs = Date.now,
  logError = (message) => console.error(message),
}) {
  for (const [name, value] of Object.entries({
    nestedField,
    normalizeTimestampValue,
    formatProjectTimestamp,
    nowUtc,
    get,
    run,
    all,
    withSqliteWriteGate,
    withImmediateTransaction,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  let outboxDrainActive = false;

  function isTelegramConfigured() {
    return Boolean(botToken && chatId);
  }

  function notificationKey(alert) {
    const level = String(nestedField(alert, 'triage.level') || 'unknown').toLowerCase();
    const ruleName = alert.rule_name || 'unknown-rule';
    const sourceIp = nestedField(alert, 'source.ip') || 'unknown-source';
    const destinationIp = nestedField(alert, 'destination.ip') || 'unknown-destination';
    return `${level}|${ruleName}|${sourceIp}|${destinationIp}`;
  }

  function secondsSince(isoTimestamp, nowIso) {
    return Math.floor((Date.parse(nowIso) - Date.parse(isoTimestamp)) / 1000);
  }

  function escapeTelegram(text) {
    return String(text ?? '').replace(/[&<>]/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
    }[char]));
  }

  function shortAlertId(alertId) {
    const value = String(alertId || 'unknown');
    const lastPart = value.split(':').pop() || value;
    return lastPart.length > 18 ? `${lastPart.slice(0, 18)}...` : lastPart;
  }

  function whyThisAlerted(triage) {
    const level = String(triage.level || 'unknown').toLowerCase();
    const direction = triage.traffic_direction || 'unknown direction';
    const reasons = Array.isArray(triage.reasons) ? triage.reasons : [];
    const notableReason = reasons.find(
      (reason) => !String(reason).startsWith('base severity score'),
    );
    if (level === 'critical') {
      return notableReason
        ? `Critical score driven by ${notableReason}.`
        : 'Critical deterministic triage score.';
    }
    if (level === 'high') {
      return notableReason
        ? `High priority because ${notableReason}.`
        : 'High deterministic triage score.';
    }
    return `Alert routed as ${level} based on ${direction} traffic and rule context.`;
  }

  function formatTelegramAlert(alert, storedAlert) {
    const triage = alert.triage || {};
    const level = String(
      triage.level || storedAlert.triage_level || 'unknown',
    ).toUpperCase();
    const score = triage.score ?? storedAlert.triage_score ?? 'unknown';
    const direction = (
      triage.traffic_direction || storedAlert.traffic_direction || 'unknown'
    );
    const sourceIp = nestedField(alert, 'source.ip') || storedAlert.source_ip || 'unknown';
    const destinationIp = (
      nestedField(alert, 'destination.ip') || storedAlert.destination_ip || 'unknown'
    );
    const timestamp = (
      normalizeTimestampValue(alert.timestamp || storedAlert.timestamp) || 'unknown time'
    );
    const alertId = shortAlertId(alert.alert_id || storedAlert.alert_id);
    const reasons = Array.isArray(triage.reasons) ? triage.reasons.slice(0, 4) : [];
    const reasonText = reasons.length
      ? reasons.map((reason) => `- ${escapeTelegram(reason)}`).join('\n')
      : '- no deterministic reasons provided';

    return [
      `<b>[${escapeTelegram(level)}] Security Onion Alert</b>`,
      escapeTelegram(alert.rule_name || storedAlert.rule_name || 'Unknown rule'),
      '',
      `Time: ${escapeTelegram(timestamp)}`,
      `Alert ID: ${escapeTelegram(alertId)}`,
      `Score: ${escapeTelegram(score)}`,
      `Direction: ${escapeTelegram(direction)}`,
      `Route: ${escapeTelegram(triage.routing || storedAlert.routing || 'unknown')}`,
      '',
      `${escapeTelegram(sourceIp)} -> ${escapeTelegram(destinationIp)}`,
      '',
      '<b>Why this alerted</b>',
      escapeTelegram(whyThisAlerted(triage)),
      '',
      '<b>Reasons</b>',
      reasonText,
    ].join('\n');
  }

  function postTelegramMessage(text) {
    if (controlledEvaluationMode) {
      return Promise.reject(new Error('Telegram is disabled in controlled evaluation mode'));
    }
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      });
      const request = httpsRequest({
        hostname: 'api.telegram.org',
        port: 443,
        path: `/bot${botToken}/sendMessage`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
        timeout: 10000,
      }, (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => body += chunk);
        response.on('end', () => {
          if (response.statusCode >= 200 && response.statusCode < 300) {
            resolve({ok: true, statusCode: response.statusCode});
          } else {
            reject(new Error(
              `Telegram returned HTTP ${response.statusCode}: ${body.slice(0, 300)}`,
            ));
          }
        });
      });
      request.on('timeout', () => request.destroy(new Error('Telegram request timed out')));
      request.on('error', reject);
      request.write(payload);
      request.end();
    });
  }

  async function queueTelegramNotification(
    alert,
    storedAlert,
    inserted,
    now,
    suppression = {status: 'accepted'},
  ) {
    if (!inserted) return {channel: 'telegram', status: 'skipped_duplicate'};
    if (suppression.status === 'suppressed') {
      return {
        channel: 'telegram',
        status: 'skipped_suppression',
        suppression_key: suppression.key || null,
        suppression_rule: suppression.rule || null,
        suppression_ttl_seconds: suppression.ttl_seconds || null,
        suppression_seen_count: suppression.seen_count || null,
      };
    }
    if (!isTelegramConfigured()) return {channel: 'telegram', status: 'disabled'};

    const triageLevel = String(nestedField(alert, 'triage.level') || '').toLowerCase();
    if (!alertLevels.has(triageLevel)) {
      return {channel: 'telegram', status: 'skipped_level', triage_level: triageLevel};
    }

    const key = notificationKey(alert);
    const existing = await get(
      'SELECT last_sent, sent_count FROM notification_log WHERE notification_key = ?',
      [key],
    );
    if (existing && secondsSince(existing.last_sent, now) < cooldownSeconds) {
      return {
        channel: 'telegram',
        status: 'skipped_cooldown',
        cooldown_seconds: cooldownSeconds,
      };
    }
    const pending = await get(
      `SELECT id FROM notification_outbox
       WHERE notification_key = ? AND status IN ('pending', 'delivering')
       ORDER BY id DESC LIMIT 1`,
      [key],
    );
    if (pending) {
      return {channel: 'telegram', status: 'skipped_pending', triage_level: triageLevel};
    }
    await run(
      `
        INSERT INTO notification_outbox (
          notification_key, channel, alert_id, triage_level, rule_name,
          source_ip, destination_ip, payload_json, status, attempt_count,
          next_attempt_at, created_at, updated_at
        )
        VALUES (?, 'telegram', ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)
      `,
      [
        key,
        alert.alert_id,
        triageLevel,
        alert.rule_name || null,
        nestedField(alert, 'source.ip'),
        nestedField(alert, 'destination.ip'),
        JSON.stringify({text: formatTelegramAlert(alert, storedAlert)}),
        now,
        now,
        now,
      ],
    );
    return {channel: 'telegram', status: 'queued', triage_level: triageLevel};
  }

  function outboxRetryTimestamp(attemptCount) {
    const delaySeconds = Math.min(
      outboxMaxRetrySeconds,
      outboxBaseRetrySeconds * (2 ** Math.max(0, attemptCount - 1)),
    );
    return formatProjectTimestamp(new Date(nowMs() + delaySeconds * 1000));
  }

  async function claimTelegramOutboxItem() {
    return withSqliteWriteGate(() => withImmediateTransaction(async () => {
      const row = await get(
        `SELECT * FROM notification_outbox
         WHERE status = 'pending' AND next_attempt_at <= ?
         ORDER BY next_attempt_at ASC, id ASC LIMIT 1`,
        [nowUtc()],
      );
      if (!row) return null;
      await run(
        "UPDATE notification_outbox SET status = 'delivering', attempt_count = attempt_count + 1, updated_at = ? WHERE id = ?",
        [nowUtc(), row.id],
      );
      return {...row, attempt_count: Number(row.attempt_count || 0) + 1};
    }));
  }

  async function completeTelegramOutboxItem(item) {
    const sentAt = nowUtc();
    await withSqliteWriteGate(() => withImmediateTransaction(async () => {
      await run(
        "UPDATE notification_outbox SET status = 'sent', sent_at = ?, updated_at = ?, last_error = NULL WHERE id = ?",
        [sentAt, sentAt, item.id],
      );
      await run(
        `INSERT INTO notification_log (
           notification_key, last_sent, sent_count, channel, alert_id,
           triage_level, rule_name, source_ip, destination_ip
         ) VALUES (?, ?, 1, 'telegram', ?, ?, ?, ?, ?)
         ON CONFLICT(notification_key) DO UPDATE SET
           last_sent = excluded.last_sent,
           sent_count = notification_log.sent_count + 1,
           alert_id = excluded.alert_id,
           triage_level = excluded.triage_level,
           rule_name = excluded.rule_name,
           source_ip = excluded.source_ip,
           destination_ip = excluded.destination_ip`,
        [
          item.notification_key,
          sentAt,
          item.alert_id,
          item.triage_level,
          item.rule_name,
          item.source_ip,
          item.destination_ip,
        ],
      );
    }));
  }

  async function failTelegramOutboxItem(item, error) {
    const terminal = Number(item.attempt_count || 0) >= outboxMaxAttempts;
    await withSqliteWriteGate(() => run(
      `UPDATE notification_outbox
       SET status = ?, next_attempt_at = ?, last_error = ?, updated_at = ?
       WHERE id = ?`,
      [
        terminal ? 'failed' : 'pending',
        terminal ? nowUtc() : outboxRetryTimestamp(item.attempt_count),
        String(error.message || error).slice(0, 500),
        nowUtc(),
        item.id,
      ],
    ));
  }

  async function drainTelegramOutbox() {
    if (!outboxAutostart || !isTelegramConfigured() || outboxDrainActive) return;
    outboxDrainActive = true;
    try {
      for (let processed = 0; processed < 10; processed += 1) {
        const item = await claimTelegramOutboxItem();
        if (!item) break;
        try {
          const payload = JSON.parse(item.payload_json || '{}');
          await postTelegramMessage(String(payload.text || ''));
          await completeTelegramOutboxItem(item);
        } catch (error) {
          await failTelegramOutboxItem(item, error);
          break;
        }
      }
    } catch (error) {
      logError(`Telegram outbox drain failed: ${error.message}`);
    } finally {
      outboxDrainActive = false;
    }
  }

  async function telegramOutboxSnapshot() {
    const rows = await all(
      'SELECT status, COUNT(*) AS count FROM notification_outbox GROUP BY status',
    );
    return Object.fromEntries(rows.map((row) => [row.status, Number(row.count || 0)]));
  }

  return {
    isTelegramConfigured,
    notificationKey,
    secondsSince,
    escapeTelegram,
    shortAlertId,
    whyThisAlerted,
    formatTelegramAlert,
    postTelegramMessage,
    queueTelegramNotification,
    outboxRetryTimestamp,
    claimTelegramOutboxItem,
    completeTelegramOutboxItem,
    failTelegramOutboxItem,
    drainTelegramOutbox,
    telegramOutboxSnapshot,
  };
}

module.exports = {createNotificationService};
