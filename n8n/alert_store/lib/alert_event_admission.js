'use strict';
const fs = require('node:fs');
const path = require('node:path');
const POLICY_PATH = path.resolve(__dirname, '../../config/alert_ingestion_policy.json');

function eventAdmissionReason(alert, policy, now = new Date()) {
  if (!policy.enabled) return null;
  const value = alert.security_onion?.raw_event?.['@timestamp']
    || alert['@timestamp'] || alert.timestamp;
  const text = String(value || '').trim().replace(/\s+/g, ' ');
  if (!/(Z|[+-]\d{2}:\d{2})$/.test(text)) return 'missing_or_invalid_original_event_time';
  const event = new Date(text);
  if (!Number.isFinite(event.getTime())) return 'missing_or_invalid_original_event_time';
  const dateInZone = (date) => {
    const parts = new Intl.DateTimeFormat('en-US', {timeZone: policy.time_zone,
      year: 'numeric', month: '2-digit', day: '2-digit'}).formatToParts(date);
    const part = (name) => parts.find((item) => item.type === name).value;
    return `${part('year')}-${part('month')}-${part('day')}`;
  };
  if (!/^\d{4}-\d{2}-\d{2}$/.test(policy.min_event_date)) throw new Error('invalid cutoff');
  const today = dateInZone(now);
  const cutoff = today > policy.min_event_date ? today : policy.min_event_date;
  return dateInZone(event) < cutoff ? 'event_before_today' : null;
}

function configuredAdmissionReason(alert) {
  let contents;
  try { contents = fs.readFileSync(POLICY_PATH, 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  return eventAdmissionReason(alert, JSON.parse(contents));
}
module.exports = {eventAdmissionReason, configuredAdmissionReason};
