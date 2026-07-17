// Write one deterministic Markdown report for a durably committed alert.
// The dashboard reads SQLite; this file remains the local LLM/Obsidian corpus.
const fs = require('fs');
const path = require('path');
const reportDir = '/soc-alerts';

function firstValue(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return null;
}

function localTimestamp() {
  const date = new Date();
  const pad = (value, length = 2) => String(value).padStart(length, '0');
  const offsetMinutes = -date.getTimezoneOffset();
  const sign = offsetMinutes >= 0 ? '+' : '-';
  const absolute = Math.abs(offsetMinutes);
  const offset = `${sign}${pad(Math.floor(absolute / 60))}:${pad(absolute % 60)}`;
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}  ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}${offset}`;
}

function safePart(value, limit = 90) {
  const cleaned = String(value || 'unknown')
    .replace(/[^A-Za-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return (cleaned || 'unknown').slice(0, limit);
}

function stableReportPart(item) {
  const value = String(item.report_job_id || item.alert_id || 'alert');
  // Security Onion IDs share long prefixes; retain the unique tail when a
  // bounded filename is needed.
  return safePart(value.length > 72 ? value.slice(-72) : value, 72);
}

function md(value) {
  if (Array.isArray(value)) return value.join(', ');
  if (value && typeof value === 'object') return JSON.stringify(value);
  return value === undefined || value === null || value === '' ? 'n/a' : String(value);
}

function cell(value) {
  return md(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function table(rows) {
  const out = ['| Field | Value |', '| --- | --- |'];
  for (const [key, value] of rows) out.push(`| ${cell(key)} | ${cell(value)} |`);
  return out.join('\n');
}

function renderReport(item) {
  const originalAlert = item.original_alert || {};
  const alertId = firstValue(item.alert_id, originalAlert.alert_id);
  const ruleName = firstValue(item.rule_name, originalAlert.rule_name, 'Security Onion Alert');
  const level = String(firstValue(item.triage_level, item.severity_label, originalAlert.severity_label, 'unknown')).toUpperCase();
  const score = item.triage_score;
  const routing = firstValue(item.routing, 'unknown');
  const sourceIp = firstValue(item.source_ip, originalAlert.source?.ip);
  const sourcePort = firstValue(originalAlert.source?.port);
  const destIp = firstValue(item.destination_ip, originalAlert.destination?.ip);
  const destPort = firstValue(originalAlert.destination?.port);
  const direction = item.traffic_direction;
  const reasons = Array.isArray(item.triage_reasons) && item.triage_reasons.length
    ? item.triage_reasons
    : ['No scoring reasons returned by alert-store.'];
  // The commit timestamp is stable across retries, so rewriting the same job
  // produces byte-for-byte equivalent report metadata.
  const generatedAt = firstValue(item.committed_at, localTimestamp());

  const lines = [];
  lines.push('---');
  lines.push('type: soc-alert-report');
  lines.push(`generated_at: ${generatedAt}`);
  lines.push(`alert_id: ${JSON.stringify(alertId || '')}`);
  lines.push(`triage_level: ${JSON.stringify(level.toLowerCase())}`);
  lines.push(`triage_score: ${score ?? ''}`);
  lines.push(`status: ${JSON.stringify(item.status || '')}`);
  lines.push(`filter_status: ${JSON.stringify(item.filter_status || '')}`);
  lines.push(`source_ip: ${JSON.stringify(sourceIp || '')}`);
  lines.push(`destination_ip: ${JSON.stringify(destIp || '')}`);
  lines.push('tags:');
  lines.push('  - security-onion');
  lines.push('  - soc-alert');
  lines.push('  - n8n-generated');
  lines.push('---');
  lines.push('');
  lines.push(`# [${level}] ${ruleName}`);
  lines.push('');
  lines.push(`- **Generated:** ${generatedAt}`);
  lines.push(`- **Alert ID:** ${md(alertId)}`);
  lines.push(`- **Workflow status:** ${md(item.status)}`);
  lines.push(`- **Filter status:** ${md(item.filter_status)}`);
  lines.push(`- **Route:** ${md(routing)}`);
  lines.push(`- **Score:** ${md(score)}`);
  lines.push(`- **Direction:** ${md(direction)}`);
  lines.push(`- **Traffic:** ${md(sourceIp)}${sourcePort ? ':' + sourcePort : ''} -> ${md(destIp)}${destPort ? ':' + destPort : ''}`);
  lines.push('');
  lines.push('## Triage Reasons');
  lines.push('');
  for (const reason of reasons) lines.push(`- [ ] ${md(reason)}`);
  lines.push('');
  lines.push('## Alert Summary');
  lines.push('');
  lines.push(table([
    ['Rule name', ruleName],
    ['Event dataset', item.event_dataset],
    ['Severity', item.severity],
    ['Severity label', item.severity_label],
    ['Rule category', originalAlert.rule_category],
    ['Timestamp', originalAlert.timestamp],
    ['First seen', item.first_seen],
    ['Last seen', item.last_seen],
    ['Seen count', item.seen_count],
    ['Filter status', item.filter_status],
    ['Filter reason', item.filter_reason],
    ['Suppression rule', item.suppression_rule],
    ['Telegram notification', item.notification_status],
  ]));
  lines.push('');
  lines.push('## Analyst Notes');
  lines.push('');
  lines.push('- [ ] Confirm whether source and destination are expected for this VLAN or host role.');
  lines.push('- [ ] Pivot in Security Onion for related source, destination, DNS, HTTP, TLS, and connection events.');
  lines.push('- [ ] Decide whether this should become a tuning rule, an escalation, or a documented benign pattern.');
  lines.push('');
  lines.push('## Raw Alert');
  lines.push('');
  lines.push('```json');
  lines.push(JSON.stringify(originalAlert, null, 2));
  lines.push('```');
  lines.push('');
  return lines.join('\n');
}

if (!$json.should_write_report) {
  return [{json: {
    ...$json,
    stage: 'write-soc-markdown-report',
    report_written: false,
    report_path: null,
    report_filename: null,
  }}];
}

fs.mkdirSync(reportDir, {recursive: true});
const filenameTimestamp = String(firstValue($json.committed_at, localTimestamp()))
  .replace(/[-:]/g, '')
  .replace(/\s+/, '-')
  .replace('Z', 'Z');
const filename = `${filenameTimestamp}-${safePart($json.triage_level)}-${stableReportPart($json)}-${safePart($json.rule_name)}.md`;
const fullPath = path.join(reportDir, filename);
const temporaryPath = `${fullPath}.tmp`;
fs.writeFileSync(temporaryPath, renderReport($json), 'utf8');
fs.renameSync(temporaryPath, fullPath);

return [{json: {
  ...$json,
  stage: 'write-soc-markdown-report',
  report_written: true,
  report_path: fullPath,
  report_filename: filename,
}}];
