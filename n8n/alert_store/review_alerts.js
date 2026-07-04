#!/usr/bin/env node
// Generate a Markdown or JSON rollup from alert-store SQLite.
//
// Run inside the alert-store container:
//   node /app/review_alerts.js --hours 24 --limit 20
//
// This script is read-only and safe to run during an incident.
const path = require('path');
const sqlite3 = require('/usr/local/lib/node_modules/n8n/node_modules/.pnpm/sqlite3@5.1.7/node_modules/sqlite3');

const dbPath = process.env.ALERT_STORE_DB || '/data/alerts.sqlite3';

function isoUtc(value = new Date()) {
  return value.toISOString().replace(/\.\d{3}Z$/, 'Z').replace('T', '  ');
}

function parseArgs(argv) {
  // Keep options intentionally small so report commands are easy to paste into
  // SSH sessions, runbooks, and Obsidian notes.
  const options = {
    hours: 24,
    limit: 15,
    format: 'markdown',
    includeTests: false,
  };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--hours') options.hours = Number(argv[++i]);
    else if (arg === '--limit') options.limit = Number(argv[++i]);
    else if (arg === '--format') options.format = argv[++i];
    else if (arg === '--include-tests') options.includeTests = true;
    else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  if (!Number.isFinite(options.hours) || options.hours <= 0) {
    throw new Error('--hours must be a positive number');
  }
  if (!Number.isInteger(options.limit) || options.limit <= 0) {
    throw new Error('--limit must be a positive integer');
  }
  if (!['markdown', 'json'].includes(options.format)) {
    throw new Error('--format must be markdown or json');
  }
  return options;
}

function printHelp() {
  console.log(`Usage: node /app/review_alerts.js [options]

Options:
  --hours N          Look back N hours, default 24
  --limit N          Limit detail tables, default 15
  --format FORMAT    markdown or json, default markdown
  --include-tests    Include phase/test alerts
`);
}

function openDb() {
  // Read-only mode prevents report generation from changing alert state.
  return new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY);
}

function all(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => {
      if (error) reject(error);
      else resolve(rows);
    });
  });
}

function get(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => {
      if (error) reject(error);
      else resolve(row);
    });
  });
}

function closeDb(db) {
  return new Promise((resolve, reject) => {
    db.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function whereClause(options) {
  // Test alerts are excluded by default so validation traffic does not pollute
  // normal operational reports.
  const since = isoUtc(new Date(Date.now() - options.hours * 60 * 60 * 1000));
  const clauses = ["replace(replace(last_seen, 'T', ' '), 'Z', '') >= replace(replace(?, 'T', ' '), 'Z', '')"];
  const params = [since];
  if (!options.includeTests) {
    clauses.push("alert_id NOT LIKE 'phase%'");
    clauses.push("alert_id NOT LIKE 'config-%'");
    clauses.push("alert_id NOT LIKE 'internal-test-%'");
    clauses.push("alert_id NOT LIKE 'sqlite-%'");
    clauses.push("alert_id NOT LIKE 'policy-%'");
  }
  return {where: `WHERE ${clauses.join(' AND ')}`, params, since};
}

function mdEscape(value) {
  return String(value ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function table(headers, rows) {
  // Simple GitHub/Obsidian Markdown table renderer.
  if (!rows.length) return '_No rows._\n';
  const header = `| ${headers.join(' | ')} |`;
  const divider = `| ${headers.map(() => '---').join(' | ')} |`;
  const body = rows.map((row) => `| ${row.map(mdEscape).join(' | ')} |`);
  return [header, divider, ...body].join('\n') + '\n';
}

function shortAlertId(alertId) {
  const value = String(alertId || '');
  const lastPart = value.split(':').pop() || value;
  return lastPart.length > 18 ? `${lastPart.slice(0, 18)}...` : lastPart;
}

async function buildReport(options) {
  // Each section has its own SQL query. If a report section looks wrong, start
  // troubleshooting with the matching query below.
  const db = openDb();
  const {where, params, since} = whereClause(options);
  const notificationClauses = ['last_sent >= ?'];
  const notificationParams = [since];
  if (!options.includeTests) {
    notificationClauses.push("notification_log.alert_id NOT LIKE 'phase%'");
    notificationClauses.push("notification_log.alert_id NOT LIKE 'config-%'");
    notificationClauses.push("notification_log.alert_id NOT LIKE 'internal-test-%'");
    notificationClauses.push("notification_log.alert_id NOT LIKE 'sqlite-%'");
    notificationClauses.push("notification_log.alert_id NOT LIKE 'policy-%'");
  }
  const notificationWhere = `WHERE ${notificationClauses.join(' AND ')}`;
  try {
    const summary = await get(
      db,
      `
        SELECT
          COUNT(*) AS total_alerts,
          COALESCE(SUM(seen_count), 0) AS total_seen,
          MIN(first_seen) AS first_seen,
          MAX(last_seen) AS last_seen,
          SUM(CASE WHEN triage_level IN ('critical', 'high') THEN 1 ELSE 0 END) AS urgent_alerts
        FROM alerts
        ${where}
      `,
      params,
    );

    const byLevel = await all(
      db,
      `
        SELECT COALESCE(triage_level, 'unscored') AS triage_level,
               COALESCE(routing, 'none') AS routing,
               COUNT(*) AS alert_count,
               COALESCE(SUM(seen_count), 0) AS total_seen,
               MAX(last_seen) AS last_seen
        FROM alerts
        ${where}
        GROUP BY COALESCE(triage_level, 'unscored'), COALESCE(routing, 'none')
        ORDER BY
          CASE COALESCE(triage_level, 'unscored')
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
          END,
          alert_count DESC
      `,
      params,
    );

    const byRule = await all(
      db,
      `
        SELECT rule_name,
               COALESCE(triage_level, 'unscored') AS triage_level,
               COUNT(*) AS alert_count,
               COALESCE(SUM(seen_count), 0) AS total_seen,
               MAX(triage_score) AS max_score,
               MAX(last_seen) AS last_seen
        FROM alerts
        ${where}
        GROUP BY rule_name, COALESCE(triage_level, 'unscored')
        ORDER BY max_score DESC, alert_count DESC, last_seen DESC
        LIMIT ?
      `,
      [...params, options.limit],
    );

    const byPair = await all(
      db,
      `
        SELECT COALESCE(source_ip, 'unknown') AS source_ip,
               COALESCE(destination_ip, 'unknown') AS destination_ip,
               COALESCE(traffic_direction, 'unknown') AS traffic_direction,
               COUNT(*) AS alert_count,
               COALESCE(SUM(seen_count), 0) AS total_seen,
               MAX(triage_score) AS max_score,
               MAX(last_seen) AS last_seen
        FROM alerts
        ${where}
        GROUP BY COALESCE(source_ip, 'unknown'), COALESCE(destination_ip, 'unknown'), COALESCE(traffic_direction, 'unknown')
        ORDER BY max_score DESC, alert_count DESC, last_seen DESC
        LIMIT ?
      `,
      [...params, options.limit],
    );

    const urgent = await all(
      db,
      `
        SELECT alert_id, timestamp, rule_name, source_ip, destination_ip,
               traffic_direction, triage_score, triage_level, routing,
               seen_count, last_seen
        FROM alerts
        ${where}
          AND triage_level IN ('critical', 'high')
        ORDER BY triage_score DESC, last_seen DESC
        LIMIT ?
      `,
      [...params, options.limit],
    );

    const notifications = await all(
      db,
      `
        SELECT notification_log.alert_id,
               notification_log.channel,
               notification_log.triage_level AS sent_level,
               COALESCE(alerts.triage_level, notification_log.triage_level) AS current_level,
               alerts.triage_score AS current_score,
               notification_log.rule_name,
               notification_log.source_ip,
               notification_log.destination_ip,
               notification_log.sent_count,
               notification_log.last_sent
        FROM notification_log
        LEFT JOIN alerts ON alerts.alert_id = notification_log.alert_id
        ${notificationWhere}
        ORDER BY notification_log.last_sent DESC
        LIMIT ?
      `,
      [...notificationParams, options.limit],
    );

    return {
      generated_at: isoUtc(),
      database: path.basename(dbPath),
      lookback_hours: options.hours,
      since,
      include_tests: options.includeTests,
      summary,
      by_level: byLevel,
      top_rules: byRule,
      top_pairs: byPair,
      urgent_alerts: urgent,
      notifications,
    };
  } finally {
    await closeDb(db);
  }
}

function renderMarkdown(report) {
  // Keep headings stable so Obsidian links and future automation can target
  // specific sections.
  const lines = [];
  lines.push('# Security Onion Alert Review');
  lines.push('');
  lines.push(`Generated: ${report.generated_at}`);
  lines.push(`Lookback: ${report.lookback_hours} hours`);
  lines.push(`Since: ${report.since}`);
  lines.push(`Include test alerts: ${report.include_tests ? 'yes' : 'no'}`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push(table(
    ['Alerts', 'Total Seen', 'Urgent', 'First Seen', 'Last Seen'],
    [[
      report.summary.total_alerts || 0,
      report.summary.total_seen || 0,
      report.summary.urgent_alerts || 0,
      report.summary.first_seen || 'none',
      report.summary.last_seen || 'none',
    ]],
  ));
  lines.push('## By Triage Level');
  lines.push('');
  lines.push(table(
    ['Level', 'Routing', 'Alerts', 'Total Seen', 'Last Seen'],
    report.by_level.map((row) => [row.triage_level, row.routing, row.alert_count, row.total_seen, row.last_seen]),
  ));
  lines.push('## Top Rules');
  lines.push('');
  lines.push(table(
    ['Rule', 'Level', 'Alerts', 'Total Seen', 'Max Score', 'Last Seen'],
    report.top_rules.map((row) => [row.rule_name, row.triage_level, row.alert_count, row.total_seen, row.max_score, row.last_seen]),
  ));
  lines.push('## Top Source/Destination Pairs');
  lines.push('');
  lines.push(table(
    ['Source', 'Destination', 'Direction', 'Alerts', 'Total Seen', 'Max Score', 'Last Seen'],
    report.top_pairs.map((row) => [row.source_ip, row.destination_ip, row.traffic_direction, row.alert_count, row.total_seen, row.max_score, row.last_seen]),
  ));
  lines.push('## Urgent Alerts');
  lines.push('');
  lines.push(table(
    ['Alert ID', 'Time', 'Rule', 'Source', 'Destination', 'Direction', 'Score', 'Level', 'Seen', 'Last Seen'],
    report.urgent_alerts.map((row) => [
      shortAlertId(row.alert_id),
      row.timestamp,
      row.rule_name,
      row.source_ip,
      row.destination_ip,
      row.traffic_direction,
      row.triage_score,
      row.triage_level,
      row.seen_count,
      row.last_seen,
    ]),
  ));
  lines.push('## Telegram Notifications');
  lines.push('');
  lines.push(table(
    ['Alert ID', 'Channel', 'Sent Level', 'Current Level', 'Current Score', 'Rule', 'Source', 'Destination', 'Sent Count', 'Last Sent'],
    report.notifications.map((row) => [
      shortAlertId(row.alert_id),
      row.channel,
      row.sent_level,
      row.current_level,
      row.current_score,
      row.rule_name,
      row.source_ip,
      row.destination_ip,
      row.sent_count,
      row.last_sent,
    ]),
  ));
  return lines.join('\n');
}

async function main() {
  const options = parseArgs(process.argv);
  const report = await buildReport(options);
  if (options.format === 'json') {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(renderMarkdown(report));
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
