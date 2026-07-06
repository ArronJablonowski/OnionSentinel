#!/usr/bin/env node
// Render analyst investigation notes from alert-store SQLite.
//
// This is meant for Obsidian-friendly handoff notes: alerts become Markdown
// sections with checklists, query starters, triage reasons, and analyst space.
const path = require('path');
const sqlite3 = require('/usr/local/lib/node_modules/n8n/node_modules/.pnpm/sqlite3@5.1.7/node_modules/sqlite3');

const dbPath = process.env.ALERT_STORE_DB || '/data/alerts.sqlite3';

function projectNow() {
  return projectTimestampFromDate(new Date());
}

function projectTimestampFromDate(value) {
  const pad = (part, length = 2) => String(part).padStart(length, '0');
  const offsetMinutes = -value.getTimezoneOffset();
  const sign = offsetMinutes >= 0 ? '+' : '-';
  const absolute = Math.abs(offsetMinutes);
  const offset = `${sign}${pad(Math.floor(absolute / 60))}:${pad(absolute % 60)}`;
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}  ${pad(value.getHours())}:${pad(value.getMinutes())}:${pad(value.getSeconds())}${offset}`;
}

function parseArgs(argv) {
  // The script supports either a time window or one exact alert ID.
  const options = {
    hours: 24,
    limit: 10,
    levels: ['critical', 'high'],
    format: 'markdown',
    alertId: '',
    includeTests: false,
  };

  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--hours') options.hours = Number(argv[++i]);
    else if (arg === '--limit') options.limit = Number(argv[++i]);
    else if (arg === '--levels') {
      options.levels = String(argv[++i])
        .split(',')
        .map((level) => level.trim().toLowerCase())
        .filter(Boolean);
    } else if (arg === '--alert-id') options.alertId = argv[++i];
    else if (arg === '--format') options.format = argv[++i];
    else if (arg === '--include-tests') options.includeTests = true;
    else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!options.alertId && (!Number.isFinite(options.hours) || options.hours <= 0)) {
    throw new Error('--hours must be a positive number');
  }
  if (!Number.isInteger(options.limit) || options.limit <= 0) {
    throw new Error('--limit must be a positive integer');
  }
  if (!options.levels.length) {
    throw new Error('--levels must include at least one level');
  }
  if (!['markdown', 'json'].includes(options.format)) {
    throw new Error('--format must be markdown or json');
  }

  return options;
}

function printHelp() {
  console.log(`Usage: node /app/investigation_notes.js [options]

Options:
  --hours N             Look back N hours, default 24
  --limit N             Maximum alerts to render, default 10
  --levels LIST         Comma-separated triage levels, default critical,high
  --alert-id ID         Render one specific alert ID
  --format FORMAT       markdown or json, default markdown
  --include-tests       Include phase/test alerts
`);
}

function openDb() {
  // Read-only mode keeps note generation from changing alert state.
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

function closeDb(db) {
  return new Promise((resolve, reject) => {
    db.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function nestedField(value, dottedPath) {
  // Minimal dotted-path lookup for values stored inside alert_json.
  return dottedPath.split('.').reduce((current, part) => {
    if (!current || typeof current !== 'object') return null;
    return current[part] ?? null;
  }, value);
}

function mdEscape(value) {
  return String(value ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function codeValue(value) {
  // Obsidian inline-code formatting breaks on backticks, so replace them.
  const text = String(value ?? 'unknown');
  return text.includes('`') ? text.replace(/`/g, "'") : text;
}

function shortAlertId(alertId) {
  const value = String(alertId || '');
  const lastPart = value.split(':').pop() || value;
  return lastPart.length > 18 ? `${lastPart.slice(0, 18)}...` : lastPart;
}

function safeFilename(value) {
  // Generated filenames should be portable between macOS and Linux.
  return String(value || 'alert')
    .replace(/[^A-Za-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 160) || 'alert';
}

function table(headers, rows) {
  if (!rows.length) return '_No rows._\n';
  const header = `| ${headers.join(' | ')} |`;
  const divider = `| ${headers.map(() => '---').join(' | ')} |`;
  const body = rows.map((row) => `| ${row.map(mdEscape).join(' | ')} |`);
  return [header, divider, ...body].join('\n') + '\n';
}

function parseAlert(row) {
  // Some old rows may have malformed alert_json; keep note generation alive.
  try {
    return JSON.parse(row.alert_json || '{}');
  } catch {
    return {};
  }
}

function listValue(value) {
  if (Array.isArray(value)) return value.join(', ');
  if (value && typeof value === 'object') return JSON.stringify(value);
  return value ?? '';
}

function extractInterestingFields(alert) {
  // Curate fields analysts tend to need first without dumping the whole alert.
  const fields = [
    ['Event action', nestedField(alert, 'event.action')],
    ['Event category', listValue(nestedField(alert, 'event.category'))],
    ['Event type', listValue(nestedField(alert, 'event.type'))],
    ['Network protocol', nestedField(alert, 'network.protocol')],
    ['Transport', nestedField(alert, 'network.transport')],
    ['Source port', nestedField(alert, 'source.port')],
    ['Destination port', nestedField(alert, 'destination.port')],
    ['Rule category', alert.rule_category],
    ['Rule ruleset', alert.rule_ruleset],
    ['Signature ID', alert.signature_id || nestedField(alert, 'suricata.eve.alert.signature_id')],
  ];
  return fields.filter(([, value]) => value !== null && value !== undefined && value !== '');
}

function renderNote(row) {
  // Render a complete note for one alert. Keep section headings stable so they
  // can be linked from Obsidian or used by later automation.
  const alert = parseAlert(row);
  const triage = alert.triage || {};
  const reasons = Array.isArray(triage.reasons) ? triage.reasons : [];
  const metadata = alert.rule_metadata && typeof alert.rule_metadata === 'object'
    ? Object.entries(alert.rule_metadata).slice(0, 12)
    : [];
  const relatedQueries = [
    `source.ip:"${row.source_ip || ''}"`,
    `destination.ip:"${row.destination_ip || ''}"`,
    `rule.name:"${row.rule_name || ''}"`,
    `event.dataset:"${row.event_dataset || ''}"`,
  ].filter((item) => !item.includes('""'));

  const title = `${String(row.triage_level || 'unknown').toUpperCase()} - ${row.rule_name || 'Security Onion Alert'}`;
  const lines = [];
  lines.push(`# ${title}`);
  lines.push('');
  lines.push(`Generated: ${projectNow()}`);
  lines.push(`Alert ID: \`${codeValue(row.alert_id)}\``);
  lines.push('');
  lines.push('## Status');
  lines.push('');
  lines.push('- [ ] Confirm the alert in Security Onion SOC.');
  lines.push('- [ ] Check whether the source is expected to contact the destination.');
  lines.push('- [ ] Review related alerts for the same source, destination, and rule.');
  lines.push('- [ ] Decide: benign, tune, monitor, contain, or escalate.');
  lines.push('- [ ] Document final disposition.');
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push(table(
    ['Field', 'Value'],
    [
      ['Time', row.timestamp || 'unknown'],
      ['First Seen', row.first_seen || 'unknown'],
      ['Last Seen', row.last_seen || 'unknown'],
      ['Seen Count', row.seen_count || 0],
      ['Rule', row.rule_name || 'unknown'],
      ['Dataset', row.event_dataset || 'unknown'],
      ['Severity', row.severity_label || row.severity || 'unknown'],
      ['Triage Level', row.triage_level || 'unknown'],
      ['Triage Score', row.triage_score ?? 'unknown'],
      ['Routing', row.routing || 'unknown'],
      ['Traffic Direction', row.traffic_direction || 'unknown'],
      ['Source', row.source_ip || 'unknown'],
      ['Destination', row.destination_ip || 'unknown'],
    ],
  ));
  lines.push('## Why It Alerted');
  lines.push('');
  if (reasons.length) {
    for (const reason of reasons) lines.push(`- ${reason}`);
  } else {
    lines.push('- No deterministic triage reasons were stored with this alert.');
  }
  lines.push('');
  lines.push('## Event Details');
  lines.push('');
  lines.push(table(['Field', 'Value'], extractInterestingFields(alert)));
  lines.push('## SOC Query Starters');
  lines.push('');
  if (relatedQueries.length) {
    for (const query of relatedQueries) lines.push(`- \`${codeValue(query)}\``);
  } else {
    lines.push('- No query starters available.');
  }
  lines.push('');
  lines.push('## Rule Metadata');
  lines.push('');
  if (metadata.length) {
    lines.push(table(['Key', 'Value'], metadata.map(([key, value]) => [key, listValue(value)])));
  } else {
    lines.push('_No rule metadata stored._');
    lines.push('');
  }
  lines.push('## Analyst Notes');
  lines.push('');
  lines.push('- Disposition:');
  lines.push('- Evidence:');
  lines.push('- Follow-up:');
  lines.push('');

  return lines.join('\n');
}

async function loadRows(options) {
  // Query selection is intentionally narrow: exact alert ID, or recent alerts
  // at the requested triage levels.
  const db = openDb();
  const params = [];
  const clauses = [];
  try {
    if (options.alertId) {
      clauses.push('alert_id = ?');
      params.push(options.alertId);
    } else {
      const since = projectTimestampFromDate(new Date(Date.now() - options.hours * 60 * 60 * 1000));
      clauses.push("replace(replace(last_seen, 'T', ' '), 'Z', '') >= replace(replace(?, 'T', ' '), 'Z', '')");
      params.push(since);
      clauses.push(`triage_level IN (${options.levels.map(() => '?').join(', ')})`);
      params.push(...options.levels);
    }
    if (!options.includeTests) {
      clauses.push("alert_id NOT LIKE 'phase%'");
      clauses.push("alert_id NOT LIKE 'config-%'");
      clauses.push("alert_id NOT LIKE 'internal-test-%'");
      clauses.push("alert_id NOT LIKE 'sqlite-%'");
      clauses.push("alert_id NOT LIKE 'policy-%'");
    }

    return await all(
      db,
      `
        SELECT alert_id, first_seen, last_seen, seen_count, timestamp,
               rule_name, event_dataset, severity, severity_label,
               source_ip, destination_ip, traffic_direction, triage_score,
               triage_level, routing, alert_json
        FROM alerts
        WHERE ${clauses.join(' AND ')}
        ORDER BY
          CASE triage_level
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
          END,
          triage_score DESC,
          last_seen DESC
        LIMIT ?
      `,
      [...params, options.limit],
    );
  } finally {
    await closeDb(db);
  }
}

function rowToOutput(row) {
  // Filename is returned in JSON mode so a caller can write individual notes.
  const filenameParts = [
    (row.last_seen || row.timestamp || 'unknown-time').replace(/[:]/g, ''),
    row.triage_level || 'unknown',
    shortAlertId(row.alert_id),
    row.rule_name || 'alert',
  ];
  const filename = `${safeFilename(filenameParts.join('-'))}.md`;
  return {
    filename,
    alert_id: row.alert_id,
    triage_level: row.triage_level,
    triage_score: row.triage_score,
    rule_name: row.rule_name,
    source_ip: row.source_ip,
    destination_ip: row.destination_ip,
    markdown: renderNote(row),
  };
}

async function main() {
  const options = parseArgs(process.argv);
  const rows = await loadRows(options);
  const notes = rows.map(rowToOutput);

  if (options.format === 'json') {
    console.log(JSON.stringify({
      generated_at: projectNow(),
      database: path.basename(dbPath),
      count: notes.length,
      notes,
    }, null, 2));
    return;
  }

  if (!notes.length) {
    console.log(`# Security Onion Investigation Notes\n\nGenerated: ${projectNow()}\n\n_No matching alerts._`);
    return;
  }

  console.log(notes.map((note) => note.markdown).join('\n---\n\n'));
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
