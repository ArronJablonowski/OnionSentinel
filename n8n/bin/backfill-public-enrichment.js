#!/usr/bin/env node
// Backfill public enrichment for rows stored before the dedicated /enrich stage.
//
// Run inside the alert-store container so it can reach both localhost:8787 and
// the mounted SQLite DB:
//   docker compose exec -T alert-store node /app/bin/backfill-public-enrichment.js

const http = require('http');

function loadSqlite3() {
  const candidates = [
    process.env.SQLITE3_MODULE_PATH,
    '/usr/local/lib/node_modules/n8n/node_modules/.pnpm/sqlite3@5.1.7/node_modules/sqlite3',
    'sqlite3',
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      return require(candidate);
    } catch (error) {
      // Try the next candidate; the container path varies by n8n image.
    }
  }
  throw new Error('Unable to load sqlite3 module. Set SQLITE3_MODULE_PATH if needed.');
}

const sqlite3 = loadSqlite3();
const dbPath = process.env.ALERT_STORE_DB || '/data/alerts.sqlite3';
const enrichUrl = new URL(process.env.ALERT_STORE_ENRICH_URL || 'http://127.0.0.1:8787/enrich');
const limit = Number.parseInt(process.env.BACKFILL_LIMIT || '0', 10);
const dryRun = ['1', 'true', 'yes'].includes(String(process.env.BACKFILL_DRY_RUN || '').toLowerCase());
const refreshSparse = ['1', 'true', 'yes'].includes(String(process.env.BACKFILL_REFRESH_SPARSE || '').toLowerCase());
const refreshAll = ['1', 'true', 'yes'].includes(String(process.env.BACKFILL_REFRESH_ALL || '').toLowerCase());
const ruleLike = String(process.env.BACKFILL_RULE_LIKE || '').trim();

function openDb() {
  const db = new sqlite3.Database(dbPath);
  db.configure('busyTimeout', Number.parseInt(process.env.BACKFILL_SQLITE_BUSY_TIMEOUT_MS || '15000', 10));
  return db;
}

function all(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => (error ? reject(error) : resolve(rows)));
  });
}

function run(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(error) {
      if (error) reject(error);
      else resolve(this);
    });
  });
}

function closeDb(db) {
  return new Promise((resolve, reject) => {
    db.close((error) => (error ? reject(error) : resolve()));
  });
}

function parseObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  if (typeof value !== 'string' || !value.trim()) return {};
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (error) {
    return {};
  }
}

function hasExternalIntel(value) {
  const parsed = parseObject(value);
  const externalIntel = parsed.external_intel;
  if (!externalIntel || typeof externalIntel !== 'object' || Array.isArray(externalIntel)) return false;
  const records = Array.isArray(externalIntel.records) ? externalIntel.records : [];
  const skipped = Array.isArray(externalIntel.skipped) ? externalIntel.skipped : [];
  const errors = Array.isArray(externalIntel.errors) ? externalIntel.errors : [];
  return records.length > 0 || skipped.length > 0 || errors.length > 0;
}

function hasExternalIntelObject(value) {
  const parsed = parseObject(value);
  return Boolean(parsed.external_intel && typeof parsed.external_intel === 'object' && !Array.isArray(parsed.external_intel));
}

function postEnrich(alert) {
  const body = JSON.stringify(alert);
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        hostname: enrichUrl.hostname,
        port: enrichUrl.port || 80,
        path: `${enrichUrl.pathname}${enrichUrl.search}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
        timeout: Number.parseInt(process.env.BACKFILL_ENRICH_TIMEOUT_MS || '120000', 10),
      },
      (response) => {
        let responseBody = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => {
          responseBody += chunk;
        });
        response.on('end', () => {
          let parsed;
          try {
            parsed = JSON.parse(responseBody);
          } catch (error) {
            reject(new Error(`non-JSON enrichment response with HTTP ${response.statusCode}`));
            return;
          }
          if (response.statusCode < 200 || response.statusCode >= 300 || !parsed.ok) {
            reject(new Error(`enrichment rejected row with HTTP ${response.statusCode}`));
            return;
          }
          resolve(parsed);
        });
      },
    );
    request.on('timeout', () => request.destroy(new Error('enrichment request timed out')));
    request.on('error', reject);
    request.write(body);
    request.end();
  });
}

function buildEnrichmentRecord(alert, existingRecord) {
  return {
    message: alert.message ?? existingRecord.message ?? null,
    tags: alert.tags ?? existingRecord.tags ?? [],
    labels: alert.labels ?? existingRecord.labels ?? {},
    ecs: alert.ecs ?? existingRecord.ecs ?? {},
    agent: alert.agent ?? existingRecord.agent ?? {},
    log: alert.log ?? existingRecord.log ?? {},
    dns: alert.dns ?? existingRecord.dns ?? {},
    http: alert.http ?? existingRecord.http ?? {},
    url: alert.url ?? existingRecord.url ?? {},
    tls: alert.tls ?? existingRecord.tls ?? {},
    file: alert.file ?? existingRecord.file ?? {},
    process: alert.process ?? existingRecord.process ?? {},
    user: alert.user ?? existingRecord.user ?? {},
    related: alert.related ?? existingRecord.related ?? {},
    threat: alert.threat ?? existingRecord.threat ?? {},
    zeek: alert.zeek ?? existingRecord.zeek ?? {},
    suricata: alert.suricata ?? existingRecord.suricata ?? {},
    security_onion: alert.security_onion ?? existingRecord.security_onion ?? {},
    external_intel: alert.enrichment?.external_intel ?? existingRecord.external_intel ?? {},
  };
}

async function main() {
  const db = openDb();
  try {
    const where = refreshAll
      ? '1 = 1'
      : refreshSparse
        ? `(
            enrichment_json IS NULL
            OR enrichment_json = ''
            OR instr(enrichment_json, '"external_intel"') = 0
            OR instr(enrichment_json, '"records"') = 0
            OR (
              instr(enrichment_json, '"records":[]') > 0
              AND instr(enrichment_json, '"skipped":[]') > 0
              AND instr(enrichment_json, '"errors":[]') > 0
            )
          )`
        : `(
            enrichment_json IS NULL
            OR enrichment_json = ''
            OR instr(enrichment_json, '"external_intel"') = 0
          )`;
    const rows = await all(
      db,
      `
        SELECT alert_id, alert_json, enrichment_json
        FROM alerts
        WHERE ${where}
          ${ruleLike ? 'AND rule_name LIKE ?' : ''}
        ORDER BY last_seen ASC, alert_id ASC
        ${limit > 0 ? 'LIMIT ?' : ''}
      `,
      [
        ...(ruleLike ? [ruleLike] : []),
        ...(limit > 0 ? [limit] : []),
      ],
    );

    let updated = 0;
    let skipped = 0;
    let failed = 0;
    console.log(JSON.stringify({event: 'backfill_start', candidates: rows.length, dry_run: dryRun, refresh_sparse: refreshSparse, refresh_all: refreshAll}));

    for (const row of rows) {
      const alert = parseObject(row.alert_json);
      const existingRecord = parseObject(row.enrichment_json);
      if (!alert || !Object.keys(alert).length) {
        skipped += 1;
        continue;
      }
      if (!refreshAll && !refreshSparse && hasExternalIntel(existingRecord)) {
        skipped += 1;
        continue;
      }
      if (refreshSparse && !refreshAll && hasExternalIntel(existingRecord)) {
        skipped += 1;
        continue;
      }

      try {
        const enriched = await postEnrich(alert);
        const enrichedAlert = parseObject(enriched.alert);
        const externalIntel = parseObject(enriched.enrichment || enrichedAlert.enrichment?.external_intel);
        const mergedAlert = {
          ...alert,
          ...enrichedAlert,
          enrichment: {
            ...(alert.enrichment || {}),
            ...(enrichedAlert.enrichment || {}),
            external_intel: externalIntel,
          },
        };
        const enrichmentRecord = buildEnrichmentRecord(mergedAlert, existingRecord);
        if (!dryRun) {
          await run(
            db,
            'UPDATE alerts SET alert_json = ?, enrichment_json = ? WHERE alert_id = ?',
            [JSON.stringify(mergedAlert), JSON.stringify(enrichmentRecord), row.alert_id],
          );
        }
        updated += 1;
        if (updated % 100 === 0) {
          console.log(JSON.stringify({event: 'backfill_progress', updated, skipped, failed}));
        }
      } catch (error) {
        failed += 1;
        console.error(JSON.stringify({event: 'backfill_error', alert_id_hash: String(row.alert_id || '').slice(-12), error: String(error.message || error).slice(0, 180)}));
      }
    }

    console.log(JSON.stringify({event: 'backfill_done', updated, skipped, failed, dry_run: dryRun}));
  } finally {
    await closeDb(db);
  }
}

main().catch((error) => {
  console.error(JSON.stringify({event: 'backfill_fatal', error: String(error.message || error).slice(0, 240)}));
  process.exit(1);
});
