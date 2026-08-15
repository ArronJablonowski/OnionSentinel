'use strict';

const fs = require('fs');

const SOURCES = new Set(['osquery_apps', 'zeek_software', 'http_user_agent']);
const TIERS = new Set(['installed', 'observed', 'inferred']);
const CONFIDENCES = new Set(['low', 'medium', 'high']);
const FRESHNESS = new Set(['current', 'recent', 'historical', 'expired']);
const VERSION_CONFLICT = 'simultaneous-version-disagreement';
const WINDOWS = Object.freeze({24: '24 hours', 7: '7 days', 30: '30 days'});
const SORT_COLUMNS = Object.freeze({
  last_seen: ['record.last_seen', 'record.evidence_id'],
  first_seen: ['record.first_seen', 'record.evidence_id'],
  product: [
    'left(lower(record.product), 256)', 'lower(record.product)',
    'left(lower(record.version), 128)', 'lower(record.version)', 'record.evidence_id',
  ],
  asset: [
    'lower(record.asset_ref)', 'left(lower(record.product), 256)',
    'lower(record.product)', 'record.evidence_id',
  ],
  tier: [
    'record.tier', 'left(lower(record.product), 256)',
    'lower(record.product)', 'record.evidence_id',
  ],
  confidence: [
    'record.confidence', 'left(lower(record.product), 256)',
    'lower(record.product)', 'record.evidence_id',
  ],
});
const RECORD_FIELDS = Object.freeze([
  'evidence_id', 'source', 'source_dataset', 'tier', 'confidence',
  'asset_ref_type', 'asset_ref', 'platform', 'operating_system_type',
  'operating_system_version', 'operating_system_source',
  'operating_system_confidence', 'product', 'version', 'category',
  'first_seen', 'last_seen', 'observation_count',
]);

function text(value, maximum, field, {required = false} = {}) {
  const result = String(value ?? '').trim();
  if ((required && !result) || result.length > maximum || /[\u0000-\u001f]/.test(result)) {
    throw new Error(`${field} is invalid`);
  }
  return result;
}

function timestamp(value, field) {
  const raw = text(value, 40, field, {required: true});
  const parsed = new Date(raw);
  if (!Number.isFinite(parsed.getTime()) || !/(?:Z|[+-]\d\d:\d\d)$/.test(raw)) {
    throw new Error(`${field} must be an offset-aware timestamp`);
  }
  return parsed.toISOString();
}

function integer(value, minimum, maximum, field) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${field} is invalid`);
  }
  return parsed;
}

function normalizeCollection(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('software inventory collection is invalid');
  }
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded) > 256 * 1024) {
    throw new Error('software inventory collection is too large');
  }
  return JSON.parse(encoded);
}

function normalizeRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('software inventory record is invalid');
  }
  const evidenceId = text(value.evidence_id, 24, 'evidence_id', {required: true});
  if (!/^[0-9a-f]{24}$/.test(evidenceId)) throw new Error('evidence_id is invalid');
  const source = text(value.source, 32, 'source', {required: true});
  const tier = text(value.tier, 16, 'tier', {required: true});
  const confidence = text(value.confidence, 16, 'confidence', {required: true});
  const assetRefType = text(value.asset_ref_type, 8, 'asset_ref_type', {required: true});
  if (!SOURCES.has(source) || !TIERS.has(tier) || !CONFIDENCES.has(confidence)) {
    throw new Error('software inventory provenance is invalid');
  }
  if (!['host', 'ip'].includes(assetRefType)) throw new Error('asset_ref_type is invalid');
  const firstSeen = timestamp(value.first_seen, 'first_seen');
  const lastSeen = timestamp(value.last_seen, 'last_seen');
  if (Date.parse(lastSeen) < Date.parse(firstSeen)) throw new Error('last_seen precedes first_seen');
  const operatingSystemConfidence = text(
    value.operating_system_confidence, 16, 'operating_system_confidence',
  );
  if (operatingSystemConfidence && !CONFIDENCES.has(operatingSystemConfidence)) {
    throw new Error('operating_system_confidence is invalid');
  }
  return {
    evidence_id: evidenceId,
    source,
    source_dataset: text(value.source_dataset, 160, 'source_dataset', {required: true}),
    tier,
    confidence,
    asset_ref_type: assetRefType,
    asset_ref: text(value.asset_ref, 253, 'asset_ref', {required: true}),
    platform: text(value.platform, 160, 'platform'),
    operating_system_type: text(value.operating_system_type, 160, 'operating_system_type'),
    operating_system_version: text(value.operating_system_version, 512, 'operating_system_version'),
    operating_system_source: text(value.operating_system_source, 160, 'operating_system_source'),
    operating_system_confidence: operatingSystemConfidence,
    product: text(value.product, 4096, 'product', {required: true}),
    version: text(value.version, 2048, 'version'),
    category: text(value.category, 256, 'category'),
    first_seen: firstSeen,
    last_seen: lastSeen,
    observation_count: integer(value.observation_count, 0, 1_000_000_000, 'observation_count'),
  };
}

function parseQuery(options = {}) {
  const limit = integer(Number(options.limit ?? 100), 1, 250, 'limit');
  const offset = integer(Number(options.offset ?? 0), 0, 10_000_000, 'offset');
  const search = text(options.search, 253, 'search').toLowerCase();
  const tier = text(options.tier || 'all', 16, 'tier').toLowerCase();
  const confidence = text(options.confidence || 'all', 16, 'confidence').toLowerCase();
  const freshness = text(options.freshness || 'all', 16, 'freshness').toLowerCase();
  const platform = text(options.platform || 'all', 160, 'platform');
  const window = text(options.window || '30d', 8, 'window').toLowerCase();
  const sort = text(options.sort || 'last_seen', 16, 'sort').toLowerCase();
  const direction = text(options.direction || 'desc', 4, 'direction').toLowerCase();
  if (tier !== 'all' && !TIERS.has(tier)) throw new Error('tier is unsupported');
  if (confidence !== 'all' && !CONFIDENCES.has(confidence)) {
    throw new Error('confidence is unsupported');
  }
  if (freshness !== 'all' && !FRESHNESS.has(freshness)) {
    throw new Error('freshness is unsupported');
  }
  if (!['24h', '7d', '30d'].includes(window)) throw new Error('window is unsupported');
  if (!SORT_COLUMNS[sort]) throw new Error('sort is unsupported');
  if (!['asc', 'desc'].includes(direction)) throw new Error('direction is unsupported');
  return {limit, offset, search, tier, confidence, freshness, platform, window, sort, direction};
}

function freshnessSql(alias = 'record') {
  return `(CASE
    WHEN $2::timestamptz - ${alias}.last_seen <= interval '24 hours' THEN 'current'
    WHEN $2::timestamptz - ${alias}.last_seen <= interval '7 days' THEN 'recent'
    WHEN ${alias}.tier IN ('observed', 'inferred')
      AND $2::timestamptz - ${alias}.last_seen <= interval '30 days' THEN 'historical'
    ELSE 'expired' END)`;
}

function conflictSql(alias = 'record') {
  return `EXISTS (
    SELECT 1 FROM onion_sentinel_software.inventory_records peer
    WHERE peer.snapshot_id = ${alias}.snapshot_id
      AND peer.evidence_id <> ${alias}.evidence_id
      AND peer.asset_ref_type = ${alias}.asset_ref_type
      AND peer.asset_ref = ${alias}.asset_ref
      AND md5(lower(peer.product)) = md5(lower(${alias}.product))
      AND lower(peer.product) = lower(${alias}.product)
      AND peer.last_seen = ${alias}.last_seen
      AND peer.version <> ''
      AND ${alias}.version <> ''
      AND lower(peer.version) <> lower(${alias}.version)
  )`;
}

function publicRow(row) {
  const result = {};
  for (const field of RECORD_FIELDS) {
    let value = row[field];
    if (field === 'first_seen' || field === 'last_seen') value = new Date(value).toISOString();
    if (field === 'observation_count') value = Number(value);
    result[field] = value ?? '';
  }
  result.freshness = row.freshness;
  result.evidence_conflict = row.evidence_conflict ? VERSION_CONFLICT : '';
  result.asset_label = '';
  result.operating_system_observed_at = (
    result.source === 'osquery_apps'
    && ['osquery_manager.result:host.os', 'osquery.live:os_version']
      .includes(result.operating_system_source)
    && (result.operating_system_type || result.operating_system_version)
  ) ? result.last_seen : '';
  result.operating_system_freshness = result.operating_system_observed_at
    ? result.freshness : '';
  result.operating_system_association = '';
  if (
    result.source === 'http_user_agent'
    || (result.source === 'zeek_software' && result.category.toLowerCase() === 'http::browser')
  ) {
    result.observed_user_agent = result.source === 'http_user_agent'
      ? result.product : result.version;
  }
  return result;
}

function createPostgresSoftwareStore({pool, schemaPath, logger = console}) {
  if (!pool || typeof pool.query !== 'function') throw new Error('PostgreSQL pool is required');

  async function initialize() {
    await pool.query(fs.readFileSync(schemaPath, 'utf8'));
    const version = await pool.query(
      `SELECT version FROM onion_sentinel_software.schema_version
       WHERE component = 'software_inventory'`,
    );
    if (Number(version.rows[0]?.version || 0) !== 1) {
      throw new Error('software inventory PostgreSQL schema version is unsupported');
    }
  }

  async function startImport({snapshot_id: snapshotId, updated_at: updatedAt,
    collection, expected_records: expectedRecords}) {
    if (!/^[0-9a-f]{64}$/.test(String(snapshotId || ''))) {
      throw new Error('snapshot_id is invalid');
    }
    const normalizedUpdatedAt = timestamp(updatedAt, 'updated_at');
    const normalizedCollection = normalizeCollection(collection);
    const expected = integer(expectedRecords, 0, 250_000, 'expected_records');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const active = await client.query(
        `SELECT snapshot_id FROM onion_sentinel_software.snapshots
         WHERE snapshot_id = $1 AND status = 'active'`,
        [snapshotId],
      );
      if (active.rowCount) {
        await client.query('COMMIT');
        return {ok: true, snapshot_id: snapshotId, already_active: true};
      }
      await client.query(
        `DELETE FROM onion_sentinel_software.snapshots
         WHERE snapshot_id = $1 AND status = 'staging'`,
        [snapshotId],
      );
      await client.query(
        `INSERT INTO onion_sentinel_software.snapshots
         (snapshot_id, status, updated_at, collection, expected_records)
         VALUES ($1, 'staging', $2, $3::jsonb, $4)`,
        [snapshotId, normalizedUpdatedAt, JSON.stringify(normalizedCollection), expected],
      );
      await client.query('COMMIT');
      return {ok: true, snapshot_id: snapshotId, already_active: false};
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async function putChunk({snapshot_id: snapshotId, records}) {
    if (!/^[0-9a-f]{64}$/.test(String(snapshotId || ''))) {
      throw new Error('snapshot_id is invalid');
    }
    if (!Array.isArray(records) || records.length < 1 || records.length > 500) {
      throw new Error('software inventory chunk is invalid');
    }
    const normalized = records.map(normalizeRecord);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const locked = await client.query(
        `SELECT expected_records FROM onion_sentinel_software.snapshots
         WHERE snapshot_id = $1 AND status = 'staging' FOR UPDATE`,
        [snapshotId],
      );
      if (!locked.rowCount) throw new Error('software inventory staging snapshot is unavailable');
      await client.query(
        `INSERT INTO onion_sentinel_software.inventory_records (
           snapshot_id, evidence_id, source, source_dataset, tier, confidence,
           asset_ref_type, asset_ref, platform, operating_system_type,
           operating_system_version, operating_system_source,
           operating_system_confidence, product, version, category,
           first_seen, last_seen, observation_count
         )
         SELECT $1, item.evidence_id, item.source, item.source_dataset,
           item.tier, item.confidence, item.asset_ref_type, item.asset_ref,
           item.platform, item.operating_system_type,
           item.operating_system_version, item.operating_system_source,
           item.operating_system_confidence, item.product, item.version,
           item.category, item.first_seen::timestamptz,
           item.last_seen::timestamptz, item.observation_count
         FROM jsonb_to_recordset($2::jsonb) AS item(
           evidence_id text, source text, source_dataset text, tier text,
           confidence text, asset_ref_type text, asset_ref text, platform text,
           operating_system_type text, operating_system_version text,
           operating_system_source text, operating_system_confidence text,
           product text, version text, category text, first_seen text,
           last_seen text, observation_count bigint
         )
         ON CONFLICT (snapshot_id, evidence_id) DO UPDATE SET
           source = EXCLUDED.source, source_dataset = EXCLUDED.source_dataset,
           tier = EXCLUDED.tier, confidence = EXCLUDED.confidence,
           asset_ref_type = EXCLUDED.asset_ref_type, asset_ref = EXCLUDED.asset_ref,
           platform = EXCLUDED.platform,
           operating_system_type = EXCLUDED.operating_system_type,
           operating_system_version = EXCLUDED.operating_system_version,
           operating_system_source = EXCLUDED.operating_system_source,
           operating_system_confidence = EXCLUDED.operating_system_confidence,
           product = EXCLUDED.product, version = EXCLUDED.version,
           category = EXCLUDED.category, first_seen = EXCLUDED.first_seen,
           last_seen = EXCLUDED.last_seen,
           observation_count = EXCLUDED.observation_count`,
        [snapshotId, JSON.stringify(normalized)],
      );
      const count = await client.query(
        `SELECT count(*)::bigint AS count
         FROM onion_sentinel_software.inventory_records WHERE snapshot_id = $1`,
        [snapshotId],
      );
      if (Number(count.rows[0].count) > Number(locked.rows[0].expected_records)) {
        throw new Error('software inventory import exceeded its expected record count');
      }
      await client.query('COMMIT');
      return {ok: true, snapshot_id: snapshotId, received_records: Number(count.rows[0].count)};
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async function commitImport({snapshot_id: snapshotId}) {
    if (!/^[0-9a-f]{64}$/.test(String(snapshotId || ''))) {
      throw new Error('snapshot_id is invalid');
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const staged = await client.query(
        `SELECT expected_records FROM onion_sentinel_software.snapshots
         WHERE snapshot_id = $1 AND status = 'staging' FOR UPDATE`,
        [snapshotId],
      );
      if (!staged.rowCount) {
        const active = await client.query(
          `SELECT 1 FROM onion_sentinel_software.snapshots
           WHERE snapshot_id = $1 AND status = 'active'`,
          [snapshotId],
        );
        if (active.rowCount) {
          await client.query('COMMIT');
          return {ok: true, snapshot_id: snapshotId, already_active: true};
        }
        throw new Error('software inventory staging snapshot is unavailable');
      }
      const count = await client.query(
        `SELECT count(*)::bigint AS count
         FROM onion_sentinel_software.inventory_records WHERE snapshot_id = $1`,
        [snapshotId],
      );
      const received = Number(count.rows[0].count);
      const expected = Number(staged.rows[0].expected_records);
      if (received !== expected) {
        throw new Error(`software inventory import is incomplete (${received}/${expected})`);
      }
      await client.query(
        `UPDATE onion_sentinel_software.snapshots
         SET status = 'retired' WHERE status = 'active'`,
      );
      await client.query(
        `UPDATE onion_sentinel_software.snapshots
         SET status = 'active', activated_at = clock_timestamp()
         WHERE snapshot_id = $1 AND status = 'staging'`,
        [snapshotId],
      );
      await client.query(
        `DELETE FROM onion_sentinel_software.snapshots
         WHERE snapshot_id IN (
           SELECT snapshot_id FROM onion_sentinel_software.snapshots
           WHERE status = 'retired'
           ORDER BY activated_at DESC NULLS LAST, created_at DESC
           OFFSET 2
         )`,
      );
      await client.query(
        `DELETE FROM onion_sentinel_software.snapshots
         WHERE status = 'staging' AND created_at < clock_timestamp() - interval '24 hours'`,
      );
      await client.query('COMMIT');
      logger.log?.('info', 'software_inventory.snapshot_activated', {
        snapshot_id: snapshotId, records: received,
      });
      return {ok: true, snapshot_id: snapshotId, records: received, already_active: false};
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async function query(options = {}) {
    const filters = parseQuery(options);
    const active = await pool.query(
      `SELECT snapshot_id, updated_at, collection, expected_records
       FROM onion_sentinel_software.snapshots WHERE status = 'active'`,
    );
    if (!active.rowCount) {
      const error = new Error('software inventory database has no active snapshot');
      error.statusCode = 503;
      throw error;
    }
    const snapshot = active.rows[0];
    const observedAt = options.observed_at ? timestamp(options.observed_at, 'observed_at')
      : new Date().toISOString();
    const params = [snapshot.snapshot_id, observedAt];
    const conditions = [
      `record.snapshot_id = $1`,
      `record.last_seen >= $2::timestamptz - interval '${WINDOWS[Number(filters.window.replace(/[^\d]/g, ''))]}'`,
    ];
    if (filters.tier !== 'all') {
      params.push(filters.tier);
      conditions.push(`record.tier = $${params.length}`);
    }
    if (filters.confidence !== 'all') {
      params.push(filters.confidence);
      conditions.push(`record.confidence = $${params.length}`);
    }
    if (filters.freshness !== 'all') {
      params.push(filters.freshness);
      conditions.push(`${freshnessSql()} = $${params.length}`);
    }
    if (filters.platform.toLowerCase() !== 'all') {
      params.push(filters.platform.toLowerCase());
      conditions.push(`lower(record.platform) = $${params.length}`);
    }
    if (filters.search) {
      params.push(`%${filters.search.replaceAll('\\', '\\\\').replaceAll('%', '\\%').replaceAll('_', '\\_')}%`);
      conditions.push(`record.search_text LIKE $${params.length} ESCAPE '\\'`);
    }
    const where = conditions.join(' AND ');
    const order = SORT_COLUMNS[filters.sort].join(` ${filters.direction.toUpperCase()}, `);
    const pageParams = [...params, filters.limit, filters.offset];
    const rows = await pool.query(
      `SELECT record.*, ${freshnessSql()} AS freshness,
         ${conflictSql()} AS evidence_conflict
       FROM onion_sentinel_software.inventory_records record
       WHERE ${where}
       ORDER BY ${order} ${filters.direction.toUpperCase()}
       LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      pageParams,
    );
    const summaryResult = await pool.query(
      `SELECT count(*)::bigint AS records,
         count(DISTINCT lower(record.product))::bigint AS products,
         count(DISTINCT record.asset_ref)::bigint AS assets,
         count(*) FILTER (WHERE record.tier = 'installed')::bigint AS installed,
         count(*) FILTER (WHERE record.tier = 'observed')::bigint AS observed,
         count(*) FILTER (WHERE record.tier = 'inferred')::bigint AS inferred,
         count(*) FILTER (WHERE ${freshnessSql()} = 'current')::bigint AS current,
         count(*) FILTER (WHERE ${freshnessSql()} = 'recent')::bigint AS recent,
         count(*) FILTER (WHERE ${freshnessSql()} = 'historical')::bigint AS historical,
         count(*) FILTER (WHERE ${freshnessSql()} = 'expired')::bigint AS expired,
         count(*) FILTER (WHERE ${conflictSql()})::bigint AS conflicting_records
       FROM onion_sentinel_software.inventory_records record WHERE ${where}`,
      params,
    );
    const windowConditions = conditions.slice(0, 2).join(' AND ');
    const coverageResult = await pool.query(
      `SELECT
         count(DISTINCT record.asset_ref) FILTER (
           WHERE record.tier = 'installed' AND ${freshnessSql()} = 'current'
         )::bigint AS fresh_endpoint_inventories,
         count(DISTINCT record.asset_ref) FILTER (
           WHERE record.tier IN ('observed', 'inferred')
         )::bigint AS network_observed_assets
       FROM onion_sentinel_software.inventory_records record
       WHERE ${windowConditions}`,
      params.slice(0, 2),
    );
    const platformsResult = await pool.query(
      `SELECT min(record.platform) AS platform
       FROM onion_sentinel_software.inventory_records record
       WHERE ${windowConditions} AND record.platform <> ''
       GROUP BY lower(record.platform)
       ORDER BY lower(record.platform)`,
      params.slice(0, 2),
    );
    const summary = Object.fromEntries(
      Object.entries(summaryResult.rows[0]).map(([key, value]) => [key, Number(value)]),
    );
    const coverageRows = coverageResult.rows[0];
    const collection = snapshot.collection || {};
    const osqueryReady = Number.isSafeInteger(collection.osquery_ready)
      ? collection.osquery_ready : null;
    const coverageGaps = osqueryReady === null ? null
      : Math.max(osqueryReady - Number(coverageRows.fresh_endpoint_inventories), 0);
    const warnings = [
      'LAN software coverage has no authoritative asset denominator; counts describe only observable evidence.',
    ];
    if (collection.complete !== true) {
      warnings.push('The latest collection was incomplete; showing the last valid snapshot.');
    }
    if (collection.last_error) warnings.push(`Latest collection warning: ${collection.last_error}`);
    if (Number(coverageRows.fresh_endpoint_inventories) === 0) {
      warnings.push('No current endpoint-reported inventory is visible; passive network evidence cannot prove software is absent.');
    }
    if (summary.conflicting_records > 0) {
      warnings.push(`${summary.conflicting_records} records have simultaneous version disagreements; each evidence row is retained and no version is selected as authoritative.`);
    }
    const sourceStatuses = collection.source_statuses && typeof collection.source_statuses === 'object'
      && !Array.isArray(collection.source_statuses) ? collection.source_statuses : {};
    for (const [source, status] of Object.entries(sourceStatuses)) {
      if (!status || typeof status !== 'object' || Array.isArray(status)) continue;
      const freshness = String(status.freshness || 'unknown').toLowerCase();
      if (['stale', 'expired'].includes(freshness)) {
        const latest = status.latest_observation_at
          ? `; latest observation ${String(status.latest_observation_at)}` : '';
        warnings.push(`${source.replaceAll('_', ' ')} evidence is ${freshness}${latest}.`);
      }
    }
    return {
      ok: true,
      schema: 'onion-sentinel-software-inventory-api-v1',
      generated_at: new Date(snapshot.updated_at).toISOString(),
      observed_at: observedAt,
      storage_backend: 'postgresql',
      collection,
      summary,
      coverage: {
        authoritative_denominator: null,
        denominator_status: 'unknown',
        osquery_ready: osqueryReady,
        fresh_endpoint_inventories: Number(coverageRows.fresh_endpoint_inventories),
        network_observed_assets: Number(coverageRows.network_observed_assets),
        coverage_gaps: coverageGaps,
        labeled_visible_records: 0,
        asset_label_inventory_complete: false,
        asset_os_correlated_records: 0,
      },
      filters,
      platforms: platformsResult.rows.map((row) => row.platform),
      page: {
        limit: filters.limit,
        offset: filters.offset,
        filtered_total: summary.records,
        has_more: filters.offset + rows.rowCount < summary.records,
      },
      items: rows.rows.map(publicRow),
      warnings,
      revision: snapshot.snapshot_id,
    };
  }

  async function stats() {
    const result = await pool.query(
      `SELECT snapshot_id, expected_records, updated_at, activated_at, collection
       FROM onion_sentinel_software.snapshots WHERE status = 'active'`,
    );
    const collection = result.rows[0]?.collection;
    return {
      enabled: true,
      available: true,
      backend: 'postgresql',
      schema_version: 1,
      active_snapshot: result.rows[0]?.snapshot_id || null,
      records: Number(result.rows[0]?.expected_records || 0),
      updated_at: result.rows[0]?.updated_at
        ? new Date(result.rows[0].updated_at).toISOString() : null,
      source_statuses: collection && typeof collection === 'object'
        && !Array.isArray(collection)
        && collection.source_statuses && typeof collection.source_statuses === 'object'
        && !Array.isArray(collection.source_statuses)
        ? collection.source_statuses : {},
    };
  }

  return {initialize, startImport, putChunk, commitImport, query, stats};
}

module.exports = {
  conflictSql,
  createPostgresSoftwareStore,
  normalizeRecord,
  parseQuery,
  publicRow,
};
