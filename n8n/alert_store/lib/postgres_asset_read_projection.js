'use strict';

const {
  cleanText,
  timestamp,
  inventoryPayload,
  publicRecord,
} = require('./postgres_asset_normalization');

const SORT_COLUMNS = Object.freeze({
  asset_id: 'lower(record.asset_id)',
  criticality: `CASE record.criticality
    WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
    WHEN 'low' THEN 2 ELSE 0 END`,
  valid_from: 'record.valid_from',
  platform: 'lower(record.platform)',
  role: 'lower(record.role)',
});

function createPostgresAssetReadProjection({pool}) {
  async function rowsForQuery(client, {
    limit = 250,
    offset = 0,
    search = '',
    sort = 'asset_id',
    direction = 'asc',
    state = 'current',
    at = new Date(),
  } = {}) {
    const boundedLimit = Math.max(1, Math.min(500, Number(limit) || 250));
    const boundedOffset = Math.max(0, Math.min(10_000_000, Number(offset) || 0));
    const query = cleanText(search, 253, 'asset search').toLowerCase();
    const order = SORT_COLUMNS[sort] || SORT_COLUMNS.asset_id;
    const orderDirection = String(direction).toLowerCase() === 'desc' ? 'DESC' : 'ASC';
    const when = at instanceof Date ? at.toISOString() : timestamp(at, 'observed_at');
    const conditions = [];
    const params = [when];
    if (state === 'current') {
      conditions.push('record.valid_from <= $1::timestamptz AND (record.valid_until IS NULL OR record.valid_until > $1::timestamptz)');
    } else if (state === 'expired') {
      conditions.push('record.valid_until IS NOT NULL AND record.valid_until <= $1::timestamptz');
    } else if (state === 'scheduled') {
      conditions.push('record.valid_from > $1::timestamptz');
    } else if (state === 'all') {
      // Keep the parameter layout identical across filter modes. PostgreSQL
      // rejects surplus bind values even when the generated WHERE clause is
      // otherwise valid.
      conditions.push('$1::timestamptz IS NOT NULL');
    } else if (state !== 'all') {
      throw new Error('asset state filter is invalid');
    }
    if (query) {
      params.push(`%${query}%`);
      conditions.push(`(
        lower(record.asset_id) LIKE $${params.length}
        OR lower(record.role) LIKE $${params.length}
        OR lower(record.platform) LIKE $${params.length}
        OR lower(record.source_type) LIKE $${params.length}
        OR EXISTS (
          SELECT 1 FROM onion_sentinel_assets.identifiers candidate
          WHERE candidate.record_id = record.record_id
            AND candidate.normalized_value LIKE $${params.length}
        )
      )`);
    }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const count = await client.query(
      `SELECT COUNT(*)::BIGINT AS count
       FROM onion_sentinel_assets.inventory_records record ${where}`,
      params,
    );
    params.push(boundedLimit, boundedOffset);
    const result = await client.query(
      `SELECT record.*,
        COALESCE(array_agg(identifier.identifier_value ORDER BY identifier.normalized_value)
          FILTER (WHERE identifier.identifier_type = 'ip'), ARRAY[]::TEXT[]) AS ip_addresses,
        COALESCE(array_agg(identifier.identifier_value ORDER BY identifier.normalized_value)
          FILTER (WHERE identifier.identifier_type = 'mac'), ARRAY[]::TEXT[]) AS mac_addresses,
        COALESCE(array_agg(identifier.identifier_value ORDER BY identifier.normalized_value)
          FILTER (WHERE identifier.identifier_type = 'hostname'), ARRAY[]::TEXT[]) AS hostnames
       FROM onion_sentinel_assets.inventory_records record
       LEFT JOIN onion_sentinel_assets.identifiers identifier
         ON identifier.record_id = record.record_id
       ${where}
       GROUP BY record.record_id
       ORDER BY ${order} ${orderDirection}, record.record_id ${orderDirection}
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );
    return {
      rows: result.rows,
      total: Number(count.rows[0]?.count || 0),
      limit: boundedLimit,
      offset: boundedOffset,
      observed_at: when,
    };
  }

  async function page(options = {}) {
    const result = await rowsForQuery(pool, options);
    const when = new Date(result.observed_at);
    const counts = await pool.query(
      'SELECT * FROM onion_sentinel_assets.inventory_counts',
    );
    const identifiers = await pool.query(
      `SELECT identifier_type, COUNT(*)::BIGINT AS count
       FROM onion_sentinel_assets.identifiers identifier
       JOIN onion_sentinel_assets.inventory_records record USING (record_id)
       WHERE record.valid_from <= $1::timestamptz
         AND (record.valid_until IS NULL OR record.valid_until > $1::timestamptz)
       GROUP BY identifier_type`,
      [result.observed_at],
    );
    const identifierCounts = Object.fromEntries(
      identifiers.rows.map((row) => [row.identifier_type, Number(row.count)]),
    );
    const summary = counts.rows[0] || {};
    return {
      ok: true,
      inventory_status: 'database',
      storage_backend: 'postgresql',
      observed_at: result.observed_at,
      records_total: Number(summary.records_total || 0),
      authoritative_asset_count: Number(summary.current_records || 0),
      current_asset_count: Number(summary.current_records || 0),
      current_ip_count: identifierCounts.ip || 0,
      current_hostname_count: identifierCounts.hostname || 0,
      state_counts: {
        current: Number(summary.current_records || 0),
        scheduled: Number(summary.scheduled_records || 0),
        expired: Number(summary.expired_records || 0),
        invalid: 0,
      },
      page: {
        limit: result.limit,
        offset: result.offset,
        returned: result.rows.length,
        filtered_total: result.total,
        has_more: result.offset + result.rows.length < result.total,
      },
      assets: result.rows.map((row) => publicRecord(row, when)),
    };
  }

  async function snapshot() {
    const records = [];
    let offset = 0;
    for (;;) {
      const result = await rowsForQuery(pool, {
        limit: 500,
        offset,
        state: 'all',
        sort: 'asset_id',
      });
      records.push(...result.rows);
      offset += result.rows.length;
      if (offset >= result.total || !result.rows.length) break;
      if (records.length > 100_000) throw new Error('asset snapshot exceeds 100000 records');
    }
    return inventoryPayload(records);
  }

  return {page, snapshot};
}

module.exports = {createPostgresAssetReadProjection};
