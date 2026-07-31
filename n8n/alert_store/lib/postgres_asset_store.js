'use strict';

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');

const SORT_COLUMNS = Object.freeze({
  asset_id: 'lower(record.asset_id)',
  criticality: `CASE record.criticality
    WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
    WHEN 'low' THEN 2 ELSE 0 END`,
  valid_from: 'record.valid_from',
  platform: 'lower(record.platform)',
  role: 'lower(record.role)',
});

function cleanText(value, maximum, field, {required = false} = {}) {
  const text = String(value ?? '').trim();
  if ((required && !text) || text.length > maximum) {
    throw new Error(`${field} is invalid`);
  }
  return text;
}

function timestamp(value, field, {nullable = false} = {}) {
  if (nullable && (value === null || value === undefined || value === '')) return null;
  const parsed = new Date(String(value || ''));
  if (!Number.isFinite(parsed.getTime()) || !/(?:Z|[+-]\d\d:\d\d)$/.test(String(value || ''))) {
    throw new Error(`${field} must be an offset-aware timestamp`);
  }
  return parsed.toISOString();
}

function stringArray(value, maximumItems, maximumLength, field) {
  if (!Array.isArray(value) || value.length > maximumItems) {
    throw new Error(`${field} is invalid`);
  }
  const result = [];
  for (const item of value) {
    const cleaned = cleanText(item, maximumLength, field, {required: true});
    if (!result.includes(cleaned)) result.push(cleaned);
  }
  return result;
}

function identifiersFromRecord(record) {
  const identifiers = record && typeof record.identifiers === 'object'
    ? record.identifiers : {};
  const ips = identifiers.ip_addresses ?? identifiers.ip ?? [];
  const macs = identifiers.mac_addresses ?? identifiers.mac ?? [];
  const hostnames = identifiers.hostnames ?? identifiers.hostname ?? [];
  return {
    ip: stringArray(ips, 64, 64, 'IP identifiers').map((value) => {
      if (!net.isIP(value)) throw new Error('IP identifier is invalid');
      return value;
    }),
    mac: stringArray(macs, 64, 17, 'MAC identifiers').map((value) => {
      const normalized = value.toLowerCase().replaceAll('-', ':');
      if (!/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(normalized)) {
        throw new Error('MAC identifier is invalid');
      }
      return normalized;
    }),
    hostname: stringArray(hostnames, 64, 253, 'hostname identifiers')
      .map((value) => value.toLowerCase().replace(/\.$/, '')),
  };
}

function normalizeInventoryRecord(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new Error('asset record must be an object');
  }
  const validFrom = timestamp(record.valid_from, 'valid_from');
  const validUntil = timestamp(record.valid_until, 'valid_until', {nullable: true});
  if (validUntil && Date.parse(validUntil) <= Date.parse(validFrom)) {
    throw new Error('valid_until must be later than valid_from');
  }
  const criticality = cleanText(record.criticality || 'unknown', 16, 'criticality');
  const confidence = cleanText(record.confidence || 'unknown', 16, 'confidence');
  if (!['low', 'medium', 'high', 'critical', 'unknown'].includes(criticality)) {
    throw new Error('criticality is invalid');
  }
  if (!['low', 'medium', 'high', 'unknown'].includes(confidence)) {
    throw new Error('confidence is invalid');
  }
  if (
    record.share_with_hosted_models !== undefined
    && typeof record.share_with_hosted_models !== 'boolean'
  ) {
    throw new Error('share_with_hosted_models must be boolean');
  }
  const expectedServices = record.expected_services ?? [];
  const expectedBehaviors = record.expected_behaviors ?? [];
  if (!Array.isArray(expectedServices) || expectedServices.length > 128) {
    throw new Error('expected_services is invalid');
  }
  if (!Array.isArray(expectedBehaviors) || expectedBehaviors.length > 128) {
    throw new Error('expected_behaviors is invalid');
  }
  const identifiers = identifiersFromRecord(record);
  if (!Object.values(identifiers).some((values) => values.length)) {
    throw new Error('asset record must contain at least one identifier');
  }
  return {
    asset_id: cleanText(record.asset_id, 160, 'asset_id', {required: true}),
    valid_from: validFrom,
    valid_until: validUntil,
    identifiers,
    role: cleanText(record.role, 160, 'role'),
    platform: cleanText(record.platform, 160, 'platform'),
    owner_ref: cleanText(record.owner_ref, 300, 'owner_ref'),
    criticality,
    expected_services: expectedServices,
    expected_behaviors: expectedBehaviors,
    source_type: cleanText(record.source_type, 160, 'source_type'),
    source_ref: cleanText(record.source_ref, 500, 'source_ref'),
    confidence,
    share_with_hosted_models: Boolean(record.share_with_hosted_models),
  };
}

function inventoryPayload(records, generatedAt = new Date().toISOString()) {
  return {
    schema: 'onion-sentinel-asset-inventory-v1',
    version: 1,
    generated_at: generatedAt,
    inventory_status: 'database',
    assets: records.map((record) => ({
      asset_id: record.asset_id,
      valid_from: new Date(record.valid_from).toISOString(),
      valid_until: record.valid_until ? new Date(record.valid_until).toISOString() : null,
      identifiers: {
        ip_addresses: record.ip_addresses || [],
        mac_addresses: record.mac_addresses || [],
        hostnames: record.hostnames || [],
      },
      role: record.role,
      platform: record.platform,
      owner_ref: record.owner_ref,
      criticality: record.criticality,
      expected_services: record.expected_services || [],
      expected_behaviors: record.expected_behaviors || [],
      source_type: record.source_type,
      source_ref: record.source_ref,
      confidence: record.confidence,
      share_with_hosted_models: Boolean(record.share_with_hosted_models),
    })),
  };
}

function publicRecord(record, now) {
  const from = new Date(record.valid_from).getTime();
  const until = record.valid_until ? new Date(record.valid_until).getTime() : null;
  const point = now.getTime();
  const state = point < from ? 'scheduled' : (until !== null && point >= until ? 'expired' : 'current');
  return {
    asset_id: record.asset_id,
    state,
    ip_addresses: record.ip_addresses || [],
    mac_addresses: record.mac_addresses || [],
    hostnames: record.hostnames || [],
    role: record.role,
    platform: record.platform,
    criticality: record.criticality,
    confidence: record.confidence,
    valid_from: new Date(record.valid_from).toISOString(),
    valid_until: record.valid_until ? new Date(record.valid_until).toISOString() : '',
    source_type: record.source_type,
    source_ref: record.source_ref,
  };
}

function createPostgresAssetStore({pool, schemaPath, logger = console}) {
  if (!pool || typeof pool.query !== 'function') throw new Error('PostgreSQL pool is required');

  async function initialize() {
    const schema = fs.readFileSync(schemaPath, 'utf8');
    await pool.query(schema);
    const version = await pool.query(
      `SELECT version FROM onion_sentinel_assets.schema_version
       WHERE component = 'asset_inventory'`,
    );
    if (Number(version.rows[0]?.version || 0) !== 1) {
      throw new Error('asset inventory PostgreSQL schema version is unsupported');
    }
  }

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

  async function importInventory(rawInventory, {actor = 'migration', replace = false} = {}) {
    if (
      !rawInventory
      || rawInventory.schema !== 'onion-sentinel-asset-inventory-v1'
      || !Array.isArray(rawInventory.assets)
      || rawInventory.assets.length > 100_000
    ) {
      throw new Error('asset inventory import failed schema validation');
    }
    const records = rawInventory.assets.map(normalizeInventoryRecord);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      if (replace) {
        await client.query('DELETE FROM onion_sentinel_assets.identifiers');
        await client.query('DELETE FROM onion_sentinel_assets.inventory_records');
      }
      for (const record of records) {
        const inserted = await client.query(
          `INSERT INTO onion_sentinel_assets.inventory_records (
             asset_id, valid_from, valid_until, role, platform, owner_ref,
             criticality, expected_services, expected_behaviors, source_type,
             source_ref, confidence, share_with_hosted_models
           ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, $11, $12, $13
           )
           ON CONFLICT (asset_id, valid_from) DO UPDATE SET
             valid_until = EXCLUDED.valid_until, role = EXCLUDED.role,
             platform = EXCLUDED.platform, owner_ref = EXCLUDED.owner_ref,
             criticality = EXCLUDED.criticality,
             expected_services = EXCLUDED.expected_services,
             expected_behaviors = EXCLUDED.expected_behaviors,
             source_type = EXCLUDED.source_type, source_ref = EXCLUDED.source_ref,
             confidence = EXCLUDED.confidence,
             share_with_hosted_models = EXCLUDED.share_with_hosted_models,
             updated_at = clock_timestamp()
           RETURNING record_id`,
          [
            record.asset_id, record.valid_from, record.valid_until, record.role,
            record.platform, record.owner_ref, record.criticality,
            JSON.stringify(record.expected_services),
            JSON.stringify(record.expected_behaviors), record.source_type,
            record.source_ref, record.confidence,
            record.share_with_hosted_models,
          ],
        );
        const recordId = inserted.rows[0].record_id;
        await client.query(
          'DELETE FROM onion_sentinel_assets.identifiers WHERE record_id = $1',
          [recordId],
        );
        for (const [kind, values] of Object.entries(record.identifiers)) {
          for (const value of values) {
            await client.query(
              `INSERT INTO onion_sentinel_assets.identifiers (
                 record_id, identifier_type, identifier_value, normalized_value
               ) VALUES ($1, $2, $3, $4)`,
              [recordId, kind, value, value.toLowerCase()],
            );
          }
        }
      }
      const overlaps = await client.query(
        `SELECT left_record.asset_id
         FROM onion_sentinel_assets.inventory_records left_record
         JOIN onion_sentinel_assets.inventory_records right_record
           ON right_record.asset_id = left_record.asset_id
          AND right_record.record_id > left_record.record_id
          AND tstzrange(
                left_record.valid_from, left_record.valid_until, '[)'
              ) && tstzrange(
                right_record.valid_from, right_record.valid_until, '[)'
              )
         LIMIT 1`,
      );
      if (overlaps.rows.length) {
        throw new Error(
          `${overlaps.rows[0].asset_id} has overlapping validity intervals`,
        );
      }
      await client.query(
        `INSERT INTO onion_sentinel_assets.audit_events
           (event_type, actor, event_data)
         VALUES ('inventory.imported', $1, $2::jsonb)`,
        [cleanText(actor, 160, 'actor'), JSON.stringify({
          records: records.length,
          replace: Boolean(replace),
          source_generated_at: String(rawInventory.generated_at || ''),
        })],
      );
      await client.query('COMMIT');
      return {ok: true, imported: records.length, replace: Boolean(replace)};
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  function normalizeDhcpState(state) {
    if (
      !state
      || state.schema !== 'onion-sentinel-dhcp-asset-observations-v1'
      || !Array.isArray(state.observations)
      || state.observations.length > 100_000
      || !state.collection
      || typeof state.collection !== 'object'
    ) {
      throw new Error('DHCP observation state failed schema validation');
    }
    const observations = state.observations.map((item) => {
      if (!item || typeof item !== 'object') throw new Error('DHCP observation is invalid');
      const discoveryId = cleanText(item.discovery_id, 20, 'discovery_id', {required: true});
      if (!/^[0-9a-f]{20}$/.test(discoveryId)) throw new Error('discovery_id is invalid');
      const currentIp = cleanText(item.current_ip, 64, 'current_ip', {required: true});
      if (!net.isIP(currentIp)) throw new Error('DHCP current_ip is invalid');
      const mac = cleanText(item.mac_address, 17, 'mac_address').toLowerCase();
      if (mac && !/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) {
        throw new Error('DHCP MAC is invalid');
      }
      return {
        ...item,
        discovery_id: discoveryId,
        current_ip: currentIp,
        mac_address: mac,
        hostname: cleanText(item.hostname, 253, 'hostname').toLowerCase().replace(/\.$/, ''),
        first_seen: timestamp(item.first_seen, 'first_seen'),
        last_seen: timestamp(item.last_seen, 'last_seen'),
        lease_expires_at: timestamp(item.lease_expires_at, 'lease_expires_at', {nullable: true}),
        observation_count: Math.max(0, Number(item.observation_count) || 0),
        message_types: stringArray(item.message_types || [], 64, 80, 'message_types'),
        sensors: stringArray(item.sensors || [], 64, 160, 'sensors'),
        evidence_ids: stringArray(item.evidence_ids || [], 128, 160, 'evidence_ids'),
      };
    });
    return {...state, observations};
  }

  async function putDhcpState(rawState, {actor = 'dhcp-collector'} = {}) {
    const state = normalizeDhcpState(rawState);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const item of state.observations) {
        await client.query(
          `INSERT INTO onion_sentinel_assets.dhcp_observations (
             discovery_id, current_ip, mac_address, hostname, identity_type,
             identity_value, first_seen, last_seen, lease_expires_at,
             observation_count, message_types, sensors, evidence_ids, raw_record
           ) VALUES (
             $1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10,
             $11::jsonb, $12::jsonb, $13::jsonb, $14::jsonb
           )
           ON CONFLICT (discovery_id) DO UPDATE SET
             current_ip = EXCLUDED.current_ip,
             mac_address = EXCLUDED.mac_address,
             hostname = EXCLUDED.hostname,
             identity_type = EXCLUDED.identity_type,
             identity_value = EXCLUDED.identity_value,
             first_seen = EXCLUDED.first_seen,
             last_seen = EXCLUDED.last_seen,
             lease_expires_at = EXCLUDED.lease_expires_at,
             observation_count = EXCLUDED.observation_count,
             message_types = EXCLUDED.message_types,
             sensors = EXCLUDED.sensors,
             evidence_ids = EXCLUDED.evidence_ids,
             raw_record = EXCLUDED.raw_record,
             updated_at = clock_timestamp()`,
          [
            item.discovery_id, item.current_ip, item.mac_address, item.hostname,
            cleanText(item.identity_type, 32, 'identity_type'),
            cleanText(item.identity_value, 253, 'identity_value'),
            item.first_seen, item.last_seen, item.lease_expires_at,
            item.observation_count, JSON.stringify(item.message_types),
            JSON.stringify(item.sensors), JSON.stringify(item.evidence_ids),
            JSON.stringify(item),
          ],
        );
      }
      const ids = state.observations.map((item) => item.discovery_id);
      if (ids.length) {
        await client.query(
          `DELETE FROM onion_sentinel_assets.dhcp_observations
           WHERE NOT (discovery_id = ANY($1::text[]))`,
          [ids],
        );
      } else {
        await client.query('DELETE FROM onion_sentinel_assets.dhcp_observations');
      }
      const stateWithoutObservations = {...state, observations: []};
      await client.query(
        `UPDATE onion_sentinel_assets.dhcp_collection_state
         SET state_json = $1::jsonb, updated_at = clock_timestamp()
         WHERE singleton = TRUE`,
        [JSON.stringify(stateWithoutObservations)],
      );
      await client.query(
        `INSERT INTO onion_sentinel_assets.audit_events
           (event_type, actor, event_data)
         VALUES ('dhcp.observations_reconciled', $1, $2::jsonb)`,
        [cleanText(actor, 160, 'actor'), JSON.stringify({
          observations: state.observations.length,
          updated_at: String(state.updated_at || ''),
          status: String(state.collection.status || ''),
        })],
      );
      await client.query('COMMIT');
      return {ok: true, retained: state.observations.length};
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async function dhcpState() {
    const [stateResult, observations] = await Promise.all([
      pool.query(
        `SELECT state_json FROM onion_sentinel_assets.dhcp_collection_state
         WHERE singleton = TRUE`,
      ),
      pool.query(
        `SELECT raw_record FROM onion_sentinel_assets.dhcp_observations
         ORDER BY last_seen DESC, discovery_id`,
      ),
    ]);
    const state = stateResult.rows[0]?.state_json || {};
    return {
      schema: 'onion-sentinel-dhcp-asset-observations-v1',
      version: 1,
      ...state,
      observations: observations.rows.map((row) => row.raw_record),
      storage_backend: 'postgresql',
    };
  }

  async function promoteDhcp(payload, {actor = 'operator'} = {}) {
    if (!payload || typeof payload !== 'object') throw new Error('promotion payload is invalid');
    const discoveryId = cleanText(payload.discovery_id, 20, 'discovery_id', {required: true});
    if (!/^[0-9a-f]{20}$/.test(discoveryId)) throw new Error('discovery_id is invalid');
    const expectedIp = cleanText(payload.expected_ip, 64, 'expected_ip', {required: true});
    if (!net.isIP(expectedIp)) throw new Error('expected_ip is invalid');
    const expectedMac = cleanText(payload.expected_mac, 17, 'expected_mac').toLowerCase();
    const expectedHostname = cleanText(payload.expected_hostname, 253, 'expected_hostname')
      .toLowerCase().replace(/\.$/, '');
    const record = normalizeInventoryRecord({
      asset_id: payload.asset_id,
      valid_from: new Date().toISOString(),
      valid_until: null,
      identifiers: {
        ip_addresses: [expectedIp],
        mac_addresses: expectedMac ? [expectedMac] : [],
        hostnames: payload.hostname || expectedHostname
          ? [payload.hostname || expectedHostname] : [],
      },
      role: payload.role,
      platform: payload.platform,
      owner_ref: payload.owner_ref || 'operator-reviewed',
      criticality: payload.criticality || 'unknown',
      expected_services: [],
      expected_behaviors: [],
      source_type: 'operator-approved-dhcp',
      source_ref: `DHCP discovery ${discoveryId}`,
      confidence: 'medium',
      share_with_hosted_models: false,
    });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const observationResult = await client.query(
        `SELECT raw_record FROM onion_sentinel_assets.dhcp_observations
         WHERE discovery_id = $1 FOR UPDATE`,
        [discoveryId],
      );
      if (observationResult.rows.length !== 1) {
        throw new Error('DHCP discovery identity is missing or ambiguous');
      }
      const observation = observationResult.rows[0].raw_record;
      if (
        String(observation.current_ip || '') !== expectedIp
        || String(observation.mac_address || '').toLowerCase() !== expectedMac
        || String(observation.hostname || '').toLowerCase().replace(/\.$/, '') !== expectedHostname
      ) {
        throw new Error('DHCP identity changed after operator review');
      }
      const lastSeen = new Date(String(observation.last_seen || '')).getTime();
      const leaseExpires = new Date(
        String(observation.lease_expires_at || observation.last_seen || ''),
      ).getTime();
      if (
        !Number.isFinite(lastSeen)
        || (lastSeen < Date.now() - 24 * 60 * 60 * 1000 && leaseExpires < Date.now())
      ) {
        throw new Error('stale DHCP identity cannot be promoted');
      }
      const normalizedIdentifiers = Object.values(record.identifiers).flat()
        .map((value) => value.toLowerCase());
      const collisions = await client.query(
        `SELECT DISTINCT inventory.asset_id
         FROM onion_sentinel_assets.identifiers identifier
         JOIN onion_sentinel_assets.inventory_records inventory USING (record_id)
         WHERE identifier.normalized_value = ANY($1::text[])
           AND inventory.valid_from <= clock_timestamp()
           AND (inventory.valid_until IS NULL OR inventory.valid_until > clock_timestamp())
         ORDER BY inventory.asset_id`,
        [normalizedIdentifiers],
      );
      if (collisions.rows.length) {
        throw new Error(
          `DHCP identity overlaps authoritative asset ${collisions.rows[0].asset_id}`,
        );
      }
      const inserted = await client.query(
        `INSERT INTO onion_sentinel_assets.inventory_records (
           asset_id, valid_from, valid_until, role, platform, owner_ref,
           criticality, expected_services, expected_behaviors, source_type,
           source_ref, confidence, share_with_hosted_models
         ) VALUES (
           $1, $2, NULL, $3, $4, $5, $6, '[]'::jsonb, '[]'::jsonb,
           $7, $8, $9, FALSE
         ) RETURNING record_id, valid_from`,
        [
          record.asset_id, record.valid_from, record.role, record.platform,
          record.owner_ref, record.criticality, record.source_type,
          `${record.source_ref}; approved ${record.valid_from}`,
          record.confidence,
        ],
      );
      const recordId = inserted.rows[0].record_id;
      for (const [kind, values] of Object.entries(record.identifiers)) {
        for (const value of values) {
          await client.query(
            `INSERT INTO onion_sentinel_assets.identifiers (
               record_id, identifier_type, identifier_value, normalized_value
             ) VALUES ($1, $2, $3, $4)`,
            [recordId, kind, value, value.toLowerCase()],
          );
        }
      }
      const fingerprint = crypto.createHash('sha256')
        .update(JSON.stringify(observation, Object.keys(observation).sort()))
        .digest('hex');
      await client.query(
        `INSERT INTO onion_sentinel_assets.review_decisions (
           discovery_id, decision, asset_id, reason, operator_ref,
           observation_fingerprint
         ) VALUES ($1, 'promoted', $2, $3, $4, $5)`,
        [
          discoveryId, record.asset_id,
          cleanText(payload.reason || 'operator-approved promotion', 1000, 'reason'),
          cleanText(actor, 300, 'actor'), fingerprint,
        ],
      );
      await client.query(
        `INSERT INTO onion_sentinel_assets.audit_events (
           event_type, actor, asset_id, discovery_id, event_data
         ) VALUES ('asset.promoted_from_dhcp', $1, $2, $3, $4::jsonb)`,
        [cleanText(actor, 160, 'actor'), record.asset_id, discoveryId, JSON.stringify({
          ip_address: expectedIp,
          mac_address: expectedMac,
          hostname: expectedHostname,
          observation_fingerprint: fingerprint,
        })],
      );
      await client.query('COMMIT');
      return {
        ok: true,
        status: 'promoted',
        asset_id: record.asset_id,
        discovery_id: discoveryId,
        valid_from: inserted.rows[0].valid_from,
        observation_fingerprint: fingerprint,
      };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async function stats() {
    const [inventory, dhcp, audits] = await Promise.all([
      pool.query('SELECT * FROM onion_sentinel_assets.inventory_counts'),
      pool.query('SELECT COUNT(*)::BIGINT AS count, MAX(last_seen) AS latest FROM onion_sentinel_assets.dhcp_observations'),
      pool.query('SELECT COUNT(*)::BIGINT AS count, MAX(occurred_at) AS latest FROM onion_sentinel_assets.audit_events'),
    ]);
    return {
      enabled: true,
      backend: 'postgresql',
      schema_version: 1,
      inventory: inventory.rows[0] || {},
      dhcp_observations: {
        count: Number(dhcp.rows[0]?.count || 0),
        latest: dhcp.rows[0]?.latest || null,
      },
      audit_events: {
        count: Number(audits.rows[0]?.count || 0),
        latest: audits.rows[0]?.latest || null,
      },
    };
  }

  return {
    initialize,
    page,
    snapshot,
    importInventory,
    putDhcpState,
    dhcpState,
    promoteDhcp,
    stats,
    normalizeInventoryRecord,
    normalizeDhcpState,
  };
}

module.exports = {
  createPostgresAssetStore,
  normalizeInventoryRecord,
};
