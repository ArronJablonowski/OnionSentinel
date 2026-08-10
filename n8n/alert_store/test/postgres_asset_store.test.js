'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const {
  createPostgresAssetStore,
  normalizeInventoryRecord,
} = require('../lib/postgres_asset_store');

const schemaPath = path.join(__dirname, '../../postgres/asset-inventory-schema.sql');

function validInventoryRecord(overrides = {}) {
  return {
    asset_id: 'asset-1',
    valid_from: '2026-08-01T12:00:00-06:00',
    valid_until: null,
    identifiers: {
      ip_addresses: ['192.0.2.10'],
      mac_addresses: ['00-11-22-33-44-55'],
      hostnames: ['Example.LAN.'],
    },
    role: 'workstation',
    platform: 'macOS',
    owner_ref: 'owner',
    criticality: 'high',
    expected_services: [],
    expected_behaviors: [],
    source_type: 'operator',
    source_ref: 'review',
    confidence: 'high',
    share_with_hosted_models: false,
    ...overrides,
  };
}

test('inventory normalization preserves exact identity and provenance contract', () => {
  assert.deepEqual(normalizeInventoryRecord(validInventoryRecord()), {
    asset_id: 'asset-1',
    valid_from: '2026-08-01T18:00:00.000Z',
    valid_until: null,
    identifiers: {
      ip: ['192.0.2.10'],
      mac: ['00:11:22:33:44:55'],
      hostname: ['example.lan'],
    },
    role: 'workstation',
    platform: 'macOS',
    owner_ref: 'owner',
    criticality: 'high',
    expected_services: [],
    expected_behaviors: [],
    source_type: 'operator',
    source_ref: 'review',
    confidence: 'high',
    share_with_hosted_models: false,
  });
  assert.throws(
    () => normalizeInventoryRecord(validInventoryRecord({
      valid_until: '2026-08-01T11:59:59-06:00',
    })),
    /valid_until must be later than valid_from/,
  );
  assert.throws(
    () => normalizeInventoryRecord(validInventoryRecord({
      share_with_hosted_models: 'false',
    })),
    /share_with_hosted_models must be boolean/,
  );
});

test('DHCP normalization bounds evidence and preserves offset-aware timestamps', () => {
  const store = createPostgresAssetStore({
    pool: {query: async () => ({rows: []})},
    schemaPath: '/unused',
  });
  const normalized = store.normalizeDhcpState({
    schema: 'onion-sentinel-dhcp-asset-observations-v1',
    version: 1,
    collection: {status: 'ready'},
    observations: [{
      discovery_id: '0123456789abcdef0123',
      current_ip: '192.0.2.20',
      mac_address: '00:11:22:33:44:66',
      hostname: 'Host.LAN.',
      first_seen: '2026-08-01T12:00:00-06:00',
      last_seen: '2026-08-01T12:01:00-06:00',
      lease_expires_at: null,
      observation_count: '2',
      message_types: ['ACK', 'ACK'],
      sensors: ['sensor-1'],
      evidence_ids: ['evidence-1'],
    }],
  });
  assert.equal(normalized.observations[0].hostname, 'host.lan');
  assert.equal(normalized.observations[0].first_seen, '2026-08-01T18:00:00.000Z');
  assert.equal(normalized.observations[0].observation_count, 2);
  assert.deepEqual(normalized.observations[0].message_types, ['ACK']);
});

test('paged reads clamp bounds and retain allowlisted deterministic ordering', async () => {
  const calls = [];
  const pool = {
    query: async (sql, params = []) => {
      calls.push({sql: String(sql), params});
      if (String(sql).includes('COUNT(*)::BIGINT AS count')) {
        return {rows: [{count: '1'}]};
      }
      if (String(sql).includes('SELECT record.*')) {
        return {rows: [{
          record_id: 1,
          asset_id: 'asset-1',
          valid_from: new Date('2026-08-01T18:00:00Z'),
          valid_until: null,
          ip_addresses: ['192.0.2.10'],
          mac_addresses: ['00:11:22:33:44:55'],
          hostnames: ['asset-1.lan'],
          role: 'workstation',
          platform: 'macOS',
          criticality: 'high',
          confidence: 'high',
          source_type: 'operator',
          source_ref: 'review',
        }]};
      }
      if (String(sql).includes('inventory_counts')) {
        return {rows: [{records_total: '1', current_records: '1'}]};
      }
      if (String(sql).includes('GROUP BY identifier_type')) {
        return {rows: [
          {identifier_type: 'ip', count: '1'},
          {identifier_type: 'hostname', count: '1'},
        ]};
      }
      throw new Error(`unexpected query: ${sql}`);
    },
  };
  const store = createPostgresAssetStore({pool, schemaPath: '/unused'});
  const page = await store.page({
    limit: 999,
    offset: 99_999_999,
    state: 'all',
    sort: 'platform',
    direction: 'desc',
    at: '2026-08-02T00:00:00Z',
  });
  const recordQuery = calls.find((call) => call.sql.includes('SELECT record.*'));
  assert.deepEqual(recordQuery.params, [
    '2026-08-02T00:00:00.000Z', 500, 10_000_000,
  ]);
  assert.match(recordQuery.sql, /ORDER BY lower\(record\.platform\) DESC, record\.record_id DESC/);
  assert.equal(page.page.limit, 500);
  assert.equal(page.page.offset, 10_000_000);
  assert.equal(page.page.filtered_total, 1);
  assert.equal(page.assets[0].state, 'current');
  assert.equal(page.storage_backend, 'postgresql');
});

test('schema initialization executes the checked-in schema and requires version one', async () => {
  const calls = [];
  const store = createPostgresAssetStore({
    pool: {
      query: async (sql) => {
        calls.push(String(sql));
        if (String(sql).includes('SELECT version')) return {rows: [{version: 1}]};
        return {rows: []};
      },
    },
    schemaPath,
  });
  await store.initialize();
  assert.match(calls[0], /CREATE SCHEMA IF NOT EXISTS onion_sentinel_assets/);
  assert.match(calls[1], /WHERE component = 'asset_inventory'/);

  const rejected = createPostgresAssetStore({
    pool: {query: async (sql) => (
      String(sql).includes('SELECT version') ? {rows: [{version: 2}]} : {rows: []}
    )},
    schemaPath,
  });
  await assert.rejects(
    () => rejected.initialize(),
    /asset inventory PostgreSQL schema version is unsupported/,
  );
});

test('snapshot uses bounded all-state pages and preserves inventory schema', async () => {
  const calls = [];
  const pool = {
    query: async (sql, params = []) => {
      calls.push({sql: String(sql), params});
      if (String(sql).includes('COUNT(*)::BIGINT AS count')) {
        return {rows: [{count: '1'}]};
      }
      if (String(sql).includes('SELECT record.*')) {
        return {rows: [{
          record_id: 1,
          asset_id: 'asset-1',
          valid_from: new Date('2026-08-01T18:00:00Z'),
          valid_until: null,
          ip_addresses: ['192.0.2.10'],
          mac_addresses: [],
          hostnames: ['asset-1.lan'],
          role: 'workstation',
          platform: 'macOS',
          owner_ref: 'owner',
          criticality: 'high',
          expected_services: [],
          expected_behaviors: [],
          source_type: 'operator',
          source_ref: 'review',
          confidence: 'high',
          share_with_hosted_models: false,
        }]};
      }
      throw new Error(`unexpected query: ${sql}`);
    },
  };
  const store = createPostgresAssetStore({pool, schemaPath: '/unused'});
  const snapshot = await store.snapshot();
  const recordQuery = calls.find((call) => call.sql.includes('SELECT record.*'));
  assert.deepEqual(recordQuery.params.slice(1), [500, 0]);
  assert.match(recordQuery.sql, /\$1::timestamptz IS NOT NULL/);
  assert.equal(snapshot.schema, 'onion-sentinel-asset-inventory-v1');
  assert.equal(snapshot.inventory_status, 'database');
  assert.equal(snapshot.assets[0].asset_id, 'asset-1');
  assert.deepEqual(snapshot.assets[0].identifiers.ip_addresses, ['192.0.2.10']);
});
