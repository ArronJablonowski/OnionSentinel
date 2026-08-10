'use strict';

const {
  cleanText,
  timestamp,
  normalizeInventoryRecord,
} = require('./postgres_asset_normalization');

function createPostgresAssetInventoryRepository({pool}) {
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
      const importJson = JSON.stringify(records);
      await client.query(
        `INSERT INTO onion_sentinel_assets.inventory_records (
           asset_id, valid_from, valid_until, role, platform, owner_ref,
           criticality, expected_services, expected_behaviors, source_type,
           source_ref, confidence, share_with_hosted_models
         )
         SELECT asset_id, valid_from, valid_until, role, platform, owner_ref,
                criticality, expected_services, expected_behaviors, source_type,
                source_ref, confidence, share_with_hosted_models
         FROM jsonb_to_recordset($1::jsonb) AS incoming (
           asset_id TEXT, valid_from TIMESTAMPTZ, valid_until TIMESTAMPTZ,
           identifiers JSONB, role TEXT, platform TEXT, owner_ref TEXT,
           criticality TEXT, expected_services JSONB,
           expected_behaviors JSONB, source_type TEXT, source_ref TEXT,
           confidence TEXT, share_with_hosted_models BOOLEAN
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
           updated_at = clock_timestamp()`,
        [importJson],
      );
      await client.query(
        `DELETE FROM onion_sentinel_assets.identifiers identifier
         USING onion_sentinel_assets.inventory_records record,
               jsonb_to_recordset($1::jsonb) AS incoming (
                 asset_id TEXT, valid_from TIMESTAMPTZ
               )
         WHERE identifier.record_id = record.record_id
           AND record.asset_id = incoming.asset_id
           AND record.valid_from = incoming.valid_from`,
        [importJson],
      );
      await client.query(
        `INSERT INTO onion_sentinel_assets.identifiers (
           record_id, identifier_type, identifier_value, normalized_value
         )
         SELECT record.record_id, kind.key, value.identifier_value,
                lower(value.identifier_value)
         FROM jsonb_to_recordset($1::jsonb) AS incoming (
           asset_id TEXT, valid_from TIMESTAMPTZ, identifiers JSONB
         )
         JOIN onion_sentinel_assets.inventory_records record
           ON record.asset_id = incoming.asset_id
          AND record.valid_from = incoming.valid_from
         CROSS JOIN LATERAL jsonb_each(incoming.identifiers) kind
         CROSS JOIN LATERAL jsonb_array_elements_text(kind.value)
           value(identifier_value)`,
        [importJson],
      );
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
  async function updateAsset(payload, {actor = 'operator'} = {}) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new Error('asset edit payload is invalid');
    }
    const assetId = cleanText(payload.asset_id, 160, 'asset_id', {required: true});
    const expectedValidFrom = timestamp(
      payload.expected_valid_from,
      'expected_valid_from',
    );
    if (
      cleanText(payload.confirm, 256, 'confirm', {required: true})
      !== `EDIT:${assetId}`
    ) {
      throw new Error('explicit asset edit confirmation is required');
    }
    const reason = cleanText(payload.reason, 1000, 'reason', {required: true});
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const currentResult = await client.query(
        `SELECT record.*
         FROM onion_sentinel_assets.inventory_records record
         WHERE record.asset_id = $1
           AND record.valid_from = $2::timestamptz
           AND record.valid_from <= clock_timestamp()
           AND (
             record.valid_until IS NULL
             OR record.valid_until > clock_timestamp()
           )
         FOR UPDATE`,
        [assetId, expectedValidFrom],
      );
      if (currentResult.rows.length !== 1) {
        throw new Error('asset changed after the edit form was opened');
      }
      const current = currentResult.rows[0];
      const desired = normalizeInventoryRecord({
        asset_id: assetId,
        valid_from: new Date().toISOString(),
        valid_until: null,
        identifiers: {
          ip_addresses: payload.ip_addresses,
          mac_addresses: payload.mac_addresses,
          hostnames: payload.hostnames,
        },
        role: payload.role,
        platform: payload.platform,
        owner_ref: current.owner_ref,
        criticality: payload.criticality,
        expected_services: current.expected_services,
        expected_behaviors: current.expected_behaviors,
        source_type: 'operator-edited',
        source_ref: `Asset edit superseding record ${current.record_id}`,
        confidence: payload.confidence,
        share_with_hosted_models: current.share_with_hosted_models,
      });
      const normalizedIdentifiers = Object.values(desired.identifiers).flat()
        .map((value) => value.toLowerCase());
      const collisions = await client.query(
        `SELECT DISTINCT record.asset_id
         FROM onion_sentinel_assets.identifiers identifier
         JOIN onion_sentinel_assets.inventory_records record USING (record_id)
         WHERE identifier.normalized_value = ANY($1::text[])
           AND record.record_id <> $2
           AND record.valid_from <= clock_timestamp()
           AND (
             record.valid_until IS NULL
             OR record.valid_until > clock_timestamp()
           )
         ORDER BY record.asset_id`,
        [normalizedIdentifiers, current.record_id],
      );
      if (collisions.rows.length) {
        throw new Error(
          `edited identity overlaps authoritative asset ${collisions.rows[0].asset_id}`,
        );
      }
      const transition = await client.query(
        'SELECT clock_timestamp() AS changed_at',
      );
      const changedAt = transition.rows[0].changed_at;
      await client.query(
        `UPDATE onion_sentinel_assets.inventory_records
         SET valid_until = $1, updated_at = clock_timestamp()
         WHERE record_id = $2`,
        [changedAt, current.record_id],
      );
      const inserted = await client.query(
        `INSERT INTO onion_sentinel_assets.inventory_records (
           asset_id, valid_from, valid_until, role, platform, owner_ref,
           criticality, expected_services, expected_behaviors, source_type,
           source_ref, confidence, share_with_hosted_models
         ) VALUES (
           $1, $2, NULL, $3, $4, $5, $6, $7::jsonb, $8::jsonb,
           $9, $10, $11, $12
         )
         RETURNING record_id, valid_from`,
        [
          desired.asset_id,
          changedAt,
          desired.role,
          desired.platform,
          desired.owner_ref,
          desired.criticality,
          JSON.stringify(desired.expected_services),
          JSON.stringify(desired.expected_behaviors),
          desired.source_type,
          desired.source_ref,
          desired.confidence,
          desired.share_with_hosted_models,
        ],
      );
      const newRecordId = inserted.rows[0].record_id;
      for (const [kind, values] of Object.entries(desired.identifiers)) {
        for (const value of values) {
          await client.query(
            `INSERT INTO onion_sentinel_assets.identifiers (
               record_id, identifier_type, identifier_value, normalized_value
             ) VALUES ($1, $2, $3, $4)`,
            [newRecordId, kind, value, value.toLowerCase()],
          );
        }
      }
      await client.query(
        `INSERT INTO onion_sentinel_assets.audit_events (
           event_type, actor, asset_id, event_data
         ) VALUES ('asset.edited', $1, $2, $3::jsonb)`,
        [
          cleanText(actor, 160, 'actor'),
          assetId,
          JSON.stringify({
            reason,
            previous_record_id: current.record_id,
            current_record_id: newRecordId,
            identifiers: desired.identifiers,
            role: desired.role,
            platform: desired.platform,
            criticality: desired.criticality,
            confidence: desired.confidence,
          }),
        ],
      );
      await client.query('COMMIT');
      return {
        ok: true,
        status: 'edited',
        asset_id: assetId,
        valid_from: inserted.rows[0].valid_from,
      };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }
  async function demoteAsset(payload, {actor = 'operator'} = {}) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new Error('asset demotion payload is invalid');
    }
    const assetId = cleanText(payload.asset_id, 160, 'asset_id', {required: true});
    const expectedValidFrom = timestamp(
      payload.expected_valid_from,
      'expected_valid_from',
    );
    if (
      cleanText(payload.confirm, 256, 'confirm', {required: true})
      !== `DEMOTE:${assetId}`
    ) {
      throw new Error('explicit asset demotion confirmation is required');
    }
    const reason = cleanText(payload.reason, 1000, 'reason', {required: true});
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const currentResult = await client.query(
        `SELECT record.*
         FROM onion_sentinel_assets.inventory_records record
         WHERE record.asset_id = $1
           AND record.valid_from = $2::timestamptz
           AND record.valid_from <= clock_timestamp()
           AND (
             record.valid_until IS NULL
             OR record.valid_until > clock_timestamp()
           )
         FOR UPDATE`,
        [assetId, expectedValidFrom],
      );
      if (currentResult.rows.length !== 1) {
        throw new Error('asset changed after the demotion form was opened');
      }
      const current = currentResult.rows[0];
      const identifierResult = await client.query(
        `SELECT identifier_type, normalized_value
         FROM onion_sentinel_assets.identifiers
         WHERE record_id = $1`,
        [current.record_id],
      );
      const identifiers = {
        ip: identifierResult.rows
          .filter((item) => item.identifier_type === 'ip')
          .map((item) => item.normalized_value),
        mac: identifierResult.rows
          .filter((item) => item.identifier_type === 'mac')
          .map((item) => item.normalized_value),
        hostname: identifierResult.rows
          .filter((item) => item.identifier_type === 'hostname')
          .map((item) => item.normalized_value),
      };
      const observations = await client.query(
        `SELECT discovery_id, last_seen
         FROM onion_sentinel_assets.dhcp_observations
         WHERE current_ip::text = ANY($1::text[])
            OR lower(mac_address) = ANY($2::text[])
            OR lower(hostname) = ANY($3::text[])
         ORDER BY last_seen DESC, discovery_id`,
        [identifiers.ip, identifiers.mac, identifiers.hostname],
      );
      if (!observations.rows.length) {
        throw new Error(
          'asset has no preserved DHCP observation to return to review',
        );
      }
      const transition = await client.query(
        'SELECT clock_timestamp() AS changed_at',
      );
      const changedAt = transition.rows[0].changed_at;
      await client.query(
        `UPDATE onion_sentinel_assets.inventory_records
         SET valid_until = $1, updated_at = clock_timestamp()
         WHERE record_id = $2`,
        [changedAt, current.record_id],
      );
      const discoveryIds = observations.rows.map((row) => row.discovery_id);
      await client.query(
        `INSERT INTO onion_sentinel_assets.audit_events (
           event_type, actor, asset_id, discovery_id, event_data
         ) VALUES ('asset.demoted_to_dhcp', $1, $2, $3, $4::jsonb)`,
        [
          cleanText(actor, 160, 'actor'),
          assetId,
          discoveryIds[0],
          JSON.stringify({
            reason,
            previous_record_id: current.record_id,
            returned_discovery_ids: discoveryIds,
          }),
        ],
      );
      await client.query('COMMIT');
      return {
        ok: true,
        status: 'demoted',
        asset_id: assetId,
        valid_until: changedAt,
        discovery_ids: discoveryIds,
      };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  return {importInventory, updateAsset, demoteAsset};
}

module.exports = {createPostgresAssetInventoryRepository};

