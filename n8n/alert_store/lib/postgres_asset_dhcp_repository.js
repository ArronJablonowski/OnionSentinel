'use strict';

const net = require('net');
const {
  cleanText,
  normalizeMac,
  macScope,
  normalizedHostname,
  assertFreshObservation,
  observationFingerprint,
  normalizeInventoryRecord,
  normalizeDhcpState,
} = require('./postgres_asset_normalization');

function createPostgresAssetDhcpRepository({pool}) {
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
    const expectedMac = normalizeMac(
      payload.expected_mac,
      'expected_mac',
      {required: true},
    );
    const expectedMacScope = macScope(expectedMac);
    if (expectedMacScope === 'multicast') {
      throw new Error('multicast MAC address cannot identify an asset');
    }
    if (
      expectedMacScope === 'locally_administered'
      && payload.accept_locally_administered_mac !== true
    ) {
      throw new Error(
        'locally administered MAC requires explicit operator acceptance',
      );
    }
    const expectedHostname = normalizedHostname(payload.expected_hostname);
    if (cleanText(payload.confirm, 64, 'confirm', {required: true})
      !== `PROMOTE:${discoveryId}`) {
      throw new Error('explicit DHCP promotion confirmation is required');
    }
    const reason = cleanText(payload.reason, 1000, 'reason', {required: true});
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
      assertFreshObservation(observation);
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
      const assetIdCollision = await client.query(
        `SELECT asset_id
         FROM onion_sentinel_assets.inventory_records
         WHERE lower(asset_id) = lower($1)
           AND valid_from <= clock_timestamp()
           AND (
             valid_until IS NULL
             OR valid_until > clock_timestamp()
           )
         ORDER BY valid_from DESC
         LIMIT 1`,
        [record.asset_id],
      );
      if (assetIdCollision.rows.length) {
        throw new Error(
          `asset name already belongs to authoritative asset ${assetIdCollision.rows[0].asset_id}`,
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
      const fingerprint = observationFingerprint(observation);
      await client.query(
        `INSERT INTO onion_sentinel_assets.review_decisions (
           discovery_id, decision, asset_id, reason, operator_ref,
           observation_fingerprint
         ) VALUES ($1, 'promoted', $2, $3, $4, $5)`,
        [
          discoveryId, record.asset_id,
          reason,
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

  async function approveDhcpIpChange(payload, {actor = 'operator'} = {}) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new Error('IP change payload is invalid');
    }
    const discoveryId = cleanText(
      payload.discovery_id,
      20,
      'discovery_id',
      {required: true},
    );
    if (!/^[0-9a-f]{20}$/.test(discoveryId)) {
      throw new Error('discovery_id is invalid');
    }
    const assetId = cleanText(
      payload.asset_id,
      160,
      'asset_id',
      {required: true},
    );
    const expectedIp = cleanText(
      payload.expected_ip,
      64,
      'expected_ip',
      {required: true},
    );
    if (!net.isIP(expectedIp)) throw new Error('expected_ip is invalid');
    const expectedMac = normalizeMac(payload.expected_mac, 'expected_mac');
    const expectedHostname = normalizedHostname(payload.expected_hostname);
    const reason = cleanText(payload.reason, 1000, 'reason', {required: true});
    if (
      cleanText(payload.confirm, 256, 'confirm', {required: true})
      !== `CHANGE-IP:${discoveryId}:${assetId}`
    ) {
      throw new Error('explicit DHCP IP-change confirmation is required');
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const observationResult = await client.query(
        `SELECT raw_record
         FROM onion_sentinel_assets.dhcp_observations
         WHERE discovery_id = $1
         FOR UPDATE`,
        [discoveryId],
      );
      if (observationResult.rows.length !== 1) {
        throw new Error('DHCP discovery identity is missing or ambiguous');
      }
      const observation = observationResult.rows[0].raw_record;
      if (
        String(observation.current_ip || '') !== expectedIp
        || String(observation.mac_address || '').toLowerCase() !== expectedMac
        || String(observation.hostname || '').toLowerCase().replace(/\.$/, '')
          !== expectedHostname
      ) {
        throw new Error('DHCP identity changed after operator review');
      }
      assertFreshObservation(observation);

      const currentResult = await client.query(
        `SELECT record.*
         FROM onion_sentinel_assets.inventory_records record
         WHERE record.asset_id = $1
           AND record.valid_from <= clock_timestamp()
           AND (
             record.valid_until IS NULL
             OR record.valid_until > clock_timestamp()
           )
         FOR UPDATE`,
        [assetId],
      );
      if (currentResult.rows.length !== 1) {
        throw new Error('authoritative asset identity is missing or ambiguous');
      }
      const current = currentResult.rows[0];
      const identifierResult = await client.query(
        `SELECT identifier_type, identifier_value, normalized_value
         FROM onion_sentinel_assets.identifiers
         WHERE record_id = $1
         ORDER BY identifier_type, normalized_value`,
        [current.record_id],
      );
      current.ip_addresses = identifierResult.rows
        .filter((item) => item.identifier_type === 'ip')
        .map((item) => item.identifier_value);
      current.mac_addresses = identifierResult.rows
        .filter((item) => item.identifier_type === 'mac')
        .map((item) => item.normalized_value);
      current.hostnames = identifierResult.rows
        .filter((item) => item.identifier_type === 'hostname')
        .map((item) => item.normalized_value);
      const stableMatch = (
        expectedMac && current.mac_addresses.includes(expectedMac)
      ) || (
        expectedHostname && current.hostnames.includes(expectedHostname)
      );
      if (!stableMatch) {
        throw new Error(
          'DHCP observation does not match an authoritative hostname or MAC',
        );
      }
      if (current.ip_addresses.includes(expectedIp)) {
        throw new Error('DHCP address already matches authoritative inventory');
      }
      const stableCollisions = expectedMac || expectedHostname
        ? await client.query(
          `SELECT DISTINCT record.asset_id
           FROM onion_sentinel_assets.identifiers identifier
           JOIN onion_sentinel_assets.inventory_records record USING (record_id)
           WHERE (
               (
                 identifier.identifier_type = 'mac'
                 AND identifier.normalized_value = $1
               )
               OR (
                 identifier.identifier_type = 'hostname'
                 AND identifier.normalized_value = $2
               )
             )
             AND record.asset_id <> $3
             AND record.valid_from <= clock_timestamp()
             AND (
               record.valid_until IS NULL
               OR record.valid_until > clock_timestamp()
             )
           ORDER BY record.asset_id`,
          [expectedMac, expectedHostname, assetId],
        )
        : {rows: []};
      if (stableCollisions.rows.length) {
        throw new Error(
          `DHCP stable identity overlaps authoritative asset ${stableCollisions.rows[0].asset_id}`,
        );
      }
      const ipCollision = await client.query(
        `SELECT DISTINCT record.asset_id
         FROM onion_sentinel_assets.identifiers identifier
         JOIN onion_sentinel_assets.inventory_records record USING (record_id)
         WHERE identifier.identifier_type = 'ip'
           AND identifier.normalized_value = $1
           AND record.asset_id <> $2
           AND record.valid_from <= clock_timestamp()
           AND (
             record.valid_until IS NULL
             OR record.valid_until > clock_timestamp()
           )
         ORDER BY record.asset_id`,
        [expectedIp.toLowerCase(), assetId],
      );
      if (ipCollision.rows.length) {
        throw new Error(
          `DHCP address belongs to authoritative asset ${ipCollision.rows[0].asset_id}`,
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
      const sourceRef = cleanText(
        `DHCP discovery ${discoveryId}; supersedes record ${current.record_id}`,
        500,
        'source_ref',
      );
      const inserted = await client.query(
        `INSERT INTO onion_sentinel_assets.inventory_records (
           asset_id, valid_from, valid_until, role, platform, owner_ref,
           criticality, expected_services, expected_behaviors, source_type,
           source_ref, confidence, share_with_hosted_models
         ) VALUES (
           $1, $2, NULL, $3, $4, $5, $6, $7::jsonb, $8::jsonb,
           'operator-approved-dhcp-ip-change', $9, $10, $11
         )
         RETURNING record_id, valid_from`,
        [
          current.asset_id,
          changedAt,
          current.role,
          current.platform,
          current.owner_ref,
          current.criticality,
          JSON.stringify(current.expected_services),
          JSON.stringify(current.expected_behaviors),
          sourceRef,
          current.confidence,
          current.share_with_hosted_models,
        ],
      );
      const newRecordId = inserted.rows[0].record_id;
      await client.query(
        `INSERT INTO onion_sentinel_assets.identifiers (
           record_id, identifier_type, identifier_value, normalized_value
         )
         SELECT $1, identifier_type, identifier_value, normalized_value
         FROM onion_sentinel_assets.identifiers
         WHERE record_id = $2
           AND identifier_type <> 'ip'`,
        [newRecordId, current.record_id],
      );
      await client.query(
        `INSERT INTO onion_sentinel_assets.identifiers (
           record_id, identifier_type, identifier_value, normalized_value
         ) VALUES ($1, 'ip', $2, $3)`,
        [newRecordId, expectedIp, expectedIp.toLowerCase()],
      );
      const fingerprint = observationFingerprint(observation);
      await client.query(
        `INSERT INTO onion_sentinel_assets.review_decisions (
           discovery_id, decision, asset_id, reason, operator_ref,
           observation_fingerprint
         ) VALUES ($1, 'ip_change_approved', $2, $3, $4, $5)`,
        [
          discoveryId,
          assetId,
          reason,
          cleanText(actor, 300, 'actor'),
          fingerprint,
        ],
      );
      await client.query(
        `INSERT INTO onion_sentinel_assets.audit_events (
           event_type, actor, asset_id, discovery_id, event_data
         ) VALUES (
           'asset.ip_address_changed_from_dhcp',
           $1, $2, $3, $4::jsonb
         )`,
        [
          cleanText(actor, 160, 'actor'),
          assetId,
          discoveryId,
          JSON.stringify({
            previous_ip_addresses: current.ip_addresses,
            current_ip_address: expectedIp,
            previous_record_id: current.record_id,
            current_record_id: newRecordId,
            observation_fingerprint: fingerprint,
          }),
        ],
      );
      await client.query('COMMIT');
      return {
        ok: true,
        status: 'ip_change_approved',
        asset_id: assetId,
        discovery_id: discoveryId,
        previous_ip_addresses: current.ip_addresses,
        current_ip_address: expectedIp,
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

  return {putDhcpState, dhcpState, promoteDhcp, approveDhcpIpChange};
}

module.exports = {createPostgresAssetDhcpRepository};

