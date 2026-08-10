'use strict';

function createPostgresAssetHealthProjection({pool}) {
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

  return {stats};
}

module.exports = {createPostgresAssetHealthProjection};
