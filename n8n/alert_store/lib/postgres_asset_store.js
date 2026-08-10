'use strict';

const {createPostgresAssetSchema} = require('./postgres_asset_schema');
const {
  createPostgresAssetReadProjection,
} = require('./postgres_asset_read_projection');
const {
  createPostgresAssetInventoryRepository,
} = require('./postgres_asset_inventory_repository');
const {
  createPostgresAssetDhcpRepository,
} = require('./postgres_asset_dhcp_repository');
const {
  createPostgresAssetHealthProjection,
} = require('./postgres_asset_health_projection');
const {
  normalizeInventoryRecord,
  normalizeDhcpState,
} = require('./postgres_asset_normalization');

function createPostgresAssetStore({pool, schemaPath, logger = console}) {
  if (!pool || typeof pool.query !== 'function') {
    throw new Error('PostgreSQL pool is required');
  }
  // Retain the accepted compatibility option without granting it persistence
  // or credential ownership.
  void logger;
  const schema = createPostgresAssetSchema({pool, schemaPath});
  const reads = createPostgresAssetReadProjection({pool});
  const inventory = createPostgresAssetInventoryRepository({pool});
  const dhcp = createPostgresAssetDhcpRepository({pool});
  const health = createPostgresAssetHealthProjection({pool});

  return {
    initialize: schema.initialize,
    page: reads.page,
    snapshot: reads.snapshot,
    importInventory: inventory.importInventory,
    putDhcpState: dhcp.putDhcpState,
    dhcpState: dhcp.dhcpState,
    promoteDhcp: dhcp.promoteDhcp,
    approveDhcpIpChange: dhcp.approveDhcpIpChange,
    updateAsset: inventory.updateAsset,
    demoteAsset: inventory.demoteAsset,
    stats: health.stats,
    normalizeInventoryRecord,
    normalizeDhcpState,
  };
}

module.exports = {
  createPostgresAssetStore,
  normalizeInventoryRecord,
};
