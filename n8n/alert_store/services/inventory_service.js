'use strict';

function requireFunction(value, name) {
  if (typeof value !== 'function') {
    throw new TypeError(`${name} must be a function`);
  }
  return value;
}

function createInventoryService({
  requireAcHunterStore,
  requireSoftwareStore,
  requireAssetStore,
}) {
  const acHunterStore = requireFunction(requireAcHunterStore, 'requireAcHunterStore');
  const softwareStore = requireFunction(requireSoftwareStore, 'requireSoftwareStore');
  const assetStore = requireFunction(requireAssetStore, 'requireAssetStore');

  return {
    latestAcHunterSnapshot: () => acHunterStore().latest(),
    ingestAcHunterSnapshot: (payload) => acHunterStore().ingest(payload),
    querySoftwareInventory: (query) => softwareStore().query(query),
    startSoftwareImport: (payload) => softwareStore().startImport(payload),
    putSoftwareImportChunk: (payload) => softwareStore().putChunk(payload),
    commitSoftwareImport: (payload) => softwareStore().commitImport(payload),
    pageAssets: (query) => assetStore().page(query),
    assetSnapshot: () => assetStore().snapshot(),
    assetDhcpState: () => assetStore().dhcpState(),
    importAssets: (payload) => assetStore().importInventory(payload.inventory, {
      actor: payload.actor || 'migration',
      replace: payload.replace === true,
    }),
    putAssetDhcpState: (payload) => assetStore().putDhcpState(payload.state, {
      actor: payload.actor || 'dhcp-collector',
    }),
    promoteDhcpAsset: (payload) => assetStore().promoteDhcp(payload, {
      actor: payload.operator_ref || 'operator',
    }),
    approveDhcpIpChange: (payload) => assetStore().approveDhcpIpChange(payload, {
      actor: payload.operator_ref || 'operator',
    }),
    updateAsset: (payload) => assetStore().updateAsset(payload, {
      actor: payload.operator_ref || 'operator',
    }),
    demoteAsset: (payload) => assetStore().demoteAsset(payload, {
      actor: payload.operator_ref || 'operator',
    }),
  };
}

module.exports = {createInventoryService};
