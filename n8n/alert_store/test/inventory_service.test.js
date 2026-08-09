'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createInventoryService} = require('../services/inventory_service');

test('keeps asset actor defaults and replacement semantics in one service boundary', async () => {
  const calls = [];
  const assetStore = {
    importInventory: async (...args) => calls.push(args),
    updateAsset: async (...args) => calls.push(args),
  };
  const service = createInventoryService({
    requireAcHunterStore: () => ({}),
    requireSoftwareStore: () => ({}),
    requireAssetStore: () => assetStore,
  });
  await service.importAssets({inventory: [{asset_id: 'asset-1'}], replace: true});
  await service.updateAsset({asset_id: 'asset-1', operator_ref: 'operator-7'});
  assert.deepEqual(calls, [
    [[{asset_id: 'asset-1'}], {actor: 'migration', replace: true}],
    [{asset_id: 'asset-1', operator_ref: 'operator-7'}, {actor: 'operator-7'}],
  ]);
});

test('fails closed when a required persistence provider is missing', () => {
  assert.throws(() => createInventoryService({
    requireAcHunterStore: () => ({}),
    requireSoftwareStore: null,
    requireAssetStore: () => ({}),
  }), /requireSoftwareStore must be a function/);
});
