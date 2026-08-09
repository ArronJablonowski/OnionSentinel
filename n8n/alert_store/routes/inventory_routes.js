'use strict';

function createInventoryRoutes({
  service,
  authorizeWrite,
  readJsonBody,
  sendJson,
  now = () => new Date(),
}) {
  if (!service || typeof service !== 'object') {
    throw new TypeError('inventory service is required');
  }
  for (const [name, value] of Object.entries({authorizeWrite, readJsonBody, sendJson, now})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  const writePayload = async (request) => {
    authorizeWrite(request);
    return readJsonBody(request);
  };

  return [
    {
      method: 'GET',
      path: '/ac-hunter/snapshot',
      handler: async ({response}) => {
        const snapshot = await service.latestAcHunterSnapshot();
        if (!snapshot) {
          sendJson(response, 404, {
            ok: false,
            status: 'not_collected',
            error: 'AC Hunter has not completed a scheduled database collection yet',
          });
          return;
        }
        sendJson(response, 200, snapshot);
      },
    },
    {
      method: 'POST',
      path: '/ac-hunter/snapshots',
      handler: async ({request, response}) => {
        const result = await service.ingestAcHunterSnapshot(await writePayload(request));
        sendJson(response, result.changed ? 201 : 200, result);
      },
    },
    {
      method: 'GET',
      path: '/software-inventory',
      handler: async ({response, parsedUrl}) => {
        const result = await service.querySoftwareInventory({
          limit: parsedUrl.searchParams.get('limit') || 100,
          offset: parsedUrl.searchParams.get('offset') || 0,
          search: parsedUrl.searchParams.get('search') || '',
          tier: parsedUrl.searchParams.get('tier') || 'all',
          confidence: parsedUrl.searchParams.get('confidence') || 'all',
          freshness: parsedUrl.searchParams.get('freshness') || 'all',
          platform: parsedUrl.searchParams.get('platform') || 'all',
          window: parsedUrl.searchParams.get('window') || '30d',
          sort: parsedUrl.searchParams.get('sort') || 'last_seen',
          direction: parsedUrl.searchParams.get('direction') || 'desc',
          observed_at: parsedUrl.searchParams.get('observed_at') || now().toISOString(),
        });
        sendJson(response, 200, result);
      },
    },
    ...[
      ['/software-inventory/import/start', 'startSoftwareImport'],
      ['/software-inventory/import/chunk', 'putSoftwareImportChunk'],
      ['/software-inventory/import/commit', 'commitSoftwareImport'],
    ].map(([path, method]) => ({
      method: 'POST',
      path,
      handler: async ({request, response}) => {
        sendJson(response, 200, await service[method](await writePayload(request)));
      },
    })),
    {
      method: 'GET',
      path: '/assets/inventory',
      handler: async ({response, parsedUrl}) => {
        const result = await service.pageAssets({
          limit: parsedUrl.searchParams.get('limit') || 250,
          offset: parsedUrl.searchParams.get('offset') || 0,
          search: parsedUrl.searchParams.get('search') || '',
          sort: parsedUrl.searchParams.get('sort') || 'asset_id',
          direction: parsedUrl.searchParams.get('direction') || 'asc',
          state: parsedUrl.searchParams.get('state') || 'current',
          at: parsedUrl.searchParams.get('at') || now(),
        });
        sendJson(response, 200, result);
      },
    },
    {
      method: 'GET',
      path: '/assets/snapshot',
      handler: async ({response}) => {
        sendJson(response, 200, {ok: true, inventory: await service.assetSnapshot()});
      },
    },
    {
      method: 'GET',
      path: '/assets/dhcp-state',
      handler: async ({response}) => {
        sendJson(response, 200, {ok: true, state: await service.assetDhcpState()});
      },
    },
    ...[
      ['/assets/import', 'importAssets', 200],
      ['/assets/dhcp-state', 'putAssetDhcpState', 200],
      ['/assets/promote-dhcp', 'promoteDhcpAsset', 201],
      ['/assets/approve-dhcp-ip-change', 'approveDhcpIpChange', 201],
      ['/assets/update', 'updateAsset', 200],
      ['/assets/demote', 'demoteAsset', 200],
    ].map(([path, method, status]) => ({
      method: 'POST',
      path,
      handler: async ({request, response}) => {
        sendJson(response, status, await service[method](await writePayload(request)));
      },
    })),
  ];
}

module.exports = {createInventoryRoutes};
