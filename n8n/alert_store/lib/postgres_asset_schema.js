'use strict';

const fs = require('fs');

function createPostgresAssetSchema({pool, schemaPath, fsApi = fs}) {
  async function initialize() {
    const schema = fsApi.readFileSync(schemaPath, 'utf8');
    await pool.query(schema);
    const version = await pool.query(
      `SELECT version FROM onion_sentinel_assets.schema_version
       WHERE component = 'asset_inventory'`,
    );
    if (Number(version.rows[0]?.version || 0) !== 1) {
      throw new Error('asset inventory PostgreSQL schema version is unsupported');
    }
  }

  return {initialize};
}

module.exports = {createPostgresAssetSchema};
