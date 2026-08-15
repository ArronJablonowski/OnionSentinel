'use strict';

const ALERT_STORE_SCHEMA_VERSION = 1;
const SCHEMA_VERSION_KEY = 'schema_version';

function createAlertStoreSchemaVersion({run, get}) {
  for (const [name, value] of Object.entries({run, get})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function parseVersion(row, {required}) {
    if (!row) {
      if (required) throw new Error('alert-store schema version is missing');
      return null;
    }
    const text = String(row.value || '');
    if (!/^[1-9][0-9]*$/.test(text) || !Number.isSafeInteger(Number(text))) {
      throw new Error('alert-store schema version is invalid');
    }
    return Number(text);
  }

  async function readVersion({required}) {
    let row;
    try {
      row = await get(
        'SELECT value FROM alert_store_metadata WHERE key = ?',
        [SCHEMA_VERSION_KEY],
      );
    } catch (error) {
      if (required && /no such table/i.test(String(error?.message || error))) {
        throw new Error('alert-store schema version is missing');
      }
      throw error;
    }
    return parseVersion(row, {required});
  }

  async function prepareMigration() {
    await run(`
      CREATE TABLE IF NOT EXISTS alert_store_metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);
    const current = await readVersion({required: false});
    if (current !== null && current > ALERT_STORE_SCHEMA_VERSION) {
      throw new Error(`alert-store database has newer schema version ${current}`);
    }
    return {from: current, to: ALERT_STORE_SCHEMA_VERSION};
  }

  async function persistCurrent() {
    await run(
      `INSERT INTO alert_store_metadata (key, value, updated_at)
       VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
       ON CONFLICT(key) DO UPDATE SET
         value = excluded.value,
         updated_at = excluded.updated_at`,
      [SCHEMA_VERSION_KEY, String(ALERT_STORE_SCHEMA_VERSION)],
    );
  }

  async function assertCurrent() {
    const current = await readVersion({required: true});
    if (current !== ALERT_STORE_SCHEMA_VERSION) {
      throw new Error(
        `alert-store schema version ${current} is unsupported; expected ${ALERT_STORE_SCHEMA_VERSION}`,
      );
    }
  }

  return {assertCurrent, persistCurrent, prepareMigration};
}

module.exports = {ALERT_STORE_SCHEMA_VERSION, createAlertStoreSchemaVersion};
