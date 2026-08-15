'use strict';

function requireSection(options, name) {
  const section = options && options[name];
  if (!section || typeof section !== 'object') {
    throw new Error(`${name} startup persistence compatibility section is required`);
  }
  return section;
}

function createStartupPersistenceCompatibility(options = {}) {
  const database = requireSection(options, 'database');
  const identity = requireSection(options, 'identity');
  const serialization = requireSection(options, 'serialization');

  function tableColumns(tableName) {
    return new Promise((resolve, reject) => {
      database.db.all(`PRAGMA table_info(${tableName})`, [], (error, rows) => {
        if (error) reject(error);
        else resolve(rows.map((row) => row.name));
      });
    });
  }

  async function ensureColumn(tableName, columnName, columnType) {
    const columns = await tableColumns(tableName);
    if (!columns.includes(columnName)) {
      await database.run(
        `ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnType}`,
      );
    }
  }

  async function persistStableIdentity(alertId, row, alert = {}) {
    const identityRow = {...row, rule_id: alert.rule_id || row.rule_id};
    const key = identity.stableGroupKey(identityRow);
    const id = identity.stableGroupId(identityRow);
    await database.run(
      'UPDATE alerts SET rule_id = COALESCE(?, rule_id), stable_group_key = ?, stable_group_id = ? WHERE alert_id = ?',
      [alert.rule_id || null, key, id, alertId],
    );
    return {stable_group_key: key, stable_group_id: id};
  }

  async function backfillStableGroupIdentity() {
    const pending = await database.all(
      "SELECT * FROM alerts WHERE stable_group_id IS NULL OR stable_group_id = ''",
    );
    if (!pending.length) return 0;
    await database.withTransaction(async () => {
      for (const item of pending) {
        await persistStableIdentity(
          item.alert_id,
          item,
          serialization.parseJsonObject(item.alert_json),
        );
      }
    });
    return pending.length;
  }

  function createSchemaInitializer(owners = {}) {
    const required = [
      'alertStoreSchemaVersion',
      'alertStoreSchemaFoundation',
      'incidentAnalysisSchema',
      'aiReviewSchema',
      'notificationEnrichmentSchema',
      'pcapSchema',
      'startupPersistenceOrchestrator',
    ];
    for (const name of required) {
      if (!owners[name] || typeof owners[name] !== 'object') {
        throw new Error(`${name} startup schema owner is required`);
      }
    }
    return async function initDb() {
      if (await owners.alertStoreSchemaFoundation.configureRuntime()) {
        await owners.alertStoreSchemaVersion.assertCurrent();
        return;
      }
      await database.withTransaction(async () => {
        await owners.alertStoreSchemaVersion.prepareMigration();
        await owners.alertStoreSchemaFoundation.installFoundation();
        await owners.incidentAnalysisSchema.install();
        await owners.aiReviewSchema.install();
        await owners.notificationEnrichmentSchema.install();
        await owners.pcapSchema.install();
        await owners.startupPersistenceOrchestrator.initialize();
        await owners.alertStoreSchemaVersion.persistCurrent();
      });
    };
  }

  return {
    ensureColumn,
    persistStableIdentity,
    backfillStableGroupIdentity,
    createSchemaInitializer,
  };
}

module.exports = {createStartupPersistenceCompatibility};
