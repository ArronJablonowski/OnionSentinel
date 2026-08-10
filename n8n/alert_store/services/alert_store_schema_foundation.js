'use strict';

function createAlertStoreSchemaFoundation({
  run,
  ensureColumn,
  assertControlledSchema,
  controlledEvaluationMode,
  sqliteBusyTimeoutMs,
  allowedJournalModes,
  sqliteJournalMode,
  allowedSynchronousModes,
  sqliteSynchronous,
  allowedTempStoreModes,
  sqliteTempStore,
  alertGroupKeySql,
}) {
  for (const [name, value] of Object.entries({run, ensureColumn, assertControlledSchema})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function configureRuntime() {
    if (controlledEvaluationMode) {
      await run(`PRAGMA busy_timeout = ${sqliteBusyTimeoutMs}`);
      await assertControlledSchema();
      return true;
    }
    const journalMode = allowedJournalModes.has(sqliteJournalMode) ? sqliteJournalMode : 'DELETE';
    const synchronousMode = allowedSynchronousModes.has(sqliteSynchronous)
      ? sqliteSynchronous : 'FULL';
    const tempStoreMode = allowedTempStoreModes.has(sqliteTempStore)
      ? sqliteTempStore : 'DEFAULT';
    await run(`PRAGMA journal_mode = ${journalMode}`);
    await run(`PRAGMA synchronous = ${synchronousMode}`);
    await run(`PRAGMA temp_store = ${tempStoreMode}`);
    await run(`PRAGMA busy_timeout = ${sqliteBusyTimeoutMs}`);
    if (journalMode === 'WAL') await run('PRAGMA wal_autocheckpoint = 1000');
    return false;
  }

  async function installAlerts() {
    await run(`
      CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        seen_count INTEGER NOT NULL DEFAULT 1,
        timestamp TEXT,
        rule_name TEXT,
        event_dataset TEXT,
        severity INTEGER,
        severity_label TEXT,
        source_ip TEXT,
        source_port INTEGER,
        destination_ip TEXT,
        destination_port INTEGER,
        network_protocol TEXT,
        transport_protocol TEXT,
        traffic_direction TEXT,
        triage_score INTEGER,
        triage_level TEXT,
        routing TEXT,
        filter_status TEXT,
        filter_reason TEXT,
        suppression_key TEXT,
        raw_event_json TEXT,
        enrichment_json TEXT,
        alert_json TEXT NOT NULL
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen)');
    await run('CREATE INDEX IF NOT EXISTS idx_alerts_rule_name ON alerts(rule_name)');
    const columns = [
      ['traffic_direction', 'TEXT'], ['source_port', 'INTEGER'],
      ['destination_port', 'INTEGER'], ['network_protocol', 'TEXT'],
      ['transport_protocol', 'TEXT'], ['triage_score', 'INTEGER'],
      ['triage_level', 'TEXT'], ['routing', 'TEXT'], ['filter_status', 'TEXT'],
      ['filter_reason', 'TEXT'], ['suppression_key', 'TEXT'],
      ['raw_event_json', 'TEXT'], ['enrichment_json', 'TEXT'], ['rule_id', 'TEXT'],
      ['stable_group_key', 'TEXT'], ['stable_group_id', 'TEXT'],
    ];
    for (const [name, definition] of columns) await ensureColumn('alerts', name, definition);
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_alerts_stable_group_id ON alerts(stable_group_id)',
      'CREATE INDEX IF NOT EXISTS idx_alerts_triage_level ON alerts(triage_level)',
      'CREATE INDEX IF NOT EXISTS idx_alerts_filter_status ON alerts(filter_status)',
      'CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)',
      'CREATE INDEX IF NOT EXISTS idx_alerts_destination_ip ON alerts(destination_ip)',
      'CREATE INDEX IF NOT EXISTS idx_alerts_source_port ON alerts(source_port)',
      'CREATE INDEX IF NOT EXISTS idx_alerts_destination_port ON alerts(destination_port)',
      'CREATE INDEX IF NOT EXISTS idx_alerts_transport_protocol ON alerts(transport_protocol)',
      'DROP INDEX IF EXISTS idx_alerts_group_key_expr',
      `CREATE INDEX IF NOT EXISTS idx_alerts_group_key_expr_v2 ON alerts(${alertGroupKeySql})`,
    ];
    for (const sql of indexes) await run(sql);
  }

  async function installGroups() {
    await run(`
      CREATE TABLE IF NOT EXISTS alert_group_summary (
        group_id TEXT PRIMARY KEY, group_key TEXT NOT NULL UNIQUE,
        representative_alert_id TEXT, first_seen TEXT, last_seen TEXT,
        raw_alert_count INTEGER NOT NULL DEFAULT 0,
        total_seen_count INTEGER NOT NULL DEFAULT 0,
        timestamp TEXT, rule_name TEXT, event_dataset TEXT, severity INTEGER,
        severity_label TEXT, source_ip TEXT, source_port INTEGER,
        destination_ip TEXT, destination_port INTEGER, network_protocol TEXT,
        transport_protocol TEXT, traffic_direction TEXT, triage_score INTEGER,
        triage_level TEXT, routing TEXT, filter_status TEXT, filter_reason TEXT,
        suppression_key TEXT, updated_at TEXT NOT NULL
      )
    `);
    const summaryIndexes = [
      'CREATE INDEX IF NOT EXISTS idx_alert_group_summary_last_seen ON alert_group_summary(last_seen)',
      'CREATE INDEX IF NOT EXISTS idx_alert_group_summary_triage_level ON alert_group_summary(triage_level)',
      'CREATE INDEX IF NOT EXISTS idx_alert_group_summary_filter_status ON alert_group_summary(filter_status)',
      'CREATE INDEX IF NOT EXISTS idx_alert_group_summary_rule_name ON alert_group_summary(rule_name)',
      'CREATE INDEX IF NOT EXISTS idx_alert_group_summary_source_ip ON alert_group_summary(source_ip)',
      'CREATE INDEX IF NOT EXISTS idx_alert_group_summary_destination_ip ON alert_group_summary(destination_ip)',
    ];
    for (const sql of summaryIndexes) await run(sql);
    await run(`
      CREATE TABLE IF NOT EXISTS analyst_alert_group_state (
        group_id TEXT PRIMARY KEY, group_key TEXT,
        status TEXT NOT NULL CHECK(status IN ('acknowledged', 'suppressed')),
        repeat_count INTEGER NOT NULL DEFAULT 0, reason TEXT,
        updated_at TEXT NOT NULL, updated_by TEXT
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_alert_group_state_status ON analyst_alert_group_state(status)');
    await run('CREATE INDEX IF NOT EXISTS idx_alert_group_state_updated_at ON analyst_alert_group_state(updated_at)');
    await run(`
      CREATE TABLE IF NOT EXISTS alert_group_alias (
        legacy_group_id TEXT PRIMARY KEY, stable_group_id TEXT NOT NULL,
        stable_group_key TEXT NOT NULL, updated_at TEXT NOT NULL
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_alert_group_alias_stable ON alert_group_alias(stable_group_id)');
    await run(`
      CREATE TABLE IF NOT EXISTS alert_observables (
        group_id TEXT NOT NULL, group_key TEXT NOT NULL, alert_id TEXT NOT NULL,
        observable_type TEXT NOT NULL, observable_value TEXT NOT NULL,
        role TEXT NOT NULL, source TEXT NOT NULL, first_seen TEXT, last_seen TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (group_id, alert_id, observable_type, observable_value, role, source)
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_alert_observables_lookup ON alert_observables(observable_type, observable_value, group_id)');
    await run('CREATE INDEX IF NOT EXISTS idx_alert_observables_group ON alert_observables(group_id, last_seen)');
    await run('CREATE INDEX IF NOT EXISTS idx_alert_observables_alert ON alert_observables(alert_id)');
  }

  async function installCampaigns() {
    await run(`
      CREATE TABLE IF NOT EXISTS authorized_activity_campaigns (
        campaign_id TEXT PRIMARY KEY, campaign_key TEXT NOT NULL UNIQUE,
        policy_id TEXT NOT NULL, representative_alert_id TEXT NOT NULL,
        representative_group_id TEXT NOT NULL, bucket_start TEXT NOT NULL,
        bucket_end TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        member_count INTEGER NOT NULL DEFAULT 0,
        distinct_target_count INTEGER NOT NULL DEFAULT 0,
        authorization_json TEXT NOT NULL, policy_json TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_authorized_campaign_policy_time ON authorized_activity_campaigns(policy_id, bucket_start, bucket_end)');
    await run('CREATE INDEX IF NOT EXISTS idx_authorized_campaign_representative ON authorized_activity_campaigns(representative_group_id)');
    await run(`
      CREATE TABLE IF NOT EXISTS authorized_activity_campaign_members (
        campaign_id TEXT NOT NULL, alert_id TEXT NOT NULL UNIQUE,
        stable_group_id TEXT NOT NULL, destination_ip TEXT,
        destination_port INTEGER, observed_at TEXT NOT NULL, created_at TEXT NOT NULL,
        PRIMARY KEY (campaign_id, alert_id),
        FOREIGN KEY(campaign_id) REFERENCES authorized_activity_campaigns(campaign_id)
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_authorized_campaign_member_group ON authorized_activity_campaign_members(stable_group_id, campaign_id)');
    await run('CREATE INDEX IF NOT EXISTS idx_authorized_campaign_member_time ON authorized_activity_campaign_members(campaign_id, observed_at)');
  }

  async function installFoundation() {
    await installAlerts();
    await installGroups();
    await installCampaigns();
  }

  return {configureRuntime, installFoundation};
}

module.exports = {createAlertStoreSchemaFoundation};
