'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');
const {createRuntimeConfiguration} = require('../lib/runtime_configuration');

const releaseId = 'a'.repeat(40);
const evaluationToken = 'b'.repeat(64);
const scoringPath = '/runtime/scoring.json';

function fixture(overrides = {}) {
  const policyCalls = [];
  const metadata = overrides.metadata || {
    uid: 501,
    mode: 0o100600,
    isFile: () => true,
    isSymbolicLink: () => false,
  };
  const dependencies = {
    env: {...(overrides.env || {})},
    fs: {
      lstatSync: (value) => {
        assert.equal(value, scoringPath);
        return metadata;
      },
      realpathSync: (value) => overrides.realpath || value,
    },
    path,
    os: {homedir: () => '/Users/tester'},
    dirname: '/repo/n8n/alert_store',
    getuid: () => 501,
    loadAuthorizedActivityPolicy: (value) => {
      policyCalls.push(value);
      return {source: value};
    },
  };
  return {
    config: () => createRuntimeConfiguration(dependencies),
    policyCalls,
  };
}

function controlledEnvironment(overrides = {}) {
  return {
    ONION_SENTINEL_EVALUATION_MODE: '1',
    ONION_SENTINEL_RELEASE_ID: releaseId,
    ONION_SENTINEL_EVALUATION_TOKEN: evaluationToken,
    ALERT_STORE_DB: '/runtime/alerts.sqlite3',
    ALERT_STORE_HOST: '127.0.0.1',
    ALERT_STORE_PORT: '18787',
    SCORING_RULES_PATH: scoringPath,
    ...overrides,
  };
}

test('production defaults preserve paths, bounds, timers, and wake fan-out', () => {
  const owner = fixture();
  const config = owner.config();

  assert.equal(config.dbPath, '/data/alerts.sqlite3');
  assert.equal(config.host, '127.0.0.1');
  assert.equal(config.port, 8787);
  assert.equal(config.maxRequestBytes, 10 * 1024 * 1024);
  assert.equal(config.diskHardMaxUsedPercent, 80);
  assert.equal(config.diskStartMaxUsedPercent, 75);
  assert.equal(config.runtimeDir, '/Users/tester/n8n-local');
  assert.deepEqual(config.aiAnalysisWakePaths, [
    '/Users/tester/n8n-local/run/ai-analysis-ollama.wake',
    '/Users/tester/n8n-local/run/ai-analysis-cli.wake',
  ]);
  assert.deepEqual([...config.telegramAlertLevels], ['critical', 'high']);
  assert.equal(config.telegramOutboxAutostart, true);
  assert.equal(config.authorizedActivityPolicy.source, owner.policyCalls[0]);
  assert.equal(owner.policyCalls.length, 1);
  assert.equal(Object.values(config.enrichmentSecrets).every((value) => value === ''), true);
});

test('overrides preserve fallbacks, clamps, trimming, and wake deduplication', () => {
  const config = fixture({env: {
    ASSET_POSTGRES_ENABLED: ' YES ',
    SOFTWARE_POSTGRES_ENABLED: '0',
    AC_HUNTER_POSTGRES_ENABLED: 'true',
    ASSET_STORE_WRITE_TOKEN: ' xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ',
    ALERT_STORE_MAX_REQUEST_BYTES: '1',
    ALERT_STORE_MAX_CONNECTIONS: '2',
    ALERT_STORE_DISK_HARD_MAX_USED_PERCENT: '91',
    ALERT_STORE_DISK_START_MAX_USED_PERCENT: '90',
    TELEGRAM_ALERT_LEVELS: ' HIGH, low, ',
    TELEGRAM_OUTBOX_AUTOSTART: 'no',
    AI_ANALYSIS_WAKE_PATHS: ' /one , /one, /two ',
    ABUSEIPDB_API_KEY: ' secret-one ',
    CENSYS_API_SECRET: ' secret-two ',
  }}).config();

  assert.equal(config.assetPostgresEnabled, true);
  assert.equal(config.softwarePostgresEnabled, false);
  assert.equal(config.acHunterPostgresEnabled, true);
  assert.equal(config.assetStoreWriteToken, 'x'.repeat(32));
  assert.equal(config.maxRequestBytes, 1024);
  assert.equal(config.httpMaxConnections, 8);
  assert.equal(config.diskHardMaxUsedPercent, 80);
  assert.equal(config.diskStartMaxUsedPercent, 79.9);
  assert.deepEqual([...config.telegramAlertLevels], ['high', 'low']);
  assert.equal(config.telegramOutboxAutostart, false);
  assert.deepEqual(config.aiAnalysisWakePaths, ['/one', '/two']);
  assert.equal(config.enrichmentSecrets.abuseipdb, 'secret-one');
  assert.equal(config.enrichmentSecrets.censysSecret, 'secret-two');
});

test('invalid evaluation mode fails before controlled configuration', () => {
  assert.throws(
    fixture({env: {ONION_SENTINEL_EVALUATION_MODE: 'true'}}).config,
    /must be unset, 0, or 1/,
  );
});

test('production PostgreSQL assets require a sufficiently long write token', () => {
  assert.throws(
    fixture({env: {ASSET_POSTGRES_ENABLED: '1'}}).config,
    /ASSET_STORE_WRITE_TOKEN must contain at least 32 characters/,
  );
});

test('controlled evaluation accepts only the exact isolated runtime identity', () => {
  const config = fixture({env: controlledEnvironment()}).config();
  assert.equal(config.controlledEvaluationMode, true);
  assert.equal(config.runtimeReleaseIdValue, releaseId);
  assert.equal(config.controlledEvaluationToken, evaluationToken);
});

test('controlled evaluation rejects missing identity and production credentials', () => {
  for (const mutation of [
    {ALERT_STORE_HOST: '0.0.0.0'},
    {ALERT_STORE_PORT: '8787'},
    {ONION_SENTINEL_RELEASE_ID: 'invalid'},
    {ONION_SENTINEL_EVALUATION_TOKEN: 'invalid'},
    {TELEGRAM_BOT_TOKEN: 'configured'},
    {ASSET_STORE_WRITE_TOKEN: 'configured'},
    {NVD_API_KEY: 'configured'},
  ]) {
    assert.throws(
      fixture({env: controlledEnvironment(mutation)}).config,
      /controlled evaluation requires loopback/,
    );
  }
  const missing = controlledEnvironment();
  delete missing.SCORING_RULES_PATH;
  assert.throws(
    fixture({env: missing}).config,
    /controlled evaluation requires loopback/,
  );
});

test('controlled scoring file must remain canonical, regular, and owner-only', () => {
  assert.throws(
    fixture({env: controlledEnvironment(), realpath: '/other/scoring.json'}).config,
    /owner-controlled regular file/,
  );
  assert.throws(
    fixture({
      env: controlledEnvironment(),
      metadata: {
        uid: 501,
        mode: 0o100660,
        isFile: () => true,
        isSymbolicLink: () => false,
      },
    }).config,
    /owner-controlled regular file/,
  );
});
