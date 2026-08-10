'use strict';

const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  createRuntimeFoundationComposition,
} = require('../composition/runtime_foundation_composition');

test('fails closed before side effects when a required section is absent', () => {
  assert.throws(
    () => createRuntimeFoundationComposition({runtime: {}}),
    /platform runtime foundation composition section is required/,
  );
});

test('constructs the complete foundation in an isolated child runtime', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'onion-runtime-composition-'));
  const script = String.raw`
    const assert = require('node:assert/strict');
    const crypto = require('node:crypto');
    const fs = require('node:fs');
    const path = require('node:path');
    const {createRuntimeFoundationComposition} = require(
      './n8n/alert_store/composition/runtime_foundation_composition'
    );
    const root = process.env.TEST_ROOT;
    const dbPath = path.join(root, 'alerts.sqlite3');
    const scoringRulesPath = path.join(root, 'scoring_rules.json');
    fs.writeFileSync(dbPath, '');
    fs.writeFileSync(scoringRulesPath, '{}');
    class Database {
      configure() {}
      run(sql, params, callback) { callback.call({changes: 0}, null); }
      get(sql, params, callback) { callback(null, undefined); }
      all(sql, params, callback) { callback(null, []); }
      close(callback) { callback(null); }
    }
    const runtime = new Proxy({
      dbPath,
      scoringRulesPath,
      applicationLogPath: path.join(root, 'application.log'),
      applicationLogMaxBytes: 1024 * 1024,
      applicationLogBackups: 1,
      runtimeReleaseIdValue: 'a'.repeat(40),
      host: '127.0.0.1',
      port: 8787,
      controlledEvaluationMode: false,
      assetStoreWriteToken: 'asset-write-token-value',
      controlledEvaluationToken: '',
      runtimeDir: root,
      diskStartMaxUsedPercent: 80,
      diskHardMaxUsedPercent: 90,
      diskMinFreeBytes: 1,
      maxRequestBytes: 1024,
      aiAnalysisWakePaths: [],
      enrichmentSecrets: {},
      enrichmentSourceTtlDefaults: {},
      telegramAlertLevels: new Set(),
      beaconPaths: [],
      beaconHistoryPaths: [],
      assetPostgresEnabled: false,
      softwarePostgresEnabled: false,
      acHunterPostgresEnabled: false,
      enrichmentCacheL1MaxEntries: 8,
      enrichmentCacheL1TtlSeconds: 60,
      enrichmentCacheL1MaxBytes: 4096,
      enrichmentCacheMaxEntries: 32,
      enrichmentCacheMaxBytes: 65536,
      enrichmentCacheRawResponseMaxBytes: 4096,
      enrichmentCacheDefaultTtlSeconds: 3600,
      vulnerabilityCacheDefaultTtlSeconds: 3600,
      enrichmentNegativeCacheTtlSeconds: 60,
      enrichmentStaleIfErrorSeconds: 300,
      enrichmentVulnerabilityStaleIfErrorSeconds: 300,
      enrichmentTimeoutMs: 1000,
      httpJsonMaxResponseBytes: 4096,
      enrichmentCircuitFailureThreshold: 3,
      enrichmentCircuitResetMs: 1000,
      enrichmentCircuitMaxResetMs: 4000,
      virustotalMinimumLevel: 'high',
      urlscanSubmitEnabled: false,
      httpMaxActivePosts: 8,
    }, {get: (target, key) => key in target ? target[key] : 0});
    const composition = createRuntimeFoundationComposition({
      runtime,
      platform: {
        fs,
        path,
        processApi: process,
        sqlite3: {Database},
        crypto,
        createPostgresPool: () => { throw new Error('disabled pool constructed'); },
      },
      serialization: {
        nowUtc: () => '2026-08-10T00:00:00.000Z',
        normalizeTimestampValue: (value) => value,
        formatProjectTimestamp: (value) => value,
        parseProjectTimestamp: (value) => value,
      },
      normalization: {
        nestedField: () => undefined,
        integerField: () => 0,
        nonNegativeIntegerField: () => 0,
        normalizeTriageLevel: (value) => value,
        safeString: (value) => String(value || ''),
        parseJsonObject: () => ({}),
      },
      network: {
        boundedRequestJson: async () => ({}),
        isRelayHeartbeat: () => false,
      },
    });
    assert.equal(typeof composition.requestAuthorization.requireAssetWrite, 'function');
    assert.equal(typeof composition.sqliteRuntime.withImmediateTransaction, 'function');
    assert.equal(typeof composition.notificationService.queueTelegramNotification, 'function');
    assert.equal(typeof composition.enrichmentOrchestrator.enrichAlert, 'function');
    assert.equal(typeof composition.postgresAuxiliaryStores.initializeAssetStore, 'function');
    assert.equal(typeof composition.alertGroupService.rebuildAlertGroupSummaries, 'function');
    assert.equal(composition.serviceMetrics.ingest_requests, 0);
    assert.equal(composition.supportedAgentRoles.has('incident-responder'), true);
  `;
  const result = spawnSync(process.execPath, ['-e', script], {
    cwd: path.resolve(__dirname, '../../..'),
    env: {...process.env, TEST_ROOT: root},
    encoding: 'utf8',
  });
  spawnSync('/usr/bin/trash', [root]);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});
