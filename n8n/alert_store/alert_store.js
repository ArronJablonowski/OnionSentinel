// alert-store is the policy and persistence layer for Security Onion alerts.
//
// n8n calls POST /alert with one normalized alert at a time. This service then
// scores, deduplicates, applies hard drops and TTL suppressions, stores the
// result in SQLite, and sends Telegram notifications when policy allows.
//
// First troubleshooting checks:
//   1. GET /health from inside the n8n Docker network.
//   2. Inspect /data/alerts.sqlite3 for alert/filter state.
//   3. Inspect /app/config/scoring_rules.json for tuning rules.
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  createRuntimeFoundationComposition,
} = require('./composition/runtime_foundation_composition');
const {
  createApplicationGraphRuntime,
} = require('./composition/application_graph_runtime');
const {
  createHttpApplicationRuntime,
} = require('./composition/http_application_runtime');
const {createProjectSerialization} = require('./lib/project_serialization');
const {createRuntimeConfiguration} = require('./lib/runtime_configuration');
const {
  isRelayHeartbeat,
  nestedField,
  integerField,
  nonNegativeIntegerField,
  normalizeTriageLevel,
  safeString,
  parseJsonObject,
} = require('./lib/alert_value_normalization');
const {loadAuthorizedActivityPolicy} = require('./lib/authorized_activity_policy');
const {requestJson: boundedRequestJson} = require('./lib/http_json_client');

let sqlite3;
try {
  // Host-native launchd deployments install sqlite3 beside this script.
  sqlite3 = require('sqlite3');
} catch (error) {
  // The Docker proxy is preferred for n8n reachability, but this fallback keeps
  // older container-based DR deployments bootable.
  sqlite3 = require('/usr/local/lib/node_modules/n8n/node_modules/.pnpm/sqlite3@5.1.7/node_modules/sqlite3');
}
const serialization = createProjectSerialization();

// Runtime values come from docker-compose.yml and .env. Keep real tokens in
// .env only; this DR repo stores placeholders and source code.
const runtimeConfiguration = createRuntimeConfiguration({
  env: process.env,
  fs,
  path,
  os,
  dirname: __dirname,
  getuid: typeof process.getuid === 'function' ? () => process.getuid() : null,
  loadAuthorizedActivityPolicy,
});
const runtimeFoundation = createRuntimeFoundationComposition({
  runtime: runtimeConfiguration,
  platform: {
    fs,
    path,
    processApi: process,
    sqlite3,
    crypto,
    createPostgresPool: (config) => {
      const {Pool} = require('pg');
      return new Pool(config);
    },
  },
  serialization,
  normalization: {
    nestedField,
    integerField,
    nonNegativeIntegerField,
    normalizeTriageLevel,
    safeString,
    parseJsonObject,
  },
  network: {boundedRequestJson, isRelayHeartbeat},
});
const applicationGraph = createApplicationGraphRuntime({
  runtime: runtimeConfiguration,
  platform: {
    env: process.env,
    path,
    consoleLike: console,
    createPostgresPool: (config) => {
      const {Pool} = require('pg');
      return new Pool(config);
    },
    randomUUID: crypto.randomUUID,
    sha256Text: (value) => crypto.createHash('sha256').update(value).digest('hex'),
    warn: (...args) => console.warn(...args),
  },
  foundation: runtimeFoundation,
  serialization,
});
const httpApplicationRuntime = createHttpApplicationRuntime({
  runtime: runtimeConfiguration,
  platform: {
    httpCreateServer: (listener) => require('http').createServer(listener),
    processLike: process,
    consoleLike: console,
    dateNow: Date.now,
    randomUUID: crypto.randomUUID,
    monotonicNow: process.hrtime.bigint,
    setIntervalFn: setInterval,
    setTimeoutFn: setTimeout,
  },
  database: {
    db: runtimeFoundation.sqliteRuntime.database,
    get: runtimeFoundation.sqliteRuntime.get,
    all: runtimeFoundation.sqliteRuntime.all,
    withWriteGate: runtimeFoundation.sqliteRuntime.withWriteGate,
    withTransaction: runtimeFoundation.sqliteRuntime.withImmediateTransaction,
    sqliteRuntime: runtimeFoundation.sqliteRuntime,
  },
  foundation: runtimeFoundation,
  application: applicationGraph.applicationOwners,
  controlled: applicationGraph.controlledIncident,
  evidence: {
    ...applicationGraph.evidenceProcessing,
    aiAnalysisAcceptance: applicationGraph.aiAnalysisAcceptance,
  },
  mutable: applicationGraph.mutableRuntimeOwners,
  startup: {initDb: applicationGraph.initDb},
  serialization: {
    nowUtc: serialization.nowUtc,
    safeString,
    isRelayHeartbeat,
    incidentIdentityConflict: applicationGraph.incidentIdentityConflict,
    requestHasOwnField: applicationGraph.requestHasOwnField,
  },
});

httpApplicationRuntime.run();
