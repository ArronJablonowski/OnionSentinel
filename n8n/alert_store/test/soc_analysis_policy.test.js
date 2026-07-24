'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  createSocAnalysisPolicy,
  legacyPcapThreshold,
  matchesSeverityThreshold,
} = require('../lib/soc_analysis_policy');

assert.strictEqual(matchesSeverityThreshold('critical', 'high'), true);
assert.strictEqual(matchesSeverityThreshold('high', 'high'), true);
assert.strictEqual(matchesSeverityThreshold('medium', 'high'), false);
assert.strictEqual(matchesSeverityThreshold('info', 'informational'), true);
assert.strictEqual(matchesSeverityThreshold('critical', 'disabled'), false);
assert.strictEqual(legacyPcapThreshold('critical,high,medium'), 'medium');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'onion-sentinel-policy-'));
const settingsPath = path.join(root, 'ai_model_settings.json');
fs.writeFileSync(settingsPath, JSON.stringify({
  soc_analyst_pcap_min_severity: 'medium',
  soc_analyst_incident_min_severity: 'high',
}));
const policy = createSocAnalysisPolicy({settingsPath, cacheTtlMs: 1});
assert.strictEqual(policy.matchesPcap('low'), false);
assert.strictEqual(policy.matchesPcap('medium'), true);
assert.strictEqual(policy.matchesPcap('critical'), true);
assert.strictEqual(policy.matchesIncident('medium'), false);
assert.strictEqual(policy.matchesIncident('high'), true);

fs.writeFileSync(settingsPath, JSON.stringify({
  soc_analyst_pcap_min_severity: 'disabled',
  soc_analyst_incident_min_severity: 'critical',
}));
assert.strictEqual(policy.read(true).soc_analyst_pcap_min_severity, 'disabled');
assert.strictEqual(policy.matchesPcap('critical'), false);
assert.strictEqual(policy.matchesIncident('critical'), true);

fs.rmSync(root, {recursive: true, force: true});
console.log('soc analysis policy tests passed');
