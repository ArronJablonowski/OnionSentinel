'use strict';

const fs = require('node:fs');

const EXPECTED_ALLOW_SCRIPTS = Object.freeze({ 'sqlite3@6.0.1': true });

function verifyInstallScriptPolicy(packageJson, pending) {
  const configured = packageJson && packageJson.allowScripts;
  if (JSON.stringify(configured) !== JSON.stringify(EXPECTED_ALLOW_SCRIPTS)) {
    throw new Error(
      'allowScripts must approve only the pinned sqlite3@6.0.1 installer',
    );
  }
  if (!pending || !Array.isArray(pending.allowScripts)) {
    throw new Error('npm install-scripts output is invalid');
  }
  if (pending.allowScripts.length > 0) {
    const names = pending.allowScripts
      .map((item) => String((item && item.name) || 'unknown'))
      .sort();
    throw new Error(`unreviewed dependency install scripts: ${names.join(', ')}`);
  }
}

if (require.main === module) {
  try {
    const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    const pending = JSON.parse(fs.readFileSync(0, 'utf8'));
    verifyInstallScriptPolicy(packageJson, pending);
    process.stdout.write('install-script policy verified\n');
  } catch (error) {
    process.stderr.write(`install-script policy failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { EXPECTED_ALLOW_SCRIPTS, verifyInstallScriptPolicy };
