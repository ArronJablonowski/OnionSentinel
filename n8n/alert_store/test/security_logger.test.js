'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {createSecurityLogger} = require('../lib/security_logger');

test('structured logger timestamps and redacts security-sensitive fields', (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'onion-log-'));
  context.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const file = path.join(directory, 'application.jsonl');
  const logger = createSecurityLogger({
    file,
    service: 'test-service',
    releaseId: 'abc1234',
  });
  logger.log('error', 'request.failed', {
    request_id: 'req-1',
    authorization: 'Bearer should-not-appear',
    message: 'token=also-secret failure',
  });
  const record = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.match(record.timestamp, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(record.timestamp_epoch_ms > 0, true);
  assert.equal(record.authorization, '[REDACTED]');
  assert.doesNotMatch(JSON.stringify(record), /should-not-appear|also-secret/);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});

test('structured logger rotates bounded files', (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'onion-log-'));
  context.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const file = path.join(directory, 'application.jsonl');
  const logger = createSecurityLogger({
    file,
    service: 'test-service',
    maxBytes: 200,
    backups: 2,
  });
  for (let index = 0; index < 10; index += 1) {
    logger.log('info', 'rotation.test', {index, message: 'x'.repeat(80)});
  }
  assert.equal(fs.existsSync(`${file}.1`), true);
  assert.equal(fs.existsSync(`${file}.3`), false);
});
