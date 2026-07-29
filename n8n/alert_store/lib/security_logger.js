'use strict';

const fs = require('node:fs');
const path = require('node:path');

const SECRET_KEY = /(authorization|cookie|password|secret|token|api[_-]?key|credential)/i;
const SECRET_TEXT = /((?:authorization|password|secret|token|api[_-]?key)\s*[=:]\s*)[^\s,;]+/gi;

function sanitize(value, depth = 0) {
  if (depth > 4) return '[depth-limited]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    return value.replace(SECRET_TEXT, '$1[REDACTED]').slice(0, 2000);
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 64).map((item) => sanitize(item, depth + 1));
  if (typeof value === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value).slice(0, 64)) {
      result[key] = SECRET_KEY.test(key) ? '[REDACTED]' : sanitize(item, depth + 1);
    }
    return result;
  }
  return String(value).slice(0, 2000);
}

function createSecurityLogger({
  file,
  service,
  releaseId = 'unversioned',
  maxBytes = 10 * 1024 * 1024,
  backups = 5,
}) {
  const destination = path.resolve(file);
  fs.mkdirSync(path.dirname(destination), {recursive: true, mode: 0o700});
  let sequence = 0;

  function rotate() {
    let size = 0;
    try {
      size = fs.statSync(destination).size;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (size < maxBytes) return;
    for (let index = backups - 1; index >= 1; index -= 1) {
      const source = `${destination}.${index}`;
      const target = `${destination}.${index + 1}`;
      if (fs.existsSync(source)) fs.renameSync(source, target);
    }
    if (fs.existsSync(destination)) fs.renameSync(destination, `${destination}.1`);
  }

  function log(level, event, fields = {}) {
    try {
      rotate();
      sequence += 1;
      const timestamp = new Date().toISOString();
      const record = {
        timestamp,
        timestamp_epoch_ms: Date.now(),
        level: String(level || 'info').toLowerCase(),
        service,
        release_id: releaseId,
        process_id: process.pid,
        sequence,
        event: String(event || 'application.event').slice(0, 160),
        ...sanitize(fields),
      };
      fs.appendFileSync(destination, `${JSON.stringify(record)}\n`, {
        encoding: 'utf8',
        mode: 0o600,
        flag: 'a',
      });
      fs.chmodSync(destination, 0o600);
    } catch (error) {
      // Logging is diagnostic; it must not take down the persistence service.
      process.stderr.write(`security logger failure: ${error.message}\n`);
    }
  }

  function captureConsole(consoleObject = console) {
    for (const [method, level] of [['log', 'info'], ['warn', 'warning'], ['error', 'error']]) {
      const original = consoleObject[method].bind(consoleObject);
      consoleObject[method] = (...args) => {
        log(level, 'console.message', {
          message: args.map((item) => (
            item instanceof Error ? item.message : (
              typeof item === 'string' ? item : JSON.stringify(sanitize(item))
            )
          )).join(' '),
        });
        original(...args);
      };
    }
  }

  return {log, captureConsole, sanitize, file: destination};
}

module.exports = {createSecurityLogger, sanitize};
