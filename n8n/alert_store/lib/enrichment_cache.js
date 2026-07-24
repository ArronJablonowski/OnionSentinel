'use strict';

const crypto = require('node:crypto');
const net = require('node:net');
const {URL, domainToASCII} = require('node:url');

function positiveInteger(value, fallback, minimum = 1) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.max(minimum, Math.floor(parsed)) : fallback;
}

function normalizeIndicator(indicatorType, indicator) {
  const type = String(indicatorType || '').trim().toLowerCase();
  const text = String(indicator || '').trim();
  if (!text) return '';
  if (type === 'ip') {
    if (net.isIP(text) === 6) {
      try {
        return new URL(`http://[${text}]`).hostname.replace(/^\[|\]$/g, '').toLowerCase();
      } catch (_error) {
        return text.toLowerCase();
      }
    }
    return text.toLowerCase();
  }
  if (type === 'domain') {
    const domain = text.replace(/\.+$/, '').toLowerCase();
    return domainToASCII(domain) || domain;
  }
  if (type === 'url') {
    try {
      const parsed = new URL(text);
      parsed.username = '';
      parsed.password = '';
      parsed.hash = '';
      parsed.hostname = parsed.hostname.toLowerCase();
      return parsed.toString();
    } catch (_error) {
      return text;
    }
  }
  if (type === 'cve') return text.toUpperCase();
  if (type === 'hash') return text.toLowerCase();
  return text;
}

function cacheKey(source, indicatorType, indicator) {
  const normalizedSource = String(source || '').trim().toLowerCase();
  const normalizedType = String(indicatorType || '').trim().toLowerCase();
  const normalizedIndicator = normalizeIndicator(normalizedType, indicator);
  return crypto
    .createHash('sha256')
    .update(`${normalizedSource}|${normalizedType}|${normalizedIndicator}`)
    .digest('hex');
}

function parseJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch (_error) {
    return fallback;
  }
}

function boundedRawResponse(value, maxBytes) {
  const serialized = JSON.stringify(value ?? null);
  const bytes = Buffer.byteLength(serialized);
  if (bytes <= maxBytes) return {serialized, bytes, truncated: false};
  const replacement = JSON.stringify({
    truncated: true,
    original_size_bytes: bytes,
    reason: 'Provider response exceeded the configured enrichment-cache evidence limit.',
  });
  return {serialized: replacement, bytes: Buffer.byteLength(replacement), truncated: true};
}

function isNegativeRecord(record) {
  if (record?.cache_result_kind === 'negative') return true;
  return String(record?.verdict || '').toLowerCase() === 'unknown'
    && Number(record?.confidence || 0) === 0;
}

function createEnrichmentCache(options = {}) {
  const {run, get, all} = options;
  if (![run, get, all].every((dependency) => typeof dependency === 'function')) {
    throw new TypeError('createEnrichmentCache requires run, get, and all SQLite helpers');
  }
  const withWriteGate = options.withWriteGate || ((task) => task());
  const withTransaction = options.withTransaction || ((task) => task());
  const now = options.now || (() => new Date());
  const formatTimestamp = options.formatTimestamp || ((date) => date.toISOString());
  const l1MaxEntries = positiveInteger(options.l1MaxEntries, 2048);
  const l1TtlSeconds = positiveInteger(options.l1TtlSeconds, 300);
  const l1MaxBytes = positiveInteger(options.l1MaxBytes, 64 * 1024 * 1024, 1024);
  const maxEntries = positiveInteger(options.maxEntries, 10000);
  const maxBytes = positiveInteger(options.maxBytes, 256 * 1024 * 1024, 1024);
  const rawResponseMaxBytes = positiveInteger(options.rawResponseMaxBytes, 128 * 1024, 1024);
  const defaultStaleIfErrorSeconds = positiveInteger(options.staleIfErrorSeconds, 7 * 86400);
  const vulnerabilityStaleIfErrorSeconds = positiveInteger(
    options.vulnerabilityStaleIfErrorSeconds,
    30 * 86400,
  );
  const memory = new Map();
  let memoryBytes = 0;
  const inFlight = new Map();
  const counters = {
    l1_hits: 0,
    l2_hits: 0,
    misses: 0,
    coalesced: 0,
    provider_loads: 0,
    provider_errors: 0,
    stale_fallbacks: 0,
    writes: 0,
    raw_responses_truncated: 0,
    pruned: 0,
  };
  const cachePayloadBytesSql = `
    COALESCE(length(source), 0) + COALESCE(length(indicator), 0) +
    COALESCE(length(indicator_type), 0) + COALESCE(length(verdict), 0) +
    COALESCE(length(tags_json), 0) + COALESCE(length(first_seen), 0) +
    COALESCE(length(last_seen), 0) + COALESCE(length(raw_response_json), 0) +
    COALESCE(length(cached_at), 0) + COALESCE(length(expires_at), 0)
  `;

  function currentMs() {
    const value = now();
    return value instanceof Date ? value.getTime() : new Date(value).getTime();
  }

  function timestamp(valueMs = currentMs()) {
    return formatTimestamp(new Date(valueMs));
  }

  function parseTimestamp(value) {
    const parsed = new Date(String(value || '').replace('  ', 'T')).getTime();
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function cloneRecord(record) {
    return {
      ...record,
      tags: Array.isArray(record?.tags) ? [...record.tags] : [],
    };
  }

  function recordBytes(record) {
    try {
      return Buffer.byteLength(JSON.stringify(record));
    } catch (_error) {
      return rawResponseMaxBytes;
    }
  }

  function forget(key) {
    const existing = memory.get(key);
    if (!existing) return;
    memoryBytes = Math.max(0, memoryBytes - Number(existing.bytes || 0));
    memory.delete(key);
  }

  function remember(key, record, expiresAtMs) {
    forget(key);
    const cloned = cloneRecord(record);
    const bytes = recordBytes(cloned);
    memory.set(key, {
      record: cloned,
      bytes,
      expires_at_ms: Math.min(expiresAtMs, currentMs() + (l1TtlSeconds * 1000)),
    });
    memoryBytes += bytes;
    while (memory.size > l1MaxEntries || memoryBytes > l1MaxBytes) {
      forget(memory.keys().next().value);
    }
  }

  function fromRow(row, state) {
    return {
      source: row.source,
      indicator: row.indicator,
      indicator_type: row.indicator_type,
      verdict: row.verdict || 'unknown',
      confidence: row.confidence ?? 0,
      tags: parseJson(row.tags_json || '[]', []),
      first_seen: row.first_seen || null,
      last_seen: row.last_seen || null,
      raw_response: parseJson(row.raw_response_json || 'null', null),
      cached_at: row.cached_at,
      expires_at: row.expires_at,
      cache_state: state,
    };
  }

  async function install() {
    await run(`
      CREATE TABLE IF NOT EXISTS enrichment_cache (
        cache_key TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        indicator TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        verdict TEXT,
        confidence INTEGER,
        tags_json TEXT,
        first_seen TEXT,
        last_seen TEXT,
        raw_response_json TEXT,
        cached_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_enrichment_cache_expires_at ON enrichment_cache(expires_at)');
    await run('CREATE INDEX IF NOT EXISTS idx_enrichment_cache_indicator ON enrichment_cache(indicator)');
    await run('CREATE INDEX IF NOT EXISTS idx_enrichment_cache_source_type ON enrichment_cache(source, indicator_type)');
  }

  async function read(source, indicatorType, indicator, countMetrics = true) {
    const key = cacheKey(source, indicatorType, indicator);
    const hot = memory.get(key);
    const nowMs = currentMs();
    if (hot && hot.expires_at_ms > nowMs) {
      memory.delete(key);
      memory.set(key, hot);
      if (countMetrics) counters.l1_hits += 1;
      return {
        key,
        state: 'fresh',
        record: {...cloneRecord(hot.record), cache_state: 'fresh'},
        expires_at_ms: hot.expires_at_ms,
      };
    }
    if (hot) forget(key);

    const row = await withWriteGate(() => get('SELECT * FROM enrichment_cache WHERE cache_key = ?', [key]));
    if (!row) {
      if (countMetrics) counters.misses += 1;
      return {key, state: 'miss', record: null, expires_at_ms: 0};
    }
    const expiresAtMs = parseTimestamp(row.expires_at);
    if (expiresAtMs > nowMs) {
      const record = fromRow(row, 'fresh');
      remember(key, record, expiresAtMs);
      if (countMetrics) counters.l2_hits += 1;
      return {key, state: 'fresh', record, expires_at_ms: expiresAtMs};
    }
    if (countMetrics) counters.misses += 1;
    return {key, state: 'stale', record: fromRow(row, 'stale'), expires_at_ms: expiresAtMs};
  }

  async function write(record, ttlSeconds) {
    const normalizedSource = String(record.source || '').trim().toLowerCase();
    const normalizedType = String(record.indicator_type || '').trim().toLowerCase();
    const normalizedIndicator = normalizeIndicator(normalizedType, record.indicator);
    const normalized = {
      ...record,
      source: normalizedSource,
      indicator: normalizedIndicator,
      indicator_type: normalizedType,
    };
    const nowMs = currentMs();
    const cachedAt = timestamp(nowMs);
    const expiresAt = timestamp(nowMs + (positiveInteger(ttlSeconds, 86400) * 1000));
    const bounded = boundedRawResponse(normalized.raw_response, rawResponseMaxBytes);
    await withWriteGate(() => withTransaction(() => run(
      `
        INSERT INTO enrichment_cache (
          cache_key, source, indicator, indicator_type, verdict, confidence, tags_json,
          first_seen, last_seen, raw_response_json, cached_at, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cache_key) DO UPDATE SET
          source = excluded.source,
          indicator = excluded.indicator,
          indicator_type = excluded.indicator_type,
          verdict = excluded.verdict,
          confidence = excluded.confidence,
          tags_json = excluded.tags_json,
          first_seen = excluded.first_seen,
          last_seen = excluded.last_seen,
          raw_response_json = excluded.raw_response_json,
          cached_at = excluded.cached_at,
          expires_at = excluded.expires_at
      `,
      [
        cacheKey(normalizedSource, normalizedType, normalizedIndicator),
        normalizedSource,
        normalizedIndicator,
        normalizedType,
        normalized.verdict,
        normalized.confidence,
        JSON.stringify(normalized.tags || []),
        normalized.first_seen || null,
        normalized.last_seen || null,
        bounded.serialized,
        cachedAt,
        expiresAt,
      ],
    )));
    counters.writes += 1;
    if (bounded.truncated) counters.raw_responses_truncated += 1;
    const saved = {
      ...normalized,
      raw_response: parseJson(bounded.serialized, null),
      cached_at: cachedAt,
      expires_at: expiresAt,
      cache_state: 'refreshed',
    };
    remember(cacheKey(normalizedSource, normalizedType, normalizedIndicator), saved, parseTimestamp(expiresAt));
    return saved;
  }

  async function lookup({
    source,
    indicatorType,
    indicator,
    loader,
    ttlSeconds,
    negativeTtlSeconds,
    staleIfErrorSeconds = defaultStaleIfErrorSeconds,
  }) {
    if (typeof loader !== 'function') throw new TypeError('enrichment cache lookup requires a loader');
    const normalizedSource = String(source || '').trim().toLowerCase();
    const normalizedType = String(indicatorType || '').trim().toLowerCase();
    const normalizedIndicator = normalizeIndicator(normalizedType, indicator);
    const firstRead = await read(normalizedSource, normalizedType, normalizedIndicator, true);
    if (firstRead.state === 'fresh') {
      return {record: firstRead.record, cached: true, cache_state: 'fresh'};
    }
    if (inFlight.has(firstRead.key)) {
      counters.coalesced += 1;
      return inFlight.get(firstRead.key);
    }

    const pending = (async () => {
      // Recheck after registering the single-flight operation. Another request
      // may have refreshed this indicator while the original caller was waiting.
      const current = await read(normalizedSource, normalizedType, normalizedIndicator, false);
      if (current.state === 'fresh') {
        return {record: current.record, cached: true, cache_state: 'fresh'};
      }
      const stale = current.state === 'stale' ? current : firstRead;
      try {
        counters.provider_loads += 1;
        const loaded = await loader(normalizedIndicator);
        const effectiveTtl = isNegativeRecord(loaded)
          ? positiveInteger(negativeTtlSeconds, ttlSeconds)
          : positiveInteger(ttlSeconds, 86400);
        const saved = await write({
          ...loaded,
          source: normalizedSource,
          indicator: normalizedIndicator,
          indicator_type: normalizedType,
        }, effectiveTtl);
        return {record: saved, cached: false, cache_state: 'refreshed'};
      } catch (error) {
        counters.provider_errors += 1;
        const staleAgeMs = currentMs() - Number(stale.expires_at_ms || 0);
        if (stale.record && staleAgeMs <= positiveInteger(staleIfErrorSeconds, defaultStaleIfErrorSeconds) * 1000) {
          counters.stale_fallbacks += 1;
          return {
            record: {...cloneRecord(stale.record), cache_state: 'stale'},
            cached: true,
            cache_state: 'stale',
            fallback_error: String(error?.message || error).slice(0, 300),
          };
        }
        throw error;
      }
    })();
    inFlight.set(firstRead.key, pending);
    try {
      return await pending;
    } finally {
      if (inFlight.get(firstRead.key) === pending) inFlight.delete(firstRead.key);
    }
  }

  async function prune() {
    const defaultCutoff = timestamp(currentMs() - (defaultStaleIfErrorSeconds * 1000));
    const vulnerabilityCutoff = timestamp(currentMs() - (vulnerabilityStaleIfErrorSeconds * 1000));
    const result = await withWriteGate(() => withTransaction(async () => {
      const deletedExpired = await run(`
        DELETE FROM enrichment_cache
        WHERE (
          source IN ('cisa_kev', 'epss', 'nvd') AND
          julianday(replace(expires_at, '  ', 'T')) < julianday(replace(?, '  ', 'T'))
        ) OR (
          source NOT IN ('cisa_kev', 'epss', 'nvd') AND
          julianday(replace(expires_at, '  ', 'T')) < julianday(replace(?, '  ', 'T'))
        )
      `, [vulnerabilityCutoff, defaultCutoff]);

      // Older deployments stored full provider responses without a byte
      // ceiling. Compact those legacy values in place so upgrading cannot
      // leave a cache that permanently violates its configured disk budget.
      const oversizedRawRows = await all(`
        SELECT cache_key, length(raw_response_json) AS original_size_bytes
        FROM enrichment_cache
        WHERE length(raw_response_json) > ?
      `, [rawResponseMaxBytes]);
      for (const row of oversizedRawRows) {
        await run(
          'UPDATE enrichment_cache SET raw_response_json = ? WHERE cache_key = ?',
          [JSON.stringify({
            truncated: true,
            original_size_bytes: Number(row.original_size_bytes || 0),
            reason: 'Legacy provider response exceeded the configured enrichment-cache evidence limit.',
          }), row.cache_key],
        );
      }

      const countRow = await get('SELECT COUNT(*) AS count FROM enrichment_cache');
      const overflow = Math.max(0, Number(countRow?.count || 0) - maxEntries);
      let overflowKeys = [];
      if (overflow > 0) {
        overflowKeys = (await all(`
          SELECT cache_key FROM enrichment_cache
          ORDER BY julianday(replace(cached_at, '  ', 'T')) ASC
          LIMIT ?
        `, [overflow])).map((row) => row.cache_key);
        for (let index = 0; index < overflowKeys.length; index += 500) {
          const batch = overflowKeys.slice(index, index + 500);
          await run(
            `DELETE FROM enrichment_cache WHERE cache_key IN (${batch.map(() => '?').join(',')})`,
            batch,
          );
        }
      }

      const byteRow = await get(`SELECT COALESCE(SUM(${cachePayloadBytesSql}), 0) AS bytes FROM enrichment_cache`);
      let byteOverflow = Math.max(0, Number(byteRow?.bytes || 0) - maxBytes);
      const byteKeys = [];
      while (byteOverflow > 0) {
        const oldest = await all(`
          SELECT cache_key, (${cachePayloadBytesSql}) AS entry_bytes
          FROM enrichment_cache
          ORDER BY julianday(replace(cached_at, '  ', 'T')) ASC
          LIMIT 500
        `);
        if (!oldest.length) break;
        const batch = [];
        for (const row of oldest) {
          batch.push(row.cache_key);
          byteKeys.push(row.cache_key);
          byteOverflow -= Number(row.entry_bytes || 0);
          if (byteOverflow <= 0) break;
        }
        await run(
          `DELETE FROM enrichment_cache WHERE cache_key IN (${batch.map(() => '?').join(',')})`,
          batch,
        );
      }
      return {
        expired: Number(deletedExpired?.changes || 0),
        oversizedRawKeys: oversizedRawRows.map((row) => row.cache_key),
        overflowKeys,
        byteKeys,
      };
    }));

    // Entries removed from L2 must not remain temporarily authoritative in L1.
    for (const key of [...result.oversizedRawKeys, ...result.overflowKeys, ...result.byteKeys]) forget(key);
    for (const [key, item] of memory) {
      if (item.expires_at_ms <= currentMs()) forget(key);
    }
    counters.raw_responses_truncated += result.oversizedRawKeys.length;
    const pruned = result.expired + result.overflowKeys.length + result.byteKeys.length;
    counters.pruned += pruned;
    return {
      pruned,
      expired_pruned: result.expired,
      legacy_raw_responses_truncated: result.oversizedRawKeys.length,
      overflow_pruned: result.overflowKeys.length,
      byte_pruned: result.byteKeys.length,
    };
  }

  async function stats() {
    const row = await withWriteGate(() => get(`SELECT
      COUNT(*) AS entries,
      COALESCE(SUM(julianday(replace(expires_at, '  ', 'T')) > julianday('now')), 0) AS fresh_entries,
      COALESCE(SUM(julianday(replace(expires_at, '  ', 'T')) <= julianday('now')), 0) AS stale_entries,
      COALESCE(SUM(${cachePayloadBytesSql}), 0) AS payload_bytes,
      COALESCE(SUM(length(raw_response_json)), 0) AS raw_response_bytes,
      COALESCE(MAX(length(raw_response_json)), 0) AS largest_raw_response_bytes
      FROM enrichment_cache`));
    return {
      ...snapshot(),
      entries: Number(row?.entries || 0),
      fresh_entries: Number(row?.fresh_entries || 0),
      stale_entries: Number(row?.stale_entries || 0),
      payload_bytes: Number(row?.payload_bytes || 0),
      raw_response_bytes: Number(row?.raw_response_bytes || 0),
      largest_raw_response_bytes: Number(row?.largest_raw_response_bytes || 0),
    };
  }

  function snapshot() {
    return {
      ...counters,
      l1_entries: memory.size,
      l1_bytes: memoryBytes,
      in_flight: inFlight.size,
      max_entries: maxEntries,
      max_bytes: maxBytes,
      l1_max_entries: l1MaxEntries,
      l1_max_bytes: l1MaxBytes,
      raw_response_max_bytes: rawResponseMaxBytes,
    };
  }

  return {install, lookup, prune, snapshot, stats};
}

module.exports = {
  boundedRawResponse,
  cacheKey,
  createEnrichmentCache,
  normalizeIndicator,
};
