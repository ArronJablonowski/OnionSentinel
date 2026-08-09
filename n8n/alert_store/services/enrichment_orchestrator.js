'use strict';

function createEnrichmentOrchestrator({
  cache,
  scheduler,
  providers,
  policy,
  extractAlertIndicators,
  isRelayHeartbeat,
  nowUtc,
  formatProjectTimestamp,
  withSqliteWriteGate,
  withImmediateTransaction,
  get,
  run,
  defaultTtlSeconds,
  vulnerabilityTtlSeconds,
  negativeTtlSeconds,
  virusTotalMinimumLevel,
  urlscanSubmitEnabled,
  nowMs = Date.now,
  delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
}) {
  for (const [name, value] of Object.entries({
    extractAlertIndicators,
    isRelayHeartbeat,
    nowUtc,
    formatProjectTimestamp,
    withSqliteWriteGate,
    withImmediateTransaction,
    get,
    run,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function epochMs(value = new Date(nowMs())) {
    return value instanceof Date ? value.getTime() : new Date(value).getTime();
  }

  function isoFromMs(value) {
    return formatProjectTimestamp(new Date(value));
  }

  async function reserveProviderRateLimitSlot(source) {
    const minimumMs = policy.sourceRateLimitMs(source);
    return withSqliteWriteGate(() => withImmediateTransaction(async () => {
      const row = await get(
        'SELECT last_request_at FROM enrichment_rate_limit WHERE source = ?',
        [source],
      );
      const currentMs = epochMs();
      const parsedLastMs = row?.last_request_at
        ? epochMs(String(row.last_request_at).replace('  ', 'T'))
        : Number.NaN;
      const maximumCredibleFutureMs = currentMs + Math.max(60000, minimumMs * 4);
      const lastMs = Number.isFinite(parsedLastMs) && parsedLastMs <= maximumCredibleFutureMs
        ? parsedLastMs : currentMs - minimumMs;
      const reservedMs = Math.max(currentMs, lastMs + minimumMs);
      await run(
        'INSERT INTO enrichment_rate_limit (source, last_request_at) VALUES (?, ?) ON CONFLICT(source) DO UPDATE SET last_request_at = excluded.last_request_at',
        [source, isoFromMs(reservedMs).replace('T', '  ')],
      );
      return Math.max(0, reservedMs - currentMs);
    }));
  }

  async function cachedLookup(source, indicatorType, indicator, lookup) {
    const ttlSeconds = policy.sourceTtlSeconds(source);
    return cache.lookup({
      source,
      indicatorType,
      indicator,
      ttlSeconds,
      negativeTtlSeconds: Math.min(ttlSeconds, negativeTtlSeconds),
      staleIfErrorSeconds: policy.sourceStaleIfErrorSeconds(source),
      loader: () => scheduler.run(source, async () => {
        const waitMs = await reserveProviderRateLimitSlot(source);
        if (waitMs > 0) await delay(waitMs);
        return lookup();
      }),
    });
  }

  async function runEnrichmentLookup(source, indicatorType, indicator, lookup, summary) {
    if (!policy.sourceConfigured(source)) {
      summary.skipped.push({
        source,
        indicator,
        indicator_type: indicatorType,
        reason: 'missing_api_key',
        limit_note: policy.sourceLimitNote(source),
      });
      return;
    }
    try {
      const result = await cachedLookup(source, indicatorType, indicator, lookup);
      summary.records.push(result.record);
      summary.sources[source] = {
        status: result.cache_state === 'stale'
          ? 'stale_cache' : result.cached ? 'cached' : 'queried',
        cache_state: result.cache_state,
        limit_note: policy.sourceLimitNote(source),
      };
      if (result.fallback_error) {
        summary.warnings.push({
          source,
          indicator,
          indicator_type: indicatorType,
          reason: 'provider_refresh_failed_stale_cache_used',
          detail: result.fallback_error,
        });
      }
    } catch (error) {
      summary.errors.push({
        source,
        indicator,
        indicator_type: indicatorType,
        reason: error.message,
        limit_note: policy.sourceLimitNote(source),
      });
    }
  }

  async function enrichAlert(alert) {
    if (!alert || typeof alert !== 'object' || isRelayHeartbeat(alert)) {
      return {
        ok: true,
        status: isRelayHeartbeat(alert) ? 'heartbeat_skipped' : 'invalid_skipped',
        alert,
        enrichment: {records: [], skipped: [], errors: [], indicators: {}, sources: {}},
      };
    }
    const indicators = extractAlertIndicators(alert);
    const summary = {
      generated_at: nowUtc(),
      cache_ttl_seconds: defaultTtlSeconds,
      vulnerability_cache_ttl_seconds: vulnerabilityTtlSeconds,
      indicators,
      sources: {},
      records: [],
      skipped: [],
      warnings: [],
      errors: [],
      privacy: {
        submitted_private_ips: false,
        submitted_internal_urls: false,
        url_query_strings_redacted: true,
        urlscan_submit_enabled: urlscanSubmitEnabled,
      },
    };
    const jobs = [];
    const schedule = (source, indicatorType, indicator, lookup) => {
      jobs.push(runEnrichmentLookup(source, indicatorType, indicator, lookup, summary));
    };

    for (const ip of indicators.public_ips.slice(0, 4)) {
      schedule('abuseipdb', 'ip', ip, () => providers.lookupAbuseIpdb(ip));
      schedule('greynoise', 'ip', ip, () => providers.lookupGreynoise(ip));
      schedule('shodan_internetdb', 'ip', ip, () => providers.lookupShodanInternetDb(ip));
      schedule('otx', 'ip', ip, () => providers.lookupOtx('ip', ip));
      schedule('shodan', 'ip', ip, () => providers.lookupShodan(ip));
      schedule('censys', 'ip', ip, () => providers.lookupCensys(ip));
    }
    for (const domain of indicators.domains.slice(0, 4)) {
      schedule('otx', 'domain', domain, () => providers.lookupOtx('domain', domain));
      schedule('urlscan', 'domain', domain, () => providers.lookupUrlscan('domain', domain));
      schedule('threatfox', 'domain', domain, () => providers.lookupThreatFox('domain', domain));
      if (policy.shouldUseVirusTotal(alert)) {
        schedule(
          'virustotal', 'domain', domain,
          () => providers.lookupVirusTotal('domain', domain),
        );
      } else {
        summary.skipped.push({
          source: 'virustotal', indicator: domain, indicator_type: 'domain',
          reason: `below_${virusTotalMinimumLevel}_severity`,
          limit_note: policy.sourceLimitNote('virustotal'),
        });
      }
    }
    for (const urlValue of indicators.urls.slice(0, 3)) {
      schedule('urlhaus', 'url', urlValue, () => providers.lookupUrlhaus(urlValue));
      schedule('urlscan', 'url', urlValue, () => providers.lookupUrlscan('url', urlValue));
      schedule(
        'google_safe_browsing', 'url', urlValue,
        () => providers.lookupGoogleSafeBrowsing(urlValue),
      );
      schedule('phishtank', 'url', urlValue, () => providers.lookupPhishTank(urlValue));
      schedule('otx', 'url', urlValue, () => providers.lookupOtx('url', urlValue));
      if (policy.shouldUseVirusTotal(alert)) {
        schedule(
          'virustotal', 'url', urlValue,
          () => providers.lookupVirusTotal('url', urlValue),
        );
      } else {
        summary.skipped.push({
          source: 'virustotal', indicator: urlValue, indicator_type: 'url',
          reason: `below_${virusTotalMinimumLevel}_severity`,
          limit_note: policy.sourceLimitNote('virustotal'),
        });
      }
    }
    for (const hash of indicators.hashes.slice(0, 4)) {
      schedule(
        'malwarebazaar', 'hash', hash.value,
        () => providers.lookupMalwareBazaar(hash.value),
      );
      schedule('otx', 'hash', hash.value, () => providers.lookupOtx('hash', hash.value));
      schedule(
        'threatfox', 'hash', hash.value,
        () => providers.lookupThreatFox('hash', hash.value),
      );
      if (policy.shouldUseVirusTotal(alert)) {
        schedule(
          'virustotal', 'hash', hash.value,
          () => providers.lookupVirusTotal('hash', hash.value),
        );
      } else {
        summary.skipped.push({
          source: 'virustotal', indicator: hash.value, indicator_type: 'hash',
          reason: `below_${virusTotalMinimumLevel}_severity`,
          limit_note: policy.sourceLimitNote('virustotal'),
        });
      }
    }
    for (const cve of indicators.cves.slice(0, 6)) {
      schedule('cisa_kev', 'cve', cve, () => providers.lookupCisaKev(cve));
      schedule('epss', 'cve', cve, () => providers.lookupEpss(cve));
      schedule('nvd', 'cve', cve, () => providers.lookupNvd(cve));
    }

    await Promise.all(jobs);
    const stableOrder = (left, right) => (
      `${left.source}|${left.indicator_type}|${left.indicator}`
        .localeCompare(`${right.source}|${right.indicator_type}|${right.indicator}`)
    );
    summary.records.sort(stableOrder);
    summary.skipped.sort(stableOrder);
    summary.errors.sort(stableOrder);
    const enrichedAlert = {
      ...alert,
      enrichment: {
        ...(alert.enrichment || {}),
        external_intel: {
          ...summary,
          verdict_counts: summary.records.reduce((counts, record) => {
            counts[record.verdict] = (counts[record.verdict] || 0) + 1;
            return counts;
          }, {}),
        },
      },
    };
    return {
      ok: true,
      status: 'enriched',
      alert: enrichedAlert,
      enrichment: enrichedAlert.enrichment.external_intel,
    };
  }

  async function cachedInvestigationEnrichment(indicatorType, indicator) {
    const normalized = policy.normalizeInvestigationEnrichmentIndicator(
      indicatorType,
      indicator,
    );
    const records = [];
    const misses = [];
    const skipped = [];
    for (const source of policy.investigationEnrichmentSources[normalized.type]) {
      if (!policy.sourceConfigured(source)) {
        skipped.push({source, reason: 'missing_api_key'});
        continue;
      }
      const found = await cache.peek(source, normalized.type, normalized.value);
      if (found.cached && found.record) records.push(found.record);
      else misses.push({source, cache_state: found.cache_state});
    }
    records.sort((left, right) => String(left.source).localeCompare(String(right.source)));
    return {
      ok: true,
      schema: 'onion-sentinel-investigation-enrichment-v1',
      indicator_type: normalized.type,
      indicator: normalized.value,
      cache_complete: misses.length === 0,
      records,
      misses,
      skipped,
    };
  }

  async function queryInvestigationEnrichment(indicatorType, indicator) {
    const normalized = policy.normalizeInvestigationEnrichmentIndicator(
      indicatorType,
      indicator,
    );
    const result = await enrichAlert(
      policy.investigationIndicatorAlert(normalized.type, normalized.value),
    );
    return {
      ok: result.ok,
      schema: 'onion-sentinel-investigation-enrichment-v1',
      status: result.status,
      indicator_type: normalized.type,
      indicator: normalized.value,
      enrichment: result.enrichment,
    };
  }

  return {
    reserveProviderRateLimitSlot,
    cachedLookup,
    runEnrichmentLookup,
    enrichAlert,
    cachedInvestigationEnrichment,
    queryInvestigationEnrichment,
  };
}

module.exports = {createEnrichmentOrchestrator};
