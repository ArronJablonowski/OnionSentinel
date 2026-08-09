'use strict';

const crypto = require('crypto');

const sourceLimitNotes = Object.freeze({
  abuseipdb: 'Free AbuseIPDB accounts are commonly limited to 1,000 checks/day.',
  greynoise: 'GreyNoise Community lookups are low-volume; cache aggressively.',
  shodan_internetdb: 'Shodan InternetDB is keyless, free for non-commercial use, and updated weekly.',
  otx: 'OTX authenticated API limits depend on account tier; 429 responses are cached as skips.',
  urlhaus: 'URLhaus community API uses an abuse.ch Auth-Key and fair-use expectations.',
  virustotal: 'VirusTotal Public API is throttled here to 4 requests/minute and used only for high/critical by default.',
  urlscan: 'urlscan.io quotas vary by account and action; URL submissions are disabled unless explicitly enabled.',
  google_safe_browsing: 'Google Safe Browsing uses API-key quota; public URLs are redacted before lookup.',
  phishtank: 'PhishTank publishes rate-limit headers and returns over-limit responses when exceeded.',
  malwarebazaar: 'MalwareBazaar hash lookups use an abuse.ch Auth-Key; file downloads are not performed.',
  threatfox: 'ThreatFox IOC lookups use an abuse.ch Auth-Key.',
  shodan: 'Shodan host API uses account quota; InternetDB runs separately without a key.',
  censys: 'Censys API quotas depend on account tier; IP lookups are throttled conservatively.',
  cisa_kev: 'CISA KEV is a public JSON catalog and is cached longer than alert IOC lookups.',
  epss: 'FIRST EPSS CVE lookups are public and cached longer than alert IOC lookups.',
  nvd: 'NVD allows 5 requests/30s without a key or 50 requests/30s with a key; this workflow throttles more conservatively.',
});

const investigationEnrichmentSources = Object.freeze({
  ip: ['abuseipdb', 'greynoise', 'shodan_internetdb', 'otx', 'shodan', 'censys'],
  domain: ['otx', 'urlscan', 'threatfox', 'virustotal'],
  url: ['urlhaus', 'urlscan', 'google_safe_browsing', 'phishtank', 'otx', 'virustotal'],
  hash: ['malwarebazaar', 'otx', 'threatfox', 'virustotal'],
  cve: ['cisa_kev', 'epss', 'nvd'],
});

function createEnrichmentPolicy({
  normalizeTimestampValue,
  nowUtc,
  isConfiguredSecret,
  enrichmentSecrets,
  defaultTtlSeconds,
  vulnerabilityTtlSeconds,
  sourceTtlDefaults,
  staleIfErrorSeconds,
  vulnerabilityStaleIfErrorSeconds,
  severityRank,
  virusTotalMinimumLevel,
  parseIpv4,
  isPrivateIpv4,
  publicHostname,
  redactUrlForPublicLookup,
  environment = process.env,
}) {
  for (const [name, value] of Object.entries({
    normalizeTimestampValue,
    nowUtc,
    isConfiguredSecret,
    parseIpv4,
    isPrivateIpv4,
    publicHostname,
    redactUrlForPublicLookup,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function normalizedEnrichmentRecord(
    source,
    indicator,
    indicatorType,
    verdict,
    confidence,
    tags,
    rawResponse,
    firstSeen = null,
    lastSeen = null,
  ) {
    return {
      source,
      indicator,
      indicator_type: indicatorType,
      verdict,
      confidence,
      tags: Array.isArray(tags) ? tags.filter(Boolean).slice(0, 20) : [],
      first_seen: normalizeTimestampValue(firstSeen),
      last_seen: normalizeTimestampValue(lastSeen),
      raw_response: rawResponse ?? null,
      cached_at: nowUtc(),
    };
  }

  function notFoundEnrichmentRecord(source, indicator, indicatorType, rawResponse) {
    return normalizedEnrichmentRecord(
      source,
      indicator,
      indicatorType,
      'unknown',
      0,
      ['not_found'],
      rawResponse || {status: 'not_found'},
    );
  }

  function verdictFromStats(stats = {}) {
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    if (malicious > 0) {
      return {verdict: 'malicious', confidence: Math.min(100, 70 + malicious * 5)};
    }
    if (suspicious > 0) {
      return {verdict: 'suspicious', confidence: Math.min(95, 50 + suspicious * 10)};
    }
    if (harmless > 0) return {verdict: 'benign', confidence: 60};
    return {verdict: 'unknown', confidence: 0};
  }

  function sourceLimitNote(source) {
    return sourceLimitNotes[source] || null;
  }

  function sourceConfigured(source) {
    switch (source) {
      case 'abuseipdb': return isConfiguredSecret(enrichmentSecrets.abuseipdb);
      case 'greynoise': return isConfiguredSecret(enrichmentSecrets.greynoise);
      case 'otx': return isConfiguredSecret(enrichmentSecrets.otx);
      case 'urlhaus': return isConfiguredSecret(enrichmentSecrets.urlhaus);
      case 'virustotal': return isConfiguredSecret(enrichmentSecrets.virustotal);
      case 'urlscan': return isConfiguredSecret(enrichmentSecrets.urlscan);
      case 'google_safe_browsing': return isConfiguredSecret(enrichmentSecrets.googleSafeBrowsing);
      case 'phishtank': return isConfiguredSecret(enrichmentSecrets.phishtank);
      case 'malwarebazaar': return isConfiguredSecret(enrichmentSecrets.malwarebazaar);
      case 'threatfox': return isConfiguredSecret(enrichmentSecrets.threatfox);
      case 'shodan': return isConfiguredSecret(enrichmentSecrets.shodan);
      case 'censys':
        return isConfiguredSecret(enrichmentSecrets.censysToken) || (
          isConfiguredSecret(enrichmentSecrets.censysId)
          && isConfiguredSecret(enrichmentSecrets.censysSecret)
        );
      case 'shodan_internetdb':
      case 'cisa_kev':
      case 'epss':
      case 'nvd':
        return true;
      default:
        return false;
    }
  }

  function sourceRateLimitMs(source) {
    const limits = {
      abuseipdb: 1000,
      greynoise: 2000,
      shodan_internetdb: 1000,
      otx: 500,
      urlhaus: 1000,
      virustotal: 15000,
      urlscan: 2000,
      google_safe_browsing: 1000,
      phishtank: 2000,
      malwarebazaar: 1000,
      threatfox: 1000,
      shodan: 1200,
      censys: 2500,
      cisa_kev: 60000,
      epss: 3000,
      nvd: isConfiguredSecret(enrichmentSecrets.nvd) ? 1000 : 7000,
    };
    return limits[source] || 1000;
  }

  function sourceTtlSeconds(source) {
    const normalizedSource = String(source || '').trim().toLowerCase();
    const sourceOverride = Number(
      environment[
        `ENRICHMENT_CACHE_${normalizedSource.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_TTL_SECONDS`
      ],
    );
    if (Number.isFinite(sourceOverride) && sourceOverride >= 300) {
      return Math.floor(sourceOverride);
    }
    if (['cisa_kev', 'epss', 'nvd'].includes(normalizedSource)) {
      return Math.max(300, vulnerabilityTtlSeconds);
    }
    return Math.max(300, sourceTtlDefaults[normalizedSource] || defaultTtlSeconds);
  }

  function sourceStaleIfErrorSeconds(source) {
    return ['cisa_kev', 'epss', 'nvd'].includes(String(source || '').toLowerCase())
      ? vulnerabilityStaleIfErrorSeconds
      : staleIfErrorSeconds;
  }

  function shouldUseVirusTotal(alert) {
    const level = String(alert.triage?.level || alert.severity_label || '').toLowerCase();
    return (severityRank[level] ?? 0) >= (
      severityRank[virusTotalMinimumLevel] ?? severityRank.high
    );
  }

  function normalizeInvestigationEnrichmentIndicator(indicatorType, indicator) {
    const type = String(indicatorType || '').trim().toLowerCase();
    const value = String(indicator || '').trim();
    if (!Object.hasOwn(investigationEnrichmentSources, type)) {
      throw Object.assign(
        new Error('unsupported enrichment indicator type'),
        {statusCode: 400},
      );
    }
    let normalized = '';
    if (type === 'ip') {
      normalized = parseIpv4(value) && !isPrivateIpv4(value) ? value : '';
    } else if (type === 'domain') {
      normalized = publicHostname(value) || '';
    } else if (type === 'url') {
      normalized = redactUrlForPublicLookup(value) || '';
    } else if (type === 'hash') {
      normalized = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value)
        ? value.toLowerCase() : '';
    } else if (type === 'cve') {
      normalized = /^CVE-\d{4}-\d{4,7}$/i.test(value) ? value.toUpperCase() : '';
    }
    if (!normalized) {
      throw Object.assign(
        new Error('indicator is invalid, private, internal, or unsafe for public enrichment'),
        {statusCode: 400},
      );
    }
    return {type, value: normalized};
  }

  function investigationIndicatorAlert(type, value) {
    const correlationToken = crypto
      .createHash('sha256')
      .update(`${type}:${value}`)
      .digest('hex')
      .slice(0, 16);
    const alert = {
      alert_id: `investigation-enrichment:${correlationToken}`,
      timestamp: nowUtc(),
      rule_name: 'Bounded investigation enrichment pivot',
      event_dataset: 'onion_sentinel.investigation_enrichment',
      severity_label: 'high',
      triage: {level: 'high'},
    };
    if (type === 'ip') alert.destination = {ip: value};
    if (type === 'domain') alert.dns = {question: {name: value}};
    if (type === 'url') alert.url = {full: value};
    if (type === 'hash' || type === 'cve') alert.message = value;
    return alert;
  }

  return {
    investigationEnrichmentSources,
    normalizedEnrichmentRecord,
    notFoundEnrichmentRecord,
    verdictFromStats,
    sourceLimitNote,
    sourceConfigured,
    sourceRateLimitMs,
    sourceTtlSeconds,
    sourceStaleIfErrorSeconds,
    shouldUseVirusTotal,
    normalizeInvestigationEnrichmentIndicator,
    investigationIndicatorAlert,
  };
}

module.exports = {createEnrichmentPolicy};
