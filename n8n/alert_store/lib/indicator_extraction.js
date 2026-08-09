'use strict';

function createIndicatorExtraction({parseIpv4, isPrivateIpv4, nestedField}) {
  for (const [name, value] of Object.entries({parseIpv4, isPrivateIpv4, nestedField})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function isProbablyPlaceholderSecret(value) {
    if (!value) return true;
    const text = String(value).trim().toLowerCase();
    return !text
      || text.includes('replace')
      || text.includes('placeholder')
      || text.includes('your-')
      || text.includes('changeme');
  }

  function isConfiguredSecret(value) {
    return !isProbablyPlaceholderSecret(value);
  }

  function publicHostname(value) {
    if (!value || typeof value !== 'string') return null;
    const hostname = value.trim().toLowerCase().replace(/\.$/, '');
    if (!hostname || hostname === 'localhost') return null;
    if (!hostname.includes('.')) return null;
    if (/\.local$|\.lan$|\.home$|\.internal$|\.corp$/.test(hostname)) return null;
    if (/^(tls\.sni|h2\.http|suricata\.alert|document\.packet|ds-logs-suricata\.alerts)$/.test(hostname)) return null;
    if (/^\d+\.json$/.test(hostname)) return null;
    if (parseIpv4(hostname)) return isPrivateIpv4(hostname) ? null : hostname;
    return hostname;
  }

  function redactUrlForPublicLookup(value) {
    if (!value || typeof value !== 'string') return null;
    try {
      const parsed = new URL(value);
      const hostname = publicHostname(parsed.hostname);
      if (!hostname) return null;
      parsed.username = '';
      parsed.password = '';
      parsed.search = '';
      parsed.hash = '';
      return parsed.toString();
    } catch {
      return null;
    }
  }

  function collectStrings(value, results = []) {
    if (typeof value === 'string') {
      results.push(value);
      return results;
    }
    if (Array.isArray(value)) {
      for (const item of value) collectStrings(item, results);
      return results;
    }
    if (value && typeof value === 'object') {
      for (const item of Object.values(value)) collectStrings(item, results);
    }
    return results;
  }

  function collectValuesByKey(value, keyMatcher, results = []) {
    if (Array.isArray(value)) {
      for (const item of value) collectValuesByKey(item, keyMatcher, results);
      return results;
    }
    if (!value || typeof value !== 'object') return results;
    for (const [key, item] of Object.entries(value)) {
      if (keyMatcher(String(key))) results.push(item);
      collectValuesByKey(item, keyMatcher, results);
    }
    return results;
  }

  function extractUrlsFromText(value) {
    const urls = [];
    for (const text of collectStrings(value)) {
      for (const match of text.match(/\bhttps?:\/\/[^\s<>"'`]+/gi) || []) {
        const cleaned = match.replace(/[),.;\]]+$/, '');
        const redacted = redactUrlForPublicLookup(cleaned);
        if (redacted) urls.push(redacted);
      }
    }
    return urls;
  }

  function extractIpv4sFromText(value) {
    const ips = [];
    for (const text of collectStrings(value)) {
      for (const match of text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []) {
        if (parseIpv4(match) && !isPrivateIpv4(match)) ips.push(match);
      }
    }
    return ips;
  }

  function extractDomainsFromText(value) {
    const domains = [];
    for (const text of collectStrings(value)) {
      const normalizedText = text.replace(/\s+\./g, '.').replace(/\.\s+/g, '.');
      for (const match of normalizedText.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi) || []) {
        const normalized = publicHostname(match);
        if (normalized) domains.push(normalized);
      }
    }
    return domains;
  }

  function domainTextCandidateFields(alert) {
    return [
      alert.message,
      alert.rule_name,
      nestedField(alert, 'rule.name'),
      nestedField(alert, 'event.reason'),
      nestedField(alert, 'suricata.eve.alert.signature'),
      nestedField(alert, 'security_onion.raw_event.alert.signature'),
    ];
  }

  function domainCandidateFields(alert) {
    return [
      nestedField(alert, 'url.domain'),
      nestedField(alert, 'dns.question.name'),
      nestedField(alert, 'dns.question.registered_domain'),
      nestedField(alert, 'dns.question.top_level_domain'),
      nestedField(alert, 'dns.answers.data'),
      nestedField(alert, 'dns.answers.name'),
      nestedField(alert, 'tls.client.server_name'),
      nestedField(alert, 'tls.server.x509.subject.common_name'),
      nestedField(alert, 'tls.server.x509.issuer.common_name'),
      nestedField(alert, 'http.request.referrer'),
      nestedField(alert, 'http.request.headers.host'),
      nestedField(alert, 'http.response.headers.location'),
      nestedField(alert, 'suricata.eve.dns.rrname'),
      nestedField(alert, 'suricata.eve.dns.query'),
      nestedField(alert, 'suricata.eve.dns.answers.rrname'),
      nestedField(alert, 'suricata.eve.dns.answers.rdata'),
      nestedField(alert, 'suricata.eve.tls.sni'),
      nestedField(alert, 'suricata.eve.http.hostname'),
      nestedField(alert, 'security_onion.raw_event.dns.rrname'),
      nestedField(alert, 'security_onion.raw_event.dns.query'),
      nestedField(alert, 'security_onion.raw_event.dns.answers.rrname'),
      nestedField(alert, 'security_onion.raw_event.dns.answers.rdata'),
      nestedField(alert, 'security_onion.raw_event.tls.sni'),
      nestedField(alert, 'security_onion.raw_event.http.hostname'),
      ...(alert.related?.hosts || []),
      ...extractDomainsFromText(domainTextCandidateFields(alert)),
    ];
  }

  function urlCandidateFields(alert) {
    return [
      alert.url?.full,
      alert.url?.original,
      nestedField(alert, 'http.request.referrer'),
      nestedField(alert, 'http.response.headers.location'),
      nestedField(alert, 'suricata.eve.http.url'),
      nestedField(alert, 'suricata.eve.http.http_refer'),
      nestedField(alert, 'security_onion.raw_event.url.full'),
      nestedField(alert, 'security_onion.raw_event.url.original'),
      nestedField(alert, 'security_onion.raw_event.http.url'),
      nestedField(alert, 'security_onion.raw_event.http.http_refer'),
    ];
  }

  function extractCvesFromText(value) {
    const text = typeof value === 'string' ? value : JSON.stringify(value || {});
    return [...new Set(
      (text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((cve) => cve.toUpperCase()),
    )];
  }

  function extractHashesFromText(value) {
    const text = typeof value === 'string' ? value : JSON.stringify(value || {});
    const hashes = [];
    for (const match of text.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g) || []) {
      const length = match.length;
      hashes.push({
        type: length === 32 ? 'md5' : length === 40 ? 'sha1' : 'sha256',
        value: match.toLowerCase(),
      });
    }
    return [...new Map(
      hashes.map((item) => [`${item.type}:${item.value}`, item]),
    ).values()];
  }

  function extractAlertIndicators(alert) {
    const evidenceAlert = {...(alert || {})};
    delete evidenceAlert.enrichment;
    const indicators = {
      public_ips: [], domains: [], urls: [], hashes: [], cves: [],
    };
    for (const ip of [
      nestedField(alert, 'source.ip'),
      nestedField(alert, 'destination.ip'),
      nestedField(alert, 'client.ip'),
      nestedField(alert, 'server.ip'),
      nestedField(alert, 'host.ip'),
      ...(alert.related?.ip || []),
      ...collectValuesByKey(evidenceAlert, (key) => /(^|_|\.)ip$/i.test(key)),
      ...extractIpv4sFromText(evidenceAlert),
    ]) {
      if (typeof ip === 'string' && parseIpv4(ip) && !isPrivateIpv4(ip)) {
        indicators.public_ips.push(ip);
      }
      if (Array.isArray(ip)) {
        for (const item of ip) {
          if (typeof item === 'string' && parseIpv4(item) && !isPrivateIpv4(item)) {
            indicators.public_ips.push(item);
          }
        }
      }
    }
    for (const hostname of domainCandidateFields(evidenceAlert)) {
      const values = Array.isArray(hostname) ? hostname : [hostname];
      for (const value of values) {
        const normalized = publicHostname(value);
        if (normalized) indicators.domains.push(normalized);
      }
    }
    for (const candidate of urlCandidateFields(evidenceAlert)) {
      const values = Array.isArray(candidate) ? candidate : [candidate];
      for (const value of values) {
        const redacted = redactUrlForPublicLookup(value);
        if (redacted) indicators.urls.push(redacted);
        try {
          const parsed = new URL(String(value));
          const hostname = publicHostname(parsed.hostname);
          if (hostname) indicators.domains.push(hostname);
        } catch {
          // Non-URL strings are handled by the domain field extraction above.
        }
      }
    }
    indicators.hashes = extractHashesFromText(evidenceAlert);
    indicators.cves = extractCvesFromText(evidenceAlert);
    for (const key of Object.keys(indicators)) {
      indicators[key] = [...new Set(
        indicators[key].map(
          (item) => (typeof item === 'string' ? item : JSON.stringify(item)),
        ),
      )].map((item) => {
        try {
          return item.startsWith('{') ? JSON.parse(item) : item;
        } catch {
          return item;
        }
      });
    }
    return indicators;
  }

  function hasUsableExternalIntel(alert) {
    const externalIntel = alert?.enrichment?.external_intel;
    if (!externalIntel || typeof externalIntel !== 'object') return false;
    return (
      Array.isArray(externalIntel.records) && externalIntel.records.length > 0
    ) || (
      Array.isArray(externalIntel.skipped) && externalIntel.skipped.length > 0
    ) || (
      Array.isArray(externalIntel.errors) && externalIntel.errors.length > 0
    );
  }

  return {
    isProbablyPlaceholderSecret,
    isConfiguredSecret,
    publicHostname,
    redactUrlForPublicLookup,
    extractUrlsFromText,
    extractIpv4sFromText,
    extractDomainsFromText,
    extractCvesFromText,
    extractHashesFromText,
    extractAlertIndicators,
    hasUsableExternalIntel,
  };
}

module.exports = {createIndicatorExtraction};
