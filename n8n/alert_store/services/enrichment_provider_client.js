'use strict';

function createEnrichmentProviderClient({
  controlledEvaluationMode,
  boundedRequestJson,
  timeoutMs,
  maxResponseBytes,
  safeString,
  normalizedEnrichmentRecord,
  notFoundEnrichmentRecord,
  verdictFromStats,
  enrichmentSecrets,
  isConfiguredSecret,
  formatProjectTimestamp,
}) {
  for (const [name, value] of Object.entries({
    boundedRequestJson,
    safeString,
    normalizedEnrichmentRecord,
    notFoundEnrichmentRecord,
    verdictFromStats,
    isConfiguredSecret,
    formatProjectTimestamp,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function requestJson(options) {
    if (controlledEvaluationMode) {
      throw new Error('outbound HTTP is disabled in controlled evaluation mode');
    }
    return boundedRequestJson({timeoutMs, maxResponseBytes, ...options});
  }

  function providerErrorDetail(body) {
    if (!body || typeof body !== 'object') return '';
    const errors = Array.isArray(body.errors)
      ? body.errors.map((item) => safeString(item?.message || item, 160)).filter(Boolean)
      : [];
    return safeString(
      errors.join('; ') || body.detail || body.message || body.error,
      240,
    );
  }

  function isoFromMs(value) {
    return formatProjectTimestamp(new Date(value));
  }

  async function lookupAbuseIpdb(ip) {
    const response = await requestJson({
      url: `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
      headers: {Key: enrichmentSecrets.abuseipdb},
    });
    const data = response.body?.data || {};
    const score = Number(data.abuseConfidenceScore || 0);
    const verdict = score >= 75
      ? 'malicious' : score >= 25 ? 'suspicious' : score > 0 ? 'unknown' : 'benign';
    return normalizedEnrichmentRecord(
      'abuseipdb', ip, 'ip', verdict, score,
      [data.usageType, data.isp, data.countryCode], response.body,
      null, data.lastReportedAt || null,
    );
  }

  async function lookupGreynoise(ip) {
    const response = await requestJson({
      url: `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`,
      headers: {key: enrichmentSecrets.greynoise},
      allowedStatusCodes: [404],
    });
    if (response.statusCode === 404) {
      return notFoundEnrichmentRecord('greynoise', ip, 'ip', response.body);
    }
    const body = response.body || {};
    const classification = String(body.classification || '').toLowerCase();
    const verdict = classification === 'malicious'
      ? 'malicious'
      : classification === 'benign' ? 'noise/scanner' : body.noise ? 'noise/scanner' : 'unknown';
    return normalizedEnrichmentRecord(
      'greynoise', ip, 'ip', verdict, body.noise ? 80 : 30,
      [body.classification, body.name, body.link ? 'greynoise-link' : null],
      body, null, body.last_seen || null,
    );
  }

  async function lookupShodanInternetDb(ip) {
    const response = await requestJson({
      url: `https://internetdb.shodan.io/${encodeURIComponent(ip)}`,
      allowedStatusCodes: [404],
    });
    const body = response.statusCode === 404 ? {status: 'not_found'} : response.body || {};
    if (response.statusCode === 404) {
      return notFoundEnrichmentRecord('shodan_internetdb', ip, 'ip', body);
    }
    const cves = Array.isArray(body.vulns) ? body.vulns : Object.keys(body.vulns || {});
    const verdict = cves.length
      ? 'suspicious' : Array.isArray(body.ports) && body.ports.length ? 'unknown' : 'benign';
    return normalizedEnrichmentRecord(
      'shodan_internetdb', ip, 'ip', verdict, cves.length ? 65 : 30,
      [...(body.tags || []), ...cves.slice(0, 5)], body,
    );
  }

  async function lookupOtx(indicatorType, indicator) {
    const typeMap = {ip: 'IPv4', domain: 'domain', url: 'url', hash: 'file'};
    const response = await requestJson({
      url: `https://otx.alienvault.com/api/v1/indicators/${typeMap[indicatorType]}/${encodeURIComponent(indicator)}/general`,
      headers: {'X-OTX-API-KEY': enrichmentSecrets.otx},
      allowedStatusCodes: [404],
    });
    if (response.statusCode === 404) {
      return notFoundEnrichmentRecord('otx', indicator, indicatorType, response.body);
    }
    const pulses = response.body?.pulse_info?.count || 0;
    return normalizedEnrichmentRecord(
      'otx', indicator, indicatorType, pulses > 0 ? 'suspicious' : 'unknown',
      pulses > 0 ? 55 : 0, [`pulses:${pulses}`], response.body,
    );
  }

  async function lookupUrlhaus(urlValue) {
    const response = await requestJson({
      method: 'POST',
      url: 'https://urlhaus-api.abuse.ch/v1/url/',
      headers: {
        'Auth-Key': enrichmentSecrets.urlhaus,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(urlValue)}`,
    });
    const queryStatus = response.body?.query_status;
    return normalizedEnrichmentRecord(
      'urlhaus', urlValue, 'url', queryStatus === 'ok' ? 'malicious' : 'unknown',
      queryStatus === 'ok' ? 85 : 0,
      [response.body?.threat, response.body?.url_status], response.body,
      response.body?.date_added || null, response.body?.last_online || null,
    );
  }

  async function lookupVirusTotal(indicatorType, indicator) {
    const pathMap = {
      ip: `ip_addresses/${encodeURIComponent(indicator)}`,
      domain: `domains/${encodeURIComponent(indicator)}`,
      hash: `files/${encodeURIComponent(indicator)}`,
      url: `urls/${Buffer.from(indicator).toString('base64url')}`,
    };
    const response = await requestJson({
      url: `https://www.virustotal.com/api/v3/${pathMap[indicatorType]}`,
      headers: {'x-apikey': enrichmentSecrets.virustotal},
      allowedStatusCodes: [404],
    });
    if (response.statusCode === 404) {
      return notFoundEnrichmentRecord('virustotal', indicator, indicatorType, response.body);
    }
    const attrs = response.body?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || attrs.last_http_response_content_sha256
      ? attrs.last_analysis_stats : {};
    const verdict = verdictFromStats(stats);
    return normalizedEnrichmentRecord(
      'virustotal', indicator, indicatorType, verdict.verdict, verdict.confidence,
      Object.keys(stats).map((key) => `${key}:${stats[key]}`), response.body, null,
      attrs.last_analysis_date ? isoFromMs(Number(attrs.last_analysis_date) * 1000) : null,
    );
  }

  async function lookupUrlscan(indicatorType, indicator) {
    const query = indicatorType === 'domain' ? `domain:${indicator}` : indicator;
    const response = await requestJson({
      url: `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(query)}&size=10`,
      headers: {'API-Key': enrichmentSecrets.urlscan},
    });
    const results = response.body?.results || [];
    const malicious = results.some(
      (item) => item.verdicts?.overall?.malicious || item.verdicts?.engines?.malicious,
    );
    return normalizedEnrichmentRecord(
      'urlscan', indicator, indicatorType, malicious ? 'malicious' : 'unknown',
      malicious ? 75 : 15, [`results:${results.length}`], response.body,
    );
  }

  async function lookupGoogleSafeBrowsing(urlValue) {
    const response = await requestJson({
      method: 'POST',
      url: `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(enrichmentSecrets.googleSafeBrowsing)}`,
      body: {
        client: {clientId: 'onion-sentinel', clientVersion: '1.0'},
        threatInfo: {
          threatTypes: [
            'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{url: urlValue}],
        },
      },
    });
    const matches = response.body?.matches || [];
    return normalizedEnrichmentRecord(
      'google_safe_browsing', urlValue, 'url',
      matches.length ? 'malicious' : 'benign', matches.length ? 90 : 65,
      matches.map((item) => item.threatType), response.body,
    );
  }

  async function lookupPhishTank(urlValue) {
    const body = `url=${encodeURIComponent(urlValue)}&format=json&app_key=${encodeURIComponent(enrichmentSecrets.phishtank)}`;
    const response = await requestJson({
      method: 'POST',
      url: 'https://checkurl.phishtank.com/checkurl/',
      headers: {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'OnionSentinel/1.0'},
      body,
    });
    const result = response.body?.results || {};
    const phishing = Boolean(result.in_database && result.valid);
    return normalizedEnrichmentRecord(
      'phishtank', urlValue, 'url', phishing ? 'malicious' : 'unknown',
      phishing ? 85 : 0, [result.verified ? 'verified' : null], response.body,
    );
  }

  async function lookupMalwareBazaar(hash) {
    const response = await requestJson({
      method: 'POST',
      url: 'https://mb-api.abuse.ch/api/v1/',
      headers: {
        'Auth-Key': enrichmentSecrets.malwarebazaar,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `query=get_info&hash=${encodeURIComponent(hash)}`,
    });
    const found = response.body?.query_status === 'ok';
    const first = Array.isArray(response.body?.data) ? response.body.data[0] : {};
    return normalizedEnrichmentRecord(
      'malwarebazaar', hash, 'hash', found ? 'malicious' : 'unknown', found ? 85 : 0,
      [first?.signature, first?.file_type, first?.tags?.slice?.(0, 5)?.join(',')],
      response.body, first?.first_seen || null, first?.last_seen || null,
    );
  }

  async function lookupThreatFox(indicatorType, indicator) {
    const response = await requestJson({
      method: 'POST',
      url: 'https://threatfox-api.abuse.ch/api/v1/',
      headers: {'Auth-Key': enrichmentSecrets.threatfox},
      body: {query: 'search_ioc', search_term: indicator},
    });
    const found = response.body?.query_status === 'ok';
    const first = Array.isArray(response.body?.data) ? response.body.data[0] : {};
    return normalizedEnrichmentRecord(
      'threatfox', indicator, indicatorType, found ? 'malicious' : 'unknown',
      found ? 80 : 0, [first?.malware, first?.ioc_type, first?.threat_type],
      response.body, first?.first_seen || null, first?.last_seen || null,
    );
  }

  async function lookupShodan(ip) {
    const response = await requestJson({
      url: `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(enrichmentSecrets.shodan)}`,
      allowedStatusCodes: [404],
    });
    if (response.statusCode === 404) {
      return notFoundEnrichmentRecord('shodan', ip, 'ip', response.body);
    }
    const body = response.body || {};
    const vulns = Array.isArray(body.vulns) ? body.vulns : Object.keys(body.vulns || {});
    return normalizedEnrichmentRecord(
      'shodan', ip, 'ip', vulns.length ? 'suspicious' : 'unknown',
      vulns.length ? 70 : 25, [...(body.tags || []), ...vulns.slice(0, 5)],
      body, null, body.last_update || null,
    );
  }

  async function lookupCensys(ip) {
    if (isConfiguredSecret(enrichmentSecrets.censysToken)) {
      const headers = {
        Authorization: `Bearer ${enrichmentSecrets.censysToken}`,
        Accept: 'application/vnd.censys.api.v3.host.v1+json',
      };
      if (isConfiguredSecret(enrichmentSecrets.censysOrganizationId)) {
        headers['X-Organization-ID'] = enrichmentSecrets.censysOrganizationId;
      }
      const response = await requestJson({
        url: `https://api.platform.censys.io/v3/global/asset/host/${encodeURIComponent(ip)}`,
        headers,
        allowedStatusCodes: [404],
      });
      if (response.statusCode === 404) {
        return notFoundEnrichmentRecord('censys', ip, 'ip', response.body);
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        const detail = providerErrorDetail(response.body);
        throw new Error(
          `Censys Platform API returned HTTP ${response.statusCode}${detail ? `: ${detail}` : ''}`,
        );
      }
      const body = response.body || {};
      const services = body.result?.services || body.resource?.services || body.host?.services || [];
      const tags = services.map(
        (service) => service.service_name || service.port || service.transport_protocol,
      ).filter(Boolean).slice(0, 10);
      return normalizedEnrichmentRecord(
        'censys', ip, 'ip', 'unknown', services.length ? 35 : 0, tags, body,
      );
    }
    const auth = Buffer.from(
      `${enrichmentSecrets.censysId}:${enrichmentSecrets.censysSecret}`,
    ).toString('base64');
    const response = await requestJson({
      url: `https://search.censys.io/api/v2/hosts/${encodeURIComponent(ip)}`,
      headers: {Authorization: `Basic ${auth}`},
      allowedStatusCodes: [404],
    });
    if (response.statusCode === 404) {
      return notFoundEnrichmentRecord('censys', ip, 'ip', response.body);
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      const detail = providerErrorDetail(response.body);
      throw new Error(
        `Censys Search API returned HTTP ${response.statusCode}${detail ? `: ${detail}` : ''}`,
      );
    }
    const body = response.body || {};
    const services = body.result?.services || [];
    const tags = services.map((service) => service.service_name).filter(Boolean).slice(0, 10);
    return normalizedEnrichmentRecord(
      'censys', ip, 'ip', 'unknown', services.length ? 35 : 0, tags, body,
    );
  }

  async function lookupCisaKev(cve) {
    const response = await requestJson({
      url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    });
    const vuln = (response.body?.vulnerabilities || []).find(
      (item) => String(item.cveID || '').toUpperCase() === cve,
    );
    return normalizedEnrichmentRecord(
      'cisa_kev', cve, 'cve', vuln ? 'malicious' : 'unknown', vuln ? 90 : 0,
      [vuln?.vendorProject, vuln?.product, vuln?.knownRansomwareCampaignUse], response.body,
    );
  }

  async function lookupEpss(cve) {
    const response = await requestJson({
      url: `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`,
    });
    const item = Array.isArray(response.body?.data) ? response.body.data[0] : null;
    const epss = Number(item?.epss || 0);
    return normalizedEnrichmentRecord(
      'epss', cve, 'cve', epss >= 0.7 ? 'suspicious' : 'unknown',
      Math.round(epss * 100), [`percentile:${item?.percentile || 'n/a'}`], response.body,
    );
  }

  async function lookupNvd(cve) {
    const headers = isConfiguredSecret(enrichmentSecrets.nvd)
      ? {apiKey: enrichmentSecrets.nvd} : {};
    const response = await requestJson({
      url: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve)}`,
      headers,
    });
    const vuln = Array.isArray(response.body?.vulnerabilities)
      ? response.body.vulnerabilities[0]?.cve : null;
    const metrics = vuln?.metrics || {};
    const score = metrics.cvssMetricV31?.[0]?.cvssData?.baseScore
      || metrics.cvssMetricV30?.[0]?.cvssData?.baseScore
      || metrics.cvssMetricV2?.[0]?.cvssData?.baseScore || 0;
    return normalizedEnrichmentRecord(
      'nvd', cve, 'cve', Number(score) >= 9 ? 'suspicious' : 'unknown',
      Math.round(Number(score) * 10), [`cvss:${score || 'n/a'}`], response.body,
      vuln?.published || null, vuln?.lastModified || null,
    );
  }

  return {
    requestJson,
    providerErrorDetail,
    lookupAbuseIpdb,
    lookupGreynoise,
    lookupShodanInternetDb,
    lookupOtx,
    lookupUrlhaus,
    lookupVirusTotal,
    lookupUrlscan,
    lookupGoogleSafeBrowsing,
    lookupPhishTank,
    lookupMalwareBazaar,
    lookupThreatFox,
    lookupShodan,
    lookupCensys,
    lookupCisaKev,
    lookupEpss,
    lookupNvd,
  };
}

module.exports = {createEnrichmentProviderClient};
