'use strict';

function createScoringPolicy({rules, nestedField}) {
  if (!rules || typeof rules !== 'object') {
    throw new TypeError('scoring rules are required');
  }
  if (typeof nestedField !== 'function') {
    throw new TypeError('nestedField must be a function');
  }

  function parseIpv4(ip) {
    if (typeof ip !== 'string') return null;
    const parts = ip.split('.').map((part) => Number(part));
    if (
      parts.length !== 4
      || parts.some((part) => (
        !Number.isInteger(part) || part < 0 || part > 255
      ))
    ) return null;
    return parts;
  }

  function isPrivateIpv4(ip) {
    const parts = parseIpv4(ip);
    if (!parts) return false;
    const [a, b] = parts;
    return a === 10
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 100 && b >= 64 && b <= 127)
      || a === 127;
  }

  function isInfrastructureIp(ip) {
    return rules.infrastructure_ips.includes(ip);
  }

  function trafficDirection(sourceIp, destinationIp) {
    const srcPrivate = isPrivateIpv4(sourceIp);
    const dstPrivate = isPrivateIpv4(destinationIp);
    if (srcPrivate && dstPrivate) return 'internal';
    if (!srcPrivate && dstPrivate) return 'inbound';
    if (srcPrivate && !dstPrivate) return 'outbound';
    if (!srcPrivate && !dstPrivate && sourceIp && destinationIp) return 'external';
    return 'unknown';
  }

  function severityBase(alert) {
    const base = rules.severity_base;
    const label = String(alert.severity_label || '').toLowerCase();
    const severity = Number(alert.severity);
    if (label.includes('critical')) return base.critical;
    if (label.includes('high')) return base.high;
    if (label.includes('medium')) return base.medium;
    if (label.includes('low')) return base.low;
    if (Number.isFinite(severity)) {
      if (severity >= 4) return base.numeric_4_or_more;
      if (severity === 3) return base.numeric_3;
      if (severity === 2) return base.numeric_2;
      if (severity === 1) return base.numeric_1;
    }
    return base.default;
  }

  function alertText(alert) {
    return [
      alert.rule_name,
      alert.rule_category,
      alert.rule_ruleset,
      JSON.stringify(alert.rule_metadata || {}),
    ].join(' ').toLowerCase();
  }

  function matchesText(text, keywords = []) {
    return keywords.some(
      (keyword) => text.includes(String(keyword).toLowerCase()),
    );
  }

  function matchesAdjustment(adjustment, alert, text) {
    const sourceIp = nestedField(alert, 'source.ip');
    const destinationIp = nestedField(alert, 'destination.ip');
    if (adjustment.source_ip && adjustment.source_ip !== sourceIp) return false;
    if (
      adjustment.destination_ip
      && adjustment.destination_ip !== destinationIp
    ) return false;
    if (
      adjustment.rule_contains
      && !String(alert.rule_name || '').toLowerCase().includes(
        String(adjustment.rule_contains).toLowerCase(),
      )
    ) return false;
    if (adjustment.keywords && !matchesText(text, adjustment.keywords)) return false;
    return true;
  }

  function ruleName(rule) {
    return rule.name
      || rule.reason
      || rule.rule_contains
      || 'unnamed policy rule';
  }

  function findDropRule(alert) {
    const text = alertText(alert);
    const dropRules = [
      ...(rules.drop_rules || []),
      ...((rules.filter_rules && rules.filter_rules.drop_alerts) || []),
    ];
    return dropRules.find(
      (rule) => matchesAdjustment(rule, alert, text),
    ) || null;
  }

  function levelAllowed(rule, level) {
    const levels = rule.levels || rule.triage_levels;
    if (!levels || !levels.length) return true;
    return levels
      .map((item) => String(item).toLowerCase())
      .includes(String(level || '').toLowerCase());
  }

  function policyKeyPart(alert, field) {
    if (field === 'rule_name') return alert.rule_name || 'unknown-rule';
    if (field === 'triage.level') {
      return nestedField(alert, 'triage.level') || 'unknown-level';
    }
    return nestedField(alert, field) || `unknown-${field}`;
  }

  function suppressionKey(rule, alert) {
    const fields = rule.key_fields
      || ['triage.level', 'rule_name', 'source.ip', 'destination.ip'];
    return fields
      .map((field) => `${field}=${policyKeyPart(alert, field)}`)
      .join('|');
  }

  function findSuppressRule(alert) {
    const text = alertText(alert);
    const level = nestedField(alert, 'triage.level');
    return (rules.suppress_rules || []).find((rule) => (
      levelAllowed(rule, level) && matchesAdjustment(rule, alert, text)
    )) || null;
  }

  function scoreAlert(alert) {
    const sourceIp = nestedField(alert, 'source.ip');
    const destinationIp = nestedField(alert, 'destination.ip');
    const direction = trafficDirection(sourceIp, destinationIp);
    const text = alertText(alert);
    const reasons = [];
    let score = severityBase(alert);
    reasons.push(`base severity score ${score}`);

    const directionDelta = rules.direction_adjustments[direction] || 0;
    if (directionDelta) {
      score += directionDelta;
      const labels = {
        inbound: 'public-to-private inbound traffic',
        outbound: 'private-to-public outbound traffic',
        internal: 'internal private traffic',
        external: 'external-to-external traffic',
      };
      reasons.push(labels[direction] || `${direction} traffic`);
    }

    if (isInfrastructureIp(destinationIp)) {
      score += rules.infrastructure_adjustments.destination || 0;
      reasons.push('destination is monitored infrastructure');
    }
    if (isInfrastructureIp(sourceIp)) {
      score += rules.infrastructure_adjustments.source || 0;
      reasons.push('source is monitored infrastructure');
    }

    for (const adjustment of rules.keyword_adjustments || []) {
      if (matchesText(text, adjustment.keywords || [])) {
        score += Number(adjustment.score_delta || 0);
        if (adjustment.reason) reasons.push(adjustment.reason);
      }
    }

    if (String(alert.severity_label || '').toLowerCase() === 'low') {
      const lowAdjustment = (rules.keyword_adjustments || []).find(
        (item) => item.name === 'informational or low severity',
      );
      const delta = lowAdjustment ? Number(lowAdjustment.score_delta || 0) : -8;
      score += delta;
      reasons.push(
        lowAdjustment?.reason || 'rule appears informational or low severity',
      );
    }

    for (const adjustment of [
      ...(rules.rule_adjustments || []),
      ...(rules.pair_adjustments || []),
    ]) {
      if (matchesAdjustment(adjustment, alert, text)) {
        score += Number(adjustment.score_delta || 0);
        if (adjustment.reason) reasons.push(adjustment.reason);
      }
    }

    score = Math.max(0, Math.min(100, Math.round(score)));
    const thresholds = rules.thresholds;
    let level = 'low';
    if (score >= thresholds.critical_min) level = 'critical';
    else if (score >= thresholds.high_min) level = 'high';
    else if (score >= thresholds.medium_min) level = 'medium';

    let routing = 'store-only';
    if (level === 'critical' || level === 'high') {
      routing = 'analyst-review-immediate';
    } else if (level === 'medium') routing = 'analyst-review';

    return {
      score,
      level,
      routing,
      traffic_direction: direction,
      source_is_private: isPrivateIpv4(sourceIp),
      destination_is_private: isPrivateIpv4(destinationIp),
      source_is_infrastructure: isInfrastructureIp(sourceIp),
      destination_is_infrastructure: isInfrastructureIp(destinationIp),
      reasons,
    };
  }

  return {
    parseIpv4,
    isPrivateIpv4,
    trafficDirection,
    ruleName,
    findDropRule,
    suppressionKey,
    findSuppressRule,
    scoreAlert,
  };
}

module.exports = {createScoringPolicy};
