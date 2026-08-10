'use strict';

function defaultScoringRules() {
  return {
    thresholds: {medium_min: 40, high_min: 70, critical_min: 85},
    severity_base: {
      critical: 85,
      high: 70,
      medium: 45,
      low: 25,
      numeric_4_or_more: 75,
      numeric_3: 60,
      numeric_2: 45,
      numeric_1: 25,
      default: 30,
    },
    infrastructure_ips: ['192.168.1.7', '10.77.7.225'],
    direction_adjustments: {
      inbound: 15,
      outbound: 10,
      internal: 3,
      external: 0,
      unknown: 0,
    },
    infrastructure_adjustments: {destination: 15, source: 5},
    keyword_adjustments: [],
    rule_adjustments: [],
    pair_adjustments: [],
    drop_rules: [],
    suppress_rules: [],
  };
}

function createScoringRulesRuntime({fs, scoringRulesPath, logError}) {
  function load() {
    // Fallbacks keep ingestion alive if scoring_rules.json is missing or invalid.
    // Normal tuning should happen in config/scoring_rules.json.
    const fallback = defaultScoringRules();
    try {
      return {
        ...fallback,
        ...JSON.parse(fs.readFileSync(scoringRulesPath, 'utf8')),
      };
    } catch (error) {
      logError(`Unable to load scoring rules from ${scoringRulesPath}: ${error.message}`);
      return fallback;
    }
  }

  return {load};
}

module.exports = {createScoringRulesRuntime, defaultScoringRules};
