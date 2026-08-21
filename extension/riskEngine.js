/**
 * riskEngine.js — PhishGuard Transparent Risk Scoring Engine
 * 
 * Computes a normalized 0–100 risk score based on detected heuristic flags,
 * maps scores to risk tiers (SAFE, SUSPICIOUS, HIGH_RISK), and provides
 * explainable point breakdowns.
 */

// Default weights aligned with SIH 2026 CYB02 roadmap specifications
export const DEFAULT_RISK_CONFIG = {
  weights: {
    BRAND_IMPERSONATION: 20,  // Disguised brand inside unauthorized domain
    IP_HOST: 20,              // Direct IP address used instead of domain
    AT_SYMBOL: 20,            // '@' symbol authority deception
    INSECURE_HTTP: 15,        // Insecure unencrypted HTTP protocol
    PUNYCODE_HOMOGRAPH: 15,   // Punycode / IDN homograph attack
    SUSPICIOUS_KEYWORDS: 10,  // Phishing/banking/security keywords (base)
    KEYWORD_MULTIPLE_BONUS: 5,// Extra weight if multiple keywords match
    SUSPICIOUS_TLD: 10,       // Abused / free / high-risk TLD
    EXCESSIVE_SUBDOMAINS: 10, // Multi-level subdomain chaining (3+ subdomains)
    EXCESSIVE_HYPHENS: 10,    // 2+ hyphens in domain name
    REDIRECT_IN_PATH: 10,     // Double slash redirect trick in path
    LONG_URL: 5,              // Abnormally long URL (>90 chars)
    LONG_HOSTNAME: 5          // Abnormally long domain name (>35 chars)
  },
  thresholds: {
    SAFE_MAX: 30,             // 0 - 30: SAFE
    SUSPICIOUS_MAX: 60,       // 31 - 60: SUSPICIOUS
    HIGH_RISK_MIN: 61         // 61 - 100: HIGH RISK
  }
};

/**
 * Calculates risk score and assigns risk classification
 * @param {object} analysis - Output object from urlAnalyzer.js
 * @param {object} [customConfig] - Optional override for weights/thresholds
 * @returns {object} Scored evaluation result
 */
export function calculateRisk(analysis, customConfig = {}) {
  const config = {
    weights: { ...DEFAULT_RISK_CONFIG.weights, ...(customConfig.weights || {}) },
    thresholds: { ...DEFAULT_RISK_CONFIG.thresholds, ...(customConfig.thresholds || {}) }
  };

  let rawScore = 0;
  const breakdown = [];

  if (!analysis || !analysis.flags) {
    return {
      score: 0,
      level: 'SAFE',
      levelKey: 'safe',
      color: '#22c55e',
      breakdown: [],
      summary: 'No analysis data available.'
    };
  }

  // Iterate over detected flags and sum points
  for (const flag of analysis.flags) {
    let points = config.weights[flag] || 0;

    // Apply keyword bonus if more than 1 keyword matched
    if (flag === 'SUSPICIOUS_KEYWORDS' && analysis.features?.matchedKeywords?.length > 1) {
      points += config.weights.KEYWORD_MULTIPLE_BONUS || 5;
    }

    rawScore += points;

    breakdown.push({
      flag: flag,
      points: points,
      description: getFlagDescription(flag, analysis)
    });
  }

  // Clamp final score strictly to [0, 100]
  // const finalScore = 100;
  const finalScore = Math.min(100, Math.max(0, rawScore));

  // Determine Risk Tier
  let level = 'SAFE';
  let levelKey = 'safe';
  let color = '#22c55e'; // Green
  let summary = 'Standard URL structure. No significant risk signals.';

  if (finalScore > config.thresholds.SUSPICIOUS_MAX) {
    level = 'HIGH RISK';
    levelKey = 'high-risk';
    color = '#ff4d4d'; // Red
    summary = 'Multiple critical indicators detected! Exercise extreme caution before entering any sensitive data.';
  } else if (finalScore > config.thresholds.SAFE_MAX) {
    level = 'SUSPICIOUS';
    levelKey = 'suspicious';
    color = '#f0b429'; // Amber/Yellow
    summary = 'Caution advised: Suspicious URL characteristics detected.';
  }

  return {
    score: finalScore,
    level: level,
    levelKey: levelKey,
    color: color,
    breakdown: breakdown,
    summary: summary,
    flagCount: analysis.flags.length
  };
}

/**
 * Returns a human-friendly label for a given flag
 */
function getFlagDescription(flag, analysis) {
  switch (flag) {
    case 'BRAND_IMPERSONATION':
      return 'Brand Impersonation / Disguise (+20 pts)';
    case 'IP_HOST':
      return 'Raw IP Host (+20 pts)';
    case 'AT_SYMBOL':
      return 'Embedded @ Authority Symbol (+20 pts)';
    case 'INSECURE_HTTP':
      return 'Insecure HTTP Transport (+15 pts)';
    case 'PUNYCODE_HOMOGRAPH':
      return 'Punycode Homograph (+15 pts)';
    case 'SUSPICIOUS_KEYWORDS':
      return `Phishing Trigger Keywords (+${(analysis.features?.matchedKeywords?.length > 1 ? 15 : 10)} pts)`;
    case 'SUSPICIOUS_TLD':
      return `High-Risk TLD .${analysis.features?.tld || ''} (+10 pts)`;
    case 'EXCESSIVE_SUBDOMAINS':
      return 'Deep Subdomain Chaining (+10 pts)';
    case 'EXCESSIVE_HYPHENS':
      return 'Excessive Host Hyphens (+10 pts)';
    case 'REDIRECT_IN_PATH':
      return 'Redirect Structure in Path (+10 pts)';
    case 'LONG_URL':
      return 'Abnormal URL Length (+5 pts)';
    case 'LONG_HOSTNAME':
      return 'Abnormal Host Length (+5 pts)';
    default:
      return `${flag} (+10 pts)`;
  }
}

// Support CommonJS for Node test scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { calculateRisk, DEFAULT_RISK_CONFIG };
}
