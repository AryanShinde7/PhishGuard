/**
 * riskEngine.js — PhishGuard Transparent Risk Scoring Engine
 *
 * Computes a normalized 0–100 risk score based on detected URL heuristic flags
 * AND page-level DOM signals (Phase 5). Maps scores to risk tiers and provides
 * explainable point breakdowns for every contributing indicator.
 */

// Default weights — URL heuristics + DOM page signals
export const DEFAULT_RISK_CONFIG = {
  weights: {
    // ── URL Heuristic Flags (Phase 2) ──────────────────────────────────────
    BRAND_IMPERSONATION: 20,       // Brand spoofed inside unauthorized domain
    IP_HOST: 20,                   // Direct IP address instead of domain
    AT_SYMBOL: 20,                 // '@' authority trickery
    INSECURE_HTTP: 15,             // Unencrypted HTTP protocol
    PUNYCODE_HOMOGRAPH: 15,        // Punycode / IDN homograph attack
    SUSPICIOUS_KEYWORDS: 10,       // Phishing trigger keywords (base)
    KEYWORD_MULTIPLE_BONUS: 5,     // Bonus for multiple keyword matches
    SUSPICIOUS_TLD: 10,            // Abused / disposable TLD
    EXCESSIVE_SUBDOMAINS: 10,      // Deep subdomain chaining
    EXCESSIVE_HYPHENS: 10,         // Multiple hyphens in domain
    REDIRECT_IN_PATH: 10,          // Double-slash redirect
    LONG_URL: 5,                   // Abnormal URL length
    LONG_HOSTNAME: 5,              // Abnormal hostname length

    // ── DOM Page Signals (Phase 5) ─────────────────────────────────────────
    CROSS_DOMAIN_FORM: 20,         // Credentials sent to external domain
    PASSWORD_ON_HTTP: 15,          // Password field on insecure HTTP page
    LOGIN_FORM_DETECTED: 10,       // Username + password form present
    HTTP_FORM_ACTION: 15,          // Form POSTs to insecure HTTP endpoint
    SUSPICIOUS_FORM_TLD: 10,       // Form targets a high-risk TLD
    TITLE_BRAND_IMPERSONATION: 15, // Brand name in page title (possible spoof)
    URGENCY_LANGUAGE: 10,          // Social-engineering urgency text
    SUSPICIOUS_EXTERNAL_SCRIPT: 10,// Script loaded from suspicious TLD
    EXTERNAL_IFRAME: 10,           // External iframe (clickjacking)
    EXCESSIVE_HIDDEN_INPUTS: 5,    // Many hidden inputs (data harvesting)
    HIGH_EXTERNAL_LINK_RATIO: 5,   // >80% links are external
    NO_FAVICON_WITH_LOGIN: 5       // Login page with no favicon
  },
  thresholds: {
    SAFE_MAX: 30,       // 0  – 30 : SAFE
    SUSPICIOUS_MAX: 60, // 31 – 60 : SUSPICIOUS
    HIGH_RISK_MIN: 61   // 61 – 100: HIGH RISK
  }
};

/**
 * Calculates risk score and assigns risk classification.
 * Merges URL analysis flags (Phase 2) with DOM signals (Phase 5).
 *
 * @param {object} analysis   - Output from urlAnalyzer.js
 * @param {object} [domSignals] - Output from content.js domAnalyzer (optional)
 * @param {object} [customConfig] - Optional weight/threshold overrides
 * @returns {object} Scored evaluation result
 */
export function calculateRisk(analysis, domSignals = null, customConfig = {}) {
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

  // Collect all flags — URL flags first, then DOM signals (if available)
  const urlFlags = (analysis && analysis.flags) ? analysis.flags : [];
  const domFlags = (domSignals && domSignals.flags) ? domSignals.flags : [];
  const allFlags = [...urlFlags, ...domFlags];

  // Score URL flags
  for (const flag of urlFlags) {
    let points = config.weights[flag] || 0;
    if (flag === 'SUSPICIOUS_KEYWORDS' && analysis.features?.matchedKeywords?.length > 1) {
      points += config.weights.KEYWORD_MULTIPLE_BONUS || 5;
    }
    rawScore += points;
    breakdown.push({ flag, points, source: 'url', description: getFlagDescription(flag, analysis) });
  }

  // Score DOM flags
  for (const flag of domFlags) {
    const points = config.weights[flag] || 0;
    rawScore += points;
    breakdown.push({ flag, points, source: 'dom', description: getFlagDescription(flag, domSignals) });
  }

  // Clamp final score strictly to [0, 100]
  const finalScore = Math.min(100, Math.max(0, rawScore));

  // Determine Risk Tier
  let level = 'SAFE';
  let levelKey = 'safe';
  let color = '#22c55e';
  let summary = 'Standard URL and page structure. No significant risk signals.';

  if (finalScore > config.thresholds.SUSPICIOUS_MAX) {
    level = 'HIGH RISK';
    levelKey = 'high-risk';
    color = '#ff4d4d';
    summary = 'Multiple critical indicators detected! Do not enter any sensitive data on this page.';
  } else if (finalScore > config.thresholds.SAFE_MAX) {
    level = 'SUSPICIOUS';
    levelKey = 'suspicious';
    color = '#f0b429';
    summary = 'Caution advised: Suspicious URL and/or page characteristics detected.';
  }

  return {
    score: finalScore,
    level,
    levelKey,
    color,
    breakdown,
    summary,
    flagCount: allFlags.length,
    urlFlagCount: urlFlags.length,
    domFlagCount: domFlags.length
  };
}

/**
 * Returns a human-friendly label for a given flag
 */
function getFlagDescription(flag, analysisOrSignals) {
  const a = analysisOrSignals || {};
  switch (flag) {
    // URL flags
    case 'BRAND_IMPERSONATION':          return 'Brand Impersonation / Disguise (+20 pts)';
    case 'IP_HOST':                      return 'Raw IP Host (+20 pts)';
    case 'AT_SYMBOL':                    return 'Embedded @ Authority Symbol (+20 pts)';
    case 'INSECURE_HTTP':                return 'Insecure HTTP Transport (+15 pts)';
    case 'PUNYCODE_HOMOGRAPH':           return 'Punycode Homograph Attack (+15 pts)';
    case 'SUSPICIOUS_KEYWORDS':          return `Phishing Trigger Keywords (+${a.features?.matchedKeywords?.length > 1 ? 15 : 10} pts)`;
    case 'SUSPICIOUS_TLD':               return `High-Risk TLD .${a.features?.tld || ''} (+10 pts)`;
    case 'EXCESSIVE_SUBDOMAINS':         return 'Deep Subdomain Chaining (+10 pts)';
    case 'EXCESSIVE_HYPHENS':            return 'Excessive Domain Hyphens (+10 pts)';
    case 'REDIRECT_IN_PATH':             return 'Open Redirect in Path (+10 pts)';
    case 'LONG_URL':                     return 'Abnormal URL Length (+5 pts)';
    case 'LONG_HOSTNAME':                return 'Abnormal Hostname Length (+5 pts)';
    // DOM flags
    case 'CROSS_DOMAIN_FORM':            return 'Form Submits to External Domain (+20 pts)';
    case 'PASSWORD_ON_HTTP':             return 'Password Field on Insecure HTTP (+15 pts)';
    case 'LOGIN_FORM_DETECTED':          return 'Login Form Detected on Page (+10 pts)';
    case 'HTTP_FORM_ACTION':             return 'Form POSTs Over Insecure HTTP (+15 pts)';
    case 'SUSPICIOUS_FORM_TLD':          return 'Form Targets High-Risk TLD (+10 pts)';
    case 'TITLE_BRAND_IMPERSONATION':    return `Page Title Brand Spoof [${(a.features?.titleBrandMatches || []).slice(0,2).join(', ')}] (+15 pts)`;
    case 'URGENCY_LANGUAGE':             return `Social Engineering Language Detected (+10 pts)`;
    case 'SUSPICIOUS_EXTERNAL_SCRIPT':   return 'Script from Suspicious External Domain (+10 pts)';
    case 'EXTERNAL_IFRAME':              return 'External Iframe / Clickjacking Risk (+10 pts)';
    case 'EXCESSIVE_HIDDEN_INPUTS':      return 'Excessive Hidden Inputs (+5 pts)';
    case 'HIGH_EXTERNAL_LINK_RATIO':     return 'Unusual High External Link Ratio (+5 pts)';
    case 'NO_FAVICON_WITH_LOGIN':        return 'Login Page Missing Favicon (+5 pts)';
    default:                             return `${flag} (+5 pts)`;
  }
}

// Support CommonJS for Node test scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { calculateRisk, DEFAULT_RISK_CONFIG };
}
