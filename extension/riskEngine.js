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
    // ── URL Heuristic Flags (Phase 2) ──────────────────────────────────────────
    BRAND_IMPERSONATION: 20, // Brand spoofed inside unauthorized domain
    IP_HOST: 20,             // Direct IP address instead of domain
    AT_SYMBOL: 20,           // '@' authority trickery (authority section only)
    INSECURE_HTTP: 20,       // Unencrypted HTTP
    PUNYCODE_HOMOGRAPH: 15,  // Punycode / IDN homograph attack
    FREE_HOSTING_PLATFORM: 15, // Anonymous hosting platform
    SUSPICIOUS_KEYWORDS: 10, // Phishing trigger keywords (base)
    KEYWORD_MULTIPLE_BONUS: 5, // Bonus for multiple keyword matches
    SUSPICIOUS_TLD: 12,      // Abused / disposable TLD
    EXCESSIVE_SUBDOMAINS: 10,// Deep subdomain chaining
    EXCESSIVE_HYPHENS: 10,   // Multiple hyphens in domain
    NUMERIC_DOMAIN: 10,      // 5+ consecutive digits in domain
    REDIRECT_IN_PATH: 10,    // Double-slash redirect
    LONG_URL: 5,             // Egregiously long URL (>200 chars)
    LONG_HOSTNAME: 5,        // Abnormal hostname length

    // ── DOM Page Signals (Phase 5) ─────────────────────────────────────────
    CROSS_DOMAIN_FORM: 20,       // Credentials sent to external domain
    PASSWORD_ON_HTTP: 15,        // Password field on insecure HTTP page
    LOGIN_FORM_DETECTED: 10,     // Username + password form present
    HTTP_FORM_ACTION: 15,        // Form POSTs to insecure HTTP endpoint
    SUSPICIOUS_FORM_TLD: 10,     // Form targets a high-risk TLD
    TITLE_BRAND_IMPERSONATION: 15, // Brand name in page title (possible spoof)
    URGENCY_LANGUAGE: 10,        // Social-engineering urgency text
    SUSPICIOUS_EXTERNAL_SCRIPT: 10, // Script loaded from suspicious TLD
    EXTERNAL_IFRAME: 10,         // External iframe (clickjacking)
    EXCESSIVE_HIDDEN_INPUTS: 5,  // Many hidden inputs (data harvesting)
    HIGH_EXTERNAL_LINK_RATIO: 5, // >80% links are external
    NO_FAVICON_WITH_LOGIN: 5,    // Login page with no favicon
  },

  /**
   * Priority multipliers — applied on top of base weights.
   * > 1.0 = critical indicator, score it harder.
   * < 1.0 = weak / noisy indicator, dampen its contribution.
   * Flags not listed here default to 1.0 (no change).
   */
  priorities: {
    // Critical — near-definitive phishing signals
    IP_HOST:              1.5,
    BRAND_IMPERSONATION:  1.5,
    AT_SYMBOL:            1.5,
    CROSS_DOMAIN_FORM:    1.5,
    PASSWORD_ON_HTTP:     1.4,
    HTTP_FORM_ACTION:     1.4,
    PUNYCODE_HOMOGRAPH:   1.3,
    INSECURE_HTTP:        1.2,
    TITLE_BRAND_IMPERSONATION: 1.3,

    // Low-signal / noisy — reduce contribution to avoid false positives
    LONG_URL:                  0.5,
    LONG_HOSTNAME:             0.6,
    HIGH_EXTERNAL_LINK_RATIO:  0.5,
    NO_FAVICON_WITH_LOGIN:     0.5,
    EXCESSIVE_HIDDEN_INPUTS:   0.7,
    EXTERNAL_IFRAME:           0.8,
  },

  thresholds: {
    SAFE_MAX:     10, // 0  – 10  : SAFE
    SUSPICIOUS_MAX: 29, // 11 – 29  : SUSPICIOUS (popup auto-opens)
    HIGH_RISK_MIN:  30, // 30+      : HIGH RISK (block page shown)
  },
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
    weights: {
      ...DEFAULT_RISK_CONFIG.weights,
      ...(customConfig.weights || {}),
    },
    priorities: {
      ...DEFAULT_RISK_CONFIG.priorities,
      ...(customConfig.priorities || {}),
    },
    thresholds: {
      ...DEFAULT_RISK_CONFIG.thresholds,
      ...(customConfig.thresholds || {}),
    },
  };

  let rawScore = 0;
  const breakdown = [];

  if (!analysis || !analysis.flags) {
    return {
      score: 0,
      level: "SAFE",
      levelKey: "safe",
      color: "#22c55e",
      breakdown: [],
      summary: "No analysis data available.",
    };
  }

  // Collect all flags — URL flags first, then DOM signals (if available)
  const urlFlags = analysis && analysis.flags ? analysis.flags : [];
  const domFlags = domSignals && domSignals.flags ? domSignals.flags : [];
  const allFlags = [...urlFlags, ...domFlags];

  // Helper: get effective weight for a flag (base weight × priority multiplier)
  const effectiveWeight = (flag, basePoints) => {
    const multiplier = config.priorities[flag] !== undefined ? config.priorities[flag] : 1.0;
    return Math.round(basePoints * multiplier);
  };

  // Score URL flags
  for (const flag of urlFlags) {
    const basePoints = config.weights[flag] || 0;
    let points = effectiveWeight(flag, basePoints);
    if (
      flag === "SUSPICIOUS_KEYWORDS" &&
      analysis.features?.matchedKeywords?.length > 1
    ) {
      points += config.weights.KEYWORD_MULTIPLE_BONUS || 5;
    }
    rawScore += points;
    breakdown.push({
      flag,
      points,
      source: "url",
      description: getFlagDescription(flag, analysis, points),
    });
  }

  // Score DOM flags
  for (const flag of domFlags) {
    const basePoints = config.weights[flag] || 0;
    const points = effectiveWeight(flag, basePoints);
    rawScore += points;
    breakdown.push({
      flag,
      points,
      source: "dom",
      description: getFlagDescription(flag, domSignals, points),
    });
  }

  // Clamp final score strictly to [0, 100]
  const finalScore = Math.min(100, Math.max(0, rawScore));

  // Determine Risk Tier
  let level = "SAFE";
  let levelKey = "safe";
  let color = "#22c55e";
  let summary = "Standard URL and page structure. No significant risk signals.";

  if (finalScore >= config.thresholds.HIGH_RISK_MIN) {
    level = "HIGH RISK";
    levelKey = "high-risk";
    color = "#ff4d4d";
    summary =
      "Multiple critical indicators detected! Do not enter any sensitive data on this page.";
  } else if (finalScore > config.thresholds.SAFE_MAX) {
    level = "SUSPICIOUS";
    levelKey = "suspicious";
    color = "#f0b429";
    summary =
      "Caution advised: Suspicious URL and/or page characteristics detected.";
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
    domFlagCount: domFlags.length,
  };
}

/**
 * Returns a human-friendly label for a given flag.
 * Points are passed in so the label reflects the priority-adjusted value.
 */
function getFlagDescription(flag, analysisOrSignals, points) {
  const a = analysisOrSignals || {};
  const pts = points !== undefined ? points : '?';
  switch (flag) {
    // URL flags
    case "BRAND_IMPERSONATION":
      return `Brand Impersonation / Disguise (+${pts} pts) ⚠️ High Priority`;
    case "IP_HOST":
      return `Raw IP Host (+${pts} pts) ⚠️ High Priority`;
    case "AT_SYMBOL":
      return `Embedded @ Authority Symbol (+${pts} pts) ⚠️ High Priority`;
    case "INSECURE_HTTP":
      return `Insecure HTTP Transport (+${pts} pts)`;
    case "PUNYCODE_HOMOGRAPH":
      return `Punycode Homograph Attack (+${pts} pts) ⚠️ High Priority`;
    case "FREE_HOSTING_PLATFORM":
      return `Anonymous Free Hosting Platform (+${pts} pts)`;
    case "SUSPICIOUS_KEYWORDS":
      return `Phishing Trigger Keywords (+${pts} pts)`;
    case "SUSPICIOUS_TLD":
      return `High-Risk TLD .${a.features?.tld || ""} (+${pts} pts)`;
    case "EXCESSIVE_SUBDOMAINS":
      return `Deep Subdomain Chaining (+${pts} pts)`;
    case "EXCESSIVE_HYPHENS":
      return `Excessive Domain Hyphens (+${pts} pts)`;
    case "NUMERIC_DOMAIN":
      return `Suspicious Numeric Sequence in Domain (+${pts} pts)`;
    case "REDIRECT_IN_PATH":
      return `Open Redirect in Path (+${pts} pts)`;
    case "LONG_URL":
      return `Abnormal URL Length (+${pts} pts)`;
    case "LONG_HOSTNAME":
      return `Abnormal Hostname Length (+${pts} pts)`;
    // DOM flags
    case "CROSS_DOMAIN_FORM":
      return `Form Submits to External Domain (+${pts} pts) ⚠️ High Priority`;
    case "PASSWORD_ON_HTTP":
      return `Password Field on Insecure HTTP (+${pts} pts) ⚠️ High Priority`;
    case "LOGIN_FORM_DETECTED":
      return `Login Form Detected on Page (+${pts} pts)`;
    case "HTTP_FORM_ACTION":
      return `Form POSTs Over Insecure HTTP (+${pts} pts) ⚠️ High Priority`;
    case "SUSPICIOUS_FORM_TLD":
      return `Form Targets High-Risk TLD (+${pts} pts)`;
    case "TITLE_BRAND_IMPERSONATION":
      return `Page Title Brand Spoof [${(a.features?.titleBrandMatches || []).slice(0, 2).join(", ")}] (+${pts} pts) ⚠️ High Priority`;
    case "URGENCY_LANGUAGE":
      return `Social Engineering Language Detected (+${pts} pts)`;
    case "SUSPICIOUS_EXTERNAL_SCRIPT":
      return `Script from Suspicious External Domain (+${pts} pts)`;
    case "EXTERNAL_IFRAME":
      return `External Iframe / Clickjacking Risk (+${pts} pts)`;
    case "EXCESSIVE_HIDDEN_INPUTS":
      return `Excessive Hidden Inputs (+${pts} pts)`;
    case "HIGH_EXTERNAL_LINK_RATIO":
      return `Unusual High External Link Ratio (+${pts} pts)`;
    case "NO_FAVICON_WITH_LOGIN":
      return `Login Page Missing Favicon (+${pts} pts)`;
    default:
      return `${flag} (+${pts} pts)`;
  }
}

// Support CommonJS for Node test scripts
if (typeof module !== "undefined" && module.exports) {
  module.exports = { calculateRisk, DEFAULT_RISK_CONFIG };
}
