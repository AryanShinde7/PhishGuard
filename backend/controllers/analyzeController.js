/**
 * controllers/analyzeController.js — PhishGuard URL Analysis Endpoint
 *
 * POST /api/analyze
 * Accepts a URL (and optional DOM signals) from the extension,
 * runs server-side heuristic analysis, and returns the risk result.
 * Also persists the detection to MongoDB (once Phase 7 is connected).
 */

const { body, validationResult } = require('express-validator');

// ── Validation Rules ──────────────────────────────────────────────────────────
const analyzeValidation = [
  body('url')
    .notEmpty().withMessage('url is required.')
    .isURL({ require_protocol: true }).withMessage('url must be a valid URL with protocol.')
    .isLength({ max: 2048 }).withMessage('url must be under 2048 characters.'),
  body('domSignals').optional().isObject().withMessage('domSignals must be an object.')
];

// ── Inline scoring weights (mirrors riskEngine.js — stays in sync) ────────────
const WEIGHTS = {
  BRAND_IMPERSONATION: 20, IP_HOST: 20, AT_SYMBOL: 20,
  INSECURE_HTTP: 15, PUNYCODE_HOMOGRAPH: 15,
  SUSPICIOUS_KEYWORDS: 10, SUSPICIOUS_TLD: 10,
  EXCESSIVE_SUBDOMAINS: 10, EXCESSIVE_HYPHENS: 10,
  REDIRECT_IN_PATH: 10, LONG_URL: 5, LONG_HOSTNAME: 5,
  // DOM
  CROSS_DOMAIN_FORM: 20, PASSWORD_ON_HTTP: 15, LOGIN_FORM_DETECTED: 10,
  HTTP_FORM_ACTION: 15, SUSPICIOUS_FORM_TLD: 10,
  TITLE_BRAND_IMPERSONATION: 15, URGENCY_LANGUAGE: 10,
  SUSPICIOUS_EXTERNAL_SCRIPT: 10, EXTERNAL_IFRAME: 10,
  EXCESSIVE_HIDDEN_INPUTS: 5, HIGH_EXTERNAL_LINK_RATIO: 5, NO_FAVICON_WITH_LOGIN: 5
};

function scoreFlags(urlFlags = [], domFlags = []) {
  let score = 0;
  const breakdown = [];
  [...urlFlags.map(f => ({ f, src: 'url' })), ...domFlags.map(f => ({ f, src: 'dom' }))].forEach(({ f, src }) => {
    const pts = WEIGHTS[f] || 0;
    score += pts;
    breakdown.push({ flag: f, points: pts, source: src });
  });
  score = Math.min(100, Math.max(0, score));
  const level = score > 60 ? 'HIGH RISK' : score > 30 ? 'SUSPICIOUS' : 'SAFE';
  return { score, level, breakdown };
}

// ── Handler ───────────────────────────────────────────────────────────────────
async function analyzeUrl(req, res) {
  // Validate input
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const { url, urlFlags = [], domFlags = [], domSignals = null, reasons = [] } = req.body;

  try {
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch {
      return res.status(400).json({ success: false, error: 'Malformed URL.' });
    }

    const domain = parsedUrl.hostname.toLowerCase();

    // Score the flags sent from the extension
    const { score, level, breakdown } = scoreFlags(urlFlags, domFlags);

    const detectionResult = {
      url,
      domain,
      riskScore: score,
      riskLevel: level,
      urlFlags,
      domFlags,
      reasons,
      breakdown,
      analyzedAt: new Date().toISOString()
    };

    // Phase 7: Persist to MongoDB
    // const Detection = require('../models/Detection');
    // await Detection.create({ url, domain, riskScore: score, riskLevel: level, urlFlags, domFlags, reasons });

    return res.status(200).json({
      success: true,
      data: detectionResult
    });

  } catch (err) {
    console.error('[analyzeController] Error:', err.message);
    return res.status(500).json({ success: false, error: 'Analysis failed.' });
  }
}

module.exports = { analyzeUrl, analyzeValidation };
