/**
 * controllers/analyzeController.js — PhishGuard URL Analysis Endpoint
 *
 * POST /api/analyze
 * Accepts a URL (and optional DOM signals) from the extension,
 * runs server-side heuristic analysis, queries the Python ML microservice (port 5001),
 * fuses heuristic + ML predictions into a hybrid ensemble score, and persists to MongoDB.
 */

const { body, validationResult } = require('express-validator');
const Detection = require('../models/Detection');

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001';

// ── Validation Rules ──────────────────────────────────────────────────────────
const analyzeValidation = [
  body('url')
    .notEmpty().withMessage('url is required.')
    .isURL({ require_protocol: true }).withMessage('url must be a valid URL with protocol.')
    .isLength({ max: 2048 }).withMessage('url must be under 2048 characters.'),
  body('domSignals').optional().isObject().withMessage('domSignals must be an object.')
];

// ── Inline scoring weights (mirrors riskEngine.js) ────────────────────────────
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

// ── Helper: Query Python ML Microservice ─────────────────────────────────────
async function queryMlService(url, domSignals, path = '/predict') {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1500); // 1.5s timeout

    const response = await fetch(`${ML_SERVICE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, domSignals }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) return null;
    const json = await response.json();
    return json.success ? json.prediction : null;
  } catch (err) {
    // Graceful fallback when Python ML service is offline
    return null;
  }
}

// ── Handler ───────────────────────────────────────────────────────────────────
async function analyzeUrl(req, res) {
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

    // 1. Rule-Based Heuristics (always runs, never blocked)
    const { score: ruleScore, level: ruleLevel, breakdown } = scoreFlags(urlFlags, domFlags);

    // 2. Query both ML endpoints in parallel (Phase 9 + Phase 10)
    const [mlResult, uciResult] = await Promise.all([
      queryMlService(url, domSignals),
      queryMlService(url, domSignals, '/predict/uci')
    ]);

    // 3. Ensemble: 45% rule-based + 55% UCI ML (when UCI model is available)
    //    Falls back to 50/50 with Phase-9 model, then pure rules.
    let finalScore = ruleScore;
    let finalLevel = ruleLevel;
    let mlAnalysis = { status: 'offline', fallback: 'rule-based heuristics' };

    if (uciResult) {
      finalScore = Math.min(100, Math.max(0, Math.round(0.45 * ruleScore + 0.55 * uciResult.riskScore)));
      finalLevel = finalScore > 60 ? 'HIGH RISK' : finalScore > 30 ? 'SUSPICIOUS' : 'SAFE';
      mlAnalysis = {
        model: uciResult.model,
        probability: uciResult.probability,
        isPhishing: uciResult.isPhishing,
        confidence: uciResult.confidence,
        uciFeatures: uciResult.features,
        phase9: mlResult ? { probability: mlResult.probability } : null
      };
    } else if (mlResult) {
      finalScore = Math.min(100, Math.max(0, Math.round(0.5 * ruleScore + 0.5 * mlResult.riskScore)));
      finalLevel = finalScore > 60 ? 'HIGH RISK' : finalScore > 30 ? 'SUSPICIOUS' : 'SAFE';
      mlAnalysis = {
        model: mlResult.model,
        probability: mlResult.probability,
        isPhishing: mlResult.isPhishing,
        confidence: mlResult.confidence,
        phase9Only: true
      };
    }

    // 4. Persist to MongoDB
    let saved = null;
    try {
      saved = await Detection.create({
        url,
        domain,
        riskScore: finalScore,
        riskLevel: finalLevel,
        urlFlags,
        domFlags,
        reasons,
        features: {
          ...(domSignals?.features || {}),
          uciProbability: uciResult?.probability ?? null,
          mlProbability:  mlResult?.probability ?? null,
        },
        source: 'extension'
      });
    } catch (dbErr) {
      console.warn('[analyzeController] DB write skipped:', dbErr.message);
    }

    const detectionResult = {
      id:          saved?._id || null,
      url,
      domain,
      riskScore:   finalScore,
      riskLevel:   finalLevel,
      urlFlags,
      domFlags,
      reasons,
      breakdown,
      mlAnalysis,
      analyzedAt:  new Date().toISOString()
    };

    return res.status(200).json({ success: true, data: detectionResult });

  } catch (err) {
    console.error('[analyzeController] Error:', err.message);
    return res.status(500).json({ success: false, error: 'Analysis failed.' });
  }
}

module.exports = { analyzeUrl, analyzeValidation };
