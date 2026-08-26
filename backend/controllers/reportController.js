/**
 * controllers/reportController.js — User Phishing Report Handler
 *
 * POST /api/report
 * Accepts a user-initiated phishing report from the extension popup.
 * Phase 7: Persists report to MongoDB as a Detection document.
 */

const { body, validationResult } = require('express-validator');
const Detection = require('../models/Detection');

// ── Validation Rules ──────────────────────────────────────────────────────────
const reportValidation = [
  body('url')
    .notEmpty().withMessage('url is required.')
    .isURL({ require_protocol: true }).withMessage('url must be a valid URL.'),
  body('riskScore')
    .optional()
    .isFloat({ min: 0, max: 100 }).withMessage('riskScore must be between 0 and 100.'),
  body('riskLevel')
    .optional()
    .isIn(['SAFE', 'SUSPICIOUS', 'HIGH RISK']).withMessage('Invalid riskLevel.'),
  body('comment')
    .optional()
    .isLength({ max: 500 }).withMessage('Comment must be under 500 characters.')
    .trim().escape()
];

// ── Handler ───────────────────────────────────────────────────────────────────
async function submitReport(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const {
    url,
    riskScore  = null,
    riskLevel  = 'SUSPICIOUS',
    urlFlags   = [],
    domFlags   = [],
    reasons    = [],
    comment    = ''
  } = req.body;

  try {
    let domain;
    try {
      domain = new URL(url).hostname.toLowerCase();
    } catch {
      return res.status(400).json({ success: false, error: 'Malformed URL.' });
    }

    // Persist to MongoDB (Phase 7)
    let saved = null;
    try {
      saved = await Detection.create({
        url,
        domain,
        riskScore:  riskScore ?? 50,
        riskLevel:  riskLevel || 'SUSPICIOUS',
        urlFlags,
        domFlags,
        reasons,
        source: 'extension'
      });
    } catch (dbErr) {
      console.warn('[reportController] DB write skipped:', dbErr.message);
    }

    const report = {
      id:         saved?._id || null,
      url,
      domain,
      riskScore,
      riskLevel,
      urlFlags,
      domFlags,
      reasons,
      comment,
      reportedAt: new Date().toISOString()
    };

    console.log(`[PhishGuard] New user report: ${domain} (${riskLevel})`);

    return res.status(201).json({
      success: true,
      message: 'Report received. Thank you for helping keep the web safe.',
      data: report
    });

  } catch (err) {
    console.error('[reportController] Error:', err.message);
    return res.status(500).json({ success: false, error: 'Failed to save report.' });
  }
}

module.exports = { submitReport, reportValidation };
