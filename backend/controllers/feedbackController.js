/**
 * controllers/feedbackController.js — User Feedback Handler
 *
 * POST /api/feedback
 * Accepts user feedback on the accuracy of a PhishGuard detection.
 * Phase 7: Persists feedback to MongoDB Feedback collection.
 */

const { body, validationResult } = require('express-validator');
const Feedback = require('../models/Feedback');

// ── Validation ────────────────────────────────────────────────────────────────
const feedbackValidation = [
  body('url')
    .notEmpty().withMessage('url is required.')
    .isURL({ require_protocol: true }).withMessage('url must be a valid URL.'),
  body('feedbackType')
    .notEmpty().withMessage('feedbackType is required.')
    .isIn(['suspicious', 'safe', 'false_positive', 'false_negative'])
    .withMessage('feedbackType must be: suspicious, safe, false_positive, or false_negative.'),
  body('riskScore').optional().isFloat({ min: 0, max: 100 }),
  body('riskLevel').optional().isIn(['SAFE', 'SUSPICIOUS', 'HIGH RISK']),
  body('comment').optional().isLength({ max: 500 }).trim().escape()
];

// ── Handler ───────────────────────────────────────────────────────────────────
async function submitFeedback(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const {
    url,
    feedbackType,
    riskScore  = null,
    riskLevel  = null,
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
      saved = await Feedback.create({
        url,
        domain,
        feedbackType,
        riskScore,
        riskLevel,
        comment
      });
    } catch (dbErr) {
      console.warn('[feedbackController] DB write skipped:', dbErr.message);
    }

    console.log(`[PhishGuard] Feedback received: "${feedbackType}" for ${domain}`);

    const messages = {
      suspicious:      'Thanks! This site has been flagged for review.',
      safe:            "Got it — we've noted this as a safe page.",
      false_positive:  "Thanks for the correction. We'll improve our detection.",
      false_negative:  "Thanks for flagging this phishing site we missed!"
    };

    return res.status(201).json({
      success: true,
      message: messages[feedbackType] || 'Feedback received.',
      data: {
        id: saved?._id || null,
        url,
        domain,
        feedbackType,
        riskScore,
        riskLevel,
        comment,
        submittedAt: new Date().toISOString()
      }
    });

  } catch (err) {
    console.error('[feedbackController] Error:', err.message);
    return res.status(500).json({ success: false, error: 'Failed to save feedback.' });
  }
}

module.exports = { submitFeedback, feedbackValidation };
