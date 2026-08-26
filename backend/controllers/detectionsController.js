/**
 * controllers/detectionsController.js — Detection History Handler
 *
 * GET /api/detections          — paginated list of all detections
 * GET /api/detections/:domain  — detections for a specific domain
 *
 * Phase 7: Real MongoDB queries replace the stubs below.
 */

const { query, param, validationResult } = require('express-validator');

// ── Validation ────────────────────────────────────────────────────────────────
const listValidation = [
  query('page').optional().isInt({ min: 1 }).withMessage('page must be a positive integer.'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('limit must be 1–100.'),
  query('level').optional().isIn(['SAFE', 'SUSPICIOUS', 'HIGH RISK']).withMessage('Invalid level filter.')
];

const domainValidation = [
  param('domain').notEmpty().withMessage('domain param is required.')
];

// ── Handler: GET /api/detections ─────────────────────────────────────────────
async function getAllDetections(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });

  const page  = parseInt(req.query.page  || '1', 10);
  const limit = parseInt(req.query.limit || '20', 10);
  const level = req.query.level || null;

  try {
    // Phase 7: MongoDB query
    // const filter = level ? { riskLevel: level } : {};
    // const [detections, total] = await Promise.all([
    //   Detection.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
    //   Detection.countDocuments(filter)
    // ]);

    // Phase 6 stub — empty result set
    const detections = [];
    const total = 0;

    return res.status(200).json({
      success: true,
      data: detections,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      },
      note: 'Live data available after Phase 7 (MongoDB) is connected.'
    });

  } catch (err) {
    console.error('[detectionsController] Error:', err.message);
    return res.status(500).json({ success: false, error: 'Failed to retrieve detections.' });
  }
}

// ── Handler: GET /api/detections/:domain ─────────────────────────────────────
async function getDetectionsByDomain(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });

  const domain = req.params.domain.toLowerCase();

  try {
    // Phase 7: MongoDB query
    // const detections = await Detection.find({ domain }).sort({ createdAt: -1 }).limit(50).lean();

    // Phase 6 stub
    return res.status(200).json({
      success: true,
      domain,
      data: [],
      note: 'Live data available after Phase 7 (MongoDB) is connected.'
    });

  } catch (err) {
    console.error('[detectionsController] Error:', err.message);
    return res.status(500).json({ success: false, error: 'Failed to retrieve detections for domain.' });
  }
}

module.exports = {
  getAllDetections,
  getDetectionsByDomain,
  listValidation,
  domainValidation
};
