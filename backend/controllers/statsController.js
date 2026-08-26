/**
 * controllers/statsController.js — Detection Statistics Handler
 *
 * GET /api/stats
 * Returns aggregated stats about PhishGuard detections.
 * Phase 7: MongoDB aggregation pipeline will replace in-memory data.
 */

// ── In-memory mock stats (Phase 6) ───────────────────────────────────────────
// Phase 7: Replace with real MongoDB aggregation queries.
const MOCK_STATS = {
  totalScanned:   0,
  totalFlagged:   0,
  highRiskCount:  0,
  suspiciousCount: 0,
  safeCount:      0,
  topFlagsThisWeek: [],
  detectionsByDay:  []
};

// ── Handler ───────────────────────────────────────────────────────────────────
async function getStats(req, res) {
  try {
    // Phase 7: Real aggregation
    // const Detection = require('../models/Detection');
    // const [total, highRisk, suspicious] = await Promise.all([
    //   Detection.countDocuments(),
    //   Detection.countDocuments({ riskLevel: 'HIGH RISK' }),
    //   Detection.countDocuments({ riskLevel: 'SUSPICIOUS' })
    // ]);

    const stats = {
      ...MOCK_STATS,
      timestamp: new Date().toISOString(),
      note: 'Live database stats available after Phase 7 (MongoDB) is connected.'
    };

    return res.status(200).json({ success: true, data: stats });

  } catch (err) {
    console.error('[statsController] Error:', err.message);
    return res.status(500).json({ success: false, error: 'Failed to retrieve stats.' });
  }
}

module.exports = { getStats };
