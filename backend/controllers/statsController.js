/**
 * controllers/statsController.js — Detection Statistics Handler
 *
 * GET /api/stats
 * Returns aggregated stats about PhishGuard detections.
 * Phase 7: Real MongoDB aggregation pipeline.
 */

const Detection = require('../models/Detection');
const Feedback  = require('../models/Feedback');
const mongoose  = require('mongoose');

// ── Handler ───────────────────────────────────────────────────────────────────
async function getStats(req, res) {
  try {
    const isDbConnected = mongoose.connection.readyState === 1;

    if (!isDbConnected) {
      // Return empty stats gracefully if DB is not connected
      return res.status(200).json({
        success: true,
        data: {
          totalScanned: 0,
          highRiskCount: 0,
          suspiciousCount: 0,
          safeCount: 0,
          totalFeedback: 0,
          topFlagsThisWeek: [],
          note: 'Connect MongoDB to see live stats.'
        }
      });
    }

    // Parallel queries for efficiency
    const [
      totalScanned,
      highRiskCount,
      suspiciousCount,
      safeCount,
      totalFeedback,
      topFlags
    ] = await Promise.all([
      Detection.countDocuments(),
      Detection.countDocuments({ riskLevel: 'HIGH RISK' }),
      Detection.countDocuments({ riskLevel: 'SUSPICIOUS' }),
      Detection.countDocuments({ riskLevel: 'SAFE' }),
      Feedback.countDocuments(),
      // Top URL flags across all detections (last 7 days)
      Detection.aggregate([
        {
          $match: {
            createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
          }
        },
        { $unwind: '$urlFlags' },
        { $group: { _id: '$urlFlags', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 5 },
        { $project: { flag: '$_id', count: 1, _id: 0 } }
      ])
    ]);

    // Last 7 days detections per day
    const detectionsByDay = await Detection.aggregate([
      {
        $match: {
          createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } },
      { $project: { date: '$_id', count: 1, _id: 0 } }
    ]);

    return res.status(200).json({
      success: true,
      data: {
        totalScanned,
        highRiskCount,
        suspiciousCount,
        safeCount,
        totalFeedback,
        topFlagsThisWeek: topFlags,
        detectionsByDay,
        generatedAt: new Date().toISOString()
      }
    });

  } catch (err) {
    console.error('[statsController] Error:', err.message);
    return res.status(500).json({ success: false, error: 'Failed to retrieve stats.' });
  }
}

module.exports = { getStats };
