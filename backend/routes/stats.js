/**
 * routes/stats.js — GET /api/stats
 */
const express  = require('express');
const router   = express.Router();
const { getStats } = require('../controllers/statsController');

/**
 * @route  GET /api/stats
 * @desc   Get aggregated detection statistics
 * @access Public
 */
router.get('/', getStats);

module.exports = router;
