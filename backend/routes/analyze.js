/**
 * routes/analyze.js — POST /api/analyze
 */
const express  = require('express');
const router   = express.Router();
const { analyzeUrl, analyzeValidation } = require('../controllers/analyzeController');

/**
 * @route  POST /api/analyze
 * @desc   Run URL + DOM analysis and return risk score
 * @body   { url: string, urlFlags?: string[], domFlags?: string[], domSignals?: object, reasons?: string[] }
 * @access Public
 */
router.post('/', analyzeValidation, analyzeUrl);

module.exports = router;
