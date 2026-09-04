/**
 * routes/report.js — POST /api/report
 */
const express  = require('express');
const router   = express.Router();
const { submitReport, removeReport, reportValidation } = require('../controllers/reportController');

/**
 * @route  POST /api/report
 * @desc   Submit a user-reported phishing URL
 * @body   { url: string, riskScore?: number, riskLevel?: string, comment?: string }
 * @access Public
 */
router.post('/', reportValidation, submitReport);

/**
 * @route  DELETE /api/report
 * @desc   Remove a user-reported phishing URL (untoggle)
 * @body   { url: string }
 * @access Public
 */
router.delete('/', removeReport);

module.exports = router;
