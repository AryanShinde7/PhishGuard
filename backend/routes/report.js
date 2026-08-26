/**
 * routes/report.js — POST /api/report
 */
const express  = require('express');
const router   = express.Router();
const { submitReport, reportValidation } = require('../controllers/reportController');

/**
 * @route  POST /api/report
 * @desc   Submit a user-reported phishing URL
 * @body   { url: string, riskScore?: number, riskLevel?: string, comment?: string }
 * @access Public
 */
router.post('/', reportValidation, submitReport);

module.exports = router;
