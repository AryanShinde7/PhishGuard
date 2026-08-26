/**
 * routes/feedback.js — POST /api/feedback
 */
const express  = require('express');
const router   = express.Router();
const { submitFeedback, feedbackValidation } = require('../controllers/feedbackController');

/**
 * @route  POST /api/feedback
 * @desc   Submit user feedback about detection accuracy
 * @body   { url: string, feedbackType: 'suspicious'|'safe'|'false_positive'|'false_negative', comment?: string }
 * @access Public
 */
router.post('/', feedbackValidation, submitFeedback);

module.exports = router;
