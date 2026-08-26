/**
 * routes/detections.js — GET /api/detections
 */
const express  = require('express');
const router   = express.Router();
const {
  getAllDetections,
  getDetectionsByDomain,
  listValidation,
  domainValidation
} = require('../controllers/detectionsController');

/**
 * @route  GET /api/detections
 * @desc   Get paginated list of all past detections
 * @query  page, limit, level (SAFE | SUSPICIOUS | HIGH RISK)
 * @access Public
 */
router.get('/', listValidation, getAllDetections);

/**
 * @route  GET /api/detections/:domain
 * @desc   Get detection history for a specific domain
 * @access Public
 */
router.get('/:domain', domainValidation, getDetectionsByDomain);

module.exports = router;
