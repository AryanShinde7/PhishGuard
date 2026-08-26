/**
 * server.js — PhishGuard Backend Entry Point
 *
 * Express REST API server for PhishGuard SIH 2026.
 * Phase 6: Core API routes (analyze, report, feedback, stats, detections).
 * Phase 7: MongoDB connection added.
 */

const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const morgan   = require('morgan');
const rateLimiter = require('./middleware/rateLimiter');
require('dotenv').config();

// Route imports
const analyzeRoutes    = require('./routes/analyze');
const reportRoutes     = require('./routes/report');
const feedbackRoutes   = require('./routes/feedback');
const statsRoutes      = require('./routes/stats');
const detectionsRoutes = require('./routes/detections');

const app  = express();
const PORT = process.env.PORT || 5000;

// ── Security Middleware ──────────────────────────────────────────────────────
app.use(helmet());                                // Set secure HTTP headers
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));

// ── Parsing Middleware ───────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));         // Parse JSON body (max 10kb)
app.use(express.urlencoded({ extended: false }));

// ── Logging ──────────────────────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('dev'));
}

// ── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status:  'ok',
    service: 'PhishGuard API',
    version: '0.1.0',
    time:    new Date().toISOString()
  });
});

// ── API Routes ────────────────────────────────────────────────────────────────
app.use('/api', rateLimiter);   // Apply rate limiter to all /api routes
app.use('/api/analyze',    analyzeRoutes);
app.use('/api/report',     reportRoutes);
app.use('/api/feedback',   feedbackRoutes);
app.use('/api/stats',      statsRoutes);
app.use('/api/detections', detectionsRoutes);

// ── 404 Handler ───────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, error: `Route ${req.method} ${req.path} not found.` });
});

// ── Global Error Handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[PhishGuard] Unhandled error:', err.message);
  res.status(err.status || 500).json({
    success: false,
    error:   process.env.NODE_ENV === 'production' ? 'Internal server error.' : err.message
  });
});

// ── Start Server ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡️  PhishGuard API running on http://localhost:${PORT}`);
  console.log(`    Health check: http://localhost:${PORT}/health`);
  console.log(`    Environment: ${process.env.NODE_ENV}`);
  console.log('\nAvailable endpoints:');
  console.log('  POST /api/analyze');
  console.log('  POST /api/report');
  console.log('  POST /api/feedback');
  console.log('  GET  /api/stats');
  console.log('  GET  /api/detections\n');
});

module.exports = app;
