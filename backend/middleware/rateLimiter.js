/**
 * middleware/rateLimiter.js — Request Rate Limiter
 *
 * Basic in-memory rate limiting to prevent API abuse.
 * For production, replace with express-rate-limit + Redis.
 */

const requestCounts = new Map();
const WINDOW_MS  = 60 * 1000; // 1 minute
const MAX_REQ    = 60;        // max 60 requests per IP per minute

function rateLimiter(req, res, next) {
  const ip  = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();

  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, { count: 1, windowStart: now });
    return next();
  }

  const record = requestCounts.get(ip);

  // Reset window if expired
  if (now - record.windowStart > WINDOW_MS) {
    record.count = 1;
    record.windowStart = now;
    return next();
  }

  record.count++;

  if (record.count > MAX_REQ) {
    return res.status(429).json({
      success: false,
      error: 'Too many requests — please slow down.',
      retryAfter: Math.ceil((WINDOW_MS - (now - record.windowStart)) / 1000)
    });
  }

  return next();
}

module.exports = rateLimiter;
