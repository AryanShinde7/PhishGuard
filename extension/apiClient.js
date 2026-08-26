/**
 * utils/apiClient.js — PhishGuard Extension → Backend API Client
 *
 * This utility lives in the EXTENSION (not the backend).
 * It provides helper functions for the extension to communicate with
 * the PhishGuard REST API (background.js can import this).
 *
 * Phase 6: Sends analysis results to the backend for persistence.
 */

const API_BASE = 'http://localhost:5000'; // Change to production URL when deployed

/**
 * Send a URL + DOM analysis result to the backend for storage.
 * @param {object} evaluationResult - The full evaluation from riskEngine.js
 */
async function syncAnalysisToBackend(evaluationResult) {
  try {
    const { url, analysis, domSignals, risk } = evaluationResult;

    const payload = {
      url,
      urlFlags:   analysis?.flags       || [],
      domFlags:   domSignals?.flags     || [],
      reasons:    domSignals?.reasons   || [],
      riskScore:  risk?.score,
      riskLevel:  risk?.level,
      domSignals
    };

    const response = await fetch(`${API_BASE}/api/analyze`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload)
    });

    if (!response.ok) {
      console.warn('[PhishGuard API] Sync failed:', response.status);
      return null;
    }

    const data = await response.json();
    return data;

  } catch (err) {
    // Backend may be offline — extension works offline, this is non-blocking
    console.warn('[PhishGuard API] Backend unreachable. Running in offline mode.');
    return null;
  }
}

/**
 * Submit a user phishing report to the backend.
 * @param {object} reportData - { url, riskScore, riskLevel, comment }
 */
async function submitReport(reportData) {
  try {
    const response = await fetch(`${API_BASE}/api/report`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(reportData)
    });
    return response.ok ? await response.json() : null;
  } catch {
    return null;
  }
}

/**
 * Submit user feedback about detection accuracy.
 * @param {object} feedbackData - { url, feedbackType, riskScore, riskLevel, comment }
 */
async function submitFeedback(feedbackData) {
  try {
    const response = await fetch(`${API_BASE}/api/feedback`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(feedbackData)
    });
    return response.ok ? await response.json() : null;
  } catch {
    return null;
  }
}

export { syncAnalysisToBackend, submitReport, submitFeedback };
