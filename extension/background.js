/**
 * background.js — PhishGuard Background Service Worker (Manifest V3)
 *
 * Flow:
 *   1. Tab navigates → URL-only heuristic score computed locally (no backend call yet).
 *   2. content.js injects into the page and extracts DOM signals.
 *   3. PAGE_SIGNALS_COLLECTED fires → DOM signals merged → backend called NOW.
 *      This ensures the ML microservice receives real DOM features, not nulls.
 *   4. Backend runs UCI ML model + rule-score ensemble → authoritative score stored.
 */

import { analyzeUrl } from './urlAnalyzer.js';
import { calculateRisk } from './riskEngine.js';
import { syncAnalysisToBackend } from './apiClient.js';

// In-memory cache for tab evaluations
const tabDataCache = new Map();

/**
 * Evaluate a tab URL combined with any cached DOM signals.
 */
function evaluateTabUrl(url, domSignals = null) {
  const analysis = analyzeUrl(url);
  const risk = calculateRisk(analysis, domSignals);
  return {
    url,
    domain: analysis.hostname,
    protocol: analysis.protocol,
    analysis,
    domSignals,
    risk,
    analyzedAt: Date.now()
  };
}

// ── Tab navigated: run URL-only analysis locally, do NOT call backend yet ─────
// Backend is called after DOM signals arrive so the ML model gets real features.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
      // Reset DOM signals on navigation — stale DOM from previous page must not bleed over
      const evaluation = evaluateTabUrl(tab.url, null);
      tabDataCache.set(tabId, { ...evaluation, domSignals: null, backendResult: null });
      console.log(`[PhishGuard] #${tabId} → ${evaluation.domain} | Local heuristic: ${evaluation.risk.score} (${evaluation.risk.level})`);
      // Backend NOT called here — DOM signals unavailable at this point.
    }
  }
});

// Tab closed — cleanup cache
chrome.tabs.onRemoved.addListener((tabId) => {
  tabDataCache.delete(tabId);
});

// ── Central Message Hub ────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // Popup / popup.js requests current evaluation for this tab
  if (message.type === 'ANALYZE_URL') {
    const { url, tabId } = message;
    const existing = tabDataCache.get(tabId) || {};
    const domSignals = existing.domSignals || null;
    const evaluation = evaluateTabUrl(url, domSignals);
    if (tabId) tabDataCache.set(tabId, { ...existing, ...evaluation });

    // If we have a server-side result, prefer it (it has ML score)
    const serverResult = existing.backendResult;
    if (serverResult) {
      evaluation.risk = {
        ...evaluation.risk,
        score:    serverResult.riskScore,
        level:    serverResult.riskLevel,
        levelKey: serverResult.riskLevel === 'HIGH RISK' ? 'high-risk'
                : serverResult.riskLevel === 'SUSPICIOUS' ? 'suspicious' : 'safe',
        mlAnalysis: serverResult.mlAnalysis
      };
    }

    sendResponse({ status: 'ok', evaluation });
    return true;
  }

  // content.js has finished DOM extraction — this is the moment we have all features
  if (message.type === 'PAGE_SIGNALS_COLLECTED') {
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      const existing = tabDataCache.get(tabId) || {};
      const domSignals = message.data?.domSignals || null;

      if (domSignals && existing.url) {
        const merged = evaluateTabUrl(existing.url, domSignals);
        tabDataCache.set(tabId, { ...existing, ...merged, domSignals, backendResult: null });
        console.log(`[PhishGuard] DOM ready for #${tabId}. Local score: ${merged.risk.score} → calling backend+ML...`);

        // Backend + ML call with full features (DOM signals present)
        syncAnalysisToBackend(merged).then(backendResult => {
          if (backendResult?.data) {
            const br = backendResult.data;
            const mlProb = br.mlAnalysis?.probability;
            console.log(`[PhishGuard] ML score for #${tabId}: ${br.riskScore} (${br.riskLevel}) | P(phishing)=${mlProb ?? 'offline'}`);
            // Store server-authoritative result — popup will use this on next open
            tabDataCache.set(tabId, { ...tabDataCache.get(tabId), backendResult: br });

            // Push updated badge to popup if it's open
            chrome.runtime.sendMessage({ type: 'BACKEND_SCORE_UPDATE', tabId, data: br }).catch(() => {});
          }
        }).catch(() => {});

      } else {
        tabDataCache.set(tabId, { ...existing, domSignals });
      }
    }
    sendResponse({ status: 'received' });
    return true;
  }

  if (message.type === 'USER_REPORT') {
    chrome.storage.local.get(['user_reports'], (res) => {
      const reports = res.user_reports || [];
      reports.push({
        url: message.url,
        domain: message.domain,
        reportType: message.reportType,
        riskScore: message.riskScore || 0,
        riskLevel: message.riskLevel || 'UNKNOWN',
        timestamp: Date.now()
      });
      chrome.storage.local.set({ user_reports: reports });
    });
    sendResponse({ status: 'success' });
    return true;
  }

  return false;
});
