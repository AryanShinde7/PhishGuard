/**
 * background.js — PhishGuard Background Service Worker (Manifest V3)
 *
 * Coordinates URL analysis, risk scoring, content script messaging, and popup requests.
 * Phase 5: Merges DOM signals from content.js into the risk score.
 */

import { analyzeUrl } from './urlAnalyzer.js';
import { calculateRisk } from './riskEngine.js';

// In-memory cache for tab evaluations
const tabDataCache = new Map();

/**
 * Evaluate a tab URL combined with any cached DOM signals.
 * @param {string} url - Full page URL
 * @param {object|null} domSignals - Optional DOM signals from content.js
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

// Tab updated (navigation, reload)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
      // Get cached DOM signals for this tab if already collected by content.js
      const existing = tabDataCache.get(tabId) || {};
      const domSignals = existing.domSignals || null;
      const evaluation = evaluateTabUrl(tab.url, domSignals);
      tabDataCache.set(tabId, { ...existing, ...evaluation });
      console.log(`[PhishGuard] Tab #${tabId} ${evaluation.domain} -> Score: ${evaluation.risk.score} (${evaluation.risk.level}) | URL: ${evaluation.risk.urlFlagCount} flags, DOM: ${evaluation.risk.domFlagCount} flags`);
    }
  }
});

// Tab closed - cleanup cache
chrome.tabs.onRemoved.addListener((tabId) => {
  tabDataCache.delete(tabId);
});

// Central Message Hub
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYZE_URL') {
    const { url, tabId } = message;
    // Merge with any cached DOM signals for this tab
    const existing = tabDataCache.get(tabId) || {};
    const domSignals = existing.domSignals || null;
    const evaluation = evaluateTabUrl(url, domSignals);

    if (tabId) {
      tabDataCache.set(tabId, { ...existing, ...evaluation });
    }

    sendResponse({ status: 'ok', evaluation });
    return true;
  }

  if (message.type === 'PAGE_SIGNALS_COLLECTED') {
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      const existing = tabDataCache.get(tabId) || {};
      // Store DOM signals and recompute risk score fusing URL + DOM
      const domSignals = message.data?.domSignals || null;
      if (domSignals && existing.url) {
        const merged = evaluateTabUrl(existing.url, domSignals);
        tabDataCache.set(tabId, { ...existing, ...merged, domSignals });
        console.log(`[PhishGuard] DOM signals merged for tab #${tabId}. New score: ${merged.risk.score}`);
      } else {
        tabDataCache.set(tabId, { ...existing, pageSignals: message.data, domSignals });
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
