/**
 * background.js — PhishGuard Background Service Worker (Manifest V3)
 *
 * Coordinates URL analysis, risk scoring, content script messaging, and popup requests.
 */

import { analyzeUrl } from './urlAnalyzer.js';
import { calculateRisk } from './riskEngine.js';

// In-memory cache for tab evaluations
const tabDataCache = new Map();

// Helper to evaluate a tab URL
function evaluateTabUrl(url) {
  const analysis = analyzeUrl(url);
  const risk = calculateRisk(analysis);
  return {
    url,
    domain: analysis.hostname,
    protocol: analysis.protocol,
    analysis,
    risk,
    analyzedAt: Date.now()
  };
}

// Tab updated (navigation, reload)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
      const evaluation = evaluateTabUrl(tab.url);
      tabDataCache.set(tabId, evaluation);
      console.log(`[PhishGuard] Tab #${tabId} ${evaluation.domain} -> Score: ${evaluation.risk.score} (${evaluation.risk.level})`);
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
    const evaluation = evaluateTabUrl(url);

    if (tabId) {
      const existing = tabDataCache.get(tabId) || {};
      tabDataCache.set(tabId, {
        ...existing,
        ...evaluation
      });
    }

    sendResponse({
      status: 'ok',
      evaluation: evaluation
    });
    return true;
  }

  if (message.type === 'PAGE_SIGNALS_COLLECTED') {
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      const existing = tabDataCache.get(tabId) || {};
      tabDataCache.set(tabId, {
        ...existing,
        pageSignals: message.data
      });
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
