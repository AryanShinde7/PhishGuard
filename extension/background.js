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

// URLs that the user has explicitly chosen to bypass/proceed to.
// Also persisted in chrome.storage.session so it survives service worker restarts.
const bypassedUrls = new Set();

// Load any previously stored bypasses from session storage on startup
chrome.storage.session.get(['pg_bypassed_urls'], (res) => {
  const stored = res.pg_bypassed_urls || [];
  stored.forEach(u => bypassedUrls.add(u));
});

/** Persist the current bypassedUrls Set to session storage */
function persistBypasses() {
  chrome.storage.session.set({ pg_bypassed_urls: [...bypassedUrls] }).catch(() => {});
}

/** Add a URL to the bypass list (memory + session storage) */
function addBypass(url) {
  bypassedUrls.add(url);
  persistBypasses();
}

/** Check if a URL is bypassed — checks both memory and session storage */
async function isBypassed(url) {
  if (bypassedUrls.has(url)) return true;
  try {
    const res = await chrome.storage.session.get(['pg_bypassed_urls']);
    const stored = res.pg_bypassed_urls || [];
    if (stored.includes(url)) {
      bypassedUrls.add(url); // Re-populate in-memory cache
      return true;
    }
  } catch { /* ignore */ }
  return false;
}

// Tabs where the popup has already automatically opened for this navigation
const autoPoppedTabs = new Set();

/**
 * Automatically opens the extension popup when a site is classified as SUSPICIOUS
 */
function triggerSuspiciousPopup(tabId) {
  if (!tabId || autoPoppedTabs.has(tabId)) return;
  autoPoppedTabs.add(tabId);

  // Set action badge to caution symbol
  if (chrome.action && chrome.action.setBadgeText) {
    chrome.action.setBadgeText({ text: '!', tabId }).catch(() => {});
    chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId }).catch(() => {});
  }

  // Attempt to open the extension popup automatically
  if (chrome.action && typeof chrome.action.openPopup === 'function') {
    chrome.tabs.get(tabId).then(tab => {
      if (tab && tab.active) {
        chrome.action.openPopup({ windowId: tab.windowId }).catch(() => {
          chrome.action.openPopup().catch(() => {});
        });
        console.log(`[PhishGuard] ⚠️ Automatically opened extension popup for SUSPICIOUS site on tab #${tabId}`);
      }
    }).catch(() => {
      chrome.action.openPopup().catch(() => {});
    });
  }
}

/**
 * Redirects a tab to the PhishGuard Interstitial Block Page
 */
function redirectToWarningPage(tabId, targetUrl, evaluation) {
  if (!tabId || !targetUrl || bypassedUrls.has(targetUrl)) return;
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) return;

  const warningBase = chrome.runtime.getURL('warning.html');
  // Avoid redirect loop if already on warning page
  if (targetUrl.startsWith(warningBase)) return;

  const score = evaluation?.risk?.score || 75;
  const level = evaluation?.risk?.level || 'HIGH RISK';
  const reasons = (evaluation?.risk?.breakdown || []).map(b => b.description || b.flag);

  const warningUrl = `${warningBase}?url=${encodeURIComponent(targetUrl)}` +
    `&score=${encodeURIComponent(score)}` +
    `&level=${encodeURIComponent(level)}` +
    `&reasons=${encodeURIComponent(JSON.stringify(reasons))}`;

  console.warn(`[PhishGuard] 🚨 INTERCEPTING HIGH RISK SITE #${tabId}: ${targetUrl} (Score: ${score})`);

  chrome.tabs.update(tabId, { url: warningUrl }).catch(err => {
    console.warn('[PhishGuard] Failed to redirect tab to warning page:', err);
  });
}

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

// ── Tab navigated: run URL-only analysis locally, intercept if HIGH RISK or popup if SUSPICIOUS ───────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  const currentUrl = changeInfo.url || tab.url;
  if (!currentUrl) return;

  // Reset auto-pop flag on new navigation
  if (changeInfo.url) {
    autoPoppedTabs.delete(tabId);
    if (chrome.action && chrome.action.setBadgeText) {
      chrome.action.setBadgeText({ text: '', tabId }).catch(() => {});
    }
  }

  // Only check standard HTTP/HTTPS navigations
  if (!currentUrl.startsWith('http://') && !currentUrl.startsWith('https://')) return;

  // Ignore if user explicitly bypassed this destination (check storage too)
  if (await isBypassed(currentUrl)) return;

  // Evaluate URL heuristic flags as early as possible
  if (changeInfo.status === 'loading' || changeInfo.status === 'complete') {
    const evaluation = evaluateTabUrl(currentUrl, null);
    tabDataCache.set(tabId, { ...evaluation, domSignals: null, backendResult: null });

    console.log(`[PhishGuard] #${tabId} → ${evaluation.domain} | Local heuristic: ${evaluation.risk.score} (${evaluation.risk.level})`);

    // Automatic Interception: If classified as HIGH RISK, block immediately
    if (evaluation.risk.level === 'HIGH RISK') {
      redirectToWarningPage(tabId, currentUrl, evaluation);
    } else if (evaluation.risk.level === 'SUSPICIOUS' && changeInfo.status === 'complete') {
      // Automatic Popup: If classified as SUSPICIOUS, pop up the extension automatically!
      triggerSuspiciousPopup(tabId);
    }
  }
});

// Tab closed — cleanup cache
chrome.tabs.onRemoved.addListener((tabId) => {
  tabDataCache.delete(tabId);
  autoPoppedTabs.delete(tabId);
});

// ── Central Message Hub ────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // Bypass warning request from warning.html
  if (message.type === 'BYPASS_WARNING') {
    const { url } = message;
    if (url) {
      addBypass(url);  // Persist to session storage so bypass survives SW restart
      console.log(`[PhishGuard] User bypassed warning for: ${url}`);
    }
    sendResponse({ status: 'ok', bypassed: true });
    return true;
  }

  // Request warning data from warning.html
  if (message.type === 'GET_WARNING_DATA') {
    const { url } = message;
    let evalData = null;

    if (url) {
      for (const [, entry] of tabDataCache) {
        if (entry.url === url) {
          evalData = entry;
          break;
        }
      }
      if (!evalData) {
        evalData = evaluateTabUrl(url, null);
      }
    }

    sendResponse({ status: 'ok', evaluation: evalData });
    return true;
  }

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
        syncAnalysisToBackend(merged).then(async backendResult => {
          if (backendResult?.data) {
            const br = backendResult.data;
            const mlProb = br.mlAnalysis?.probability;
            console.log(`[PhishGuard] ML score for #${tabId}: ${br.riskScore} (${br.riskLevel}) | P(phishing)=${mlProb ?? 'offline'}`);
            // Store server-authoritative result — popup will use this on next open
            tabDataCache.set(tabId, { ...tabDataCache.get(tabId), backendResult: br });

            // Push updated badge to popup if it's open
            chrome.runtime.sendMessage({ type: 'BACKEND_SCORE_UPDATE', tabId, data: br }).catch(() => {});

            // If backend ML + DOM analysis elevated this site to HIGH RISK, intercept tab now
            // Only intercept if the user hasn't already bypassed this URL
            if (br.riskLevel === 'HIGH RISK' && !(await isBypassed(existing.url))) {
              redirectToWarningPage(tabId, existing.url, {
                ...merged,
                risk: {
                  ...merged.risk,
                  score: br.riskScore,
                  level: br.riskLevel,
                  mlAnalysis: br.mlAnalysis
                }
              });
            } else if (br.riskLevel === 'SUSPICIOUS' || merged.risk.level === 'SUSPICIOUS') {
              // If classified as SUSPICIOUS, automatically pop up extension!
              triggerSuspiciousPopup(tabId);
            }
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
    const { url, domain, reportType, riskScore, riskLevel } = message;

    chrome.storage.local.get(['user_reports', 'user_report_states'], (res) => {
      const reports = res.user_reports || [];
      const states = res.user_report_states || {};

      const existingState = states[url];
      // Toggle: if same reportType clicked again → undo (remove)
      if (existingState === reportType) {
        delete states[url];
        const filtered = reports.filter(r => !(r.url === url && r.reportType === reportType));
        chrome.storage.local.set({ user_reports: filtered, user_report_states: states });
        
        // Also remove from backend dashboard
        fetch('http://localhost:5000/api/report', {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        }).catch(() => {});
        
        sendResponse({ status: 'removed', toggled: true });
        return;
      }

      // Remove any previous opposite report for this URL first
      const filtered = reports.filter(r => r.url !== url);
      filtered.push({
        url,
        domain,
        reportType,
        riskScore: riskScore || 0,
        riskLevel: riskLevel || 'UNKNOWN',
        timestamp: Date.now()
      });
      states[url] = reportType;
      chrome.storage.local.set({ user_reports: filtered, user_report_states: states });

      // Also forward to backend so it appears on dashboard
      fetch('http://localhost:5000/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, riskScore, riskLevel })
      }).catch(() => {}); // Non-blocking — extension works offline too
    });

    sendResponse({ status: 'success' });
    return true;
  }

  // Popup requests the saved report state for the current URL
  if (message.type === 'GET_REPORT_STATE') {
    chrome.storage.local.get(['user_report_states'], (res) => {
      const states = res.user_report_states || {};
      sendResponse({ reportType: states[message.url] || null });
    });
    return true;
  }

  return false;
});
