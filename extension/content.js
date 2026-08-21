/**
 * content.js — PhishGuard Content Script
 * 
 * Injected into matching web pages.
 * Phase 1: Reads page URL, title, and establishes communication with the background worker.
 * Future phases (Phase 5) will extract DOM features (forms, password inputs, external links, etc.).
 */

'use strict';

(function () {
  // Prevent multiple injections
  if (window.__PHISHGUARD_INJECTED__) return;
  window.__PHISHGUARD_INJECTED__ = true;

  console.log('[PhishGuard] Content script initialized on:', window.location.href);

  /**
   * Extract basic page metadata
   */
  function extractBasicPageSignals() {
    return {
      url: window.location.href,
      hostname: window.location.hostname,
      protocol: window.location.protocol,
      title: document.title || '',
      hasForms: document.forms.length > 0,
      hasPasswordFields: document.querySelectorAll('input[type="password"]').length > 0,
      timestamp: Date.now()
    };
  }

  /**
   * Notify background service worker about current page state
   */
  function notifyBackground() {
    try {
      const signals = extractBasicPageSignals();
      chrome.runtime.sendMessage({
        type: 'PAGE_SIGNALS_COLLECTED',
        data: signals
      }, (response) => {
        if (chrome.runtime.lastError) {
          // Worker might be dormant or context invalidated, silent catch
          return;
        }
      });
    } catch (e) {
      // Catch any messaging exceptions
    }
  }

  // Listen for messages from popup or background
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_PAGE_DATA') {
      const signals = extractBasicPageSignals();
      sendResponse({ status: 'ok', data: signals });
      return true;
    }
  });

  // Run on initial load
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    notifyBackground();
  } else {
    window.addEventListener('DOMContentLoaded', notifyBackground);
  }
})();
