/**
 * content.js — PhishGuard Content Script
 *
 * Injected into matching web pages (document_idle).
 * Phase 5: Full DOM analysis via domAnalyzer.js.
 *          Sends rich page signals to background service worker.
 */

'use strict';

(function () {
  // Prevent multiple injections on SPA navigations
  if (window.__PHISHGUARD_INJECTED__) return;
  window.__PHISHGUARD_INJECTED__ = true;

  // ── Inline DOM Analyzer ─────────────────────────────────────────────────────
  // Note: Manifest V3 content scripts run as classic scripts, so we inline the
  // domAnalyzer logic here instead of importing it as an ES module.

  const BRAND_KEYWORDS = [
    'paypal', 'apple', 'google', 'microsoft', 'amazon',
    'netflix', 'facebook', 'instagram', 'bank', 'chase',
    'wellsfargo', 'citibank', 'hdfc', 'sbi', 'icici',
    'coinbase', 'binance', 'metamask', 'irs', 'income tax'
  ];

  const URGENCY_KEYWORDS = [
    'verify your account', 'confirm your identity', 'your account has been suspended',
    'account will be closed', 'update your information', 'limited time',
    'immediate action required', 'unusual activity', 'click here to secure',
    'your password has expired', 'unauthorized access', 'act now',
    'winner', 'you have been selected', 'claim your reward'
  ];

  const SUSPICIOUS_TLDS = new Set([
    'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work',
    'buzz', 'click', 'icu', 'cam', 'sbs', 'monster', 'fun'
  ]);

  function safeHostname(urlString) {
    try { return new URL(urlString).hostname.toLowerCase(); } catch { return ''; }
  }

  function getTld(hostname) {
    const parts = hostname.split('.').filter(Boolean);
    return parts.length > 0 ? parts[parts.length - 1].toLowerCase() : '';
  }

  function isExternal(targetHost, pageHost) {
    if (!targetHost || !pageHost) return false;
    const base = h => h.split('.').slice(-2).join('.');
    return base(targetHost) !== base(pageHost);
  }

  function normalizeText(t) {
    return (t || '').toLowerCase().replace(/\s+/g, ' ').trim();
  }

  /**
   * Performs full DOM phishing signal extraction.
   */
  function extractDomSignals() {
    const pageHost = window.location.hostname.toLowerCase();
    const isHttp = window.location.protocol === 'http:';
    const signals = { flags: [], reasons: [], features: {} };

    // 1. Password fields on HTTP
    const pwFields = document.querySelectorAll('input[type="password"]');
    signals.features.passwordFieldCount = pwFields.length;
    if (pwFields.length > 0 && isHttp) {
      signals.flags.push('PASSWORD_ON_HTTP');
      signals.reasons.push(`Password input on insecure HTTP page (${pwFields.length} field${pwFields.length > 1 ? 's' : ''}).`);
    }

    // 2. Login form (username + password pair)
    const hasPassword = pwFields.length > 0;
    const userField = Array.from(document.querySelectorAll('input:not([type="hidden"])')).some(i => {
      const hint = (i.name + i.id + i.placeholder).toLowerCase();
      return ['email', 'username', 'user', 'phone', 'mobile', 'login'].some(k => hint.includes(k));
    });
    signals.features.hasLoginForm = hasPassword && userField;
    if (hasPassword && userField) {
      signals.flags.push('LOGIN_FORM_DETECTED');
      signals.reasons.push('Login form with username and password fields detected.');
    }

    // 3. Form action endpoint analysis
    const forms = Array.from(document.forms);
    signals.features.formCount = forms.length;
    let crossForms = 0, httpForms = 0, badTldForms = 0;
    forms.forEach(form => {
      const action = form.action || '';
      const aHost = safeHostname(action);
      if (action.startsWith('http:')) httpForms++;
      if (aHost && isExternal(aHost, pageHost)) crossForms++;
      if (SUSPICIOUS_TLDS.has(getTld(aHost))) badTldForms++;
    });
    signals.features.crossDomainFormCount = crossForms;
    if (crossForms > 0) {
      signals.flags.push('CROSS_DOMAIN_FORM');
      signals.reasons.push(`Form submits credentials to an external domain (${crossForms} form${crossForms > 1 ? 's' : ''}).`);
    }
    if (httpForms > 0) {
      signals.flags.push('HTTP_FORM_ACTION');
      signals.reasons.push('Form submits data over insecure HTTP — interception risk.');
    }
    if (badTldForms > 0) {
      signals.flags.push('SUSPICIOUS_FORM_TLD');
      signals.reasons.push('Form action targets a high-risk / disposable TLD domain.');
    }

    // 4. Excessive hidden inputs
    const hiddenCount = document.querySelectorAll('input[type="hidden"]').length;
    signals.features.hiddenInputCount = hiddenCount;
    if (hiddenCount > 8) {
      signals.flags.push('EXCESSIVE_HIDDEN_INPUTS');
      signals.reasons.push(`${hiddenCount} hidden input fields — potential silent data collection.`);
    }

    // 5. Brand impersonation in page title
    const title = normalizeText(document.title);
    const brandMatches = BRAND_KEYWORDS.filter(b => title.includes(b));
    signals.features.titleBrandMatches = brandMatches;
    if (brandMatches.length > 0) {
      signals.flags.push('TITLE_BRAND_IMPERSONATION');
      signals.reasons.push(`Page title impersonates brand(s): [${brandMatches.slice(0, 2).join(', ')}].`);
    }

    // 6. Urgency / social engineering text
    const bodyText = normalizeText((document.body?.innerText || '').slice(0, 4000));
    const urgencyMatches = URGENCY_KEYWORDS.filter(kw => bodyText.includes(kw));
    signals.features.urgencyKeywords = urgencyMatches;
    if (urgencyMatches.length > 0) {
      signals.flags.push('URGENCY_LANGUAGE');
      signals.reasons.push(`Social engineering detected: "${urgencyMatches[0]}".`);
    }

    // 7. External scripts from suspicious TLDs
    let suspiciousScripts = 0;
    document.querySelectorAll('script[src]').forEach(s => {
      const sHost = safeHostname(s.getAttribute('src') || '');
      if (sHost && isExternal(sHost, pageHost) && SUSPICIOUS_TLDS.has(getTld(sHost))) {
        suspiciousScripts++;
      }
    });
    signals.features.suspiciousScriptCount = suspiciousScripts;
    if (suspiciousScripts > 0) {
      signals.flags.push('SUSPICIOUS_EXTERNAL_SCRIPT');
      signals.reasons.push(`Script from high-risk external domain loaded (${suspiciousScripts}).`);
    }

    // 8. External iframes (clickjacking / overlays)
    let extIframes = 0;
    document.querySelectorAll('iframe').forEach(f => {
      const fHost = safeHostname(f.getAttribute('src') || '');
      if (fHost && isExternal(fHost, pageHost)) extIframes++;
    });
    signals.features.suspiciousIframeCount = extIframes;
    if (extIframes > 0) {
      signals.flags.push('EXTERNAL_IFRAME');
      signals.reasons.push(`External iframe detected (${extIframes}) — possible clickjacking overlay.`);
    }

    // 9. External link ratio
    let extLinks = 0, intLinks = 0;
    document.querySelectorAll('a[href]').forEach(a => {
      const href = a.getAttribute('href') || '';
      if (/^https?:\/\//.test(href)) {
        isExternal(safeHostname(href), pageHost) ? extLinks++ : intLinks++;
      } else if (/^[/.#]/.test(href)) {
        intLinks++;
      }
    });
    const totalLinks = extLinks + intLinks;
    const extRatio = totalLinks > 0 ? parseFloat((extLinks / totalLinks).toFixed(2)) : 0;
    signals.features.externalLinkRatio = extRatio;
    if (totalLinks > 5 && extRatio > 0.8) {
      signals.flags.push('HIGH_EXTERNAL_LINK_RATIO');
      signals.reasons.push(`${Math.round(extRatio * 100)}% of links point externally — unusual for a legitimate site.`);
    }

    // 10. Missing favicon on a login page
    const hasFavicon = Array.from(document.querySelectorAll('link[rel]'))
      .some(l => l.getAttribute('rel').toLowerCase().includes('icon'));
    signals.features.hasFavicon = hasFavicon;
    if (!hasFavicon && hasPassword) {
      signals.flags.push('NO_FAVICON_WITH_LOGIN');
      signals.reasons.push('Login page is missing a favicon — common in phishing clones.');
    }

    return signals;
  }

  // ── Send signals to background ───────────────────────────────────────────────
  function notifyBackground() {
    const domSignals = extractDomSignals();
    const payload = {
      url: window.location.href,
      hostname: window.location.hostname,
      protocol: window.location.protocol,
      title: document.title || '',
      timestamp: Date.now(),
      domSignals: domSignals
    };

    console.log(`[PhishGuard] DOM analysis: ${domSignals.flags.length} flag(s) found.`, domSignals.flags);

    try {
      chrome.runtime.sendMessage({
        type: 'PAGE_SIGNALS_COLLECTED',
        data: payload
      }, (response) => {
        if (chrome.runtime.lastError) return; // Worker dormant — silent skip
      });
    } catch (e) {
      // Extension context invalidated (happens on extension reload)
    }
  }

  // ── Listen for on-demand requests from popup ─────────────────────────────────
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_PAGE_DATA') {
      const domSignals = extractDomSignals();
      sendResponse({
        status: 'ok',
        data: {
          url: window.location.href,
          hostname: window.location.hostname,
          protocol: window.location.protocol,
          title: document.title || '',
          timestamp: Date.now(),
          domSignals: domSignals
        }
      });
      return true;
    }
  });

  // ── Trigger on page ready ────────────────────────────────────────────────────
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    notifyBackground();
  } else {
    window.addEventListener('DOMContentLoaded', notifyBackground);
  }

})();
