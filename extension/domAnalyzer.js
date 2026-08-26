/**
 * domAnalyzer.js — PhishGuard Page & DOM Signal Extractor
 *
 * Runs inside the page context (content script) and extracts structural
 * DOM signals that indicate credential harvesting, fake login pages,
 * brand impersonation, and suspicious page behaviour.
 *
 * Designed to be called from content.js after DOMContentLoaded.
 * Returns a serializable plain-object (no DOM nodes in output).
 */

'use strict';

// ── Constants ──────────────────────────────────────────────────────────────────

// Brands to watch for in page title / visible text impersonation
const BRAND_KEYWORDS = [
  'paypal', 'apple', 'google', 'microsoft', 'amazon',
  'netflix', 'facebook', 'instagram', 'bank', 'chase',
  'wellsfargo', 'citibank', 'hdfc', 'sbi', 'icici',
  'coinbase', 'binance', 'metamask', 'irs', 'income tax'
];

// Urgency / social engineering language in visible page text
const URGENCY_KEYWORDS = [
  'verify your account', 'confirm your identity', 'your account has been suspended',
  'account will be closed', 'update your information', 'limited time',
  'immediate action required', 'unusual activity', 'click here to secure',
  'your password has expired', 'unauthorized access', 'act now',
  'winner', 'you have been selected', 'claim your reward'
];

// Suspicious TLDs for external script/form-action checks
const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work',
  'buzz', 'click', 'icu', 'cam', 'sbs', 'monster', 'fun'
]);

// ── Helpers ────────────────────────────────────────────────────────────────────

function extractHostname(urlString) {
  try {
    return new URL(urlString).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function getTld(hostname) {
  const parts = hostname.split('.').filter(Boolean);
  return parts.length > 0 ? parts[parts.length - 1].toLowerCase() : '';
}

function isExternalHost(targetHostname, pageHostname) {
  if (!targetHostname || !pageHostname) return false;
  // Treat as external if base domain differs
  const getBaseDomain = (h) => h.split('.').slice(-2).join('.');
  return getBaseDomain(targetHostname) !== getBaseDomain(pageHostname);
}

function normalizeText(text) {
  return text.toLowerCase().replace(/\s+/g, ' ').trim();
}

// ── Main DOM Extraction ────────────────────────────────────────────────────────

/**
 * Extracts phishing-relevant DOM signals from the current page.
 * Safe to call at DOMContentLoaded or document_idle.
 *
 * @returns {object} domSignals — serializable plain object
 */
function extractDomSignals() {
  const pageHostname = window.location.hostname.toLowerCase();
  const isHttp = window.location.protocol === 'http:';
  const signals = {
    flags: [],
    reasons: [],
    features: {}
  };

  // ── 1. Password Fields on HTTP ─────────────────────────────────────────────
  const passwordFields = document.querySelectorAll('input[type="password"]');
  const passwordCount = passwordFields.length;
  signals.features.passwordFieldCount = passwordCount;
  if (passwordCount > 0 && isHttp) {
    signals.flags.push('PASSWORD_ON_HTTP');
    signals.reasons.push(`Password input field detected on insecure HTTP page (${passwordCount} field${passwordCount > 1 ? 's' : ''}).`);
  }

  // ── 2. Login Form Detection ────────────────────────────────────────────────
  const hasPasswordField = passwordCount > 0;
  const allInputs = document.querySelectorAll('input:not([type="hidden"])');
  const hasUserField = Array.from(allInputs).some(i => {
    const name = (i.name || i.id || i.placeholder || '').toLowerCase();
    return ['email', 'username', 'user', 'phone', 'mobile', 'login'].some(k => name.includes(k));
  });
  signals.features.hasLoginForm = hasPasswordField && hasUserField;
  if (hasPasswordField && hasUserField) {
    signals.flags.push('LOGIN_FORM_DETECTED');
    signals.reasons.push('Login form with username and password fields detected on this page.');
  }

  // ── 3. Suspicious Form Action Endpoint ────────────────────────────────────
  const forms = Array.from(document.forms);
  signals.features.formCount = forms.length;
  let crossDomainFormCount = 0;
  let httpFormCount = 0;
  let suspiciousTldFormCount = 0;

  forms.forEach((form) => {
    const action = form.action || '';
    const actionHostname = extractHostname(action);
    const actionTld = getTld(actionHostname);

    if (action.startsWith('http:')) httpFormCount++;

    if (actionHostname && isExternalHost(actionHostname, pageHostname)) {
      crossDomainFormCount++;
    }

    if (SUSPICIOUS_TLDS.has(actionTld)) {
      suspiciousTldFormCount++;
    }
  });

  signals.features.crossDomainFormCount = crossDomainFormCount;
  signals.features.httpFormCount = httpFormCount;

  if (crossDomainFormCount > 0) {
    signals.flags.push('CROSS_DOMAIN_FORM');
    signals.reasons.push(`Form submits data to an external domain (${crossDomainFormCount} form${crossDomainFormCount > 1 ? 's' : ''}) — credential exfiltration risk.`);
  }
  if (httpFormCount > 0) {
    signals.flags.push('HTTP_FORM_ACTION');
    signals.reasons.push(`Form submits data over insecure HTTP endpoint — password interception risk.`);
  }
  if (suspiciousTldFormCount > 0) {
    signals.flags.push('SUSPICIOUS_FORM_TLD');
    signals.reasons.push('Form action targets a high-risk / disposable TLD domain.');
  }

  // ── 4. Hidden Form Inputs (Data Exfiltration Tricks) ──────────────────────
  const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
  signals.features.hiddenInputCount = hiddenInputs.length;
  if (hiddenInputs.length > 8) {
    signals.flags.push('EXCESSIVE_HIDDEN_INPUTS');
    signals.reasons.push(`Unusually large number of hidden input fields (${hiddenInputs.length}) — potential data collection.`);
  }

  // ── 5. Page Title Brand Impersonation ─────────────────────────────────────
  const pageTitle = normalizeText(document.title || '');
  const matchedBrandsInTitle = BRAND_KEYWORDS.filter(b => pageTitle.includes(b));
  signals.features.titleBrandMatches = matchedBrandsInTitle;
  if (matchedBrandsInTitle.length > 0) {
    signals.flags.push('TITLE_BRAND_IMPERSONATION');
    signals.reasons.push(`Page title contains brand name(s) [${matchedBrandsInTitle.slice(0, 2).join(', ')}] which could indicate spoofing.`);
  }

  // ── 6. Urgency / Social Engineering Text Scan ─────────────────────────────
  // Sample visible text from body (first 4000 characters for performance)
  const bodyText = normalizeText(
    (document.body ? document.body.innerText || document.body.textContent : '').slice(0, 4000)
  );
  const matchedUrgency = URGENCY_KEYWORDS.filter(kw => bodyText.includes(kw));
  signals.features.urgencyKeywords = matchedUrgency;
  if (matchedUrgency.length > 0) {
    signals.flags.push('URGENCY_LANGUAGE');
    signals.reasons.push(`Social engineering language detected on page: "${matchedUrgency[0]}".`);
  }

  // ── 7. External Scripts from Suspicious Hosts ─────────────────────────────
  const scripts = document.querySelectorAll('script[src]');
  let suspiciousScriptCount = 0;
  scripts.forEach((s) => {
    const src = s.getAttribute('src') || '';
    const srcHostname = extractHostname(src);
    const srcTld = getTld(srcHostname);
    if (srcHostname && isExternalHost(srcHostname, pageHostname) && SUSPICIOUS_TLDS.has(srcTld)) {
      suspiciousScriptCount++;
    }
  });
  signals.features.suspiciousScriptCount = suspiciousScriptCount;
  if (suspiciousScriptCount > 0) {
    signals.flags.push('SUSPICIOUS_EXTERNAL_SCRIPT');
    signals.reasons.push(`External JavaScript loaded from high-risk domain (${suspiciousScriptCount} script${suspiciousScriptCount > 1 ? 's' : ''}).`);
  }

  // ── 8. Iframe Injection (Clickjacking / Phishing Overlays) ────────────────
  const iframes = document.querySelectorAll('iframe');
  let suspiciousIframeCount = 0;
  iframes.forEach((iframe) => {
    const src = iframe.getAttribute('src') || '';
    const iframeHostname = extractHostname(src);
    if (iframeHostname && isExternalHost(iframeHostname, pageHostname)) {
      suspiciousIframeCount++;
    }
  });
  signals.features.suspiciousIframeCount = suspiciousIframeCount;
  if (suspiciousIframeCount > 0) {
    signals.flags.push('EXTERNAL_IFRAME');
    signals.reasons.push(`External iframe element detected (${suspiciousIframeCount}) — potential clickjacking or phishing overlay.`);
  }

  // ── 9. External Link Ratio (Legitimate sites mostly link internally) ───────
  const allLinks = document.querySelectorAll('a[href]');
  let externalLinkCount = 0;
  let internalLinkCount = 0;
  allLinks.forEach((a) => {
    const href = a.getAttribute('href') || '';
    if (href.startsWith('http://') || href.startsWith('https://')) {
      const linkHost = extractHostname(href);
      if (isExternalHost(linkHost, pageHostname)) {
        externalLinkCount++;
      } else {
        internalLinkCount++;
      }
    } else if (href.startsWith('/') || href.startsWith('#') || href.startsWith('.')) {
      internalLinkCount++;
    }
  });

  const totalLinks = externalLinkCount + internalLinkCount;
  const externalRatio = totalLinks > 0 ? externalLinkCount / totalLinks : 0;
  signals.features.externalLinkCount = externalLinkCount;
  signals.features.internalLinkCount = internalLinkCount;
  signals.features.externalLinkRatio = parseFloat(externalRatio.toFixed(2));

  if (totalLinks > 5 && externalRatio > 0.8) {
    signals.flags.push('HIGH_EXTERNAL_LINK_RATIO');
    signals.reasons.push(`${Math.round(externalRatio * 100)}% of page links point to external domains — unusual for a legitimate website.`);
  }

  // ── 10. Missing Favicon (Many phishing clones forget the favicon) ──────────
  const hasFavicon = Array.from(document.querySelectorAll('link[rel]')).some(l => {
    const rel = (l.getAttribute('rel') || '').toLowerCase();
    return rel.includes('icon');
  });
  signals.features.hasFavicon = hasFavicon;
  if (!hasFavicon && hasPasswordField) {
    signals.flags.push('NO_FAVICON_WITH_LOGIN');
    signals.reasons.push('Login page missing favicon — a common trait of phishing clones.');
  }

  return signals;
}

// Export for content.js usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { extractDomSignals };
}
