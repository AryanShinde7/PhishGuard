/**
 * urlAnalyzer.js — PhishGuard URL & Domain Heuristic Analysis Engine
 * 
 * Extracts static, explainable URL security features, brand impersonation signals,
 * and rule matches. Designed for client-side evaluation (Manifest V3 and Node.js compatible).
 */

// Known frequently abused / free / high-risk TLDs
const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work', 'buzz', 'fit',
  'click', 'surf', 'rest', 'bar', 'icu', 'cam', 'sbs', 'monster',
  'cyou', 'fun', 'quest', 'skin', 'beauty', 'hair', 'uno'
]);

// High-confidence phishing trigger keywords
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in',
  'verify', 'verification', 'authenticate', 'auth',
  'account', 'security', 'update-account', 'secure-update',
  'banking', 'ebanking', 'wallet', 'metamask',
  'paypal', 'appleid', 'microsoft-verify', 'netflix-billing',
  'kyc', 'confirm-identity', 'claim-reward', 'free-gift',
  'suspended-account', 'unlock-account', 'credential', 'recovery'
];

// Target Brands frequently impersonated in phishing attacks
const MONITORED_BRANDS = [
  'paypal', 'apple', 'google', 'microsoft', 'netflix', 'amazon',
  'facebook', 'instagram', 'whatsapp', 'telegram', 'binance',
  'coinbase', 'metamask', 'chase', 'wellsfargo', 'bankofamerica',
  'adobe', 'dropbox', 'dhl', 'fedex', 'usps'
];

// Popular legitimate search engines/domains to avoid false positives
const KNOWN_SEARCH_DOMAINS = new Set([
  'google.com', 'www.google.com',
  'bing.com', 'www.bing.com',
  'duckduckgo.com', 'www.duckduckgo.com',
  'yahoo.com', 'search.yahoo.com',
  'github.com', 'www.github.com',
  'wikipedia.org', 'en.wikipedia.org'
]);

/**
 * Checks if a hostname is an IPv4 or IPv6 address
 */
function isIpAddress(hostname) {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
  const ipv6Regex = /^(\[[0-9a-fA-F:]+\]|[0-9a-fA-F:]+)$/;
  return ipv4Regex.test(hostname) || (hostname.includes(':') && ipv6Regex.test(hostname));
}

/**
 * Parses URL safely
 */
function safeParseUrl(rawUrl) {
  try {
    let urlString = rawUrl.trim();
    if (!urlString.includes('://')) {
      urlString = 'http://' + urlString;
    }
    return new URL(urlString);
  } catch {
    return null;
  }
}

/**
 * Core URL Analyzer Function
 * @param {string} rawUrl - Full URL string to analyze
 * @returns {object} Analysis result containing detected indicators, reasons, and raw feature metrics
 */
export function analyzeUrl(rawUrl) {
  const result = {
    url: rawUrl,
    isValid: false,
    hostname: '',
    protocol: '',
    pathname: '',
    search: '',
    flags: [],        // Machine-readable keys
    reasons: [],      // Human-readable explainable reasons
    features: {}      // Extracted numeric/boolean features for future ML
  };

  if (!rawUrl || typeof rawUrl !== 'string') {
    result.reasons.push('Invalid or empty URL provided.');
    return result;
  }

  const parsed = safeParseUrl(rawUrl);
  if (!parsed) {
    result.reasons.push('Malformed URL structure.');
    return result;
  }

  result.isValid = true;
  result.protocol = parsed.protocol.replace(':', '').toLowerCase();
  result.hostname = parsed.hostname.toLowerCase();
  result.pathname = parsed.pathname.toLowerCase();
  result.search = parsed.search.toLowerCase();

  const hostname = result.hostname;
  const pathname = result.pathname;
  const isSearchEngine = KNOWN_SEARCH_DOMAINS.has(hostname);

  // Feature 1: Protocol Security (HTTP vs HTTPS)
  const isHttp = result.protocol === 'http';
  result.features.isHttp = isHttp;
  if (isHttp && !hostname.endsWith('.localhost') && hostname !== '127.0.0.1') {
    result.flags.push('INSECURE_HTTP');
    result.reasons.push('Insecure connection (HTTP): Unencrypted traffic allows credential interception.');
  }

  // Feature 2: IP Address in Hostname
  const isIp = isIpAddress(hostname);
  result.features.isIpAddress = isIp;
  if (isIp) {
    result.flags.push('IP_HOST');
    result.reasons.push('Direct IP address used instead of a legitimate domain name.');
  }

  // Feature 3: Embedded '@' Symbol (Authority Trickery)
  const hasAtSymbol = rawUrl.includes('@');
  result.features.hasAtSymbol = hasAtSymbol;
  if (hasAtSymbol) {
    result.flags.push('AT_SYMBOL');
    result.reasons.push("Contains '@' symbol in URL, often used to disguise malicious target hosts.");
  }

  // Feature 4: Subdomain Depth
  const domainParts = hostname.split('.').filter(Boolean);
  const subdomainCount = Math.max(0, domainParts.length - 2);
  result.features.subdomainCount = subdomainCount;
  if (subdomainCount >= 3) {
    result.flags.push('EXCESSIVE_SUBDOMAINS');
    result.reasons.push(`Unusually high number of subdomains (${domainParts.length} levels) indicates nested spoofing.`);
  }

  // Feature 5: Brand Impersonation / Spoofing in Subdomain or Non-primary host
  if (domainParts.length >= 2) {
    const primaryDomain = domainParts.slice(-2).join('.'); // e.g. "alert.xyz"
    const subdomains = domainParts.slice(0, -2).join('.');   // e.g. "paypal.com.verify-account"
    
    for (const brand of MONITORED_BRANDS) {
      if (subdomains.includes(brand) || (hostname.includes(brand) && !primaryDomain.startsWith(brand))) {
        result.flags.push('BRAND_IMPERSONATION');
        result.reasons.push(`Brand spoofing alert: Recognized brand name [${brand}] found disguised inside a sub-domain of ${primaryDomain}.`);
        break;
      }
    }
  }

  // Feature 6: Punycode / Internationalized Domain Homograph
  const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
  result.features.isPunycode = isPunycode;
  if (isPunycode) {
    result.flags.push('PUNYCODE_HOMOGRAPH');
    result.reasons.push('Punycode domain detected (potential homograph attack spoofing real characters).');
  }

  // Feature 7: Excessive Hyphens in Domain
  const cleanHostname = hostname.replace(/xn--/g, '');
  const hyphenCount = (cleanHostname.match(/-/g) || []).length;
  result.features.hyphenCount = hyphenCount;
  if (hyphenCount >= 2) {
    result.flags.push('EXCESSIVE_HYPHENS');
    result.reasons.push(`Suspicious domain formatting (${hyphenCount} hyphens) commonly found in phishing clones.`);
  }

  // Feature 8: Suspicious Keywords in Domain or Path
  const matchedKeywords = [];
  const keywordTarget = isSearchEngine ? hostname : (hostname + ' ' + pathname);
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (keywordTarget.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }
  result.features.matchedKeywords = matchedKeywords;
  if (matchedKeywords.length > 0) {
    result.flags.push('SUSPICIOUS_KEYWORDS');
    result.reasons.push(`Contains high-risk security/banking keywords: [${matchedKeywords.slice(0, 3).join(', ')}]`);
  }

  // Feature 9: High-Risk / Abused TLDs
  const tld = domainParts.length > 0 ? domainParts[domainParts.length - 1] : '';
  result.features.tld = tld;
  if (SUSPICIOUS_TLDS.has(tld)) {
    result.flags.push('SUSPICIOUS_TLD');
    result.reasons.push(`Uses a high-risk / frequently abused top-level domain (.${tld}).`);
  }

  // Feature 10: Abnormal Lengths
  const urlLength = rawUrl.length;
  const hostLength = hostname.length;
  result.features.urlLength = urlLength;
  result.features.hostLength = hostLength;
  if (urlLength > 90) {
    result.flags.push('LONG_URL');
    result.reasons.push(`Abnormally long URL (${urlLength} characters), used to hide real destination parameters.`);
  }
  if (hostLength > 35) {
    result.flags.push('LONG_HOSTNAME');
    result.reasons.push(`Abnormally long domain name (${hostLength} characters).`);
  }

  // Feature 11: Double Slash Redirect in Path
  const lastSlashIndex = rawUrl.indexOf('//', 8);
  if (lastSlashIndex > 8) {
    result.flags.push('REDIRECT_IN_PATH');
    result.reasons.push('Suspicious open redirect structure ("//") detected in URL path.');
  }

  return result;
}

// Support CommonJS for Node test scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyzeUrl, SUSPICIOUS_TLDS, SUSPICIOUS_KEYWORDS, MONITORED_BRANDS };
}
