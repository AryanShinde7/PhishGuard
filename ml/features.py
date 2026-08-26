"""
features.py — PhishGuard Machine Learning Feature Extractor

Extracts lexical, structural, statistical (entropy), and DOM-based features
from web URLs and page signals to feed the ML classification pipeline.
Uses standard Python libraries for maximum reliability and speed.
"""

import re
import math
from urllib.parse import urlparse

# ── Keywords & Dictionaries ───────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'account', 'banking',
    'secure', 'security', 'update', 'password', 'credential', 'auth',
    'wallet', 'confirm', 'suspend', 'restricted', 'support', 'service',
    'billing', 'invoice', 'claim', 'reward', 'free', 'bonus', 'gift',
    'token', 'webscr', 'cmd', 'dispatch', 'ebayisapi', 'paypal', 'apple',
    'microsoft', 'google', 'netflix', 'amazon', 'chase', 'wellsfargo'
]

HIGH_RISK_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work', 'buzz',
    'click', 'icu', 'cam', 'sbs', 'monster', 'fun', 'rest', 'surf', 'fit'
}

BRAND_LIST = [
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix',
    'facebook', 'instagram', 'bank', 'chase', 'wellsfargo', 'citibank',
    'hdfc', 'sbi', 'icici', 'coinbase', 'binance', 'metamask'
]

# ── Helper Functions ──────────────────────────────────────────────────────────

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string (measures randomness/obfuscation)."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 4)

def is_ip_address(hostname: str) -> int:
    """Checks if hostname is an IPv4 or IPv6 address."""
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return 1 if re.match(ipv4_pattern, hostname) else 0

def parse_domain_parts(hostname: str):
    """Splits hostname into subdomain, domain, and suffix."""
    if not hostname:
        return '', '', ''
    parts = hostname.split('.')
    if len(parts) == 1:
        return '', parts[0], ''
    elif len(parts) == 2:
        return '', parts[0], parts[1]
    else:
        suffix = parts[-1]
        domain = parts[-2]
        subdomain = '.'.join(parts[:-2])
        return subdomain, domain, suffix

# ── Main Feature Extractor ────────────────────────────────────────────────────

def extract_features(url: str, dom_signals: dict = None) -> dict:
    """
    Extracts numerical feature dictionary from a URL and optional DOM signals.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse('http://invalid-url.com')

    hostname = (parsed.hostname or '').lower()
    path = parsed.path or ''
    query = parsed.query or ''
    scheme = (parsed.scheme or '').lower()

    subdomain, domain_name, suffix = parse_domain_parts(hostname)

    # 1. Lexical & Length Features
    url_len = len(url)
    hostname_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    # 2. Character Counts
    count_dots = url.count('.')
    count_hyphens = url.count('-')
    count_at = url.count('@')
    count_question = url.count('?')
    count_equal = url.count('=')
    count_slash = url.count('/')
    count_percent = url.count('%')
    count_digits = sum(c.isdigit() for c in url)
    count_letters = sum(c.isalpha() for c in url)

    # Ratios
    digits_ratio = round(count_digits / url_len, 4) if url_len > 0 else 0.0
    letters_ratio = round(count_letters / url_len, 4) if url_len > 0 else 0.0

    # 3. Structural & Domain Features
    has_ip = is_ip_address(hostname)
    is_https = 1 if scheme == 'https' else 0
    is_punycode = 1 if 'xn--' in hostname else 0
    
    # Subdomain depth
    subdomain_count = len(subdomain.split('.')) if subdomain else 0
    has_excessive_subdomains = 1 if subdomain_count >= 3 else 0
    has_excessive_hyphens = 1 if hostname.count('-') >= 2 else 0

    # 4. Statistical Features
    url_entropy = calculate_entropy(url)
    hostname_entropy = calculate_entropy(hostname)

    # 5. Semantic & Keyword Features
    url_lower = url.lower()
    matched_keywords = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    is_high_risk_tld = 1 if suffix in HIGH_RISK_TLDS else 0

    # Brand Impersonation in subdomain/path
    brand_in_subdomain_or_path = 0
    for brand in BRAND_LIST:
        if (brand in subdomain or brand in path) and brand != domain_name:
            brand_in_subdomain_or_path = 1
            break

    # 6. DOM Features (defaults to baseline if not available)
    dom = dom_signals or {}
    dom_features = dom.get('features', {})
    
    has_password_field = 1 if dom_features.get('passwordFieldCount', 0) > 0 else 0
    has_login_form = 1 if dom_features.get('hasLoginForm', False) else 0
    cross_domain_form = 1 if dom_features.get('crossDomainFormCount', 0) > 0 else 0
    http_form_action = 1 if dom_features.get('httpFormCount', 0) > 0 else 0
    hidden_inputs_count = dom_features.get('hiddenInputCount', 0)
    urgency_language = 1 if len(dom_features.get('urgencyKeywords', [])) > 0 else 0
    external_link_ratio = float(dom_features.get('externalLinkRatio', 0.0))
    suspicious_scripts = dom_features.get('suspiciousScriptCount', 0)

    # Consolidated Feature Vector (33 features)
    return {
        'url_len': url_len,
        'hostname_len': hostname_len,
        'path_len': path_len,
        'query_len': query_len,
        'count_dots': count_dots,
        'count_hyphens': count_hyphens,
        'count_at': count_at,
        'count_question': count_question,
        'count_equal': count_equal,
        'count_slash': count_slash,
        'count_percent': count_percent,
        'count_digits': count_digits,
        'digits_ratio': digits_ratio,
        'letters_ratio': letters_ratio,
        'has_ip': has_ip,
        'is_https': is_https,
        'is_punycode': is_punycode,
        'subdomain_count': subdomain_count,
        'has_excessive_subdomains': has_excessive_subdomains,
        'has_excessive_hyphens': has_excessive_hyphens,
        'url_entropy': url_entropy,
        'hostname_entropy': hostname_entropy,
        'matched_keywords': matched_keywords,
        'is_high_risk_tld': is_high_risk_tld,
        'brand_impersonation': brand_in_subdomain_or_path,
        'has_password_field': has_password_field,
        'has_login_form': has_login_form,
        'cross_domain_form': cross_domain_form,
        'http_form_action': http_form_action,
        'hidden_inputs_count': hidden_inputs_count,
        'urgency_language': urgency_language,
        'external_link_ratio': external_link_ratio,
        'suspicious_scripts': suspicious_scripts
    }

FEATURE_NAMES = list(extract_features('http://example.com').keys())
