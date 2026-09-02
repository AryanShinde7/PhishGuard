"""
uci_features.py — PhishGuard UCI-Aligned Feature Extractor (Phase 10)

Extracts the 17 UCI Phishing Websites dataset features that a browser
extension can compute at runtime without any external API calls.

UCI label convention (Mohammad et al., 2013):
  -1 = Phishing
   0 = Suspicious (ternary features only)
   1 = Legitimate

All feature functions return {-1, 0, 1} to match the training distribution.
"""

import re
from urllib.parse import urlparse

# ── Constants ─────────────────────────────────────────────────────────────────

# Known URL-shortening service hostnames
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'short.link', 'rb.gy', 'cutt.ly', 'shorturl.at',
    'bl.ink', 'mcaf.ee', 'url.ie', 'x.co', 'clck.ru', 'shorte.st'
}

# ── Individual Feature Extractors ─────────────────────────────────────────────

def f_having_ip_address(hostname: str) -> int:
    """Feature 1: Is hostname a raw IPv4 address?
    -1 = yes (phishing signal), 1 = no (domain name)
    """
    ipv4 = r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
    return -1 if re.match(ipv4, hostname) else 1


def f_url_length(url: str) -> int:
    """Feature 2: URL length tier.
    1=short (<54), 0=medium (54-75), -1=long (>75, phishing signal)
    """
    n = len(url)
    if n < 54:
        return 1
    elif n <= 75:
        return 0
    return -1


def f_shortining_service(hostname: str) -> int:
    """Feature 3: Is the URL a known shortening service?
    1 = yes (phishing signal — hides real destination), -1 = no
    Note: UCI encoding has 1=shortener, -1=no shortener (opposite intuition).
    """
    return 1 if hostname in URL_SHORTENERS else -1


def f_having_at_symbol(url: str) -> int:
    """Feature 4: Does URL contain '@' symbol (authority-section trick)?
    1 = yes (phishing), -1 = no
    """
    return 1 if '@' in url else -1


def f_double_slash_redirecting(url: str) -> int:
    """Feature 5: Does '//' appear after position 7 in the URL?
    -1 = yes (redirect chain, phishing), 1 = no
    """
    # Skip the protocol's '//' (position ≤7 in 'http://' or 'https://')
    pos = url.find('//', 7)
    return -1 if pos != -1 else 1


def f_prefix_suffix(hostname: str) -> int:
    """Feature 6: Does the domain name contain a '-' separator?
    -1 = yes (phishing, e.g. 'pay-pal.tk'), 1 = no
    """
    # Strip subdomains — look at the registered domain only
    parts = hostname.split('.')
    registered = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname
    return -1 if '-' in registered else 1


def f_having_sub_domain(hostname: str) -> int:
    """Feature 7: Subdomain depth tier.
    1 = one subdomain level (typical legit), 0 = two levels, -1 = three+ (phishing)
    """
    parts = [p for p in hostname.split('.') if p]
    # parts[-2:] = registered domain; everything before = subdomains
    sub_parts = parts[:-2]
    depth = len(sub_parts)
    if depth <= 0:
        return 1
    elif depth == 1:
        return 0
    return -1


def f_https_token(hostname: str) -> int:
    """Feature 12: Does the word 'https' appear inside the domain name itself?
    (Phishers add 'https' to the domain string to fake trust.)
    -1 = yes (phishing), 1 = no
    """
    return -1 if 'https' in hostname.lower() else 1


def f_favicon(favicon_external: bool) -> int:
    """Feature 10: Is the favicon loaded from an external domain?
    -1 = yes (phishing), 1 = same-origin favicon
    """
    return -1 if favicon_external else 1


def f_port(url: str) -> int:
    """Feature 11: Does the URL use a non-standard port?
    -1 = yes (phishing, e.g. :8080, :8443), 1 = standard (80/443/none)
    """
    try:
        port = urlparse(url).port
    except Exception:
        port = None
    if port is None or port in (80, 443):
        return 1
    return -1


def f_request_url(external_resource_ratio: float) -> int:
    """Feature 13: Ratio of page resources loaded from external domains.
    1 = <22% (legit), 0 = 22-61%, -1 = >61% (phishing)
    """
    if external_resource_ratio < 0.22:
        return 1
    elif external_resource_ratio <= 0.61:
        return 0
    return -1


def f_url_of_anchor(external_link_ratio: float) -> int:
    """Feature 14: Ratio of <a href> anchors pointing to external domains.
    1 = <31% (legit), 0 = 31-67%, -1 = >67% (phishing)
    """
    if external_link_ratio < 0.31:
        return 1
    elif external_link_ratio <= 0.67:
        return 0
    return -1


def f_links_in_tags(external_tag_ratio: float) -> int:
    """Feature 15: Ratio of <link>/<script>/<meta> tags linking externally.
    1 = <17% (legit), 0 = 17-81%, -1 = >81% (phishing)
    """
    if external_tag_ratio < 0.17:
        return 1
    elif external_tag_ratio <= 0.81:
        return 0
    return -1


def f_sfh(sfh_status: str) -> int:
    """Feature 16: Server Form Handler target.
    sfh_status: 'blank' | 'external' | 'same'
    -1 = blank/about:blank (phishing), 0 = external domain, 1 = same domain
    """
    if sfh_status == 'blank':
        return -1
    elif sfh_status == 'external':
        return 0
    return 1


def f_submitting_to_email(has_mailto_form: bool) -> int:
    """Feature 17: Does any form use a mailto: action?
    -1 = yes (phishing), 1 = no
    """
    return -1 if has_mailto_form else 1


def f_on_mouseover(has_status_manipulation: bool) -> int:
    """Feature 20: Does onmouseover manipulate window.status?
    -1 = yes (phishing evasion tactic), 1 = no
    """
    return -1 if has_status_manipulation else 1


def f_right_click(right_click_disabled: bool) -> int:
    """Feature 21: Is right-click disabled via contextmenu+preventDefault?
    -1 = yes (phishing), 1 = no
    """
    return -1 if right_click_disabled else 1


# ── Ordered Feature Names (must match train_uci.py column order) ──────────────

UCI_FEATURE_NAMES = [
    'having_IP_Address',
    'URL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'HTTPS_token',
    'Favicon',
    'port',
    'Request_URL',
    'URL_of_Anchor',
    'Links_in_tags',
    'SFH',
    'Submitting_to_email',
    'on_mouseover',
    'RightClick',
]

# ── Main Extractor ────────────────────────────────────────────────────────────

def extract_uci_features(url: str, dom_signals: dict = None) -> dict:
    """
    Extracts all 17 UCI-compatible features from a URL and optional DOM signals.
    All values are in {-1, 0, 1} matching the UCI dataset encoding.

    dom_signals format (from content.js):
    {
      'features': {
        'faviconExternal':         bool,
        'externalResourceRatio':   float,   # NEW — fraction of external <img>/<script>/<link>
        'externalLinkRatio':       float,   # existing
        'externalTagRatio':        float,   # NEW — <link>/<script>/<meta> external fraction
        'sfhStatus':               str,     # NEW — 'blank' | 'external' | 'same'
        'hasMailtoForm':           bool,    # NEW
        'onMouseoverStatus':       bool,    # NEW
        'rightClickDisabled':      bool,    # NEW
      }
    }
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or '').lower()
    except Exception:
        hostname = ''

    dom = (dom_signals or {}).get('features', {})

    return {
        'having_IP_Address':      f_having_ip_address(hostname),
        'URL_Length':             f_url_length(url),
        'Shortining_Service':     f_shortining_service(hostname),
        'having_At_Symbol':       f_having_at_symbol(url),
        'double_slash_redirecting': f_double_slash_redirecting(url),
        'Prefix_Suffix':          f_prefix_suffix(hostname),
        'having_Sub_Domain':      f_having_sub_domain(hostname),
        'HTTPS_token':            f_https_token(hostname),
        'Favicon':                f_favicon(dom.get('faviconExternal', False)),
        'port':                   f_port(url),
        'Request_URL':            f_request_url(float(dom.get('externalResourceRatio', 0.0))),
        'URL_of_Anchor':          f_url_of_anchor(float(dom.get('externalLinkRatio', 0.0))),
        'Links_in_tags':          f_links_in_tags(float(dom.get('externalTagRatio', 0.0))),
        'SFH':                    f_sfh(dom.get('sfhStatus', 'same')),
        'Submitting_to_email':    f_submitting_to_email(dom.get('hasMailtoForm', False)),
        'on_mouseover':           f_on_mouseover(dom.get('onMouseoverStatus', False)),
        'RightClick':             f_right_click(dom.get('rightClickDisabled', False)),
    }
