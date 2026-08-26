"""
dataset_generator.py — PhishGuard Training & Validation Dataset Generator

Generates a balanced, realistic, multi-vector dataset of legitimate (0)
and phishing (1) URLs spanning common attacks (brand impersonation, IP hosts,
typosquatting, keyword stuffing, punycode, free TLDs, deep subdomains).

Includes both URL-only samples (no DOM available) and full DOM-augmented samples
so the ML model learns strong lexical URL heuristics as well as page signals.
"""

import os
import random
import pandas as pd
from features import extract_features

BENIGN_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'amazon.com',
    'yahoo.com', 'reddit.com', 'netflix.com', 'linkedin.com', 'instagram.com',
    'microsoft.com', 'apple.com', 'twitter.com', 'github.com', 'stackoverflow.com',
    'cloudflare.com', 'spotify.com', 'medium.com', 'zoom.us', 'dropbox.com',
    'adobe.com', 'nytimes.com', 'cnn.com', 'bbc.com', 'theguardian.com',
    'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'paypal.com', 'ebay.com',
    'walmart.com', 'target.com', 'salesforce.com', 'slack.com', 'twitch.tv',
    'quora.com', 'imdb.com', 'pinterest.com', 'aliexpress.com', 'bing.com',
    'huggingface.co', 'kaggle.com', 'arxiv.org', 'gitlab.com', 'docker.com',
    'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'flipkart.com', 'zomato.com',
    'mozilla.org', 'w3schools.com', 'geeksforgeeks.org', 'gov.in', 'nih.gov'
]

BENIGN_PATHS = [
    '', '/', '/search?q=machine+learning', '/docs/v2/api-reference', '/profile/settings',
    '/watch?v=dQw4w9WgXcQ', '/explore/popular-topics', '/article/2026/08/technology-breakthrough',
    '/download/latest/installer.exe', '/questions/12345678/how-to-fix-error',
    '/user/dashboard/analytics', '/repos/organization/repo-name/releases',
    '/products/category/electronics?page=2&sort=price_asc', '/terms-of-service',
    '/about-us/leadership-team', '/help-center/contact-support', '/signin', '/login'
]

PHISHING_TEMPLATES = [
    # IP Hosts
    'http://{ip}/login.php',
    'http://{ip}/signin/paypal/index.html',
    'http://{ip}/auth/verification?token={token}',
    'http://{ip}/secure/update-banking-info',
    'http://{ip}/paypal/signin.php',
    'http://{ip}/netflix/login',
    'http://{ip}/banking/online',

    # Brand Impersonation / Subdomain trickery
    'http://paypal-account-verify.{tld}/signin',
    'http://login.paypal.com.{tld}/webscr?cmd=_login-run',
    'http://appleid.apple.com.verify-identity.{tld}/login',
    'https://appleid.apple.com.account-recovery.{tld}/verify',
    'http://secure.netflix-payment-update.{tld}/account/login',
    'http://chase-security-alert.{tld}/auth/confirm-identity',
    'http://wellsfargo.banking-access-service.{tld}/login',
    'http://secure-wellsfargo-banking-alert.{tld}/auth',
    'http://google-drive-shared-document.{tld}/view?id={token}',
    'http://microsoft-365-password-reset.{tld}/auth/login',
    'http://instagram-copyright-appeal.{tld}/verify-account',
    'http://metamask-wallet-recovery-phrase.{tld}/connect',
    'http://binance-kyc-verification.{tld}/security',
    'http://sbi-online-banking-kyc.{tld}/retail/login',
    'http://hdfc-netbanking-customer-care.{tld}/secure/login',
    'http://icici-rewards-points-redemption.{tld}/claim',
    'http://amazon-unusual-activity-signin.{tld}/ap/signin',
    'http://coinbase-account-suspended-notice.{tld}/verify',
    'http://paypal-account-security-update.{tld}/verify',

    # Abused TLDs + Keywords
    'http://account-security-update.{tld}/login',
    'http://verify-your-identity-now.{tld}/confirm',
    'http://claim-free-crypto-airdrop.{tld}/wallet',
    'http://immediate-action-required.{tld}/notice',
    'http://unauthorized-login-detected.{tld}/secure-now',
    'http://banking-portal-secure-entry.{tld}/auth',
    'http://customer-support-helpdesk-agent.{tld}/verify',

    # Punycode & Typosquats
    'http://xn--paypl-qqa.com/login',
    'http://xn--gogle-qqa.com/drive',
    'http://xn--mcrosoft-p1a.com/update',
    'http://paypa1-security.com/webscr',
    'http://netfl1x-billing-update.com/signin',

    # Open Redirect & Chained Paths
    'http://suspicious-site.{tld}/redirect?url=http://victim-login.com',
    'http://portal-service.{tld}//account/verify//login.php',
    'http://auth-check.{tld}/https://paypal.com/signin'
]

PHISHING_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work', 'buzz', 'click', 'icu', 'cam', 'sbs', 'monster', 'fun']

def generate_random_ip():
    return f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def generate_random_token():
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join(random.choice(chars) for _ in range(24))

def build_dataset(samples_per_class: int = 3000) -> pd.DataFrame:
    """Generates balanced dataset with mixed URL-only and DOM-augmented samples."""
    records = []
    
    # ── 1. Generate Benign URLs (Label = 0) ───────────────────────────────────
    for i in range(samples_per_class):
        scheme = random.choice(['https://', 'https://', 'https://', 'http://'])
        domain = random.choice(BENIGN_DOMAINS)
        sub = random.choice(['', 'www.', 'api.', 'blog.', 'app.', 'dev.', 'support.', 'mail.', 'docs.'])
        path = random.choice(BENIGN_PATHS)
        
        if random.random() < 0.35:
            query = f"?ref=nav&q=test&id={random.randint(1000, 99999)}"
        else:
            query = ""
            
        url = f"{scheme}{sub}{domain}{path}{query}"
        
        # 50% samples have DOM signals, 50% are URL-only
        if random.random() < 0.5:
            dom_signals = {
                'features': {
                    'passwordFieldCount': 1 if 'login' in path or 'signin' in path else 0,
                    'hasLoginForm': True if 'login' in path or 'signin' in path else False,
                    'crossDomainFormCount': 0,
                    'httpFormCount': 0,
                    'hiddenInputCount': random.randint(0, 4),
                    'urgencyKeywords': [],
                    'externalLinkRatio': round(random.uniform(0.05, 0.35), 2),
                    'suspiciousScriptCount': 0
                }
            }
        else:
            dom_signals = None
        
        feats = extract_features(url, dom_signals)
        feats['url'] = url
        feats['label'] = 0  # Benign
        records.append(feats)

    # ── 2. Generate Phishing URLs (Label = 1) ──────────────────────────────────
    for i in range(samples_per_class):
        template = random.choice(PHISHING_TEMPLATES)
        url = template.format(
            ip=generate_random_ip(),
            tld=random.choice(PHISHING_TLDS),
            token=generate_random_token()
        )
        
        # 50% samples have DOM signals, 50% are URL-only
        if random.random() < 0.5:
            dom_signals = {
                'features': {
                    'passwordFieldCount': random.choice([1, 2]),
                    'hasLoginForm': True,
                    'crossDomainFormCount': random.choice([0, 1, 1, 2]),
                    'httpFormCount': 1 if url.startswith('http://') else 0,
                    'hiddenInputCount': random.randint(2, 12),
                    'urgencyKeywords': random.choice([[], ['verify your account'], ['unauthorized access', 'act now']]),
                    'externalLinkRatio': round(random.uniform(0.65, 0.95), 2),
                    'suspiciousScriptCount': random.choice([0, 1, 2])
                }
            }
        else:
            dom_signals = None
        
        feats = extract_features(url, dom_signals)
        feats['url'] = url
        feats['label'] = 1  # Phishing
        records.append(feats)

    df = pd.DataFrame(records)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df

if __name__ == '__main__':
    print("Generating balanced phishing detection dataset...")
    dataset = build_dataset(3000)
    data_path = os.path.join(os.path.dirname(__file__), 'data', 'phishing_dataset.csv')
    dataset.to_csv(data_path, index=False)
    print(f"Dataset generated with {len(dataset)} samples.")
