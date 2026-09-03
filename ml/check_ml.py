import sys
sys.path.insert(0, r'C:\Users\Aryan\Desktop\SIH 2026\phishing-detection\ml')
from uci_features import extract_uci_features
import requests

phishing_dom = {
    'features': {
        'faviconExternal': True,
        'externalResourceRatio': 0.72,
        'externalLinkRatio': 0.83,
        'externalTagRatio': 0.88,
        'sfhStatus': 'external',
        'hasMailtoForm': False,
        'onMouseoverStatus': True,
        'rightClickDisabled': True
    }
}
legit_dom = {
    'features': {
        'faviconExternal': False,
        'externalResourceRatio': 0.10,
        'externalLinkRatio': 0.25,
        'externalTagRatio': 0.12,
        'sfhStatus': 'same',
        'hasMailtoForm': False,
        'onMouseoverStatus': False,
        'rightClickDisabled': False
    }
}

cases = [
    ('http://allegrolokalnie.pl-oferta7329836.lol', phishing_dom, 'PHISHING'),
    ('https://irs.mydigitalassetcompliance.com/get-started', phishing_dom, 'PHISHING'),
    ('https://ranchodomaiarifa.netlify.app/', phishing_dom, 'PHISHING'),
    ('https://centralgeap.online/', phishing_dom, 'PHISHING'),
    ('https://antly.powervitalshop24.de/california/login', phishing_dom, 'PHISHING'),
    ('https://www.google.com/', legit_dom, 'LEGIT'),
    ('https://www.github.com/', legit_dom, 'LEGIT'),
    ('https://www.amazon.com/', legit_dom, 'LEGIT'),
]

print('ML predictions with realistic DOM signals:')
print('-'*75)
for url, dom, expected in cases:
    feats = extract_uci_features(url, dom)
    r = requests.post('http://127.0.0.1:5001/predict/uci',
                      json={'url': url, 'domSignals': dom}, timeout=5)
    p = r.json()['prediction']
    is_phish = p['isPhishing']
    prob = p['probability']
    level = p['riskLevel']
    correct = 'OK   ' if (is_phish == (expected == 'PHISHING')) else 'WRONG'
    nondefault = {k: v for k, v in feats.items() if v != 1}
    print(correct + " Expected=" + expected + " P=" + str(round(prob,3)) + "  " + level)
    print("    Non-1 features: " + str(nondefault))
    print("    URL: " + url[:60])
    print()
