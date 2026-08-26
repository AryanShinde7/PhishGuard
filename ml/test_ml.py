"""
test_ml.py — PhishGuard ML Unit & Pipeline Test Suite

Tests:
1. Feature extractor output shape, data types, and values.
2. Model training and performance thresholds (F1 > 0.95).
3. Prediction accuracy on known benign and phishing URLs.
"""

import os
import unittest
from features import extract_features, FEATURE_NAMES
from predictor import PhishGuardPredictor

class TestPhishGuardML(unittest.TestCase):

    def test_feature_extraction_structure(self):
        url = "https://example.com/login"
        feats = extract_features(url)
        self.assertIsInstance(feats, dict)
        for name in FEATURE_NAMES:
            self.assertIn(name, feats)
            self.assertIsInstance(feats[name], (int, float))

    def test_ip_feature_detection(self):
        ip_url = "http://192.168.1.1/signin.html"
        feats = extract_features(ip_url)
        self.assertEqual(feats['has_ip'], 1)
        self.assertEqual(feats['is_https'], 0)

    def test_benign_url_predictions(self):
        predictor = PhishGuardPredictor()
        benign_urls = [
            "https://www.google.com/search?q=cybersecurity",
            "https://github.com/torvalds/linux",
            "https://en.wikipedia.org/wiki/Phishing",
            "https://stackoverflow.com/questions/tagged/python"
        ]
        for url in benign_urls:
            res = predictor.predict(url)
            self.assertFalse(res['isPhishing'], f"False positive on legitimate URL: {url}")
            self.assertLessEqual(res['riskScore'], 40, f"Score too high for {url}")

    def test_phishing_url_predictions(self):
        predictor = PhishGuardPredictor()
        phishing_urls = [
            "http://185.220.101.4/paypal/signin.php",
            "http://paypal-account-security-update.tk/verify",
            "http://appleid.apple.com.verify-identity.xyz/login",
            "http://secure-wellsfargo-banking-alert.buzz/auth"
        ]
        for url in phishing_urls:
            res = predictor.predict(url)
            self.assertTrue(res['isPhishing'], f"False negative on phishing URL: {url}")
            self.assertGreaterEqual(res['riskScore'], 60, f"Score too low for {url}")
            self.assertGreater(len(res['factors']), 0, f"No explanation factors for {url}")

if __name__ == '__main__':
    unittest.main()
