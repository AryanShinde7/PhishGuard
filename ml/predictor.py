"""
predictor.py — PhishGuard ML Inference Engine

Loads trained model from `ml/models/phishguard_model.joblib` and evaluates
URLs with feature importance explanations and confidence intervals.
"""

import os
import json
import joblib
import pandas as pd
from features import extract_features, FEATURE_NAMES

class PhishGuardPredictor:
    def __init__(self, model_path: str = None, metadata_path: str = None):
        base_dir = os.path.dirname(__file__)
        self.model_path = model_path or os.path.join(base_dir, 'models', 'phishguard_model.joblib')
        self.metadata_path = metadata_path or os.path.join(base_dir, 'models', 'feature_metadata.json')
        
        self.model = None
        self.metadata = {}
        self.load_model()

    def load_model(self):
        """Loads saved joblib model and metadata."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Trained model not found at {self.model_path}. Run train.py first.")
        
        self.model = joblib.load(self.model_path)
        
        if os.path.exists(self.metadata_path):
            with open(self.metadata_path, 'r') as f:
                self.metadata = json.load(f)

    def predict(self, url: str, dom_signals: dict = None) -> dict:
        """
        Runs ML inference on a given URL and optional DOM signals.
        Returns probability, binary classification, risk score (0-100), and feature contributions.
        """
        feats_dict = extract_features(url, dom_signals)
        
        # Build dataframe row matching trained feature names
        df_row = pd.DataFrame([feats_dict])[FEATURE_NAMES]
        
        # Predict probability of class 1 (Phishing)
        proba = float(self.model.predict_proba(df_row)[0][1])
        prediction = int(self.model.predict(df_row)[0])
        
        # Normalized Risk Score (0-100) based on probability
        risk_score = round(proba * 100)
        
        # Classification Tier
        if risk_score > 60:
            tier = 'HIGH RISK'
            level_key = 'high-risk'
        elif risk_score > 30:
            tier = 'SUSPICIOUS'
            level_key = 'suspicious'
        else:
            tier = 'SAFE'
            level_key = 'safe'

        # Feature Contributions: Check which high-weight features triggered
        contributing_factors = []
        if feats_dict.get('brand_impersonation', 0) == 1:
            contributing_factors.append("Brand name detected in unauthorized domain/path")
        if feats_dict.get('has_ip', 0) == 1:
            contributing_factors.append("Host is a raw numerical IP address instead of domain")
        if feats_dict.get('is_high_risk_tld', 0) == 1:
            contributing_factors.append("Host uses a high-risk or disposable top-level domain")
        if feats_dict.get('matched_keywords', 0) > 0:
            contributing_factors.append(f"{feats_dict['matched_keywords']} phishing-associated keyword(s) detected")
        if feats_dict.get('is_https', 0) == 0:
            contributing_factors.append("Connection uses unencrypted HTTP protocol")
        if feats_dict.get('is_punycode', 0) == 1:
            contributing_factors.append("Punycode / IDN homograph character obfuscation detected")
        if feats_dict.get('cross_domain_form', 0) == 1:
            contributing_factors.append("Form submits credentials to a third-party external domain")
        if feats_dict.get('has_password_field', 0) == 1 and feats_dict.get('is_https', 0) == 0:
            contributing_factors.append("Password input on unencrypted HTTP page")
        if feats_dict.get('urgency_language', 0) == 1:
            contributing_factors.append("Social engineering urgency language identified on page")
        if feats_dict.get('external_link_ratio', 0.0) > 0.8:
            contributing_factors.append("Abnormally high ratio of external links (>80%)")

        confidence = round(abs(proba - 0.5) * 2.0, 3) # Confidence scaled 0.0 -> 1.0

        return {
            'url': url,
            'isPhishing': bool(prediction == 1),
            'probability': round(proba, 4),
            'riskScore': risk_score,
            'riskLevel': tier,
            'levelKey': level_key,
            'confidence': confidence,
            'model': 'RandomForestClassifier (v1.0.0)',
            'factors': contributing_factors,
            'rawFeatures': feats_dict
        }

# Global singleton predictor
_predictor_instance = None

def get_predictor():
    global _predictor_instance
    if _predictor_instance is None:
        _predictor_instance = PhishGuardPredictor()
    return _predictor_instance


# ── UCI-Trained Predictor (Phase 10) ─────────────────────────────────────────

class UCIPredictor:
    """
    Inference engine for the UCI-dataset-trained Random Forest.
    Uses 17 browser-extractable features encoded in {-1, 0, 1}.

    Labels: probability output is P(phishing) in [0, 1].
    The underlying model was trained with 0=legitimate, 1=phishing.
    """

    def __init__(self):
        base_dir = os.path.dirname(__file__)
        self.model_path = os.path.join(base_dir, 'models', 'phishguard_uci_model.joblib')
        self.meta_path  = os.path.join(base_dir, 'models', 'uci_metadata.json')
        self.model = None
        self.metadata = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"UCI model not found at {self.model_path}. Run train_uci.py first."
            )
        self.model = joblib.load(self.model_path)
        if os.path.exists(self.meta_path):
            with open(self.meta_path) as f:
                self.metadata = json.load(f)

    def predict(self, url: str, dom_signals: dict = None) -> dict:
        from uci_features import extract_uci_features, UCI_FEATURE_NAMES

        feats = extract_uci_features(url, dom_signals)
        row   = pd.DataFrame([feats])[UCI_FEATURE_NAMES]

        # Model was trained with: 0=legitimate, 1=phishing
        proba     = float(self.model.predict_proba(row)[0][1])
        risk_score = round(proba * 100)

        if risk_score > 60:
            tier = 'HIGH RISK'; level_key = 'high-risk'
        elif risk_score > 30:
            tier = 'SUSPICIOUS'; level_key = 'suspicious'
        else:
            tier = 'SAFE'; level_key = 'safe'

        confidence = round(abs(proba - 0.5) * 2.0, 3)

        return {
            'url':        url,
            'isPhishing': proba > 0.5,
            'probability': round(proba, 4),
            'riskScore':  risk_score,
            'riskLevel':  tier,
            'levelKey':   level_key,
            'confidence': confidence,
            'model':      'RandomForestClassifier-UCI (v2.0.0)',
            'features':   feats
        }


_uci_predictor_instance = None

def get_uci_predictor():
    global _uci_predictor_instance
    if _uci_predictor_instance is None:
        _uci_predictor_instance = UCIPredictor()
    return _uci_predictor_instance
