"""
train_uci.py — PhishGuard Phase 10 UCI Dataset Training Pipeline

Trains a Random Forest classifier on the 17 UCI-extractable features,
evaluates on a stratified held-out test set, and exports:
  - ml/models/phishguard_uci_model.joblib
  - ml/models/uci_metadata.json

UCI label convention: -1 = Phishing, 1 = Legitimate
"""

import os
import sys
import io
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix,
                             classification_report)
from uci_features import UCI_FEATURE_NAMES

ARFF_PATH = os.path.join(os.path.dirname(__file__), 'dataset', 'Training Dataset.arff')
MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
MODEL_PATH = os.path.join(MODELS_DIR, 'phishguard_uci_model.joblib')
META_PATH  = os.path.join(MODELS_DIR, 'uci_metadata.json')

# All 30 UCI attribute names in ARFF order
ALL_COLS = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe',
    'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index',
    'Links_pointing_to_page', 'Statistical_report', 'Result'
]

def load_dataset() -> pd.DataFrame:
    with open(ARFF_PATH, 'r') as f:
        content = f.read()
    data_start = content.index('@data') + len('@data')
    rows = [l.strip() for l in content[data_start:].strip().split('\n') if l.strip()]
    df = pd.read_csv(io.StringIO('\n'.join(rows)), header=None, names=ALL_COLS)
    before = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    print(f"  Loaded {before} rows, {len(df)} after deduplication ({before - len(df)} duplicates removed)")
    return df

def train():
    print("=" * 60)
    print("[*] PHISHGUARD UCI MODEL — TRAINING PIPELINE")
    print("=" * 60)

    # 1. Load & deduplicate
    print("\n[1/6] Loading UCI dataset...")
    df = load_dataset()
    print(f"  Class distribution: Phishing (-1): {(df['Result']==-1).sum()} | "
          f"Legitimate (1): {(df['Result']==1).sum()}")

    # 2. Select the 17 extractable features only
    print(f"\n[2/6] Selecting {len(UCI_FEATURE_NAMES)} extractable features...")
    X = df[UCI_FEATURE_NAMES].copy()
    # UCI labels: -1=phishing, 1=legitimate
    # Remap to binary for sklearn: 0=legitimate, 1=phishing
    y = (df['Result'] == -1).astype(int)  # 1=phishing, 0=legit
    print(f"  Feature matrix: {X.shape}  |  Phishing samples: {y.sum()} ({100*y.mean():.1f}%)")

    # 3. Stratified 80/20 split
    print("\n[3/6] Splitting 80% train / 20% test (stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train)} samples  |  Test: {len(X_test)} samples")

    # 4. Train RandomForestClassifier
    print("\n[4/6] Training RandomForestClassifier (n_estimators=200)...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # 5-fold stratified CV on training set
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_f1 = cross_val_score(clf, X_train, y_train, cv=skf, scoring='f1')
    print(f"  5-Fold CV F1 on train set: {cv_f1.mean():.4f} (+/- {cv_f1.std():.4f})")

    # 5. Evaluate on held-out test set
    print("\n[5/6] Evaluating on held-out test set...")
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]  # probability of phishing (class=1 in remapped space)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    auc  = roc_auc_score(y_test, y_prob)
    cm   = confusion_matrix(y_test, y_pred)

    print("\n" + "-" * 45)
    print(f"  Accuracy:  {acc*100:.2f}%")
    print(f"  Precision: {prec*100:.2f}%  (of predicted phishing, how many actually are)")
    print(f"  Recall:    {rec*100:.2f}%   (of actual phishing, how many we caught)")
    print(f"  F1 Score:  {f1*100:.2f}%")
    print(f"  ROC-AUC:   {auc*100:.2f}%")
    print(f"  Confusion Matrix: TN={cm[0,0]} FP={cm[0,1]} FN={cm[1,0]} TP={cm[1,1]}")
    print("-" * 45)

    # Feature importances
    importances = clf.feature_importances_
    idx_sorted = np.argsort(importances)[::-1]
    print("\n  Top 10 Most Discriminative Features (of 17):")
    for rank, i in enumerate(idx_sorted[:10], 1):
        print(f"    #{rank:02d} {UCI_FEATURE_NAMES[i]:<28}: {importances[i]*100:.2f}%")

    # 6. Export model + metadata
    print("\n[6/6] Exporting model artifacts...")
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"  Model saved: {MODEL_PATH}")

    metadata = {
        'model_type': 'RandomForestClassifier',
        'version': '2.0.0',
        'dataset': 'UCI Phishing Websites (Mohammad et al., 2013)',
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'n_features': len(UCI_FEATURE_NAMES),
        'feature_names': UCI_FEATURE_NAMES,
        'label_convention': {
            'training_binary': '0=legitimate, 1=phishing',
            'uci_original': '-1=phishing, 1=legitimate',
            'prediction_output': 'probability of phishing (0.0 to 1.0)'
        },
        'metrics': {
            'accuracy': round(acc, 4),
            'precision': round(prec, 4),
            'recall': round(rec, 4),
            'f1_score': round(f1, 4),
            'roc_auc': round(auc, 4),
            'cv_f1_mean': round(cv_f1.mean(), 4),
            'cv_f1_std': round(cv_f1.std(), 4),
        },
        'confusion_matrix': {
            'TN': int(cm[0, 0]), 'FP': int(cm[0, 1]),
            'FN': int(cm[1, 0]), 'TP': int(cm[1, 1])
        },
        'feature_importances': [
            {'feature': UCI_FEATURE_NAMES[i], 'importance': round(float(importances[i]), 4)}
            for i in idx_sorted
        ]
    }
    with open(META_PATH, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"  Metadata saved: {META_PATH}")

    print("\n[SUCCESS] UCI model training complete.\n")
    return metadata

if __name__ == '__main__':
    train()
