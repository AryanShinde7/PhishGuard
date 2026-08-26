"""
train.py — PhishGuard Machine Learning Training Pipeline

Trains Random Forest and Gradient Boosting Classifiers on extracted features,
evaluates precision/recall/F1/AUC, ranks feature importances, and exports
the production model pipeline to `ml/models/phishguard_model.joblib`.
"""

import sys
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report
from dataset_generator import build_dataset
from features import FEATURE_NAMES

# Ensure UTF-8 output on Windows
if sys.platform == 'win32' and sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def train_phishguard_model():
    print("=" * 60)
    print("[*] PHISHGUARD ML MODEL TRAINING PIPELINE")
    print("=" * 60)

    # 1. Load or Generate Dataset
    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    os.makedirs(data_dir, exist_ok=True)
    csv_path = os.path.join(data_dir, 'phishing_dataset.csv')

    print("\n[1/5] Preparing training dataset...")
    df = build_dataset(samples_per_class=2500)
    df.to_csv(csv_path, index=False)
    print(f"      Total samples: {len(df)} (Benign: {sum(df['label'] == 0)}, Phishing: {sum(df['label'] == 1)})")
    print(f"      Feature dimension: {len(FEATURE_NAMES)} features")

    # 2. Train/Test Split (80/20 stratified)
    X = df[FEATURE_NAMES]
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"\n[2/5] Training set: {len(X_train)} samples | Test set: {len(X_test)} samples")

    # 3. Model Training: Random Forest Classifier
    print("\n[3/5] Training Random Forest Classifier (100 estimators)...")
    rf_model = RandomForestClassifier(
        n_estimators=120,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    # Cross-validation
    cv_scores = cross_val_score(rf_model, X_train, y_train, cv=5, scoring='f1')
    print(f"      5-Fold Cross Validation F1-Score: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # 4. Evaluation on Test Set
    print("\n[4/5] Evaluating on unseen test set...")
    y_pred = rf_model.predict(X_test)
    y_prob = rf_model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)

    print("\n" + "-" * 40)
    print(f"  Accuracy:  {acc * 100:.2f}%")
    print(f"  Precision: {prec * 100:.2f}%")
    print(f"  Recall:    {rec * 100:.2f}%")
    print(f"  F1 Score:  {f1 * 100:.2f}%")
    print(f"  ROC-AUC:   {auc * 100:.2f}%")
    print("-" * 40)

    # Feature Importances
    importances = rf_model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    
    print("\n  Top 8 Most Discriminative Features:")
    for rank, idx in enumerate(sorted_idx[:8], 1):
        print(f"    #{rank} {FEATURE_NAMES[idx]:<25}: {importances[idx] * 100:.2f}%")

    # 5. Export Model & Metadata
    print("\n[5/5] Exporting model artifacts...")
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    model_path = os.path.join(models_dir, 'phishguard_model.joblib')
    joblib.dump(rf_model, model_path)
    print(f"      Model saved to: {model_path}")

    metadata = {
        'model_type': 'RandomForestClassifier',
        'version': '1.0.0',
        'n_features': len(FEATURE_NAMES),
        'features': FEATURE_NAMES,
        'metrics': {
            'accuracy': round(acc, 4),
            'precision': round(prec, 4),
            'recall': round(rec, 4),
            'f1_score': round(f1, 4),
            'roc_auc': round(auc, 4),
            'cv_f1_mean': round(cv_scores.mean(), 4)
        },
        'top_features': [
            {'feature': FEATURE_NAMES[i], 'importance': round(float(importances[i]), 4)}
            for i in sorted_idx[:10]
        ]
    }

    meta_path = os.path.join(models_dir, 'feature_metadata.json')
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"      Metadata saved to: {meta_path}")

    print("\n[SUCCESS] Training complete! Model is ready for inference.")
    return metadata

if __name__ == '__main__':
    train_phishguard_model()
