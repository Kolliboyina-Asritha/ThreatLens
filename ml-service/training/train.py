"""
ThreatLens AI - Random Forest Model Training Script
Trains a Random Forest classifier on deterministic URL features.
Saves model to ml-service/models/random_forest.joblib and metadata to model_metadata.json.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score
)

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.schemas import FEATURE_NAMES, SCHEMA_VERSION, MODEL_VERSION
from training.prepare_dataset import prepare_dataset, PROCESSED_DATA_PATH

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "random_forest.joblib")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")


def train_model():
    """Trains Random Forest model, evaluates performance, and persists artifacts."""
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    if not os.path.exists(PROCESSED_DATA_PATH):
        print("[*] Processed dataset not found. Generating...")
        df = prepare_dataset()
    else:
        df = pd.read_csv(PROCESSED_DATA_PATH)
        
    X = df[FEATURE_NAMES]
    y = df["label"]
    
    print(f"[*] Total dataset: {len(df)} samples ({len(y[y==0])} benign, {len(y[y==1])} malicious)")
    print(f"[*] Feature dimensions: {X.shape[1]} features in fixed contract ordering: {FEATURE_NAMES}")
    
    # Stratified Train/Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    print(f"[*] Train set: {len(X_train)} samples ({sum(y_train==0)} benign, {sum(y_train==1)} malicious)")
    print(f"[*] Test set:  {len(X_test)} samples ({sum(y_test==0)} benign, {sum(y_test==1)} malicious)")
    
    # Initialize Random Forest with reproducible seed & balanced weights
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    
    clf.fit(X_train, y_train)
    
    # Evaluate on held-out test set
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_proba))
    
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]
    
    # Feature Importances (Presented as Model Feature Importance / Association)
    importances = clf.feature_importances_
    feat_importance_list = [
        {"feature": name, "importance": round(float(imp), 4)}
        for name, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    ]
    
    metrics = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
            "matrix": [[tn, fp], [fn, tp]]
        },
        "feature_importances": feat_importance_list
    }
    
    # Build complete metadata documentation
    metadata = {
        "model_name": "ThreatLens Random Forest URL Classifier",
        "model_version": MODEL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "algorithm": "RandomForestClassifier(n_estimators=100, max_depth=15, class_weight='balanced', random_state=42)",
        "dataset_name": "ThreatLens Curated Benchmark Dataset (Tranco Top Sites + PhishTank + URLhaus)",
        "dataset_source": "Tranco Top Sites (Open License), PhishTank Verified Feed (CC-BY-NC), URLhaus (CC0)",
        "dataset_license": "Combined Open Research & Educational Dataset",
        "sample_count": len(df),
        "benign_count": int(sum(y == 0)),
        "malicious_count": int(sum(y == 1)),
        "train_count": len(X_train),
        "test_count": len(X_test),
        "feature_count": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "metrics": metrics
    }
    
    # Save Model Artifacts
    joblib.dump(clf, MODEL_PATH)
    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
        
    print("\n" + "=" * 60)
    print("         THREATLENS ML MODEL EVALUATION RESULTS         ")
    print("=" * 60)
    print(f"  Model Saved To:     {MODEL_PATH}")
    print(f"  Metadata Saved To:  {METADATA_PATH}")
    print(f"  Accuracy:           {acc * 100:.2f}%")
    print(f"  Precision:          {prec * 100:.2f}%")
    print(f"  Recall:             {rec * 100:.2f}%")
    print(f"  F1-Score:           {f1 * 100:.2f}%")
    print(f"  ROC-AUC:            {roc_auc * 100:.2f}%")
    print(f"  Confusion Matrix:   TP={tp}, TN={tn}, FP={fp}, FN={fn}")
    print("=" * 60)
    print("Top 5 Contributing Model Features:")
    for item in feat_importance_list[:5]:
        print(f"  - {item['feature']:<28} (importance: {item['importance']:.4f})")
    print("=" * 60 + "\n")
    
    return clf, metadata


if __name__ == "__main__":
    train_model()
