"""
ThreatLens AI - Model Evaluation & Reporting Script
Loads trained Random Forest model and generates evaluation report.
"""

import os
import sys
import json
import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.schemas import FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "random_forest.joblib")
METADATA_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "model_metadata.json")
PROCESSED_DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "processed", "dataset_features.csv")


def evaluate_model():
    """Runs evaluation report on trained model."""
    if not os.path.exists(MODEL_PATH):
        print("[!] Model file not found. Running training first...")
        from training.train import train_model
        train_model()
        
    model = joblib.load(MODEL_PATH)
    with open(METADATA_PATH, "r") as f:
        metadata = json.load(f)
        
    df = pd.read_csv(PROCESSED_DATA_PATH)
    X = df[FEATURE_NAMES]
    y = df["label"]
    
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)[:, 1]
    
    print("\n" + "=" * 65)
    print("      THREATLENS AI - MODEL PERFORMANCE EVALUATION REPORT       ")
    print("=" * 65)
    print(f"Dataset:         {metadata['dataset_name']}")
    print(f"Total Samples:   {len(df)} ({sum(y==0)} Benign, {sum(y==1)} Malicious)")
    print(f"Schema:          {metadata['schema_version']} ({len(FEATURE_NAMES)} features)")
    print(f"Algorithm:       {metadata['algorithm']}")
    print("-" * 65)
    print("Test Set Metrics (from stratified 20% holdout):")
    m = metadata["metrics"]
    print(f"  • Accuracy:     {m['accuracy'] * 100:.2f}%")
    print(f"  • Precision:    {m['precision'] * 100:.2f}%")
    print(f"  • Recall:       {m['recall'] * 100:.2f}%")
    print(f"  • F1-Score:     {m['f1_score'] * 100:.2f}%")
    print(f"  • ROC-AUC:      {m['roc_auc'] * 100:.2f}%")
    print("-" * 65)
    cm = m["confusion_matrix"]
    print(f"Confusion Matrix: [TP={cm['true_positives']}, TN={cm['true_negatives']}, FP={cm['false_positives']}, FN={cm['false_negatives']}]")
    print("-" * 65)
    print("Model Feature Associations (Random Forest Gini Importance):")
    for item in m["feature_importances"][:8]:
        print(f"  • {item['feature']:<28}: {item['importance']:.4f}")
    print("=" * 65 + "\n")
    return metadata


if __name__ == "__main__":
    evaluate_model()
