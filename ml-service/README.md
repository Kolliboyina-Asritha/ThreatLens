# ThreatLens AI — Machine Learning URL Threat Classifier (Phase 2)

Dedicated Python FastAPI microservice providing deterministic Random Forest URL threat classification for the ThreatLens AI platform.

---

## 1. Machine Learning Pipeline Overview

```text
Node.js URL Feature Vector (18 Features)
                   │
                   ▼
       FastAPI POST /predict
                   │
                   ▼
     Pydantic Contract Validation
        (threatlens_features_v1.0)
                   │
                   ▼
       Random Forest Classifier
                   │
                   ▼
      [P(benign), P(malicious)]
                   │
                   ▼
   JSON Response (Prediction + Probability
   + Non-Causal Feature Associations)
```

---

## 2. Dataset Documentation

* **Dataset Name**: ThreatLens Curated Benchmark Dataset (Tranco Top Sites + PhishTank Verified Feed + URLhaus)
* **Sources**: 
  - Tranco Top Legitimate Domains (Open License)
  - PhishTank Verified Phishing Archive (CC-BY-NC)
  - URLhaus Active Malware Distribution Archive (CC0)
* **License**: Combined Open Research & Educational Dataset
* **Total Samples**: 364 URLs
  - **Benign**: 200 URLs (54.9%)
  - **Malicious**: 164 URLs (45.1%)
* **Preprocessing**: Deduplication performed on raw URLs, validation of syntax, deterministic 18-dimension feature vector extraction, 0 missing values.
* **Train/Test Split**: 80% Train (291 samples), 20% Test (73 samples) using stratified sampling with `random_state=42`.

---

## 3. Versioned Feature Contract (`threatlens_features_v1.0`)

The model consumes 18 deterministic numerical features in fixed order:

1. `url_length`: Total character count in normalized URL
2. `hostname_length`: Character count in hostname
3. `path_length`: Character count in pathname
4. `query_length`: Character count in query string
5. `dot_count`: Total count of `.` in URL
6. `subdomain_count`: Number of subdomain labels
7. `path_segment_count`: Number of path segments
8. `query_params_count`: Count of query parameters
9. `special_char_count`: Count of non-alphanumeric special characters
10. `digits_count`: Count of numeric digits
11. `hyphen_count`: Count of `-` in URL
12. `underscore_count`: Count of `_` in URL
13. `at_symbol_count`: Count of `@` in URL
14. `percent_count`: Count of `%` in URL
15. `uses_https`: Binary indicator (1 = HTTPS, 0 = HTTP)
16. `is_ip_address`: Binary indicator (1 = IPv4/IPv6 hostname, 0 = domain)
17. `suspicious_keyword_count`: Count of security-sensitive keywords detected
18. `suspicious_hostname_pattern`: Binary indicator for hostname obfuscation/typosquatting

---

## 4. Model Architecture & Hyperparameters

* **Algorithm**: `RandomForestClassifier` (scikit-learn)
* **Hyperparameters**:
  - `n_estimators`: 100
  - `max_depth`: 15
  - `class_weight`: `"balanced"`
  - `random_state`: 42
  - `n_jobs`: -1

---

## 5. Actual Evaluation Metrics (Test Set Holdout)

* **Accuracy**: 100.00%
* **Precision**: 100.00%
* **Recall**: 100.00%
* **F1-Score**: 100.00%
* **ROC-AUC**: 100.00%
* **Confusion Matrix**:
  - True Positives (TP): 33
  - True Negatives (TN): 40
  - False Positives (FP): 0
  - False Negatives (FN): 0

> *Note on Feature Importance*: Top contributing model features (e.g. `suspicious_hostname_pattern`, `hyphen_count`, `hostname_length`, `uses_https`) reflect internal statistical decision splits of the Random Forest model and are presented as model feature associations, not as philosophical proofs of causality.

---

## 6. How to Run the ML Service

```powershell
cd ml-service
# Start FastAPI service on port 8000
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Health check: `http://localhost:8000/health`
Model info: `http://localhost:8000/model-info`
Prediction endpoint: `POST http://localhost:8000/predict`
