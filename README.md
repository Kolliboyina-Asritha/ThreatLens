# ThreatLens AI — Explainable URL Threat Intelligence & Protection Platform

**ThreatLens AI** is an explainable cybersecurity platform designed to detect suspicious and potentially malicious URLs through multi-layered inspection, structural feature extraction, machine learning classification, external threat intelligence, generative AI triage briefings, and user-controlled real-time browser protection.

---

## Project Status: Phase 3 — User-Controlled Protection + Browser Security + Human-Friendly Explanations (Complete)

In **Phase 3**, ThreatLens extends from **DETECT → ANALYZE → EXPLAIN** to:

$$\text{DETECT} \longrightarrow \text{ANALYZE} \longrightarrow \text{EXPLAIN} \longrightarrow \text{PROTECT}$$

### Core Design Principles
1. **ThreatLens Detects & Recommends; The User Controls Enforcement**: The backend analysis engines output risk scores and recommendations (`ALLOW`, `WARN`, `BLOCK`), while enforcement action (`ALLOW`, `WARN`, `BLOCK`) is governed by the user's active policy (`ASK_ME`, `BALANCED`, `STRICT`, `CUSTOM`).
2. **Deterministic Precedence**: 
   $$\text{Blocklist Match} \succ \text{Allowlist Match} \succ \text{User Override} \succ \text{Policy Mode Evaluation}$$
3. **Dual-Tier Human Explanations**: Every security indicator and policy action provides 3 clear views:
   - **Technical Forensic**: Exact protocol/structural violation.
   - **In Simple Words**: Jargon-free explanation for non-technical users.
   - **Why It Matters**: Concrete real-world risk impact (e.g. credential theft, interception, domain spoofing).
4. **AI Never Determines Risk**: Generative AI (LLM) only explains evidence; it never computes, alters, or inflates numerical risk scores or enforces decisions.
5. **Reversible Decisions**: Users can undo blocklist/allowlist entries, unblock sites, or temporarily override warnings at any time.
6. **Chrome Manifest V3 Extension (`extension/`)**: Real-time navigation interception, interactive warning/blocked interstitial pages, popup status monitor, and options management with zero stored secrets.

---

## 3-Phase Roadmap

| Phase | Description | Status |
| :--- | :--- | :--- |
| **Phase 1: Core Foundation** | Pure string URL parsing, 40+ feature extraction, heuristic engine (9 modular rules), bounded scoring, React UI, Node API, MongoDB persistence, in-memory JWT. | **Complete & Verified** |
| **Phase 2: Intelligence + AI Explanation** | Random Forest ML microservice, 18-feature schema contract (`threatlens_features_v1.0`), VirusTotal threat intel & caching, unified risk fusion with dynamic renormalization, Gemini LLM explanation layer, 7-stage timeline. | **Complete & Verified** |
| **Phase 3: User-Controlled Protection & Extension** | User protection policies (`ASK_ME`, `BALANCED`, `STRICT`, `CUSTOM`), reversible allowlist/blocklist, audit ledger, Chrome Manifest V3 browser extension, and Dual-Tier explanations. | **Complete & Verified** |

---

## Complete Architecture Flow

```text
Chrome Extension (Manifest V3)           React Frontend (Vite + Tailwind CSS)
      │ (webNavigation Intercept)                     │ (In-Memory Access Token / HttpOnly Cookie)
      └──────────────────────┬────────────────────────┘
                             ▼
              Node.js + Express API Gateway (Port 5000)
                             │
                             ▼
              1. URL Validation & Normalization (RFC 3986, SSRF Safe)
                             │
                             ▼
              2. URL Feature Extraction (40+ Metrics & 18-Feature ML Vector)
                             │
                             ├──► 3. Heuristic Engine (9 Modular Rules) ──────────────► Score S_heur ∈ [0, 100]
                             │
                             ├──► 4. Python FastAPI ML Service (Port 8000) ───────────► Score S_ml   ∈ [0, 100]
                             │       (Random Forest Classifier, threatlens_v1.0)
                             │
                             └──► 5. Threat Intelligence (VirusTotal + MongoDB Cache) ─► Score S_ti   ∈ [0, 100]
                                                                                           │
                             ┌─────────────────────────────────────────────────────────────┘
                             ▼
              6. Unified Risk Fusion Engine
                 Composite Score = w1' * S_heur + w2' * S_ml + w3' * S_ti  (Dynamic ∑ w_i' = 1.0)
                 Recommendation: ALLOW (0–29) | WARN (30–69) | BLOCK (70–100)
                             │
                             ▼
              7. Generative AI Explanation Service (Gemini 1.5 Flash / Deterministic Fallback)
                 (Dual-Tier Structured Briefing: Technical + In Simple Words + Why It Matters)
                             │
                             ▼
              8. Protection Decision Engine (User-Controlled Policy Layer)
                 Precedence: Blocklist ➔ Allowlist ➔ User Override ➔ Policy Mode (ASK_ME/BALANCED/STRICT/CUSTOM)
                 Action: ALLOW | WARN | BLOCK
                             │
                             ▼
              MongoDB Ledger (User-Isolated Scans, Protection Policies, Security Events & 24h Threat Intel Cache)
```

---

## Protection Policy Modes

| Policy Mode | Behavior for Safe (<30) | Behavior for Suspicious (30–69) | Behavior for High Risk (>=70) | Description |
| :--- | :--- | :--- | :--- | :--- |
| **ASK_ME** *(Default)* | `ALLOW` | `WARN` (Prompt User) | `WARN` (Prompt User) | Never blocks automatically. Recommends action and lets the user choose. |
| **BALANCED** *(Recommended)* | `ALLOW` | `WARN` (Prompt User) | `BLOCK` (Automatic Block) | Blocks high-risk threats, prompts on suspicious indicators. |
| **STRICT** | `ALLOW` | `WARN` (Prompt User) | `BLOCK` (Automatic Block) | Enforces maximum security; strictly prevents navigation to dangerous sites. |
| **CUSTOM** | `ALLOW` ($\le \text{allowMax}$) | `WARN` ($\text{allowMax} < s \le \text{warnMax}$) | `BLOCK` ($> \text{warnMax}$) | User-defined custom numerical risk boundaries ($\text{allowMax} < \text{warnMax}$). |

---

## Multi-Engine Score Normalization & Risk Fusion Formulas

### 1. Engine Score Normalizations ($S_i \in [0, 100]$)

* **Heuristics**:
  $$S_{\text{heur}} = \min\left(100, \, \sum_{j} \text{points}_j\right)$$
  *(Sum of triggered rule weights from 9 modular heuristic indicators).*

* **Machine Learning**:
  $$S_{\text{ml}} = \text{round}\left(P(\text{malicious}) \times 100\right)$$
  *(Probability score output by the Random Forest classifier).*

* **Threat Intelligence (VirusTotal)**:
  $$S_{\text{ti}} = \begin{cases} 
  100 & \text{if } \text{malicious} \ge 3 \\ 
  \min\left(100, \, \text{malicious} \times 20 + \text{suspicious} \times 10\right) & \text{if } 1 \le \text{malicious} \le 2 \\ 
  \min\left(50, \, \text{suspicious} \times 10\right) & \text{if } \text{malicious} = 0 \text{ and } \text{suspicious} > 0 \\ 
  0 & \text{if } \text{malicious} = 0 \text{ and } \text{suspicious} = 0 
  \end{cases}$$

### 2. Base Fusion Weights & Dynamic Renormalization

* **Base Weights**: $w_{\text{heur}} = 0.35, \, w_{\text{ml}} = 0.40, \, w_{\text{ti}} = 0.25$ ($\sum w_i = 1.0$).
* **Dynamic Renormalization**: If any engine $k$ is unavailable or unconfigured, active engine weights are mathematically scaled:
  $$w_i' = \frac{w_i}{\sum_{j \in \text{Active}} w_j} \quad \implies \quad \sum_{i \in \text{Active}} w_i' = 1.0$$
* **Final Fused Risk Score**:
  $$\text{Risk Score} = \text{clamp}\left(\sum_{i \in \text{Active}} w_i' \cdot S_i, \, 0, \, 100\right)$$

---

## Machine Learning Model & Benchmark Dataset

* **Schema Contract**: `threatlens_features_v1.0` (18 deterministic lexical & structural dimensions).
* **Dataset**: Real-world curated benchmark combining Tranco Top Domains (Benign, 200 URLs) and PhishTank/URLhaus (Malicious, 164 URLs). Total 364 URLs with 0 synthetic samples.
* **Classifier**: Scikit-Learn `RandomForestClassifier` (100 estimators, max depth 15, balanced class weights, random_state 42).
* **Holdout Evaluation Metrics**:
  * Accuracy: **100.00%**
  * Precision: **100.00%**
  * Recall: **100.00%**
  * F1-Score: **100.00%**
  * Confusion Matrix: TP=33, TN=40, FP=0, FN=0.

---

## Project Structure

```text
ThreatLens/
├── backend/
│   ├── src/
│   │   ├── config/          # DB connection, constants (9 heuristic rules, fusion weights), env validation
│   │   ├── controllers/     # Auth, Scan, and Protection controllers
│   │   ├── middleware/      # Auth guard, rate limiters, logger, centralized error handler
│   │   ├── models/          # User, Scan, ThreatIntelCache, ProtectionPolicy, SecurityEvent
│   │   ├── routes/          # Auth, Scan, and Protection routes (/api/protection/*)
│   │   ├── services/        # urlAnalyzer, heuristicEngine, mlService, threatIntelService, 
│   │   │                    # riskFusionEngine, llmService, protectionDecisionEngine, dualTierExplanation
│   │   ├── utils/           # API response helpers, IP address validators
│   │   └── validators/      # Zod validation schemas
│   ├── tests/               # 86 Automated tests across 16 suites
│   ├── package.json
│   └── README.md
│
├── ml-service/
│   ├── app/                 # FastAPI service, 18-feature extractor, schemas
│   ├── data/                # Raw & processed Tranco/PhishTank benchmark sets
│   ├── models/              # random_forest.joblib and model_metadata.json
│   ├── training/            # Dataset prep, training, and evaluation scripts
│   ├── tests/               # Pytest suite (4 tests passing 100%)
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/      # RiskGauge, RiskBreakdownCard, MLAnalysisCard, ThreatIntelCard, 
│   │   │                    # AIExplanationCard, ProtectionDecisionCard, DualTierExplainer, IndicatorList
│   │   ├── pages/           # ScannerPage, ScanDetailsPage, HistoryPage, ProtectionDashboardPage, Auth pages
│   │   ├── services/        # scanService, protectionService, authService
│   │   ├── context/         # AuthContext
│   │   └── App.jsx          # Protected route declarations (/protection, /scanner, /history, /scans/:id)
│   └── package.json
│
├── extension/               # Chrome Manifest V3 Browser Protection Extension
│   ├── background.js        # Service worker intercepting navigation & querying /api/protection/evaluate
│   ├── manifest.json        # Manifest V3 configuration
│   ├── pages/               # Reversible interstitial warning.html & blocked.html
│   ├── popup/               # popup.html & popup.js with tab threat indicator
│   ├── options/             # options.html & options.js for API endpoint & token configuration
│   ├── shared/              # explainerData.js and style.css
│   └── README.md
│
└── README.md
```

---

## Quick Setup & Execution

### 1. Prerequisites
* **Node.js**: v18.0.0 or higher
* **Python**: v3.10 or higher
* **MongoDB**: Running on `mongodb://127.0.0.1:27017`

### 2. Start the ML Service (Terminal 1)
```powershell
cd ml-service
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
FastAPI runs at `http://localhost:8000`.

### 3. Start the Backend API (Terminal 2)
```powershell
cd backend
npm install
npm run dev
```
Express API runs at `http://localhost:5000`.

### 4. Start the Frontend UI (Terminal 3)
```powershell
cd frontend
npm install
npm run dev
```
React UI runs at `http://localhost:5173`.

### 5. Load the Chrome Browser Extension
1. In Google Chrome / Brave / Edge, open `chrome://extensions/`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select `ThreatLens/extension`.

---

## Automated Verification & Testing

### Backend Test Suite (86 tests across 16 suites)
```powershell
cd backend
npm test
```
All 86 tests pass with 0 failures:
* 9 Modular heuristic indicator rules
* 18-Feature ML contract transformation & graceful offline handling
* Threat intelligence score normalization & MongoDB 24h caching
* Risk fusion engine dynamic weight renormalization & 0–100 boundary clamping
* Protection Decision Engine precedence rules & policy mode evaluations (`ASK_ME`, `BALANCED`, `STRICT`, `CUSTOM`)
* Reversible allowlist & blocklist management
* SecurityEvent append-only audit logging & statistics aggregation
* End-to-end multi-tenant security isolation (User A vs User B access boundaries)

### ML Service Pytest Suite (4 tests)
```powershell
cd ml-service
python -m pytest
```
All 4 Python tests pass with 100% success rate.
