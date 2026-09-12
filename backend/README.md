# ThreatLens AI — Backend API (Phase 2)

The backend engine for **ThreatLens AI**, providing authentication, SSRF-safe URL feature extraction, a 9-rule modular heuristic detection engine, Random Forest ML integration, VirusTotal threat intelligence with MongoDB caching, multi-engine risk fusion with dynamic renormalization, and Gemini GenAI explanation generation.

---

## Architecture Flow

```text
HTTP Request (Client)
        ↓
Express Middleware (Helmet, CORS, RateLimit, Parsers, Logger)
        ↓
Authentication Middleware (Bearer JWT in-memory)
        ↓
Scan Controller (7-Stage Pipeline)
        ↓
Stage 1: URL Normalizer & Validator (RFC 3986, SSRF Safe)
        ↓
Stage 2: Feature Extractor (40+ Structural Metrics & 18-Feature Vector)
        ↓
Stage 3: Heuristic Detection Engine (9 Modular Rules) -> S_heur ∈ [0, 100]
        ↓
Stage 4: Python ML Microservice (FastAPI POST /predict) -> S_ml ∈ [0, 100]
        ↓
Stage 5: Threat Intelligence (VirusTotal v3 + Mongo Cache) -> S_ti ∈ [0, 100]
        ↓
Stage 6: Unified Risk Fusion Engine (Dynamic ∑ w_i' = 1.0) -> Fused Score [0, 100]
        ↓
Stage 7: AI Explanation Service (Gemini 1.5 Flash / Fallback)
        ↓
MongoDB Ledger (User Scans & ThreatIntelCache TTL)
        ↓
JSON Response
```

---

## 9 Modular Heuristic Rules

1. `NO_HTTPS` (15 pts): URL does not use HTTPS encryption.
2. `IP_ADDRESS_HOSTNAME` (35 pts): Hostname is a raw IPv4 or IPv6 address.
3. `SUSPICIOUS_KEYWORDS` (20 pts): Sensitive credential or account action keywords detected.
4. `EXCESSIVE_SUBDOMAINS` (20 pts): Hostname contains 4 or more subdomain labels.
5. `SUSPICIOUS_PERCENT_ENCODING` (15 pts): Heavy or nested percent-encoding indicative of obfuscation.
6. `EMBEDDED_AT_SYMBOL` (25 pts): Hostname confusion using the `@` delimiter.
7. `SUSPICIOUS_PORT` (20 pts): Non-standard HTTP/HTTPS network port.
8. `EXCESSIVE_URL_LENGTH` (10 pts): URL character length exceeds 75 characters.
9. `EXCESSIVE_HYPHENS` (10 pts): Hostname contains multiple hyphens indicative of typosquatting.

---

## Multi-Engine Risk Fusion Formula

* Base weights: $w_{\text{heur}} = 0.35, \, w_{\text{ml}} = 0.40, \, w_{\text{ti}} = 0.25$.
* Dynamic Renormalization:
  $$w_i' = \frac{w_i}{\sum_{j \in \text{Active}} w_j} \quad \implies \quad \sum_{i \in \text{Active}} w_i' = 1.0$$
* Composite Score:
  $$\text{Score} = \text{clamp}\left(\sum_{i \in \text{Active}} w_i' \cdot S_i, \, 0, \, 100\right)$$
* Classification Tiers:
  - `SAFE`: 0–30
  - `SUSPICIOUS`: 31–70
  - `HIGH_RISK`: 71–100

---

## API Endpoints

### Authentication
* `POST /api/auth/register` — Create new user account with hashed password
* `POST /api/auth/login` — Authenticate and receive in-memory access token & HttpOnly refresh cookie
* `POST /api/auth/refresh` — Issue fresh access token from HttpOnly refresh cookie
* `POST /api/auth/logout` — Invalidate refresh cookie
* `GET  /api/auth/me` — Retrieve current authenticated profile (Protected)

### URL Threat Scanner (Phase 2 Intelligence)
* `POST /api/scan/url` — Scan URL across all active engines (Protected, Rate-Limited)
* `GET  /api/scans` — Retrieve paginated scan history for the user (Protected)
* `GET  /api/scans/:id` — Retrieve full forensic investigation report with multi-engine breakdown and AI triage (Protected)
* `DELETE /api/scans/:id` — Delete a specific scan record (Protected)

### System
* `GET  /api/health` — Service operational health

---

## Running the Backend

```bash
cd backend
npm install
cp .env.example .env
npm run dev
```

### Running Tests
```bash
npm test
```
All 62 tests run across 12 test suites verifying heuristics, ML contract mapping, threat intel caching, risk fusion calculations, LLM triage, and security boundaries.
