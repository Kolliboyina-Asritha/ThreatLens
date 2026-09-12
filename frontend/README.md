# ThreatLens AI — Frontend (Phase 1)

A responsive, cybersecurity-themed React web application for inspecting suspicious URLs and visualizing threat indicators.

---

## Features

* **Authentication UI**: Register and Sign In with validation feedback and session persistence via silent token refresh.
* **Interactive Threat Scanner**: Real-time analysis animation, heuristic risk meter (0–100), risk badge classification (`SAFE`, `SUSPICIOUS`, `HIGH_RISK`).
* **Explainable Indicators**: Color-coded breakdown of detected security anomalies (IP address, plaintext HTTP, excessive subdomains, suspicious keywords, obfuscated encoding, etc.).
* **Feature Inspection Grid**: Granular view of parsed structural properties (protocol, lengths, dot counts, parameter counts, and flags).
* **Scan Audit History**: Paginated ledger of past scans with instant detail navigation and record deletion.
* **Investigation View**: Dedicated forensic view for in-depth inspection of past scan results.
* **Token Security**: Zero tokens stored in `localStorage` or `sessionStorage`. Access tokens reside exclusively in application memory.

---

## Setup & Running

```bash
cd frontend
npm install
npm run dev
```

The frontend will start at `http://localhost:5173`.
API requests to `/api` are automatically proxied to the backend at `http://localhost:5000`.
