# ThreatLens AI — Smart Browser Protection (Chrome Extension)

**Manifest V3 Browser Extension for ThreatLens AI**

Extends ThreatLens from **DETECT → ANALYZE → EXPLAIN** to **DETECT → ANALYZE → EXPLAIN → PROTECT**.

---

## Features

- **Real-Time Navigation Interception**: Uses Chrome Manifest V3 service worker and `webNavigation` API to inspect links before navigation.
- **Deterministic Multi-Engine Scoring**: Communicates with the ThreatLens backend API to evaluate URLs against Heuristics, Random Forest ML, VirusTotal Threat Intel, and User Protection Policy.
- **Separated User-Controlled Enforcement**:
  - `ASK_ME`: Displays security warning, allows user conscious choice.
  - `BALANCED`: Automatically blocks high-risk threats ($\ge 70$), warns on suspicious ($30\text{--}69$).
  - `STRICT`: Blocks high-risk and enforces warnings on all anomalies.
  - `CUSTOM`: Enforces custom user-configured thresholds.
- **Reversible Interstitials**:
  - `pages/warning.html`: Suspicious URL warning with Dual-Tier explanations (Technical + Simple + Why It Matters), `[← Return to Safety]`, `[Trust & Allow Site]`, and `[Proceed Anyway / Override]`.
  - `pages/blocked.html`: High-risk block interstitial with forensic threat breakdown, `[← Return to Safety]`, `[Open Dashboard]`, and conscious override.
- **Zero Secrets**: No backend secrets, API keys, or JWT signing keys are stored in the client extension.

---

## How to Install & Load in Chrome / Edge / Brave

1. Open **Google Chrome** (or Edge/Brave) and navigate to `chrome://extensions/`.
2. Enable **Developer mode** using the toggle switch in the top right.
3. Click the **Load unpacked** button in the top left.
4. Select the `ThreatLens/extension` directory:
   ```
   C:\Users\asrit\.gemini\antigravity\scratch\ThreatLens\extension
   ```
5. The **ThreatLens AI — Smart Browser Protection** extension is now installed.

---

## Configuration

1. Click on the extension icon or right-click $\rightarrow$ **Options**.
2. Ensure the Backend URL is set to `http://localhost:5000`.
3. Paste your ThreatLens authentication token (or log in via the web application).
4. Click **Save Settings**.
