# PhishGuard — Phishing Detection Browser Assistant
> **SIH 2026 | Problem Code: CYB02 (Blockchain & Cybersecurity)**  
> Explainable, client-side phishing detection and risk analysis assistant.

---

## 📌 Project Overview
PhishGuard is an explainable browser security assistant designed to protect users against phishing attacks, credential harvesting, fake login forms, and malicious domain anomalies.

Instead of operating as an opaque blocklist, PhishGuard provides a **transparent breakdown of risk indicators** (e.g., suspicious TLD, unusual subdomain depth, brand spoofing signals, insecure forms) with actionable warnings.

---

## 🏗 System Architecture & Roadmap
The project follows a 12-phase modular roadmap:

1. **Phase 1 (Current):** Basic Chromium Extension (Manifest V3, Popup UI, Background Worker, Content Script).
2. **Phase 2:** URL & Domain Analyzer (HTTPS/HTTP, IP addresses, symbol inspection, keyword heuristics).
3. **Phase 3:** Transparent Risk Scoring Engine (0–100 score calculation with explainable reasons).
4. **Phase 4:** Warning & Status UI (Safe, Suspicious, High-Risk visual alerts & actions).
5. **Phase 5:** Page & DOM Analysis (Form inspection, password field detection, brand impersonation).
6. **Phase 6:** Node.js + Express Backend REST API.
7. **Phase 7:** MongoDB Integration (Detection logging, telemetry & user reports).
8. **Phase 8:** React Analytics Dashboard (Trends, charts & reporting).
9. **Phase 9:** External Threat Intelligence / Reputation Integration with safe fallbacks.
10. **Phase 10:** Lightweight ML Classification Layer.
11. **Phase 11:** Performance, Evaluation & Testing (Precision, Recall, Latency).
12. **Phase 12:** SIH Presentation & Deployment.

---

## 🚀 Phase 1 Setup & Testing

### How to load into Chrome:
1. Open Google Chrome (or any Chromium browser like Brave, Edge).
2. Navigate to `chrome://extensions` in the address bar.
3. Toggle on **Developer mode** in the top-right corner.
4. Click the **Load unpacked** button in the top-left corner.
5. Select the `phishing-detection/extension` directory.
6. The **PhishGuard** extension icon will now appear in your browser toolbar (pin it for quick access).

### Testing Phase 1:
- Visit any website (e.g., `https://google.com`, `https://github.com`, `https://wikipedia.org`).
- Click the PhishGuard extension icon.
- The popup displays the extracted domain, full URL, active connection status with the background service worker, and user feedback actions.

---

## 📁 Repository Structure
```
phishing-detection/
├── extension/             # Chromium Manifest V3 Extension
│   ├── manifest.json      # Extension manifest configuration
│   ├── popup.html         # Premium dark UI popup layout
│   ├── popup.css          # Glassmorphism design tokens & styles
│   ├── popup.js           # Active tab extraction & background messaging
│   ├── content.js         # Page DOM signal collector
│   ├── background.js      # Central service worker & event hub
│   └── assets/
│       └── icons/         # 16px, 32px, 48px, 128px icons
├── backend/               # Express REST API (Phase 6)
├── dashboard/             # React Admin/Analytics Dashboard (Phase 8)
├── ml/                    # Machine Learning training & evaluation (Phase 10)
└── README.md
```
