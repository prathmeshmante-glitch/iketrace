# IKETrace — VPN Security Assurance Lab

> **"See what your VPN negotiated. Prove what your security policy guarantees."**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19.0+-61DAFB.svg)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6.svg)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-8.0+-646CFF.svg)](https://vitejs.dev/)
[![Offline First](https://img.shields.io/badge/Security-100%25%20Offline-success.svg)](#)

---

## 1. Overview

**IKETrace** is a professional defensive cybersecurity workbench designed for network security architects, cryptographic engineers, and compliance auditors. It analyzes authorized IPsec/IKE packet captures and configuration files to verify declared cryptographic baselines, detect configuration drift, evaluate post-quantum readiness, and explore metadata privacy leakage—**without decrypting protected payload traffic or recovering private keys**.

Built with a bold, high-contrast **Neo-Brutalism** design system, IKETrace provides empirical evidence linking every security conclusion to specific packet bytes and proposal structures.

```
       +-------------------------------------------------------------+
       |                         IKETrace                            |
       |  +--------------------+             +--------------------+  |
       |  |  Packet Ingestion  |             |   Policy Engine    |  |
       |  |   (Scapy/TShark)   |             | (CNSA 2.0 / NIST)  |  |
       |  +---------+----------+             +---------+----------+  |
       |            |                                  |             |
       |            +----------------+-----------------+             |
       |                             |                               |
       |                             v                               |
       |       +---------------------------------------------+       |
       |       |  Deterministic Verdicts: PASS/FAIL/UNKNOWN  |       |
       |       +---------------------+-----------------------+       |
       |                             |                               |
       |       +---------------------+-----------------------+       |
       |       |                     |                       |       |
       |       v                     v                       v       |
       |  +----------+         +-----------+          +-----------+  |
       |  | PQC Lab  |         | Drift Lab |          | ML Lab    |  |
       |  +----------+         +-----------+          +-----------+  |
       +-------------------------------------------------------------+
```

---

## 2. Core Capabilities

### 🔍 Protocol Dissection & Evidence Ingestion
- Ingests **PCAP and PCAPNG** captures with magic-byte pre-validation and a 25MB safety upload limit.
- Pure Python native **Scapy** dissector extracting IKEv1/IKEv2 proposals, transforms (Encryption, PRF, Integrity, DH Groups), Key Exchange payloads, and visible ESP metadata.
- Graceful degradation and optional **TShark** adapter support.
- Rigorous 5-tier evidence taxonomy: `DIRECT_OBSERVATION`, `DETERMINISTIC_DERIVATION`, `SUPPLIED_CONFIGURATION`, `CONTROLLED_LAB_EXPERIMENT`, and `UNKNOWN_UNSUPPORTED`.

### ⚖️ Deterministic Policy Engine
- Evaluates evidence strictly using deterministic rule sets without probabilistic or LLM-based hallucination.
- Standard embedded baselines:
  - **Commercial National Security Algorithm (CNSA) 2.0**: AES-256-GCM, SHA-384 PRF, DH Group 21.
  - **NIST SP 800-77 Rev 1**: AES-128/256, SHA-256/384, DH Group $\ge$ 14.
- Four canonical outcomes: **PASS**, **FAIL**, **UNKNOWN**, and **NOT_APPLICABLE**. *Incomplete evidence is never treated as secure.*

### 🧪 Defensive Scenario Lab
- One-click execution of **8 isolated synthetic test scenarios**:
  - `SCEN-01`: Secure IKEv2 baseline.
  - `SCEN-02`: Deprecated 3DES/MD5 cipher suite rejection.
  - `SCEN-03`: Incomplete handshake yielding `UNKNOWN`.
  - `SCEN-04`: Declared CNSA policy vs actual AES-128 negotiation mismatch.
  - `SCEN-05`: Configuration drift introducing regression.
  - `SCEN-06`: Regression correction and verification.
  - `SCEN-07`: Corrupted/malformed capture safe failure handling.
  - `SCEN-08`: Inconsistent multi-proposal configuration.

### 📉 Configuration Drift & Regression Detection
- Captures verified assessment baseline snapshots.
- Compares new network evidence against baselines to flag **newly introduced violations**, resolved issues, and configuration changes.

### 🛡️ Post-Quantum Cryptographic Inventory
- Catalogs all active and configured algorithms.
- Evaluates algorithmic vulnerability against **Shor's Algorithm** (complete compromise of classical asymmetric key exchange) and **Grover's Algorithm** (effective key halving for symmetric ciphers).
- Computes an empirical **PQC Readiness Score (0-100%)** with recommended migration paths toward CNSA 2.0 and ML-KEM.

### 🔬 Encrypted Traffic Privacy Lab (ML)
- Demonstrates what metadata eavesdroppers can infer **without decrypting ESP payloads**.
- Extracts statistical flow features: packet length distributions, inter-arrival time variance, burstiness, and flow duration.
- Trains a Random Forest classifier using **`GroupShuffleSplit` across session IDs**, strictly preventing cross-session data leakage.
- Generates live confusion matrices, per-class F1-scores, and Gini feature importances.

### 🔗 Evidence Graph & Tamper-Evident Audit
- Interactive **React Flow** evidence graph visually connecting captures, packets, sessions, rules, and findings.
- **SHA-256 sequential hash chain** ensuring all audit logs are cryptographically verifiable and resistant to retroactive tampering.
- Exportable Markdown security assessment reports with cryptographic SHA-256 fingerprints.

---

## 3. Quick Start Guide (Windows PowerShell)

### Prerequisites
- Python 3.11+ (Python 3.14 recommended)
- Node.js 18+ & npm

### Step 1: Clone & Setup Backend
```powershell
git clone https://github.com/your-org/iketrace.git
cd iketrace

# Create and activate Python virtual environment
py -m venv backend/.venv
.\backend\.venv\Scripts\Activate.ps1

# Install backend dependencies
pip install -r backend/requirements.txt
```

### Step 2: Run Backend Server
```powershell
# Set python path and start FastAPI dev server
$env:PYTHONPATH="."
.\backend\.venv\Scripts\uvicorn.exe backend.app.main:app --reload --host 127.0.0.1 --port 8000
```
*API Swagger documentation available at: `http://localhost:8000/docs`*

### Step 3: Setup & Run Frontend
In a new terminal:
```powershell
cd iketrace/frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```
*Open application in your browser at: `http://localhost:5173`*

---

## 4. Automated Testing & Verification

Run the complete test suite locally:

```powershell
# Run backend pytest suite (15 automated unit & integration tests)
$env:PYTHONPATH="."
.\backend\.venv\Scripts\pytest.exe backend/tests -v

# Run frontend static code analyzer
cd frontend
npm run lint

# Run frontend TypeScript compilation & production build
npm run build
```

---

## 5. Repository Structure

```
iketrace/
├── backend/
│   ├── app/
│   │   ├── api/            # REST API route endpoints
│   │   ├── core/           # Configuration & constants
│   │   ├── ml/             # Feature extraction & training
│   │   ├── schemas/        # Pydantic v2 schemas
│   │   └── services/       # Dissectors, policy engine, drift, audit
│   ├── tests/              # 15 automated pytest suites
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/     # Neo-brutalism UI components
│   │   ├── pages/          # 12 application pages
│   │   ├── services/       # API client
│   │   └── types/          # Strict TypeScript definitions
│   ├── index.html
│   └── package.json
├── sample-data/
│   ├── captures/           # Deterministic PCAP test fixtures
│   └── generate_all_samples.py
├── docs/                   # Full technical documentation
│   ├── architecture.md
│   ├── security-model.md
│   ├── protocol-limitations.md
│   ├── ml-evaluation.md
│   ├── test-plan.md
│   ├── api-reference.md
│   └── demo-script.md
└── README.md
```

---

## 6. Security Guarantees & Non-Claims

1. **Defensive Only**: IKETrace does not generate attack traffic or exploit network endpoints.
2. **No Payload Decryption**: IKETrace does not claim to decrypt protected ESP payload traffic without authorized keylogs.
3. **No Hallucinated Verdicts**: Deterministic logic guarantees that security verdicts are reproducible and mathematically sound.
4. **Offline Resilience**: Operates 100% locally with zero cloud or telemetry dependencies.
