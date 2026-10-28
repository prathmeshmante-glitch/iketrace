# IKETrace 3-4 Minute Hackathon & Executive Demo Script

**Presenter Tagline**: *"See what your VPN negotiated. Prove what your security policy guarantees."*

---

## Act 1: The Baseline (0:00 – 0:45)
*Goal: Demonstrate empirical packet ingestion and deterministic compliance verification.*

1. **Open Overview Dashboard**:
   - Point out the Neo-Brutalism high-contrast design: *"IKETrace is an offline-first defensive security workbench for IPsec and IKE assurance."*
2. **Upload Secure Baseline Capture**:
   - Navigate to **Capture Upload** and select `sample-data/captures/secure_ikev2_baseline.pcap`.
   - Highlight the instantaneous dissection: 4 packets parsed, SHA-256 fingerprint verified, 1 IKEv2 session discovered.
3. **Inspect Session Details**:
   - Open **Session Explorer** to reveal direct evidence: `IKE_SA_INIT`, `AES_GCM_16 (256-bit)`, `HMAC_SHA384`, `Diffie-Hellman Group 19 (ECP-256)`.
4. **Evaluate Against CNSA 2.0**:
   - In **Policy Engine**, select `Commercial National Security Algorithm (CNSA) 2.0` and click **Evaluate Active Capture**.
   - Show the clean **PASS (100%)** verdict with all 5 cryptographic requirements satisfied.

---

## Act 2: Violation & Evidence Inspection (0:45 – 1:30)
*Goal: Demonstrate violation detection and granular evidence provenance.*

1. **Upload Non-Compliant Capture**:
   - Upload `sample-data/captures/prohibited_3des_md5.pcap`.
2. **Evaluate Policy**:
   - Run evaluation against `NIST SP 800-77`.
   - Watch the immediate visual status change to **FAIL (CRITICAL)**.
3. **Inspect Finding Provenance**:
   - Click the finding in **Finding Inspector**.
   - Show the exact evidence link: *"Rule POL-NIST-ENCR-ALG failed because Packet #1 contained Transform ID 3 (3DES-CBC). Evidence method: DIRECT_OBSERVATION. Provenance confidence: 100%."*
   - Note the distinction: *"We never guess what was negotiated. Every conclusion links to explicit packet bytes."*

---

## Act 3: One-Click Defensive Scenario Lab (1:30 – 2:15)
*Goal: Showcase defensive test automation across 8 real-world failure modes.*

1. **Open Scenario Lab**:
   - Show the suite of 8 isolated defensive test scenarios (`SCEN-01` to `SCEN-08`).
2. **Execute Single-Click Test Suite**:
   - Click **Run All Scenarios**.
   - Watch all 8 scenarios execute deterministically in milliseconds.
3. **Highlight `SCEN-03: Incomplete Evidence`**:
   - Point to `SCEN-03`: *"Notice this test returned `UNKNOWN` rather than `PASS`. In defensive security, incomplete evidence must never be assumed secure. IKETrace preserves uncertainty."*

---

## Act 4: Drift & Regression Detection (2:15 – 3:00)
*Goal: Prove that unauthorized configuration modifications are caught automatically.*

1. **Establish Baseline Snapshot**:
   - Navigate to **Configuration Drift** and click **Create Baseline from Current**.
2. **Compare Against Changed Capture**:
   - Compare the baseline against the deprecated 3DES capture.
   - Point to the **Regression Detected** banner:
     - 1 New Violation introduced (`POL-NIST-ENCR-ALG`).
     - Clear visual diff: `AES_GCM_16` $\to$ `3DES_CBC`.
   - *"Security teams can instantly verify whether a firewall update introduced an unauthorized cipher downgrade."*

---

## Act 5: Post-Quantum Readiness & Metadata Privacy (3:00 – 3:45)
*Goal: Demonstrate future-proof cryptography and empirical machine learning.*

1. **Open Post-Quantum Inventory**:
   - Show the **PQC Readiness Score (75%)**.
   - Point out the algorithmic asset breakdown:
     - Symmetric AES-256 is **Grover-Resistant** (retains 128-bit quantum security).
     - DH Group 19 is flagged as **Shor-Vulnerable**, with recommended migration to ML-KEM-768 or hybrid key exchange.
2. **Open Traffic Privacy Lab**:
   - Click **Train Privacy Classifier**.
   - Explain the ML integrity: *"We train a Random Forest on flow metadata—inter-arrival times, packet length variance, and burst ratios. We use GroupShuffleSplit across sessions to guarantee ZERO data leakage."*
   - Show the live confusion matrix distinguishing VoIP, Bulk Transfer, and Web traffic with $>90\%$ accuracy.
   - Reinforce: *"This proves what an adversary can infer without decrypting a single byte of ESP ciphertext."*

---

## Act 6: Tamper-Evident Audit & Report Export (3:45 – 4:00)
*Goal: Close with enterprise assurance, audit integrity, and reporting.*

1. **Open Audit Logs & Verify Hash Chain**:
   - View the sequential SHA-256 hash chain.
   - Click **Verify Audit Integrity** $\to$ *"Cryptographic Audit Log: VALID. All 14 records verified."*
2. **Generate Assessment Report**:
   - Navigate to **Report Export** and click **Download Markdown Report**.
   - Show the executive summary, methodology limitations, finding citations, and cryptographic fingerprint.
3. **Closing Statement**:
   - *"IKETrace runs 100% locally and offline without paid APIs, proving what your security policy guarantees."*
