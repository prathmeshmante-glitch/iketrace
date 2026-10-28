# IKETrace REST API Reference

Base URL: `http://localhost:8000/api/v1`

All responses use JSON format. Date-time fields follow ISO-8601 formatting.

---

## 1. System Health & Metadata

### `GET /health`
Returns system status, active version, and parser adapter capabilities.

**Response `200 OK`**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "tshark_available": false,
  "scapy_available": true,
  "pcap_upload_limit_mb": 25
}
```

---

## 2. Capture Ingestion & Dissection

### `POST /captures/upload`
Uploads and parses a PCAP or PCAPNG packet capture file. Enforces magic byte verification and a 25MB limit.

**Request**: `multipart/form-data` with `file: Binary`

**Response `200 OK`**:
```json
{
  "capture_id": "cap-20261028-123456",
  "filename": "secure_ikev2_baseline.pcap",
  "file_size_bytes": 1420,
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "packet_count": 4,
  "sessions_count": 1,
  "completeness_score": 1.0,
  "parse_warnings": [],
  "sessions": [
    {
      "session_id": "ses-ikev2-init-01",
      "initiator_ip": "192.168.1.100",
      "responder_ip": "198.51.100.1",
      "ike_version": "IKEv2",
      "exchange_type": "IKE_SA_INIT",
      "packet_count": 2,
      "negotiated_transforms": {
        "encryption": "AES_GCM_16",
        "key_length": 256,
        "prf": "HMAC_SHA384",
        "dh_group": 19
      }
    }
  ]
}
```

**Errors**:
- `400 Bad Request`: Invalid file signature, corrupted magic bytes, or file exceeds 25MB.

---

## 3. Security Policy Engine

### `GET /policies`
Returns standard embedded security baselines (`POL-DEF-CNSA-2.0` and `POL-DEF-NIST-SP800-77`).

### `POST /policies/evaluate`
Deterministically evaluates parsed capture evidence against a specified policy definition.

**Request Body**:
```json
{
  "policy": {
    "policy_id": "POL-DEF-CNSA-2.0",
    "version": "1.0.0",
    "name": "Commercial National Security Algorithm (CNSA) 2.0",
    "rules": [...]
  },
  "capture": { ... }
}
```

**Response `200 OK`**:
```json
{
  "report_id": "eval-20261028-001",
  "policy_id": "POL-DEF-CNSA-2.0",
  "policy_version": "1.0.0",
  "overall_verdict": "PASS",
  "summary": {
    "total_rules": 5,
    "passed": 5,
    "failed": 0,
    "unknown": 0,
    "not_applicable": 0
  },
  "findings": [
    {
      "finding_id": "find-POL-CNSA-ENCR-GCM",
      "rule_id": "POL-CNSA-ENCR-GCM",
      "verdict": "PASS",
      "severity": "CRITICAL",
      "observed_value": "AES_GCM_16 (256-bit)",
      "technical_reasoning": "Observed algorithm meets CNSA 2.0 requirements.",
      "remediation": "No action needed."
    }
  ]
}
```

---

## 4. Defensive Scenario Lab

### `GET /scenarios`
Lists all 8 synthetic defensive scenarios (`SCEN-01` through `SCEN-08`).

### `POST /scenarios/{scenario_id}/run`
Executes an isolated, reproducible defensive scenario and returns detailed step assertions.

**Response `200 OK`**:
```json
{
  "scenario_id": "SCEN-01-SECURE-BASELINE",
  "executed_at": "2026-10-28T12:00:00Z",
  "execution_time_ms": 14.2,
  "passed": true,
  "observed_verdicts": {
    "POL-NIST-IKE-VER": "PASS",
    "POL-NIST-ENCR-ALG": "PASS"
  },
  "assertions": [
    {
      "rule_id": "POL-NIST-IKE-VER",
      "expected_verdict": "PASS",
      "actual_verdict": "PASS",
      "passed": true
    }
  ],
  "reproducibility": {
    "fixture_type": "SYNTHETIC_EVIDENCE",
    "deterministic_seed": 42
  }
}
```

---

## 5. Configuration Drift & Regression

### `POST /drift/baseline`
Creates a verified configuration baseline snapshot.

### `POST /drift/compare`
Compares a baseline against current capture evidence to identify newly introduced violations, resolved issues, and configuration drift.

**Response `200 OK`**:
```json
{
  "report_id": "drift-20261028-01",
  "baseline_id": "base-20261028-01",
  "current_capture_id": "cap-20261028-02",
  "drift_detected": true,
  "has_regression": true,
  "new_violations": [
    {
      "rule_id": "POL-NIST-ENCR-ALG",
      "previous_verdict": "PASS",
      "current_verdict": "FAIL",
      "reasoning": "Encryption algorithm degraded to 3DES-CBC."
    }
  ],
  "resolved_violations": [],
  "configuration_changes": [
    {
      "property": "negotiated_encryption",
      "baseline_value": "AES_GCM_16",
      "current_value": "3DES_CBC"
    }
  ]
}
```

---

## 6. Encrypted Traffic Privacy Lab

### `POST /traffic-privacy/train`
Extracts flow features and trains a Random Forest classifier using `GroupShuffleSplit` across sessions.

**Response `200 OK`**:
```json
{
  "model_name": "RandomForest-Metadata-Classifier",
  "trained_at": "2026-10-28T12:00:00Z",
  "train_samples": 70,
  "test_samples": 30,
  "metrics": {
    "accuracy": 0.933,
    "macro_f1": 0.931,
    "class_metrics": {
      "VoIP": { "precision": 1.0, "recall": 0.93, "f1": 0.96 },
      "Bulk_Transfer": { "precision": 0.94, "recall": 1.0, "f1": 0.97 },
      "Interactive_Web": { "precision": 0.88, "recall": 0.88, "f1": 0.88 }
    }
  },
  "feature_importance": [
    { "feature": "std_len", "importance": 0.32 },
    { "feature": "mean_iat", "importance": 0.24 }
  ],
  "confusion_matrix": {
    "labels": ["VoIP", "Bulk_Transfer", "Interactive_Web"],
    "matrix": [[14, 0, 1], [0, 15, 0], [1, 1, 14]]
  }
}
```

---

## 7. Cryptographic Inventory & PQC Readiness

### `POST /crypto-inventory/analyze`
Catalogs all cryptographic assets and evaluates quantum vulnerability against Shor's and Grover's algorithms.

**Response `200 OK`**:
```json
{
  "inventory_id": "inv-20261028-01",
  "generated_at": "2026-10-28T12:00:00Z",
  "pqc_readiness_score": 75.0,
  "pqc_verdict": "PARTIALLY_READY",
  "assets": [
    {
      "name": "AES-256-GCM",
      "algorithm_type": "ENCRYPTION",
      "status": "APPROVED",
      "quantum_vulnerability": "GROVER_RESISTANT",
      "pqc_migration_path": "Retain AES-256 (provides 128-bit post-quantum security)"
    },
    {
      "name": "Diffie-Hellman Group 19 (ECP-256)",
      "algorithm_type": "KEY_EXCHANGE",
      "status": "APPROVED",
      "quantum_vulnerability": "SHOR_VULNERABLE",
      "pqc_migration_path": "Migrate to ML-KEM-768 or CNSA 2.0 hybrid key exchange"
    }
  ]
}
```

---

## 8. Evidence Graph, Reports & Audit

### `POST /evidence-graph`
Generates React Flow nodes and edges connecting captures, sessions, packets, policy rules, and findings.

### `POST /reports/generate`
Generates a structured, exportable Markdown security assessment report with cryptographic hash fingerprints.

### `GET /audit/logs` & `POST /audit/verify`
Retrieves and validates the tamper-evident SHA-256 hash chain, returning `valid: true` or alerting on record corruption.
