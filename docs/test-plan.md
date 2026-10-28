# IKETrace Test Plan & Verification Strategy

## 1. Quality Assurance Philosophy

IKETrace enforces a rigorous verification methodology:
1. **Zero Hallucinated Metrics**: Every finding, score, and evaluation metric must be deterministically calculated from real evidence or explicitly labelled synthetic lab runs.
2. **Defensive Isolation**: Tests must run completely offline without external network requests or paid AI APIs.
3. **Cross-Layer Validation**: Protocol parsing, policy engine, ML training, and API layers are verified through independent, decoupled test suites.

---

## 2. Test Suites & Coverage Matrix

| Test Suite | File Location | Scope & Assertions |
|---|---|---|
| **API Endpoints** | `backend/tests/test_api.py` | Health check, policy listing, scenario execution, drift comparison, traffic privacy training, and audit chain verification via `httpx`/`TestClient`. |
| **Audit Chaining & Tamper Detection** | `backend/tests/test_audit.py` | Canonical JSON serialization, sequential SHA-256 hash chaining, and detection of arbitrary record tampering. |
| **Configuration Drift & Regression** | `backend/tests/test_drift.py` | Baseline creation, detection of newly introduced violations, resolved issues, and regression detection. |
| **Machine Learning Leakage Prevention** | `backend/tests/test_ml.py` | Feature extraction, `GroupShuffleSplit` session boundary isolation (zero session leakage between train/test), and metric calculation. |
| **Protocol Parser** | `backend/tests/test_parser.py` | Direct PCAP parsing: clean IKEv2 baseline (`secure_ikev2_baseline.pcap`), prohibited suites (`prohibited_3des_md5.pcap`), and safe failure handling on corrupted PCAP files (`malformed_corrupt.pcap`). |
| **Deterministic Policy Engine** | `backend/tests/test_policy.py` | Strict four-outcome verification (`PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE`) against CNSA 2.0 and NIST SP 800-77 baselines. |
| **Defensive Scenarios** | `backend/tests/test_scenarios.py` | Full execution of all 8 standard defensive test scenarios (`SCEN-01` through `SCEN-08`). |
| **Frontend Production Build** | `frontend/` (`tsc -b && vite build`) | Strict TypeScript 7 type checking, JSX transformations, bundle optimization, and zero compiler warnings/errors. |
| **Frontend Linting** | `frontend/` (`oxlint`) | Fast static code analysis, 0 errors across 20 source files. |

---

## 3. Core Acceptance Criteria Checklist

- [x] **Secure Baseline produces PASS**: Verified in `test_policy_evaluation_pass_on_secure_baseline` and `SCEN-01`.
- [x] **Prohibited Algorithms produce FAIL**: Verified in `test_policy_evaluation_fail_on_prohibited_suite` and `SCEN-02`.
- [x] **Incomplete Handshake produces UNKNOWN**: Verified in `test_policy_evaluation_unknown_on_missing_evidence` and `SCEN-03`.
- [x] **Non-applicable rules produce NOT_APPLICABLE**: Verified on protocol version differences.
- [x] **Tampering with Audit Record is Detected**: Verified in `test_tamper_evident_audit_chain_and_detection`.
- [x] **Corrupted PCAP fails safely**: Verified in `test_parse_malformed_capture_safe_failure` and `SCEN-07`.
- [x] **Zero Session Leakage in ML**: Verified in `test_ml_workflow_zero_leakage_and_metrics`.
- [x] **100% Offline Capability**: Runs with zero cloud or external API dependencies.

---

## 4. Test Execution Instructions (Windows PowerShell)

### Run Backend Pytest Suite:
```powershell
# Set Python path to current workspace
$env:PYTHONPATH="."

# Execute all tests with detailed verbosity
.\backend\.venv\Scripts\pytest.exe backend/tests -v
```

### Run Frontend Static Verification & Build:
```powershell
cd frontend

# Run Oxlint static analyzer
npm run lint

# Run TypeScript compilation and Vite production build
npm run build
```
