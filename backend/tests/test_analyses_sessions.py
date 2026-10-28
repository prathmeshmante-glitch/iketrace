from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.capture_service import capture_service
from backend.app.repositories.session_repository import session_repository

client = TestClient(app)

PCAP_DIR = Path("sample-data/captures")
SECURE_PCAP = PCAP_DIR / "secure_ikev2_baseline.pcap"
PROHIBITED_PCAP = PCAP_DIR / "prohibited_3des_md5.pcap"


def test_session_aware_analysis_lifecycle_and_isolation():
    # 1. Ingest Capture A (Secure baseline)
    res_a = capture_service.analyze_capture("test-cap-a", "ikev2_secure_baseline.pcap", SECURE_PCAP)
    assert res_a.capture_id == "test-cap-a"
    assert res_a.file_hash_sha256 != "unknown"
    assert len(res_a.file_hash_sha256) == 64

    # 2. Ingest Capture B (Prohibited baseline)
    res_b = capture_service.analyze_capture("test-cap-b", "ikev1_prohibited_3des_md5.pcap", PROHIBITED_PCAP)
    assert res_b.capture_id == "test-cap-b"
    assert res_b.file_hash_sha256 != "unknown"
    assert res_a.file_hash_sha256 != res_b.file_hash_sha256

    # 3. Test GET /api/analyses
    resp = client.get("/api/analyses")
    assert resp.status_code == 200
    analyses = resp.json()
    ids = [a["capture_id"] for a in analyses]
    assert "test-cap-a" in ids
    assert "test-cap-b" in ids

    # 4. Test GET /api/analyses/{id}/protocols
    resp_proto_a = client.get("/api/analyses/test-cap-a/protocols")
    assert resp_proto_a.status_code == 200
    proto_data_a = resp_proto_a.json()
    assert proto_data_a["analysis_id"] == "test-cap-a"
    assert proto_data_a["ike_packets"] > 0
    assert len(proto_data_a["packets"]) > 0

    # 5. Evaluate Policy on Capture A (Should pass CNSA/NIST rules)
    eval_resp_a = client.post("/api/analyses/test-cap-a/evaluations", json={"policy_id": "POL-DEF-NIST-SP800-77"})
    assert eval_resp_a.status_code == 200
    eval_data_a = eval_resp_a.json()
    assert eval_data_a["target_id"] == "test-cap-a"
    score_a = eval_data_a["compliance_score_pct"]
    assert score_a > 80.0
    assert eval_data_a["failed_count"] == 0

    # 6. Evaluate Policy on Capture B (Prohibited - Should fail)
    eval_resp_b = client.post("/api/analyses/test-cap-b/evaluations", json={"policy_id": "POL-DEF-NIST-SP800-77"})
    assert eval_resp_b.status_code == 200
    eval_data_b = eval_resp_b.json()
    assert eval_data_b["target_id"] == "test-cap-b"
    score_b = eval_data_b["compliance_score_pct"]
    assert score_b < 50.0
    assert eval_data_b["failed_count"] > 0

    # 7. Verify Absolute Session Isolation in Findings
    findings_a = client.get("/api/analyses/test-cap-a/findings").json()
    findings_b = client.get("/api/analyses/test-cap-b/findings").json()
    
    assert findings_a["analysis_id"] == "test-cap-a"
    assert findings_b["analysis_id"] == "test-cap-b"
    assert findings_a["compliance_score_pct"] == score_a
    assert findings_b["compliance_score_pct"] == score_b
    assert findings_a["failed_count"] == 0
    assert findings_b["failed_count"] > 0

    # 8. Verify Crypto Inventory Isolation
    inv_a = client.get("/api/analyses/test-cap-a/crypto-inventory").json()
    inv_b = client.get("/api/analyses/test-cap-b/crypto-inventory").json()

    assert inv_a["target_id"] == "test-cap-a"
    assert inv_b["target_id"] == "test-cap-b"
    assert inv_a["pqc_readiness_score_pct"] != inv_b["pqc_readiness_score_pct"]

    # 9. Verify Real Traffic Flow Features Extraction
    tf_a = client.get("/api/analyses/test-cap-a/traffic-flows").json()
    assert tf_a["analysis_id"] == "test-cap-a"
    assert tf_a["flow_count"] > 0
    assert tf_a["is_real_capture"] is True
    assert len(tf_a["flows"]) == tf_a["flow_count"]
    first_flow = tf_a["flows"][0]
    assert first_flow["packet_count"] > 0
    assert first_flow["total_bytes"] > 0

    # 10. Verify Reports Association and Isolation
    rep_gen_a = client.post("/api/reports/generate", json={
        "title": "Assessment for Capture A",
        "target_id": "test-cap-a",
        "target_type": "CAPTURE",
        "policy_id": "POL-DEF-NIST-SP800-77"
    }).json()
    assert rep_gen_a["target_id"] == "test-cap-a"

    reports_a = client.get("/api/analyses/test-cap-a/reports").json()
    reports_b = client.get("/api/analyses/test-cap-b/reports").json()
    assert len(reports_a) >= 1
    assert any(r["title"] == "Assessment for Capture A" for r in reports_a)
    assert not any(r["title"] == "Assessment for Capture A" for r in reports_b)
