from pathlib import Path
import pytest
from backend.app.services.capture_service import CaptureService
from backend.app.services.policy_engine import policy_engine
from backend.app.schemas.common import EvaluationOutcome

def test_policy_evaluation_pass_on_secure_baseline():
    service = CaptureService()
    pcap_path = Path("sample-data/captures/secure_ikev2_baseline.pcap")
    analysis = service.analyze_capture("test-secure-01", "secure.pcap", pcap_path)

    report = policy_engine.evaluate_capture(analysis, "POL-DEF-NIST-SP800-77")
    assert report.total_rules > 0
    assert report.failed_count == 0, f"Expected 0 failures on secure baseline, got {report.failed_count}"
    assert report.passed_count >= 3
    assert report.compliance_score_pct == 100.0

def test_policy_evaluation_fail_on_prohibited_suite():
    service = CaptureService()
    pcap_path = Path("sample-data/captures/prohibited_3des_md5.pcap")
    analysis = service.analyze_capture("test-bad-01", "bad.pcap", pcap_path)

    report = policy_engine.evaluate_capture(analysis, "POL-DEF-NIST-SP800-77")
    assert report.failed_count > 0, "Expected failures on 3DES and MD5"

    encr_rule = next(r for r in report.results if r.category == "ENCRYPTION")
    assert encr_rule.outcome == EvaluationOutcome.FAIL
    assert "ENCR_3DES" in str(encr_rule.observed_value)

    integ_rule = next(r for r in report.results if r.category == "INTEGRITY")
    assert integ_rule.outcome == EvaluationOutcome.FAIL

def test_policy_evaluation_unknown_on_missing_evidence():
    from backend.app.schemas.capture import CaptureAnalysisResult
    empty_analysis = CaptureAnalysisResult(
        capture_id="empty-01",
        filename="empty.pcap",
        file_size_bytes=0,
        uploaded_at="",
        total_packets=0,
        ike_packets=0,
        esp_packets=0,
        other_packets=0,
        session_count=0,
        parse_completeness_pct=0.0,
        sessions=[],
        packets=[],
        evidence_items=[]
    )
    report = policy_engine.evaluate_capture(empty_analysis, "POL-DEF-NIST-SP800-77")
    assert report.unknown_count > 0
    encr_rule = next(r for r in report.results if r.category == "ENCRYPTION")
    assert encr_rule.outcome == EvaluationOutcome.UNKNOWN

def test_policy_evaluation_cnsa_compliant_pass():
    service = CaptureService()
    pcap_path = Path("sample-data/captures/cnsa_2_0_compliant.pcap")
    analysis = service.analyze_capture("test-cnsa-01", "cnsa.pcap", pcap_path)

    report = policy_engine.evaluate_capture(analysis, "POL-DEF-CNSA-2.0")
    assert report.total_rules > 0
    assert report.failed_count == 0, f"Expected 0 failures on CNSA compliant baseline, got {report.failed_count}"
    assert report.passed_count >= 4
    assert report.compliance_score_pct == 100.0

def test_incomplete_handshake_yields_unknown_on_negotiated_rules():
    service = CaptureService()
    pcap_path = Path("sample-data/captures/incomplete_handshake_offer_only.pcap")
    analysis = service.analyze_capture("test-half-01", "half.pcap", pcap_path)

    report = policy_engine.evaluate_capture(analysis, "POL-DEF-NIST-SP800-77")
    # Verify that version passes (since header was observed)
    ver_rule = next(r for r in report.results if r.category == "PROTOCOL_VERSION")
    assert ver_rule.outcome == EvaluationOutcome.PASS

    # Verify that encryption, PRF, and DH evaluate to UNKNOWN because responder never responded
    encr_rule = next(r for r in report.results if r.category == "ENCRYPTION")
    assert encr_rule.outcome == EvaluationOutcome.UNKNOWN
    assert "incomplete" in encr_rule.technical_reasoning.lower()

    prf_rule = next(r for r in report.results if r.category == "PRF")
    assert prf_rule.outcome == EvaluationOutcome.UNKNOWN

    dh_rule = next(r for r in report.results if r.category == "DH_GROUP")
    assert dh_rule.outcome == EvaluationOutcome.UNKNOWN

