from pathlib import Path
import pytest
from backend.app.services.capture_service import CaptureService
from backend.app.services.policy_engine import policy_engine
from backend.app.services.drift_engine import drift_engine

def test_drift_detection_and_regression():
    service = CaptureService()
    pcap_good = Path("sample-data/captures/secure_ikev2_baseline.pcap")
    pcap_bad = Path("sample-data/captures/prohibited_3des_md5.pcap")

    analysis_good = service.analyze_capture("drift-good", "good.pcap", pcap_good)
    analysis_bad = service.analyze_capture("drift-bad", "bad.pcap", pcap_bad)

    report_good = policy_engine.evaluate_capture(analysis_good, "POL-DEF-NIST-SP800-77")
    report_bad = policy_engine.evaluate_capture(analysis_bad, "POL-DEF-NIST-SP800-77")

    baseline = drift_engine.create_baseline("Test Baseline", report_good, "drift-good")
    drift_report = drift_engine.compare_drift(baseline.snapshot_id, report_bad)

    assert drift_report.regression_detected is True
    assert drift_report.new_violations_count > 0
    assert any(d.difference_type == "NEW_VIOLATION" for d in drift_report.differences)
