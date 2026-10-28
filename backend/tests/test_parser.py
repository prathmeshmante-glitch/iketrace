from pathlib import Path
import pytest
from backend.app.services.protocol_parser import ScapyProtocolParser
from backend.app.services.capture_service import CaptureService

def test_parse_secure_baseline_pcap():
    parser = ScapyProtocolParser()
    pcap_path = Path("sample-data/captures/secure_ikev2_baseline.pcap")
    assert pcap_path.exists(), "Sample fixture secure_ikev2_baseline.pcap must exist"

    packets, warnings = parser.parse_capture(pcap_path)
    assert len(packets) >= 2, "Expected at least IKE request and response packets"
    assert len(warnings) == 0, f"Expected no parser warnings, got: {warnings}"

    # Verify first IKE packet
    ike_pkt = packets[0]
    assert ike_pkt.is_ike is True
    assert ike_pkt.ike_version == "IKEv2"
    assert ike_pkt.exchange_type == "IKE_SA_INIT"
    assert len(ike_pkt.proposals) >= 1

    prop = ike_pkt.proposals[0]
    transform_types = [t.transform_type for t in prop.transforms]
    assert "ENCR" in transform_types
    assert "PRF" in transform_types
    assert "D-H" in transform_types
    assert "ESN" in transform_types

    encr_tr = next(t for t in prop.transforms if t.transform_type == "ENCR")
    assert encr_tr.transform_name == "ENCR_AES_GCM_16"
    assert encr_tr.key_length == 256

def test_parse_prohibited_pcap():
    parser = ScapyProtocolParser()
    pcap_path = Path("sample-data/captures/prohibited_3des_md5.pcap")
    packets, warnings = parser.parse_capture(pcap_path)
    assert len(packets) >= 1
    ike_pkt = packets[0]
    names = [t.transform_name for prop in ike_pkt.proposals for t in prop.transforms]
    assert "ENCR_3DES" in names
    assert "AUTH_HMAC_MD5_96" in names

def test_parse_malformed_capture_safe_failure():
    parser = ScapyProtocolParser()
    pcap_path = Path("sample-data/captures/malformed_corrupt.pcap")
    # Must not raise unhandled exception
    packets, warnings = parser.parse_capture(pcap_path)
    assert len(warnings) > 0 or len(packets) > 0

def test_capture_service_filename_sanitization_and_cleanup():
    service = CaptureService()
    # Test directory traversal attack payload in filename
    malicious_filename = "../../../../../etc/passwd_evil.pcap"
    dummy_pcap_header = b"\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x01"

    cap_id, target_path = service.save_temp_capture(malicious_filename, dummy_pcap_header)

    # Verify target path is strictly within the designated capture_dir
    from backend.app.core.config import settings
    assert target_path.parent.resolve() == settings.capture_dir.resolve()
    assert ".." not in target_path.name
    assert target_path.exists()

    # Verify cleanup removes file
    service.cleanup_temp_capture(target_path)
    assert not target_path.exists()

