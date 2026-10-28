import pytest
from backend.app.services.audit_service import audit_service

def test_tamper_evident_audit_chain_and_detection():
    # Verify chain is intact initially
    res_initial = audit_service.verify_chain()
    assert res_initial.chain_intact is True

    # Record new event
    rec = audit_service.record_event(
        event_type="TEST_EVENT",
        entity_id="ENTITY-123",
        entity_type="TEST",
        data={"action": "test_verification", "status": "ok"}
    )
    assert rec.sequence_number > 0
    assert rec.record_hash is not None

    # Verify chain remains intact
    res_after = audit_service.verify_chain()
    assert res_after.chain_intact is True

    # Artificially tamper with a record
    idx_to_tamper = len(audit_service.chain) - 1
    audit_service.simulate_tampering_for_test(idx_to_tamper, {"action": "malicious_modification"})

    # Verification MUST detect tampering
    res_tampered = audit_service.verify_chain()
    assert res_tampered.chain_intact is False
    assert idx_to_tamper in res_tampered.tampered_indices

def test_audit_chain_truncation_detection():
    from backend.app.services.audit_service import AuditService
    fresh_service = AuditService()
    # Add 3 records
    for i in range(3):
        fresh_service.record_event(
            event_type=f"EVENT_{i}",
            entity_id=f"ENT-{i}",
            entity_type="TEST",
            data={"counter": i}
        )
    assert len(fresh_service.chain) == 4 # genesis + 3
    final_hash = fresh_service.chain[-1].record_hash

    # Normal verification passes
    assert fresh_service.verify_chain(expected_final_hash=final_hash, expected_total_records=4).chain_intact is True

    # Truncate the chain by deleting the latest record
    fresh_service.chain.pop()

    # Verification against expected checkpoint MUST detect truncation
    res_truncated = fresh_service.verify_chain(expected_final_hash=final_hash, expected_total_records=4)
    assert res_truncated.chain_intact is False
    assert "Truncation or root hash mismatch" in res_truncated.verification_message

