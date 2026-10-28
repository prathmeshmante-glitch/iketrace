import json
import hashlib
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from ..schemas.audit import AuditRecord, AuditVerificationResult

class AuditService:
    def __init__(self):
        self.chain: List[AuditRecord] = []
        self._genesis()

    def _genesis(self) -> None:
        """Create initial genesis block in the local tamper-evident audit chain."""
        genesis_data = {
            "system": "IKETrace Security Assurance Lab",
            "event": "GENESIS_AUDIT_INITIALIZATION",
            "version": "1.0.0",
            "created_at": "2026-01-01T00:00:00Z"
        }
        canonical_json = json.dumps(genesis_data, sort_keys=True, separators=(',', ':'))
        h = hashlib.sha256(("0"*64 + ":" + canonical_json).encode('utf-8')).hexdigest()

        rec = AuditRecord(
            record_id="AUDIT-GENESIS",
            sequence_number=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="GENESIS",
            actor="system",
            entity_id="ROOT",
            entity_type="SYSTEM",
            canonical_data_json=canonical_json,
            record_hash=h,
            previous_hash="0"*64
        )
        self.chain.append(rec)

    def record_event(
        self,
        event_type: str,
        entity_id: str,
        entity_type: str,
        data: Dict[str, Any],
        actor: str = "security_engineer"
    ) -> AuditRecord:
        canonical_json = json.dumps(data, sort_keys=True, separators=(',', ':'), default=str)
        prev_hash = self.chain[-1].record_hash if self.chain else "0"*64
        seq = len(self.chain)

        # Hash(previous_hash + ":" + canonical_json)
        payload_to_hash = f"{prev_hash}:{canonical_json}".encode('utf-8')
        record_hash = hashlib.sha256(payload_to_hash).hexdigest()

        rec = AuditRecord(
            record_id=f"AUD-{uuid.uuid4().hex[:10].upper()}",
            sequence_number=seq,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            actor=actor,
            entity_id=entity_id,
            entity_type=entity_type,
            canonical_data_json=canonical_json,
            record_hash=record_hash,
            previous_hash=prev_hash
        )
        self.chain.append(rec)
        return rec

    def verify_chain(
        self,
        expected_final_hash: Optional[str] = None,
        expected_total_records: Optional[int] = None
    ) -> AuditVerificationResult:
        tampered_indices: List[int] = []
        tampered_ids: List[str] = []
        truncation_detected = False

        if expected_total_records is not None and len(self.chain) != expected_total_records:
            truncation_detected = True

        if expected_final_hash is not None:
            final_h = self.chain[-1].record_hash if self.chain else ""
            if final_h != expected_final_hash:
                truncation_detected = True

        for idx, rec in enumerate(self.chain):
            if idx == 0:
                expected_prev = "0"*64
            else:
                expected_prev = self.chain[idx-1].record_hash

            if rec.previous_hash != expected_prev:
                tampered_indices.append(idx)
                tampered_ids.append(rec.record_id)
                continue

            # Recompute hash
            recomputed = hashlib.sha256(f"{rec.previous_hash}:{rec.canonical_data_json}".encode('utf-8')).hexdigest()
            if recomputed != rec.record_hash:
                tampered_indices.append(idx)
                tampered_ids.append(rec.record_id)

        intact = len(tampered_indices) == 0 and not truncation_detected
        if truncation_detected:
            msg = f"CRITICAL: Truncation or root hash mismatch detected! Expected {expected_total_records} records with final hash {expected_final_hash}, found {len(self.chain)}."
        elif intact:
            msg = "Audit log integrity verified. All cryptographic SHA-256 hash links are valid."
        else:
            msg = f"CRITICAL: Cryptographic integrity failure! Tampered record(s) detected at indices {tampered_indices}."

        return AuditVerificationResult(
            verified_at=datetime.now(timezone.utc).isoformat(),
            total_records=len(self.chain),
            chain_intact=intact,
            tampered_indices=tampered_indices,
            tampered_record_ids=tampered_ids,
            verification_message=msg
        )

    def get_records(self) -> List[AuditRecord]:
        return list(self.chain)

    def simulate_tampering_for_test(self, index: int, new_data: Dict[str, Any]) -> None:
        """Testing utility: artificially corrupts a record's data to prove tamper detection works."""
        if 0 <= index < len(self.chain):
            self.chain[index].canonical_data_json = json.dumps(new_data, sort_keys=True)


audit_service = AuditService()
