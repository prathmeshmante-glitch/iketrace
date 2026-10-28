from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class AuditRecord(BaseModel):
    record_id: str
    sequence_number: int
    timestamp: str
    event_type: str # e.g. "CAPTURE_UPLOADED", "POLICY_EVALUATED", "SCENARIO_EXECUTED", "BASELINE_CREATED", "REPORT_GENERATED"
    actor: str = "local_security_engineer"
    entity_id: str
    entity_type: str
    canonical_data_json: str
    record_hash: str # SHA-256 of canonical payload
    previous_hash: str # SHA-256 of preceding audit record in chain

class AuditVerificationResult(BaseModel):
    verified_at: str
    total_records: int
    chain_intact: bool
    tampered_indices: List[int] = Field(default_factory=list)
    tampered_record_ids: List[str] = Field(default_factory=list)
    verification_message: str
    cryptographic_guarantees: str = Field(
        "Cryptographic SHA-256 hash chaining detects unauthorized modifications to stored records "
        "relative to a trusted anchor. Notice: Hash integrity does not validate whether untrusted external "
        "inputs were factual when originally captured, nor does a local chain alone substitute for external digital signatures."
    )
