from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from .common import ObservationProvenance, SeverityLevel

class CryptoAsset(BaseModel):
    asset_id: str
    category: str # "ENCRYPTION", "INTEGRITY", "PRF", "KEY_EXCHANGE", "PROTOCOL"
    algorithm_name: str
    key_length: Optional[int] = None
    compliance_status: str # "COMPLIANT", "DEPRECATED", "PROHIBITED", "PQC_EXPERIMENTAL"
    pqc_readiness: str # "VULNERABLE_CRQC", "QUANTUM_RESISTANT_SYMMETRIC", "HYBRID_POST_QUANTUM", "NOT_APPLICABLE"
    provenance: ObservationProvenance
    source_reference: str
    negotiated_or_configured: str # "CONFIRMED_NEGOTIATED", "PROPOSED_ONLY", "CONFIGURED_SUPPLIED"
    migration_priority: SeverityLevel # CRITICAL, HIGH, MEDIUM, LOW
    recommended_target: str
    transition_guidance: str

class CryptoInventoryReport(BaseModel):
    inventory_id: str
    target_id: str
    target_type: str # "CAPTURE", "CONFIGURATION", "SCENARIO"
    generated_at: str
    total_assets_inventoried: int
    compliant_assets_count: int
    deprecated_assets_count: int
    prohibited_assets_count: int
    quantum_vulnerable_assets_count: int
    pqc_readiness_score_pct: float
    assets: List[CryptoAsset] = Field(default_factory=list)
    migration_actions: List[Dict[str, str]] = Field(default_factory=list)
    caveats_and_unknowns: List[str] = Field(default_factory=list)
