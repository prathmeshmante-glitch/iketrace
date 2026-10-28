from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from .policy import PolicyEvaluationReport
from .drift import DriftReport
from .crypto_inventory import CryptoInventoryReport
from .audit import AuditVerificationResult

class AssessmentReport(BaseModel):
    report_id: str
    title: str
    generated_at: str
    assessor: str = "IKETrace Automated Security Engine"
    target_id: str
    target_type: str # "CAPTURE", "SCENARIO"
    executive_summary: str
    overall_verdict: str # "COMPLIANT", "VIOLATIONS_FOUND", "INSUFFICIENT_EVIDENCE", "SECURITY_REGRESSION"
    policy_report: Optional[PolicyEvaluationReport] = None
    drift_report: Optional[DriftReport] = None
    crypto_inventory: Optional[CryptoInventoryReport] = None
    audit_chain_verified: bool = True
    audit_hash: str
    reproducibility_fingerprint: str
    methodology_limitations: List[str] = Field(default_factory=list)
    markdown_content: Optional[str] = None
