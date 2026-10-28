from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from .common import EvaluationOutcome, SeverityLevel, EvidenceSufficiency

class PolicyRule(BaseModel):
    rule_id: str = Field(..., description="Unique rule ID, e.g. POL-IKE-VER-01")
    category: str = Field(..., description="Category: PROTOCOL_VERSION, ENCRYPTION, INTEGRITY, PRF, DH_GROUP, REPLAY_PROTECTION, PQC_MIGRATION")
    title: str = Field(..., description="Short human-readable title")
    description: str = Field(..., description="Detailed description of security requirement")
    severity: SeverityLevel = Field(SeverityLevel.HIGH, description="Default severity if violated")
    allowed_values: List[str] = Field(default_factory=list, description="Permitted algorithm names or values")
    prohibited_values: List[str] = Field(default_factory=list, description="Explicitly forbidden values")
    min_key_length: Optional[int] = Field(None, description="Minimum key length in bits")
    min_dh_group: Optional[int] = Field(None, description="Minimum DH group number")
    require_esn: Optional[bool] = Field(None, description="Require Extended Sequence Numbers")
    rationale: str = Field(..., description="Cryptographic rationale and NIST/RFC reference")
    remediation: str = Field(..., description="Actionable remediation steps")
    limitations: Optional[str] = Field(None, description="Scope and limitations of this rule")

class PolicyDefinition(BaseModel):
    policy_id: str = Field(..., description="Policy ID, e.g. POL-DEF-CNSA-2.0 or POL-DEF-NIST-SP800-77")
    name: str = Field(..., description="Policy display name")
    version: str = Field("1.0.0", description="Policy version string")
    author: str = Field("IKETrace Security Baseline", description="Policy author or standard body")
    description: str = Field(..., description="Policy objective and scope")
    rules: List[PolicyRule] = Field(default_factory=list)

class RuleEvaluationResult(BaseModel):
    rule_id: str
    policy_version: str
    category: str
    title: str
    outcome: EvaluationOutcome
    severity: SeverityLevel
    expected_property: str
    observed_value: Any
    evidence_ids: List[str] = Field(default_factory=list)
    evidence_sufficiency: EvidenceSufficiency
    technical_reasoning: str
    remediation_recommendation: str
    limitations: Optional[str] = None

class PolicyEvaluationReport(BaseModel):
    policy_id: str
    policy_name: str
    policy_version: str
    evaluated_at: str
    target_id: str # capture_id or scenario_id
    total_rules: int
    passed_count: int
    failed_count: int
    unknown_count: int
    not_applicable_count: int
    compliance_score_pct: float
    results: List[RuleEvaluationResult] = Field(default_factory=list)
