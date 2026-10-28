from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from .common import EvaluationOutcome, SeverityLevel

class BaselineSnapshot(BaseModel):
    snapshot_id: str = Field(..., description="Unique baseline ID, e.g. BASELINE-PROD-GATEWAY-01")
    name: str = Field(..., description="Baseline descriptive title")
    created_at: str
    target_id: str # capture_id or scenario_id
    policy_id: str
    policy_version: str
    compliance_score_pct: float
    finding_outcomes: Dict[str, str] = Field(default_factory=dict, description="Mapping rule_id -> outcome")
    observed_parameters: Dict[str, Any] = Field(default_factory=dict, description="Observed cryptographic transforms and versions")
    metadata: Dict[str, Any] = Field(default_factory=dict)

class DriftDifference(BaseModel):
    rule_id: str
    category: str
    title: str
    severity: SeverityLevel
    baseline_outcome: Optional[str] = None
    current_outcome: Optional[str] = None
    difference_type: str = Field(..., description="NEW_VIOLATION, RESOLVED_VIOLATION, NEWLY_UNKNOWN, CHANGED_POLICY_RULE, UNCHANGED")
    is_regression: bool = Field(False, description="True if a previously passing or acceptable state became failing")
    technical_explanation: str
    evidence_reference: str
    recommended_regression_tests: List[str] = Field(default_factory=list)

class DriftReport(BaseModel):
    drift_report_id: str
    baseline_id: str
    baseline_name: str
    current_target_id: str
    generated_at: str
    total_rules_compared: int
    new_violations_count: int
    resolved_violations_count: int
    newly_unknown_count: int
    regression_detected: bool
    differences: List[DriftDifference] = Field(default_factory=list)
    summary_verdict: str
