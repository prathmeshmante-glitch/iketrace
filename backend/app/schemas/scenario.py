from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from .common import EvidenceItem
from .policy import PolicyEvaluationReport

class ScenarioAssertion(BaseModel):
    assertion_id: str
    target_property: str
    expected_outcome: str # e.g. "PASS", "FAIL", "UNKNOWN", "PARSER_WARNING"
    description: str

class ScenarioDefinition(BaseModel):
    scenario_id: str = Field(..., description="Unique scenario ID, e.g. SCEN-01-SECURE-BASELINE")
    name: str = Field(..., description="Descriptive scenario name")
    category: str = Field(..., description="Scenario category: BASELINE, NEGATIVE, ROBUSTNESS, REGRESSION, INCONSISTENCY")
    description: str = Field(..., description="Defensive testing purpose and expected behavior")
    initial_conditions: Dict[str, Any] = Field(default_factory=dict)
    synthetic_input_data: Dict[str, Any] = Field(..., description="Synthetic packet negotiation or config payload")
    expected_assertions: List[ScenarioAssertion] = Field(default_factory=list)
    reproducibility_notes: str = Field("Isolated synthetic test harness. Does not interact with external networks.")

class ScenarioAssertionResult(BaseModel):
    assertion_id: str
    passed: bool
    expected: str
    observed: str
    details: str

class ScenarioResult(BaseModel):
    scenario_id: str
    scenario_name: str
    category: str
    executed_at: str
    is_synthetic: bool = Field(True, description="Always marked True to guarantee simulated data is never presented as real capture")
    status: str = Field(..., description="PASSED or FAILED")
    all_assertions_met: bool
    assertion_results: List[ScenarioAssertionResult] = Field(default_factory=list)
    generated_evidence: List[EvidenceItem] = Field(default_factory=list)
    policy_report: Optional[PolicyEvaluationReport] = None
    execution_log: List[str] = Field(default_factory=list)
