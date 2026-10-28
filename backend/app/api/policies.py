from fastapi import APIRouter, HTTPException
from typing import List
from pydantic import BaseModel

from ..schemas.policy import PolicyDefinition, PolicyEvaluationReport
from ..services.policy_engine import policy_engine
from ..services.capture_service import capture_service
from ..services.audit_service import audit_service
from ..repositories.session_repository import session_repository

router = APIRouter(prefix="/policies", tags=["Policies"])

class EvaluateRequest(BaseModel):
    capture_id: str
    policy_id: str = "POL-DEF-NIST-SP800-77"

@router.get("", response_model=List[PolicyDefinition])
def list_policies():
    return policy_engine.list_policies()

@router.get("/{policy_id}", response_model=PolicyDefinition)
def get_policy(policy_id: str):
    pol = policy_engine.get_policy(policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found.")
    return pol

@router.post("", response_model=PolicyDefinition)
def create_policy(policy: PolicyDefinition):
    policy_engine.register_policy(policy)
    audit_service.record_event(
        event_type="POLICY_REGISTERED",
        entity_id=policy.policy_id,
        entity_type="POLICY",
        data={"name": policy.name, "rules_count": len(policy.rules)}
    )
    return policy

@router.post("/evaluate", response_model=PolicyEvaluationReport)
def evaluate_policy(req: EvaluateRequest):
    analysis = capture_service.get_analysis(req.capture_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Capture ID {req.capture_id} not found.")

    report = policy_engine.evaluate_capture(analysis, req.policy_id)
    try:
        session_repository.save_evaluation(report)
    except Exception:
        pass

    audit_service.record_event(
        event_type="POLICY_EVALUATED",
        entity_id=req.capture_id,
        entity_type="EVALUATION",
        data={
            "policy_id": req.policy_id,
            "compliance_score": report.compliance_score_pct,
            "passed": report.passed_count,
            "failed": report.failed_count,
        }
    )
    return report
