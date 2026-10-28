from fastapi import APIRouter, HTTPException
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

from ..schemas.drift import BaselineSnapshot, DriftReport
from ..schemas.policy import PolicyEvaluationReport
from ..services.drift_engine import drift_engine
from ..services.policy_engine import policy_engine
from ..services.capture_service import capture_service
from ..services.audit_service import audit_service

router = APIRouter(prefix="/drift", tags=["Drift"])

class CreateBaselineRequest(BaseModel):
    name: str
    capture_id: str
    policy_id: str = "POL-DEF-NIST-SP800-77"
    metadata: Optional[Dict[str, Any]] = None

class CompareDriftRequest(BaseModel):
    baseline_id: str
    current_capture_id: str
    policy_id: Optional[str] = None

@router.get("/baselines", response_model=List[BaselineSnapshot])
def list_baselines():
    return drift_engine.list_baselines()

@router.get("/baselines/{baseline_id}", response_model=BaselineSnapshot)
def get_baseline(baseline_id: str):
    b = drift_engine.get_baseline(baseline_id)
    if not b:
        raise HTTPException(status_code=404, detail=f"Baseline {baseline_id} not found.")
    return b

@router.post("/baselines", response_model=BaselineSnapshot)
def create_baseline(req: CreateBaselineRequest):
    analysis = capture_service.get_analysis(req.capture_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Capture ID {req.capture_id} not found.")

    report = policy_engine.evaluate_capture(analysis, req.policy_id)
    baseline = drift_engine.create_baseline(
        name=req.name,
        policy_report=report,
        target_id=req.capture_id,
        observed_parameters={"ike_packets": analysis.ike_packets, "sessions": analysis.session_count},
        metadata=req.metadata
    )

    audit_service.record_event(
        event_type="BASELINE_CREATED",
        entity_id=baseline.snapshot_id,
        entity_type="BASELINE",
        data={"name": baseline.name, "target_id": req.capture_id, "score": baseline.compliance_score_pct}
    )
    return baseline

@router.post("/compare", response_model=DriftReport)
def compare_drift(req: CompareDriftRequest):
    baseline = drift_engine.get_baseline(req.baseline_id)
    if not baseline:
        raise HTTPException(status_code=404, detail=f"Baseline {req.baseline_id} not found.")

    curr_analysis = capture_service.get_analysis(req.current_capture_id)
    if not curr_analysis:
        raise HTTPException(status_code=404, detail=f"Current capture {req.current_capture_id} not found.")

    policy_to_use = req.policy_id or baseline.policy_id
    curr_report = policy_engine.evaluate_capture(curr_analysis, policy_to_use)

    drift_report = drift_engine.compare_drift(req.baseline_id, curr_report)

    audit_service.record_event(
        event_type="DRIFT_COMPARED",
        entity_id=drift_report.drift_report_id,
        entity_type="DRIFT_REPORT",
        data={
            "baseline_id": req.baseline_id,
            "target_id": req.current_capture_id,
            "regression_detected": drift_report.regression_detected,
            "new_violations": drift_report.new_violations_count,
        }
    )
    return drift_report
