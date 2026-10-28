from fastapi import APIRouter, HTTPException
from typing import List, Optional
from pydantic import BaseModel

from ..schemas.report import AssessmentReport
from ..services.report_service import report_service
from ..services.capture_service import capture_service
from ..services.scenario_engine import scenario_engine
from ..services.policy_engine import policy_engine
from ..services.crypto_inventory import crypto_inventory_service
from ..services.drift_engine import drift_engine
from ..repositories.session_repository import session_repository

router = APIRouter(prefix="/reports", tags=["Reports"])

class GenerateReportRequest(BaseModel):
    title: str
    target_id: str
    target_type: str = "CAPTURE" # "CAPTURE" or "SCENARIO"
    policy_id: str = "POL-DEF-NIST-SP800-77"
    baseline_id: Optional[str] = None

@router.get("", response_model=List[AssessmentReport])
def list_reports():
    return report_service.list_reports()

@router.get("/{report_id}", response_model=AssessmentReport)
def get_report(report_id: str):
    rep = report_service.get_report(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found.")
    return rep

@router.post("/generate", response_model=AssessmentReport)
def generate_report(req: GenerateReportRequest):
    policy_report = None
    drift_report = None
    crypto_inventory = None

    if req.target_type == "CAPTURE":
        analysis = capture_service.get_analysis(req.target_id)
        if not analysis:
            raise HTTPException(status_code=404, detail=f"Capture {req.target_id} not found.")

        policy_report = policy_engine.evaluate_capture(analysis, req.policy_id)
        crypto_inventory = crypto_inventory_service.inventory_from_capture(analysis)

        if req.baseline_id:
            drift_report = drift_engine.compare_drift(req.baseline_id, policy_report)

    elif req.target_type == "SCENARIO":
        scen_res = scenario_engine.execute_scenario(req.target_id, req.policy_id)
        policy_report = scen_res.policy_report

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported target type: {req.target_type}")

    rep = report_service.generate_assessment_report(
        title=req.title,
        target_id=req.target_id,
        target_type=req.target_type,
        policy_report=policy_report,
        drift_report=drift_report,
        crypto_inventory=crypto_inventory
    )
    if req.target_type == "CAPTURE":
        try:
            session_repository.save_report(rep)
        except Exception:
            pass
    return rep
