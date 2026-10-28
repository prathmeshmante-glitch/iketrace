from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from ..schemas.capture import CaptureAnalysisResult, SessionSummary, PacketSummary
from ..schemas.policy import PolicyEvaluationReport, RuleEvaluationResult
from ..schemas.crypto_inventory import CryptoInventoryReport
from ..schemas.report import AssessmentReport
from ..schemas.traffic_privacy import TrafficFlowFeatures
from ..services.capture_service import capture_service
from ..services.policy_engine import policy_engine
from ..services.crypto_inventory import crypto_inventory_service
from ..services.traffic_privacy import traffic_privacy_service
from ..services.report_service import report_service
from ..services.audit_service import audit_service
from ..repositories.session_repository import session_repository, AnalysisStatus

router = APIRouter(prefix="/analyses", tags=["Analyses"])


class EvaluationRequest(BaseModel):
    policy_id: str = Field(default="POL-DEF-NIST-SP800-77", description="Target policy identifier")


class AnalysisProtocolsResponse(BaseModel):
    analysis_id: str
    total_packets: int
    ike_packets: int
    esp_packets: int
    other_packets: int
    parse_completeness_pct: float
    parser_warnings: List[str]
    packets: List[PacketSummary]


class AnalysisSessionsResponse(BaseModel):
    analysis_id: str
    session_count: int
    sessions: List[SessionSummary]


class AnalysisFindingsResponse(BaseModel):
    analysis_id: str
    policy_id: str
    policy_name: str
    compliance_score_pct: float
    passed_count: int
    failed_count: int
    unknown_count: int
    not_applicable_count: int
    findings: List[RuleEvaluationResult]


class TrafficFlowsResponse(BaseModel):
    analysis_id: str
    flow_count: int
    flows: List[TrafficFlowFeatures]
    flow_classifications: List[Dict[str, Any]]
    is_real_capture: bool
    training_eligible: bool
    limitation_notice: str


@router.get("", response_model=List[CaptureAnalysisResult])
def list_analyses():
    """Retrieve all available persistent analysis sessions."""
    return capture_service.list_analyses()


@router.get("/{analysis_id}", response_model=CaptureAnalysisResult)
def get_analysis(analysis_id: str):
    """Retrieve metadata and high-level statistics for a specific analysis session."""
    analysis = capture_service.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis session '{analysis_id}' not found.")
    return analysis


@router.delete("/{analysis_id}")
def delete_analysis(analysis_id: str):
    """Delete an analysis session and cascade-delete its evaluations, inventories, and reports."""
    deleted = session_repository.delete_analysis(analysis_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Analysis session '{analysis_id}' not found.")
    
    # Also clean in-memory cache if present
    if analysis_id in capture_service.in_memory_results:
        del capture_service.in_memory_results[analysis_id]

    audit_service.record_event(
        event_type="ANALYSIS_DELETED",
        entity_id=analysis_id,
        entity_type="ANALYSIS",
        data={"analysis_id": analysis_id}
    )
    return {"status": "DELETED", "analysis_id": analysis_id}


@router.get("/{analysis_id}/protocols", response_model=AnalysisProtocolsResponse)
def get_analysis_protocols(analysis_id: str):
    """Retrieve parsed protocol observations and packet summaries for the specified analysis session."""
    analysis = capture_service.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis session '{analysis_id}' not found.")
    
    return AnalysisProtocolsResponse(
        analysis_id=analysis.capture_id,
        total_packets=analysis.total_packets,
        ike_packets=analysis.ike_packets,
        esp_packets=analysis.esp_packets,
        other_packets=analysis.other_packets,
        parse_completeness_pct=analysis.parse_completeness_pct,
        parser_warnings=analysis.parser_warnings,
        packets=analysis.packets
    )


@router.get("/{analysis_id}/sessions", response_model=AnalysisSessionsResponse)
def get_analysis_sessions(analysis_id: str):
    """Retrieve extracted IKE and ESP sessions for the specified analysis session."""
    analysis = capture_service.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis session '{analysis_id}' not found.")
    
    return AnalysisSessionsResponse(
        analysis_id=analysis.capture_id,
        session_count=analysis.session_count,
        sessions=analysis.sessions
    )


@router.post("/{analysis_id}/evaluations", response_model=PolicyEvaluationReport)
def evaluate_analysis_policy(analysis_id: str, req: EvaluationRequest):
    """Evaluate a deterministic policy against the specified analysis session and persist results."""
    analysis = capture_service.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis session '{analysis_id}' not found.")

    report = policy_engine.evaluate_capture(analysis, req.policy_id)
    
    # Persist evaluation to SQLite
    try:
        session_repository.save_evaluation(report)
    except Exception:
        pass

    audit_service.record_event(
        event_type="SESSION_POLICY_EVALUATED",
        entity_id=analysis_id,
        entity_type="EVALUATION",
        data={
            "analysis_id": analysis_id,
            "policy_id": req.policy_id,
            "compliance_score_pct": report.compliance_score_pct,
            "passed": report.passed_count,
            "failed": report.failed_count,
        }
    )
    return report


@router.get("/{analysis_id}/evaluations", response_model=List[PolicyEvaluationReport])
def list_analysis_evaluations(analysis_id: str):
    """List all saved policy evaluations for the specified analysis session."""
    analysis = capture_service.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis session '{analysis_id}' not found.")
    
    return session_repository.list_evaluations_for_analysis(analysis_id)


@router.get("/{analysis_id}/findings", response_model=AnalysisFindingsResponse)
def get_analysis_findings(analysis_id: str, policy_id: Optional[str] = Query(default="POL-DEF-NIST-SP800-77")):
    """Retrieve rule-level findings for the specified analysis session and policy."""
    analysis = capture_service.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis session '{analysis_id}' not found.")

    # Check if previously evaluated and persisted
    report = session_repository.get_evaluation(analysis_id, policy_id)
    if not report:
        # Perform deterministic evaluation on demand
        report = policy_engine.evaluate_capture(analysis, policy_id)
        try:
            session_repository.save_evaluation(report)
        except Exception:
            pass

    return AnalysisFindingsResponse(
        analysis_id=analysis_id,
        policy_id=report.policy_id,
        policy_name=report.policy_name,
        compliance_score_pct=report.compliance_score_pct,
        passed_count=report.passed_count,
        failed_count=report.failed_count,
        unknown_count=report.unknown_count,
        not_applicable_count=report.not_applicable_count,
        findings=report.results
    )


@router.get("/{analysis_id}/crypto-inventory", response_model=CryptoInventoryReport)
def get_analysis_crypto_inventory(analysis_id: str):
    """Retrieve or compute cryptographic inventory and PQC readiness score for the specified analysis."""
    analysis = capture_service.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis session '{analysis_id}' not found.")

    cached = session_repository.get_crypto_inventory(analysis_id)
    if cached:
        return cached

    inventory = crypto_inventory_service.inventory_from_capture(analysis)
    try:
        session_repository.save_crypto_inventory(inventory)
    except Exception:
        pass
    return inventory


@router.get("/{analysis_id}/reports", response_model=List[AssessmentReport])
def list_analysis_reports(analysis_id: str):
    """List all assessment reports generated for the specified analysis session."""
    analysis = capture_service.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis session '{analysis_id}' not found.")
    
    return session_repository.list_reports_for_analysis(analysis_id)


@router.get("/{analysis_id}/traffic-flows", response_model=TrafficFlowsResponse)
def get_analysis_traffic_flows(analysis_id: str):
    """Extract real flow features from the specified analysis and classify via ML model."""
    analysis = capture_service.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis session '{analysis_id}' not found.")

    flows = traffic_privacy_service.extract_features_from_capture(analysis)
    classifications = []
    for f in flows:
        pred = traffic_privacy_service.classify_flow(f)
        classifications.append({
            "flow_id": f.flow_id,
            "predicted_class": pred.get("predicted_class"),
            "confidence": pred.get("confidence"),
            "top_features": pred.get("top_contributing_features", [])
        })

    is_eligible = len(flows) >= 30
    notice = (
        "Deterministically extracted flow metadata from active capture. "
        "Classification is inference-only; model benchmark training was performed on controlled synthetic ground truth."
        if not is_eligible
        else "Eligible for fine-tuning experiment."
    )

    return TrafficFlowsResponse(
        analysis_id=analysis_id,
        flow_count=len(flows),
        flows=flows,
        flow_classifications=classifications,
        is_real_capture=True,
        training_eligible=is_eligible,
        limitation_notice=notice
    )
