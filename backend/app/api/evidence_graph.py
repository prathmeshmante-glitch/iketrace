from fastapi import APIRouter, HTTPException
from typing import Dict, Any, Optional

from ..services.evidence_engine import evidence_graph_engine
from ..services.capture_service import capture_service
from ..services.scenario_engine import scenario_engine
from ..services.policy_engine import policy_engine

router = APIRouter(prefix="/evidence-graph", tags=["EvidenceGraph"])

@router.get("/{target_id}")
def get_evidence_graph(target_id: str, policy_id: Optional[str] = "POL-DEF-NIST-SP800-77") -> Dict[str, Any]:
    # Check if capture
    analysis = capture_service.get_analysis(target_id)
    if analysis:
        policy_report = policy_engine.evaluate_capture(analysis, policy_id)
        return evidence_graph_engine.generate_graph_data(analysis, policy_report, f"Capture: {analysis.filename}")

    # Check if scenario
    scen = scenario_engine.get_scenario(target_id)
    if scen:
        res = scenario_engine.execute_scenario(target_id, policy_id)
        # Construct synthetic analysis representation
        from ..schemas.capture import CaptureAnalysisResult, SessionSummary, IKEProposal, IKETransform
        transforms = [
            IKETransform(
                transform_type=t["type"],
                transform_id=t["id"],
                transform_name=t["name"],
                key_length=t.get("key_len")
            )
            for t in scen.synthetic_input_data.get("transforms", [])
        ]
        sess = SessionSummary(
            session_id=f"synth-{target_id}",
            initiator_ip="192.0.2.1",
            responder_ip="192.0.2.2",
            initiator_port=500,
            responder_port=500,
            ike_version=scen.synthetic_input_data.get("ike_version", "IKEv2"),
            proposals_offered=[IKEProposal(proposal_num=1, protocol_id="IKE", transforms=transforms)],
            evidence_items=res.generated_evidence,
            start_time=0.0,
            end_time=0.0,
            packet_count=2
        )
        fake_analysis = CaptureAnalysisResult(
            capture_id=target_id,
            filename=f"{target_id} (Synthetic)",
            file_size_bytes=1024,
            uploaded_at="",
            total_packets=2,
            ike_packets=2,
            esp_packets=0,
            other_packets=0,
            session_count=1,
            parse_completeness_pct=100.0,
            sessions=[sess],
            evidence_items=res.generated_evidence
        )
        return evidence_graph_engine.generate_graph_data(fake_analysis, res.policy_report, f"Scenario: {scen.name}")

    raise HTTPException(status_code=404, detail=f"Target ID {target_id} not found.")
