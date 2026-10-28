from fastapi import APIRouter, HTTPException
from ..schemas.crypto_inventory import CryptoInventoryReport
from ..services.crypto_inventory import crypto_inventory_service
from ..services.capture_service import capture_service
from ..services.scenario_engine import scenario_engine

router = APIRouter(prefix="/crypto-inventory", tags=["CryptoInventory"])

@router.get("/{target_id}", response_model=CryptoInventoryReport)
def get_inventory(target_id: str):
    # Check if cached
    cached = crypto_inventory_service.get_inventory(target_id)
    if cached:
        return cached

    # Check if capture
    analysis = capture_service.get_analysis(target_id)
    if analysis:
        return crypto_inventory_service.inventory_from_capture(analysis)

    # Check if scenario
    scen = scenario_engine.get_scenario(target_id)
    if scen:
        # Run scenario if needed
        scen_res = scenario_engine.execute_scenario(target_id)
        if scen_res.policy_report:
            # Create synthetic capture analysis for inventory
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
                proposals_chosen=[IKEProposal(proposal_num=1, protocol_id="IKE", transforms=transforms)],
                start_time=0.0,
                end_time=0.0,
            )
            fake_analysis = CaptureAnalysisResult(
                capture_id=target_id,
                filename=f"{target_id}.synthetic",
                file_size_bytes=512,
                uploaded_at="",
                total_packets=1,
                ike_packets=1,
                esp_packets=0,
                other_packets=0,
                session_count=1,
                parse_completeness_pct=100.0,
                sessions=[sess]
            )
            return crypto_inventory_service.inventory_from_capture(fake_analysis)

    raise HTTPException(status_code=404, detail=f"Target ID {target_id} not found in captures or scenarios.")
